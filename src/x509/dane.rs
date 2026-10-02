//! Subphase 11.2a — the `SSL_DANE` representation and `crypto/x509/x509_vfy.c`'s DANE matrix.
//!
//! This unit transcribes two things the verify engine's closure needs and that no earlier unit
//! owned:
//!
//! * **The representation**, from `include/internal/dane.h` — the `danetls_record`,
//!   `dane_ctx_st` and `ssl_dane_st` structures (`:43-77`) and the `DANETLS_*` macro family
//!   (`:79-102`). The usage, selector and matching constants the macros read are the same header's
//!   `:20-41`. `SSL_DANE`'s public spelling is `include/openssl/types.h:170`, and its one extra
//!   public constant, `DANE_FLAG_NO_DANE_EE_NAMECHECKS`, is `include/openssl/x509_vfy.h.in:721`.
//! * **The matrix**, from `crypto/x509/x509_vfy.c:3087-3506` — `dane_i2d`, `dane_match_cert`,
//!   `check_dane_issuer`, `check_dane_pkeys`, `dane_match_rpk`, `dane_reset`, `check_leaf_suiteb`,
//!   `dane_verify_rpk`, `dane_verify` and `get1_trusted_issuer`. `X509_STORE_CTX_set0_dane`
//!   (`:3082-3085`) is **not** re-transcribed: it already landed as an accessor in
//!   [`crate::x509::x509_vfy::X509_STORE_CTX_set0_dane`] and duplicating it would give the crate
//!   two definitions of one authority symbol.
//!
//! ## The `dane` pointer and its one write-scope constraint
//!
//! [`X509StoreCtx`] (`x509_lu.rs`, 11.1a) models `SSL_DANE *dane` as `*mut c_void`, because the SSL
//! layer's type had not landed. Every function here needs the concrete [`SslDane`], so the
//! reinterpretation happens at exactly one place, [`ctx_dane`], which casts the field once and
//! documents why the cast is exact (it is a single pointer). `x509_lu.rs` is **not** edited: its
//! `dane` field stays `*mut c_void`, and the field's declared type is enough for the cast because
//! the two are the same width.
//!
//! ## What is landed, and what is withheld until 11.2
//!
//! Seven of the ten matrix functions land whole: they reach only helpers that are already in the
//! crate ([`dane_i2d`], [`ctx_dane`], `i2d_X509`/`i2d_X509_PUBKEY`/`i2d_PUBKEY`, `EVP_Digest`,
//! `X509_verify`, `X509_up_ref`/`X509_free`, the `OPENSSL_sk_*` stack and `X509_get_X509_PUBKEY`).
//! The remaining three cannot be transcribed faithfully yet and are named, not stubbed, below.
//!
//! * `check_leaf_suiteb` (`x509_vfy.c:3392-3398`) expands `CB_FAIL_IF` (`:174-176`) into a call to
//!   `verify_cb_cert` (`:162-172`). That helper **did** land, but as a *private* `unsafe fn`
//!   (`x509_vfy.rs:1936`), and it is not nameable from a sibling module. Landing `check_leaf_suiteb`
//!   therefore needs one word changed outside this unit's write scope — `pub(crate)` on
//!   `x509_vfy.rs:1936` — and is deferred until that change is made.
//! * `dane_verify_rpk` (`:3401-3428`) calls `verify_rpk` (`:240-247`), and `dane_verify`
//!   (`:3431-3490`) calls `check_id` (`:941`) and `verify_chain` (`:253`). All three are the
//!   withheld engine slice (`src/x509/x509_vfy.rs`'s module doc names them), so neither function
//!   has a callee yet.
//!
//! Each withheld function is listed with its exact authority signature and the precise call that
//! blocks it in the `TODO(11.2)` block at the foot of this file. No stub is declared: a stub would
//! put a name in the crate that the authority defines elsewhere and would silently satisfy a future
//! caller with the wrong body.
//!
//! ## Raise coordinates
//!
//! `crypto/x509/x509_vfy.c` is not in `gen_err_raise_sites.py`'s `COVERED_FILES`, so its two raise
//! coordinates on the landed paths are declared locally in the `err_sites::ErrSite` shape, exactly
//! as `x509_vfy.rs` does. `X509_R_BAD_SELECTOR` is `include/openssl/x509err.h:23` (=133) and
//! `ERR_R_ASN1_LIB` is `err.h`, against `ERR_LIB_X509` = 11 (`include/openssl/err.h.in:85`).
//!
//! SPDX-License-Identifier: Apache-2.0

// The DANE matrix lands ahead of its callers: the engine slice (`build_chain`/`check_trust`) and
// the two `dane_verify*` entry points arrive in subphase 11.2, whose commit reaches every helper
// below. The allowance is removed in that commit.
#![allow(dead_code)]

use core::ffi::{c_int, c_uchar, c_uint, c_ulong, CStr};
use core::mem::{offset_of, size_of};
use core::ptr;

use crate::evp::digest::{EVP_Digest, EvpMd};
use crate::evp::pkey::EvpPkey;
use crate::runtime::bio::sys::memcmp;
use crate::runtime::err::err_sites::ErrSite;
use crate::runtime::err::raise_site;
use crate::runtime::mem::CRYPTO_free;
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_pop, OPENSSL_sk_value, OpenSslStack};
use crate::x509::x509_lu::X509StoreCtx;
use crate::x509::x509_set::{X509_get_X509_PUBKEY, X509_up_ref};
use crate::x509::x_all::X509_verify;
use crate::x509::x_pubkey::{i2d_PUBKEY, i2d_X509_PUBKEY};
use crate::x509::x_x509::{i2d_X509, X509_free, X509};

// ---------------------------------------------------------------------------------------------
// The constants, from `include/internal/dane.h` and the headers it reads.
// ---------------------------------------------------------------------------------------------

/// `ERR_LIB_X509` — `include/openssl/err.h.in:85`.
const ERR_LIB_X509: c_int = 11;
/// `ERR_R_ASN1_LIB` — `err.h`, `(ERR_LIB_ASN1 | ERR_RFLAG_COMMON)`.
const ERR_R_ASN1_LIB: c_int = 13 | (0x2 << 18);
/// `X509_R_BAD_SELECTOR` — `include/openssl/x509err.h:23`, `133`.
const X509_R_BAD_SELECTOR: c_int = 133;

/// `X509_V_OK` — `include/openssl/x509_vfy.h.in:215`, `0`.
const X509_V_OK: c_int = 0;
/// `X509_V_ERR_OUT_OF_MEM` — `include/openssl/x509_vfy.h.in:232`, `17`. Read by the withheld
/// `dane_verify`.
const X509_V_ERR_OUT_OF_MEM: c_int = 17;
/// `X509_V_ERR_DANE_NO_MATCH` — `include/openssl/x509_vfy.h.in:287`, `65`. Read by the withheld
/// `dane_verify_rpk`.
const X509_V_ERR_DANE_NO_MATCH: c_int = 65;

/// `X509_TRUST_TRUSTED` — `include/openssl/x509_vfy.h.in:122`, `1`.
const X509_TRUST_TRUSTED: c_int = 1;
/// `X509_TRUST_UNTRUSTED` — `include/openssl/x509_vfy.h.in:124`, `3`.
const X509_TRUST_UNTRUSTED: c_int = 3;

/// `DANE_FLAG_NO_DANE_EE_NAMECHECKS` — `include/openssl/x509_vfy.h.in:721`, `(1L << 0)`. Read by
/// the withheld `dane_verify`.
const DANE_FLAG_NO_DANE_EE_NAMECHECKS: c_ulong = 1;

/// `EVP_MAX_MD_SIZE` — `include/openssl/evp.h:34`, `64`.
const EVP_MAX_MD_SIZE: usize = 64;

/// `DANETLS_NONE` — `crypto/x509/x509_vfy.c:3117`, `256 /* impossible uint8_t */`.
const DANETLS_NONE: c_uint = 256;

/// `DANETLS_USAGE_PKIX_TA` — `include/internal/dane.h:20`, `0`.
pub(crate) const DANETLS_USAGE_PKIX_TA: u8 = 0;
/// `DANETLS_USAGE_PKIX_EE` — `include/internal/dane.h:21`, `1`.
pub(crate) const DANETLS_USAGE_PKIX_EE: u8 = 1;
/// `DANETLS_USAGE_DANE_TA` — `include/internal/dane.h:22`, `2`.
pub(crate) const DANETLS_USAGE_DANE_TA: u8 = 2;
/// `DANETLS_USAGE_DANE_EE` — `include/internal/dane.h:23`, `3`.
pub(crate) const DANETLS_USAGE_DANE_EE: u8 = 3;
/// `DANETLS_USAGE_LAST` — `include/internal/dane.h:24`, `DANETLS_USAGE_DANE_EE`.
pub(crate) const DANETLS_USAGE_LAST: u8 = DANETLS_USAGE_DANE_EE;

/// `DANETLS_SELECTOR_CERT` — `include/internal/dane.h:30`, `0`.
pub(crate) const DANETLS_SELECTOR_CERT: u8 = 0;
/// `DANETLS_SELECTOR_SPKI` — `include/internal/dane.h:31`, `1`.
pub(crate) const DANETLS_SELECTOR_SPKI: u8 = 1;
/// `DANETLS_SELECTOR_LAST` — `include/internal/dane.h:32`, `DANETLS_SELECTOR_SPKI`.
pub(crate) const DANETLS_SELECTOR_LAST: u8 = DANETLS_SELECTOR_SPKI;

/// `DANETLS_MATCHING_FULL` — `include/internal/dane.h:38`, `0`.
pub(crate) const DANETLS_MATCHING_FULL: u8 = 0;
/// `DANETLS_MATCHING_2256` — `include/internal/dane.h:39`, `1`.
pub(crate) const DANETLS_MATCHING_2256: u8 = 1;
/// `DANETLS_MATCHING_2512` — `include/internal/dane.h:40`, `2`.
pub(crate) const DANETLS_MATCHING_2512: u8 = 2;
/// `DANETLS_MATCHING_LAST` — `include/internal/dane.h:41`, `DANETLS_MATCHING_2512`.
pub(crate) const DANETLS_MATCHING_LAST: u8 = DANETLS_MATCHING_2512;

/// `DANETLS_USAGE_BIT(u)` — `include/internal/dane.h:82`, `(((uint32_t)1) << u)`.
///
/// Callers pass `t->usage`, which `dane_tlsa_add` has already bounded by `DANETLS_USAGE_LAST`
/// (`ssl/ssl_lib.c:296`), so `u` is in `0..=3` at every reachable call.
pub(crate) const fn danetls_usage_bit(u: u32) -> u32 {
    (1u32) << u
}

/// `DANETLS_PKIX_TA_MASK` — `include/internal/dane.h:84`, `DANETLS_USAGE_BIT(DANETLS_USAGE_PKIX_TA)`.
pub(crate) const DANETLS_PKIX_TA_MASK: u32 = danetls_usage_bit(DANETLS_USAGE_PKIX_TA as u32);
/// `DANETLS_PKIX_EE_MASK` — `include/internal/dane.h:85`, `DANETLS_USAGE_BIT(DANETLS_USAGE_PKIX_EE)`.
pub(crate) const DANETLS_PKIX_EE_MASK: u32 = danetls_usage_bit(DANETLS_USAGE_PKIX_EE as u32);
/// `DANETLS_DANE_TA_MASK` — `include/internal/dane.h:86`, `DANETLS_USAGE_BIT(DANETLS_USAGE_DANE_TA)`.
pub(crate) const DANETLS_DANE_TA_MASK: u32 = danetls_usage_bit(DANETLS_USAGE_DANE_TA as u32);
/// `DANETLS_DANE_EE_MASK` — `include/internal/dane.h:87`, `DANETLS_USAGE_BIT(DANETLS_USAGE_DANE_EE)`.
pub(crate) const DANETLS_DANE_EE_MASK: u32 = danetls_usage_bit(DANETLS_USAGE_DANE_EE as u32);

/// `DANETLS_PKIX_MASK` — `include/internal/dane.h:89`.
pub(crate) const DANETLS_PKIX_MASK: u32 = DANETLS_PKIX_TA_MASK | DANETLS_PKIX_EE_MASK;
/// `DANETLS_DANE_MASK` — `include/internal/dane.h:90`.
pub(crate) const DANETLS_DANE_MASK: u32 = DANETLS_DANE_TA_MASK | DANETLS_DANE_EE_MASK;
/// `DANETLS_TA_MASK` — `include/internal/dane.h:91`.
pub(crate) const DANETLS_TA_MASK: u32 = DANETLS_PKIX_TA_MASK | DANETLS_DANE_TA_MASK;
/// `DANETLS_EE_MASK` — `include/internal/dane.h:92`.
pub(crate) const DANETLS_EE_MASK: u32 = DANETLS_PKIX_EE_MASK | DANETLS_DANE_EE_MASK;

// ---------------------------------------------------------------------------------------------
// The representation — `include/internal/dane.h:43-77`.
// ---------------------------------------------------------------------------------------------

/// `danetls_record` — `include/internal/dane.h:43-50`.
///
/// One parsed TLSA record. `data`/`dlen` hold the association data and `spki`, when non-NULL,
/// holds the decoded trust-anchor public key a DANE-TA(2) SPKI record matched.
#[repr(C)]
pub(crate) struct DanetlsRecord {
    /// `uint8_t usage` — one of `DANETLS_USAGE_*`.
    pub(crate) usage: u8,
    /// `uint8_t selector` — one of `DANETLS_SELECTOR_*`.
    pub(crate) selector: u8,
    /// `uint8_t mtype` — one of `DANETLS_MATCHING_*`.
    pub(crate) mtype: u8,
    /// `unsigned char *data` — the association data.
    pub(crate) data: *mut c_uchar,
    /// `size_t dlen` — the association data length.
    pub(crate) dlen: usize,
    /// `EVP_PKEY *spki` — the decoded public key, for a DANE-TA(2) SPKI(1) Full(0) record.
    pub(crate) spki: *mut EvpPkey,
}

const _: () = {
    assert!(size_of::<DanetlsRecord>() == 32);
    assert!(offset_of!(DanetlsRecord, usage) == 0);
    assert!(offset_of!(DanetlsRecord, selector) == 1);
    assert!(offset_of!(DanetlsRecord, mtype) == 2);
    assert!(offset_of!(DanetlsRecord, data) == 8);
    assert!(offset_of!(DanetlsRecord, dlen) == 16);
    assert!(offset_of!(DanetlsRecord, spki) == 24);
};

/// `struct dane_ctx_st` — `include/internal/dane.h:57-62`.
///
/// The shared, per-application DANE context: the digest table indexed by matching type, the
/// preference order that drives digest agility, the highest supported matching type and the
/// feature bits.
#[repr(C)]
pub(crate) struct DaneCtx {
    /// `const EVP_MD **mdevp` — `mtype -> digest`.
    pub(crate) mdevp: *mut *const EvpMd,
    /// `uint8_t *mdord` — `mtype -> preference`.
    pub(crate) mdord: *mut u8,
    /// `uint8_t mdmax` — the highest supported `mtype`.
    pub(crate) mdmax: u8,
    /// `unsigned long flags` — the feature bitmask.
    pub(crate) flags: c_ulong,
}

const _: () = {
    assert!(size_of::<DaneCtx>() == 32);
    assert!(offset_of!(DaneCtx, mdevp) == 0);
    assert!(offset_of!(DaneCtx, mdord) == 8);
    assert!(offset_of!(DaneCtx, mdmax) == 16);
    assert!(offset_of!(DaneCtx, flags) == 24);
};

/// `struct ssl_dane_st` — `include/internal/dane.h:67-77`.
///
/// The per-connection DANE state, installed on an `X509_STORE_CTX` by
/// [`crate::x509::x509_vfy::X509_STORE_CTX_set0_dane`] and read here.
#[repr(C)]
pub(crate) struct SslDane {
    /// `struct dane_ctx_st *dctx` — the shared context.
    pub(crate) dctx: *mut DaneCtx,
    /// `STACK_OF(danetls_record) *trecs` — the TLSA records.
    pub(crate) trecs: *mut OpenSslStack,
    /// `STACK_OF(X509) *certs` — the DANE-TA(2) Cert(0) Full(0) certificates.
    pub(crate) certs: *mut OpenSslStack,
    /// `danetls_record *mtlsa` — the matching TLSA record.
    pub(crate) mtlsa: *mut DanetlsRecord,
    /// `X509 *mcert` — the DANE-matched certificate.
    pub(crate) mcert: *mut X509,
    /// `uint32_t umask` — the usages present.
    pub(crate) umask: u32,
    /// `int mdpth` — the depth of the matched certificate.
    pub(crate) mdpth: c_int,
    /// `int pdpth` — the depth of the PKIX trust anchor.
    pub(crate) pdpth: c_int,
    /// `unsigned long flags` — the feature bitmask.
    pub(crate) flags: c_ulong,
}

const _: () = {
    assert!(size_of::<SslDane>() == 64);
    assert!(offset_of!(SslDane, dctx) == 0);
    assert!(offset_of!(SslDane, trecs) == 8);
    assert!(offset_of!(SslDane, certs) == 16);
    assert!(offset_of!(SslDane, mtlsa) == 24);
    assert!(offset_of!(SslDane, mcert) == 32);
    assert!(offset_of!(SslDane, umask) == 40);
    assert!(offset_of!(SslDane, mdpth) == 44);
    assert!(offset_of!(SslDane, pdpth) == 48);
    assert!(offset_of!(SslDane, flags) == 56);
};

// ---------------------------------------------------------------------------------------------
// The macro family — `include/internal/dane.h:79-102`.
// ---------------------------------------------------------------------------------------------

/// `DANETLS_ENABLED(dane)` — `include/internal/dane.h:79-80`.
///
/// `((dane) != NULL && sk_danetls_record_num((dane)->trecs) > 0)`. The authority returns an `int`;
/// this answers the predicate, since every caller uses it in a truth test.
///
/// # Safety
///
/// `dane` must be NULL or a live [`SslDane`], and when non-NULL its `trecs` must be a live stack.
pub(crate) unsafe fn danetls_enabled(dane: *mut SslDane) -> bool {
    !dane.is_null()
        // SAFETY: `dane` is non-NULL and live per the contract, so `trecs` is a live stack.
        && unsafe { OPENSSL_sk_num((*dane).trecs) } > 0
}

/// `DANETLS_HAS_PKIX(dane)` — `include/internal/dane.h:94`.
///
/// # Safety
///
/// `dane` must be NULL or a live [`SslDane`].
pub(crate) unsafe fn danetls_has_pkix(dane: *mut SslDane) -> bool {
    // SAFETY: `dane` is NULL or live per the contract; the NULL half short-circuits.
    !dane.is_null() && (unsafe { (*dane).umask } & DANETLS_PKIX_MASK) != 0
}

/// `DANETLS_HAS_DANE(dane)` — `include/internal/dane.h:95`.
///
/// # Safety
///
/// `dane` must be NULL or a live [`SslDane`].
pub(crate) unsafe fn danetls_has_dane(dane: *mut SslDane) -> bool {
    // SAFETY: `dane` is NULL or live per the contract; the NULL half short-circuits.
    !dane.is_null() && (unsafe { (*dane).umask } & DANETLS_DANE_MASK) != 0
}

/// `DANETLS_HAS_TA(dane)` — `include/internal/dane.h:96`.
///
/// # Safety
///
/// `dane` must be NULL or a live [`SslDane`].
pub(crate) unsafe fn danetls_has_ta(dane: *mut SslDane) -> bool {
    // SAFETY: `dane` is NULL or live per the contract; the NULL half short-circuits.
    !dane.is_null() && (unsafe { (*dane).umask } & DANETLS_TA_MASK) != 0
}

/// `DANETLS_HAS_EE(dane)` — `include/internal/dane.h:97`.
///
/// # Safety
///
/// `dane` must be NULL or a live [`SslDane`].
pub(crate) unsafe fn danetls_has_ee(dane: *mut SslDane) -> bool {
    // SAFETY: `dane` is NULL or live per the contract; the NULL half short-circuits.
    !dane.is_null() && (unsafe { (*dane).umask } & DANETLS_EE_MASK) != 0
}

/// `DANETLS_HAS_PKIX_TA(dane)` — `include/internal/dane.h:99`.
///
/// # Safety
///
/// `dane` must be NULL or a live [`SslDane`].
pub(crate) unsafe fn danetls_has_pkix_ta(dane: *mut SslDane) -> bool {
    // SAFETY: `dane` is NULL or live per the contract; the NULL half short-circuits.
    !dane.is_null() && (unsafe { (*dane).umask } & DANETLS_PKIX_TA_MASK) != 0
}

/// `DANETLS_HAS_PKIX_EE(dane)` — `include/internal/dane.h:100`.
///
/// # Safety
///
/// `dane` must be NULL or a live [`SslDane`].
pub(crate) unsafe fn danetls_has_pkix_ee(dane: *mut SslDane) -> bool {
    // SAFETY: `dane` is NULL or live per the contract; the NULL half short-circuits.
    !dane.is_null() && (unsafe { (*dane).umask } & DANETLS_PKIX_EE_MASK) != 0
}

/// `DANETLS_HAS_DANE_TA(dane)` — `include/internal/dane.h:101`.
///
/// # Safety
///
/// `dane` must be NULL or a live [`SslDane`].
pub(crate) unsafe fn danetls_has_dane_ta(dane: *mut SslDane) -> bool {
    // SAFETY: `dane` is NULL or live per the contract; the NULL half short-circuits.
    !dane.is_null() && (unsafe { (*dane).umask } & DANETLS_DANE_TA_MASK) != 0
}

/// `DANETLS_HAS_DANE_EE(dane)` — `include/internal/dane.h:102`.
///
/// # Safety
///
/// `dane` must be NULL or a live [`SslDane`].
pub(crate) unsafe fn danetls_has_dane_ee(dane: *mut SslDane) -> bool {
    // SAFETY: `dane` is NULL or live per the contract; the NULL half short-circuits.
    !dane.is_null() && (unsafe { (*dane).umask } & DANETLS_DANE_EE_MASK) != 0
}

// ---------------------------------------------------------------------------------------------
// The raise coordinates — `x509_vfy.c`, declared locally (see the module doc).
// ---------------------------------------------------------------------------------------------

/// `OPENSSL_FILE` for this unit's allocator expansions.
const FILE: &CStr = c"crypto/x509/x509_vfy.c";

/// One `x509_vfy.c` raise coordinate, declared locally (as `x509_vfy.rs` does).
const fn dane_site(line: c_int, func: &'static CStr, reason: c_int) -> ErrSite {
    ErrSite {
        file: c"../../src/openssl-3.6.4/crypto/x509/x509_vfy.c",
        line,
        func,
        lib: ERR_LIB_X509,
        reason,
        dynamic_reason: false,
    }
}

/// `dane_i2d`'s unknown selector at `x509_vfy.c:3104`.
const DANE_3104: ErrSite = dane_site(3104, c"dane_i2d", X509_R_BAD_SELECTOR);
/// `dane_i2d`'s failed ASN.1 encode at `x509_vfy.c:3109`.
const DANE_3109: ErrSite = dane_site(3109, c"dane_i2d", ERR_R_ASN1_LIB);

// ---------------------------------------------------------------------------------------------
// The single choke point for the opaque `dane` field.
// ---------------------------------------------------------------------------------------------

/// Reads `ctx->dane` as the concrete [`SslDane`].
///
/// `X509StoreCtx` (`x509_lu.rs`, 11.1a) models `SSL_DANE *dane` as `*mut c_void` because the SSL
/// layer's type had not landed when the context layout was defined. Both are single pointers, so
/// the reinterpretation is exact; this function is the one place it is written, and `x509_lu.rs`
/// is deliberately left untouched.
///
/// # Safety
///
/// `ctx` must be live, and its `dane` must be NULL or a live `SSL_DANE` installed by
/// [`crate::x509::x509_vfy::X509_STORE_CTX_set0_dane`]. A non-NULL value is required by every
/// caller here, because the engine reaches the matrix only behind `DANETLS_ENABLED`.
unsafe fn ctx_dane(ctx: *mut X509StoreCtx) -> *mut SslDane {
    // SAFETY: `ctx` is live per the contract, so its `dane` field is readable; the field holds an
    // `SSL_DANE *`, and `SslDane` is its `#[repr(C)]` transcription.
    unsafe { (*ctx).dane.cast::<SslDane>() }
}

// ---------------------------------------------------------------------------------------------
// `dane_i2d` — `crypto/x509/x509_vfy.c:3087-3115`.
// ---------------------------------------------------------------------------------------------

/// `static unsigned char *dane_i2d(X509 *cert, uint8_t selector, unsigned int *i2dlen)` —
/// `crypto/x509/x509_vfy.c:3087-3115`.
///
/// Extracts the ASN.1 DER form of `cert` (selector `CERT`) or of its `SubjectPublicKeyInfo`
/// (selector `SPKI`), writing the length through `i2dlen`. Returns an allocator-owned buffer, or
/// NULL after raising. An unknown selector raises `X509_R_BAD_SELECTOR`; a negative or empty encode
/// raises `ERR_R_ASN1_LIB`.
///
/// # Safety
///
/// `cert` must be live; `i2dlen` must be writable.
pub(crate) unsafe extern "C" fn dane_i2d(
    cert: *mut X509,
    selector: u8,
    i2dlen: *mut c_uint,
) -> *mut c_uchar {
    let mut buf: *mut c_uchar = ptr::null_mut();

    let len: c_int = match selector {
        DANETLS_SELECTOR_CERT => {
            // SAFETY: `cert` is live and `buf` is a writable local.
            unsafe { i2d_X509(cert, &raw mut buf) }
        }
        DANETLS_SELECTOR_SPKI => {
            // SAFETY: `cert` is live, so `X509_get_X509_PUBKEY` reads its own field; `buf` is a
            // writable local.
            unsafe { i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &raw mut buf) }
        }
        _ => {
            // SAFETY: the site's pointers are static.
            unsafe { raise_site(&DANE_3104) };
            return ptr::null_mut();
        }
    };

    if len < 0 || buf.is_null() {
        // SAFETY: the site's pointers are static.
        unsafe { raise_site(&DANE_3109) };
        return ptr::null_mut();
    }

    // SAFETY: `i2dlen` is writable per the contract.
    unsafe { *i2dlen = len as c_uint };
    buf
}

// ---------------------------------------------------------------------------------------------
// `dane_match_cert` — `crypto/x509/x509_vfy.c:3120-3263`.
// ---------------------------------------------------------------------------------------------

/// `static int dane_match_cert(X509_STORE_CTX *ctx, X509 *cert, int depth)` —
/// `crypto/x509/x509_vfy.c:3120-3263`.
///
/// Returns `1` on a dispositive DANE-?? match, `0` when no record matched (or only a PKIX-?? record
/// was recorded, which still requires a chain), and `-1` on internal error. The scan is the digest
/// agility of RFC 7671 section 9: the mask is narrowed by depth and by a prior PKIX match, records
/// are considered in the stack's order (DANE usages before PKIX usages, matching digests before
/// lower priorities), and the certificate or SPKI DER is regenerated only when the selector
/// changes. A match squirrels away `mcert`/`mdpth`/`mtlsa`; a DANE match is dispositive, a PKIX
/// match is not.
///
/// # Safety
///
/// `ctx` must be live with a live `dane` and a live `chain`; `cert` must be live.
pub(crate) unsafe extern "C" fn dane_match_cert(
    ctx: *mut X509StoreCtx,
    cert: *mut X509,
    depth: c_int,
) -> c_int {
    // SAFETY: `ctx` is live with a live `dane` per the contract.
    let dane = unsafe { ctx_dane(ctx) };
    let mut usage: c_uint = DANETLS_NONE;
    let mut selector: c_uint = DANETLS_NONE;
    let mut ordinal: c_uint = DANETLS_NONE;
    let mut mtype: c_uint = DANETLS_NONE;
    let mut i2dbuf: *mut c_uchar = ptr::null_mut();
    let mut i2dlen: c_uint = 0;
    let mut mdbuf = [0u8; EVP_MAX_MD_SIZE];
    let mut cmpbuf: *mut c_uchar = ptr::null_mut();
    let mut cmplen: c_uint = 0;
    let mut matched: c_int = 0;

    let mut mask: u32 = if depth == 0 {
        DANETLS_EE_MASK
    } else {
        DANETLS_TA_MASK
    };

    // The trust store is not applicable with DANE-TA(2).
    // SAFETY: `ctx` is live per the contract.
    if depth >= unsafe { (*ctx).num_untrusted } {
        mask &= DANETLS_PKIX_MASK;
    }

    // If we've previously matched a PKIX-?? record, no need to test any further PKIX-?? records.
    // SAFETY: `dane` is live per the contract.
    if unsafe { (*dane).mdpth } >= 0 {
        mask &= !DANETLS_PKIX_MASK;
    }

    // SAFETY: `dane` is live, so `umask` and `trecs` are readable; `trecs` is a live stack.
    let recnum: c_int = unsafe {
        if ((*dane).umask & mask) != 0 {
            OPENSSL_sk_num((*dane).trecs)
        } else {
            0
        }
    };

    let mut i: c_int = 0;
    while matched == 0 && i < recnum {
        // SAFETY: `trecs` is a live stack and `i` is in range.
        let t = unsafe { OPENSSL_sk_value((*dane).trecs, i) }.cast::<DanetlsRecord>();
        // SAFETY: `t` is a live record from the stack.
        if (danetls_usage_bit(u32::from(unsafe { (*t).usage })) & mask) == 0 {
            i += 1;
            continue;
        }
        // SAFETY: `t` is live.
        if u32::from(unsafe { (*t).usage }) != usage {
            // SAFETY: `t` is live.
            usage = u32::from(unsafe { (*t).usage });
            mtype = DANETLS_NONE;
            // SAFETY: `dane` is live, so `dctx` and its digest-order table are live.
            ordinal = u32::from(unsafe { *(*(*dane).dctx).mdord.add((*t).mtype as usize) });
        }
        // SAFETY: `t` is live.
        if u32::from(unsafe { (*t).selector }) != selector {
            // SAFETY: `t` is live.
            selector = u32::from(unsafe { (*t).selector });

            // Update per-selector state.
            // SAFETY: `i2dbuf` is NULL or came from `dane_i2d` and is not owned elsewhere.
            unsafe { CRYPTO_free(i2dbuf.cast(), FILE.as_ptr(), 3196) };
            // SAFETY: `cert` is live and `i2dlen` is a writable local; `t` is live.
            i2dbuf = unsafe { dane_i2d(cert, (*t).selector, &raw mut i2dlen) };
            if i2dbuf.is_null() {
                return -1;
            }

            // Reset digest agility for each usage/selector pair.
            mtype = DANETLS_NONE;
            // SAFETY: `dane` is live, so `dctx` and its digest-order table are live.
            ordinal = u32::from(unsafe { *(*(*dane).dctx).mdord.add((*t).mtype as usize) });
        } else {
            // Digest agility: for a fixed selector, ignore mtypes with lower ordinals than the
            // highest processed, other than Full.
            // SAFETY: `t` is live.
            if unsafe { (*t).mtype } != DANETLS_MATCHING_FULL {
                // SAFETY: `dane` is live, so `dctx` and its digest-order table are live; `t` is live.
                if u32::from(unsafe { *(*(*dane).dctx).mdord.add((*t).mtype as usize) }) < ordinal {
                    i += 1;
                    continue;
                }
            }
        }

        // Each time we hit a (new selector or) mtype, re-compute the relevant digest.
        // SAFETY: `t` is live.
        if u32::from(unsafe { (*t).mtype }) != mtype {
            // SAFETY: `t` is live.
            mtype = u32::from(unsafe { (*t).mtype });
            // SAFETY: `dane` is live, so `dctx` and its digest table are live; `mtype` indexes it.
            let md = unsafe { *(*(*dane).dctx).mdevp.add(mtype as usize) };

            cmpbuf = i2dbuf;
            cmplen = i2dlen;

            if !md.is_null() {
                cmpbuf = mdbuf.as_mut_ptr();
                // SAFETY: `i2dbuf` is `i2dlen` readable bytes; `cmpbuf` is `EVP_MAX_MD_SIZE` bytes
                // and `md` is a live digest; `cmplen` is writable.
                if unsafe {
                    EVP_Digest(
                        i2dbuf.cast(),
                        i2dlen as usize,
                        cmpbuf,
                        &raw mut cmplen,
                        md,
                        ptr::null_mut(),
                    )
                } == 0
                {
                    matched = -1;
                    break;
                }
            }
        }

        // Squirrel away the certificate and depth if we have a match.
        // SAFETY: `t` is live, so its `data`/`dlen` describe a readable buffer; `cmpbuf` is readable
        // for `cmplen` bytes.
        if unsafe {
            cmplen == (*t).dlen as c_uint
                && memcmp(cmpbuf.cast(), (*t).data.cast(), cmplen as usize) == 0
        } {
            if (danetls_usage_bit(usage) & DANETLS_DANE_MASK) != 0 {
                matched = 1;
            }
            // SAFETY: `dane` is live.
            if matched != 0 || unsafe { (*dane).mdpth } < 0 {
                // SAFETY: `cert` is live per the contract.
                if unsafe { X509_up_ref(cert) } == 0 {
                    matched = -1;
                    break;
                }

                // SAFETY: `dane` is live; `mcert` is NULL or a reference this context owns.
                unsafe {
                    X509_free((*dane).mcert);
                    (*dane).mcert = cert;
                    (*dane).mdpth = depth;
                    (*dane).mtlsa = t;
                }
            }
            break;
        }
        i += 1;
    }

    // Clear the one-element DER cache.
    // SAFETY: `i2dbuf` is NULL or came from `dane_i2d` and is not owned elsewhere.
    unsafe { CRYPTO_free(i2dbuf.cast(), FILE.as_ptr(), 3261) };
    matched
}

// ---------------------------------------------------------------------------------------------
// `check_dane_issuer` — `crypto/x509/x509_vfy.c:3266-3289`.
// ---------------------------------------------------------------------------------------------

/// `static int check_dane_issuer(X509_STORE_CTX *ctx, int depth)` —
/// `crypto/x509/x509_vfy.c:3266-3289`.
///
/// Returns `X509_TRUST_TRUSTED`, `X509_TRUST_UNTRUSTED`, or `-1` on internal error. When the depth
/// is not 0 and any TA usage is present, it records any DANE trust-anchor match at `depth` for the
/// first depth that has one, pruning `num_untrusted` to just below that depth.
///
/// # Safety
///
/// `ctx` must be live with a live `dane` and a live `chain`.
pub(crate) unsafe extern "C" fn check_dane_issuer(ctx: *mut X509StoreCtx, depth: c_int) -> c_int {
    // SAFETY: `ctx` is live with a live `dane` per the contract.
    let dane = unsafe { ctx_dane(ctx) };
    let mut matched: c_int = 0;

    // SAFETY: `dane` is live per the contract.
    if !unsafe { danetls_has_ta(dane) } || depth == 0 {
        return X509_TRUST_UNTRUSTED;
    }

    // SAFETY: `chain` is a live stack and `depth` is in range for the engine's caller.
    let cert = unsafe { OPENSSL_sk_value((*ctx).chain, depth) }.cast::<X509>();
    if !cert.is_null() {
        // SAFETY: `ctx` is live and `cert` is live.
        matched = unsafe { dane_match_cert(ctx, cert, depth) };
        if matched < 0 {
            return matched;
        }
    }
    if matched > 0 {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).num_untrusted = depth - 1 };
        return X509_TRUST_TRUSTED;
    }

    X509_TRUST_UNTRUSTED
}

// ---------------------------------------------------------------------------------------------
// `check_dane_pkeys` — `crypto/x509/x509_vfy.c:3291-3323`.
// ---------------------------------------------------------------------------------------------

/// `static int check_dane_pkeys(X509_STORE_CTX *ctx)` —
/// `crypto/x509/x509_vfy.c:3291-3323`.
///
/// Returns `X509_TRUST_TRUSTED` or `X509_TRUST_UNTRUSTED`. For each DANE-TA(2) SPKI(1) Full(0)
/// record whose stored public key verifies the last untrusted certificate, it clears any prior
/// PKIX match, records the bare-trust-anchor match, prunes the chain down to `num_untrusted`, and
/// reports trusted.
///
/// # Safety
///
/// `ctx` must be live with a live `dane` and a live `chain` holding at least `num_untrusted`
/// certificates.
pub(crate) unsafe extern "C" fn check_dane_pkeys(ctx: *mut X509StoreCtx) -> c_int {
    // SAFETY: `ctx` is live with a live `dane` per the contract.
    let dane = unsafe { ctx_dane(ctx) };
    // SAFETY: `ctx` is live.
    let mut num = unsafe { (*ctx).num_untrusted };
    // SAFETY: `chain` is live and holds at least `num` certificates per the contract.
    let cert = unsafe { OPENSSL_sk_value((*ctx).chain, num - 1) }.cast::<X509>();
    // SAFETY: `dane` is live, so `trecs` is a live stack.
    let recnum = unsafe { OPENSSL_sk_num((*dane).trecs) };

    let mut i: c_int = 0;
    while i < recnum {
        // SAFETY: `trecs` is a live stack and `i` is in range.
        let t = unsafe { OPENSSL_sk_value((*dane).trecs, i) }.cast::<DanetlsRecord>();
        // SAFETY: `t` is a live record; `cert` is live and `t->spki` is its decoded key.
        if unsafe {
            (*t).usage != DANETLS_USAGE_DANE_TA
                || (*t).selector != DANETLS_SELECTOR_SPKI
                || (*t).mtype != DANETLS_MATCHING_FULL
                || X509_verify(cert, (*t).spki) <= 0
        } {
            i += 1;
            continue;
        }

        // SAFETY: `dane` and `ctx` are live.
        unsafe {
            // Clear any PKIX-?? matches that failed to extend to a full chain.
            X509_free((*dane).mcert);
            (*dane).mcert = ptr::null_mut();

            // Record match via a bare TA public key.
            (*ctx).bare_ta_signed = 1;
            (*dane).mdpth = num - 1;
            (*dane).mtlsa = t;
        }

        // Prune any excess chain certificates.
        // SAFETY: `ctx` is live, so `chain` is a live stack.
        num = unsafe { OPENSSL_sk_num((*ctx).chain) };
        // SAFETY: `ctx` is live.
        let untrusted = unsafe { (*ctx).num_untrusted };
        while num > untrusted {
            // SAFETY: `chain` is a live stack with `num` elements; the popped value is an owned
            // certificate this context no longer holds.
            unsafe { X509_free(OPENSSL_sk_pop((*ctx).chain).cast::<X509>()) };
            num -= 1;
        }

        return X509_TRUST_TRUSTED;
    }

    X509_TRUST_UNTRUSTED
}

// ---------------------------------------------------------------------------------------------
// `dane_match_rpk` — `crypto/x509/x509_vfy.c:3329-3379`.
// ---------------------------------------------------------------------------------------------

/// `static int dane_match_rpk(X509_STORE_CTX *ctx, EVP_PKEY *rpk)` —
/// `crypto/x509/x509_vfy.c:3329-3379`.
///
/// Returns `1` on a match, `0` when none, and `-1` on internal error. It encodes the raw public
/// key's DER once and scans the record stack for a DANE-EE(3) SPKI(1) record, re-hashing only when
/// the matching type changes. Because only DANE-EE and SPKI are supported, one of each field is a
/// sufficient filter.
///
/// # Safety
///
/// `ctx` must be live with a live `dane`; `rpk` must be live.
pub(crate) unsafe extern "C" fn dane_match_rpk(ctx: *mut X509StoreCtx, rpk: *mut EvpPkey) -> c_int {
    // SAFETY: `ctx` is live with a live `dane` per the contract.
    let dane = unsafe { ctx_dane(ctx) };
    let mut mtype: c_int = c_int::from(DANETLS_MATCHING_FULL);
    let mut i2dbuf: *mut c_uchar = ptr::null_mut();
    let mut mdbuf = [0u8; EVP_MAX_MD_SIZE];
    // SAFETY: `dane` is live, so `trecs` is a live stack.
    let recnum = unsafe { OPENSSL_sk_num((*dane).trecs) };
    let mut matched: c_int = 0;

    // Calculate ASN.1 DER of RPK.
    // SAFETY: `rpk` is live and `i2dbuf` is a writable local.
    let len = unsafe { i2d_PUBKEY(rpk, &raw mut i2dbuf) };
    if len <= 0 {
        return -1;
    }
    let i2dlen = len as c_uint;
    let mut cmplen = len as c_uint;
    let mut cmpbuf = i2dbuf;

    let mut i: c_int = 0;
    while i < recnum {
        // SAFETY: `trecs` is a live stack and `i` is in range.
        let t = unsafe { OPENSSL_sk_value((*dane).trecs, i) }.cast::<DanetlsRecord>();
        // SAFETY: `t` is a live record.
        if unsafe { (*t).usage != DANETLS_USAGE_DANE_EE || (*t).selector != DANETLS_SELECTOR_SPKI }
        {
            i += 1;
            continue;
        }

        // Calculate hash - keep only one around.
        // SAFETY: `t` is live.
        if c_int::from(unsafe { (*t).mtype }) != mtype {
            // SAFETY: `t` is live.
            mtype = c_int::from(unsafe { (*t).mtype });
            // SAFETY: `dane` is live, so `dctx` and its digest table are live; `mtype` indexes it.
            let md = unsafe { *(*(*dane).dctx).mdevp.add(mtype as usize) };

            cmpbuf = i2dbuf;
            cmplen = i2dlen;

            if !md.is_null() {
                cmpbuf = mdbuf.as_mut_ptr();
                // SAFETY: `i2dbuf` is `i2dlen` readable bytes; `cmpbuf` is `EVP_MAX_MD_SIZE` bytes
                // and `md` is a live digest; `cmplen` is writable.
                if unsafe {
                    EVP_Digest(
                        i2dbuf.cast(),
                        i2dlen as usize,
                        cmpbuf,
                        &raw mut cmplen,
                        md,
                        ptr::null_mut(),
                    )
                } == 0
                {
                    matched = -1;
                    break;
                }
            }
        }
        // SAFETY: `t` is live, so its `data`/`dlen` describe a readable buffer; `cmpbuf` is readable
        // for `cmplen` bytes.
        if unsafe {
            cmplen == (*t).dlen as c_uint
                && memcmp(cmpbuf.cast(), (*t).data.cast(), cmplen as usize) == 0
        } {
            matched = 1;
            // SAFETY: `dane` is live; `t` is a live record from its stack.
            unsafe {
                (*dane).mdpth = 0;
                (*dane).mtlsa = t;
            }
            break;
        }
        i += 1;
    }
    // SAFETY: `i2dbuf` came from `i2d_PUBKEY` and is not owned elsewhere.
    unsafe { CRYPTO_free(i2dbuf.cast(), FILE.as_ptr(), 3377) };
    matched
}

// ---------------------------------------------------------------------------------------------
// `dane_reset` — `crypto/x509/x509_vfy.c:3381-3389`.
// ---------------------------------------------------------------------------------------------

/// `static void dane_reset(SSL_DANE *dane)` — `crypto/x509/x509_vfy.c:3381-3389`.
///
/// Resets the per-connection DANE state so another chain can be verified, or the state cleared
/// after a failure: the matched certificate reference is released, the matching record dropped and
/// both recorded depths set to `-1`.
///
/// # Safety
///
/// `dane` must be live, and its `mcert` must be NULL or a reference this context owns.
pub(crate) unsafe extern "C" fn dane_reset(dane: *mut SslDane) {
    // SAFETY: `dane` is live per the contract; `mcert` is NULL or a reference this context owns.
    unsafe {
        X509_free((*dane).mcert);
        (*dane).mcert = ptr::null_mut();
        (*dane).mtlsa = ptr::null_mut();
        (*dane).mdpth = -1;
        (*dane).pdpth = -1;
    }
}

// ---------------------------------------------------------------------------------------------
// `get1_trusted_issuer` — `crypto/x509/x509_vfy.c:3496-3506`.
// ---------------------------------------------------------------------------------------------

/// `static int get1_trusted_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *cert)` —
/// `crypto/x509/x509_vfy.c:3496-3506`.
///
/// Fetches the trusted issuer without duplicate suppression: it temporarily clears `ctx->chain` so
/// the issuer lookup cannot see the chain under construction, calls `ctx->get_issuer`, and restores
/// the chain. Returns the lookup's value, `-1` on internal error.
///
/// # Safety
///
/// `issuer` must be writable; `ctx` and `cert` must be live. `ctx->get_issuer` must be the
/// engine-installed callback (a NULL callback is unreachable here, and is reported as a failure
/// rather than faulted).
pub(crate) unsafe extern "C" fn get1_trusted_issuer(
    issuer: *mut *mut X509,
    ctx: *mut X509StoreCtx,
    cert: *mut X509,
) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let saved_chain = unsafe { (*ctx).chain };
    // SAFETY: `ctx` is live and writable.
    unsafe { (*ctx).chain = ptr::null_mut() };

    // SAFETY: `ctx` is live; the callback, when installed, has the authority's `get_issuer`
    // contract (`issuer` writable, `ctx`/`cert` live).
    let ok = match unsafe { (*ctx).get_issuer } {
        // SAFETY: the installed callback has the authority's `get_issuer` contract (`issuer`
        // writable, `ctx`/`cert` live).
        Some(cb) => unsafe { cb(issuer, ctx.cast(), cert) },
        // The authority calls a NULL pointer here; that is unreachable in the landed surface
        // because only `X509_STORE_CTX_init` (withheld) installs the callback.
        None => 0,
    };

    // SAFETY: `ctx` is live and writable.
    unsafe { (*ctx).chain = saved_chain };
    ok
}

// ---------------------------------------------------------------------------------------------
// Withheld until subphase 11.2 — `x509_vfy.c:3392-3490`.
// ---------------------------------------------------------------------------------------------
//
// These three functions are transcribed above only when their callees land. Each is listed with
// its exact authority signature and the precise call that blocks it. No stub is declared.
//
// TODO(11.2): `static int check_leaf_suiteb(X509_STORE_CTX *ctx, X509 *cert)` —
// `crypto/x509/x509_vfy.c:3392-3398`. Blocked by the *visibility* of a landed helper, not by a
// missing one: its `CB_FAIL_IF(err != X509_V_OK, ctx, cert, 0, err)` (`x509_vfy.c:174-176`)
// expands to `verify_cb_cert(ctx, cert, 0, err)` (`x509_vfy.c:162-172`), which is transcribed at
// `src/x509/x509_vfy.rs:1936` as a private `unsafe fn` with no `pub(crate)`. A sibling module
// cannot name it. Landing this function needs a one-word change outside this unit's write scope:
// `pub(crate) unsafe fn verify_cb_cert` in `x509_vfy.rs`. It additionally reads
// `ctx->param->flags` for `X509_chain_check_suiteb(NULL, cert, NULL, ctx->param->flags)`.
//
// TODO(11.2): `static int dane_verify_rpk(X509_STORE_CTX *ctx)` —
// `crypto/x509/x509_vfy.c:3401-3428`. Blocked by a missing callee: its last statement is
// `return verify_rpk(ctx)` (`crypto/x509/x509_vfy.c:3427`), and `verify_rpk` (`:240-247`) is part
// of the withheld engine slice (`src/x509/x509_vfy.rs`'s module doc names it). Its other callees,
// `dane_reset` and `dane_match_rpk`, are landed above; it also reads `ctx->rpk` (landed,
// `X509StoreCtx.rpk`) and the constants `X509_V_ERR_DANE_NO_MATCH` and `X509_V_OK`.
//
// TODO(11.2): `static int dane_verify(X509_STORE_CTX *ctx)` — `crypto/x509/x509_vfy.c:3431-3490`.
// Blocked by the withheld engine slice: it calls `check_id(ctx)` (`:3463`, defined `:941`),
// `verify_chain(ctx)` (`:3489`, defined `:253`), and `verify_cb_cert(ctx, cert, 0,
// X509_V_ERR_DANE_NO_MATCH)` (`:3482`, private at `src/x509/x509_vfy.rs:1936`); it also calls the
// deferred `check_leaf_suiteb`. Its landed callees are `dane_reset`, `dane_match_cert`,
// `X509_get_pubkey_parameters` and the constants `X509_V_ERR_OUT_OF_MEM` and
// `DANE_FLAG_NO_DANE_EE_NAMECHECKS` above.
