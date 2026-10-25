//! Phase 14.5 — `ssl/t1_lib.c`: the signature-algorithm and max-fragment-length surface.
//!
//! The plan gives 14.5 "the signature-algorithm and max-fragment-length surface" of `t1_lib.c`. This
//! module lands the nine exported rows: the two MFL setters and `SSL_SESSION_get_max_fragment_length`;
//! the four signature-algorithm readers; `SSL_check_chain`; and `SSL_get1_builtin_sigalgs`.
//!
//! ## What landed
//!
//! * **The MFL accessors.** `SSL_CTX_set_tlsext_max_fragment_length` and
//!   `SSL_set_tlsext_max_fragment_length` write the context/connection `ext.max_fragment_len_mode`
//!   after the authority's validity check; `SSL_SESSION_get_max_fragment_length` maps the session's
//!   `UNSPECIFIED` to `DISABLED`.
//! * **The sigalg readers.** `SSL_get_sigalgs` resolves each stored peer scheme through the
//!   transcribed `sigalg_lookup_tbl` plus the three provider (ML-DSA) rows, so the three NID
//!   out-parameters are the authority's `lu->sig`/`hash`/`sigandhash` (and `NID_undef` for an
//!   unknown or unavailable code point). `SSL_get_shared_sigalgs` reads the negotiated list that
//!   `tls1_set_shared_sigalgs` computes from the peer's saved order and the configured default
//!   (swapped under `SSL_OP_SERVER_PREFERENCE`), reproducing the authority's ordering, duplicate
//!   preservation and unknown-entry skipping. Both lists are object-owned element-counted member
//!   pairs (`SigalgsSlot`): the stored extent is the allocation's own count, a refused replacement
//!   leaves the incumbent installed, and a repeated save releases the previous block exactly once.
//! * **The peer vector acceptance rule.** `tls1_peer_sigalgs` is the single definition of
//!   `PACKET_as_length_prefixed_2` + `tls1_save_u16`: the length-prefixed vector must exhaust the
//!   extension body and be non-empty and even. Empty, odd, over-long and trailing-byte vectors are
//!   refused with the authority's alert and reason on both the server ClientHello and the client
//!   CertificateRequest paths.
//! * **`SSL_get1_builtin_sigalgs`.** The authority's provider probe: for each row of the static
//!   `sigalg_lookup_tbl` it fetches the hash and sets the key type, appending the row's name when
//!   both succeed. The table is transcribed below with the twenty-six rows the admitted authority's
//!   default provider enables.
//! * **`SSL_check_chain`.** The refusal arms: a NULL connection and a NULL `cert`/`pkey` pair both
//!   answer the authority's `0`.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **The sigalg lookup cache is not built at context creation.** The authority's `SSL_CTX_new_ex`
//!   runs `ssl_setup_sigalgs` (`t1_lib.c:2167-2289`), which fills `ctx->sigalg_lookup_cache` and
//!   `ctx->tls12_sigalgs`; this slice does not, exactly as 14.1's recorded divergence for
//!   `SSL_CTX_new_ex` says. The readers therefore resolve through the module's transcribed static
//!   table instead of a per-context cache. Consequence: row *availability* is the admitted build's
//!   default provider (every static row and the three provider rows resolve), not a re-probe of a
//!   caller-supplied `libctx`, and a context whose providers differ would mark fewer rows available.
//! * **The configured/preference lists are the default.** `client_sigalgs`/`conf_sigalgs` (the
//!   `SSL_CTX_set1_sigalgs` commands) and Suite B are not wired, so `tls1_set_shared_sigalgs` uses
//!   `CLIENT_SIGALGS` — the authority's `ctx->tls12_sigalgs` order for the admitted build — as both
//!   the preference and the allowed list. `valid_flags` is not modelled because the reduced
//!   certificate path does not consume it; only the shared list, which the accessor observes, is
//!   derived.
//! * **The default security callback remains the permissive stub.** `ssl_security` is invoked by
//!   the shared-list walk exactly as the authority invokes it, but this crate's default callback
//!   answers 1 for every operation, so the authority's level-1 rejection of SHA-1 rows (64 security
//!   bits < 80) is not reproduced. A configured callback sees the walk and its answer is honoured.
//! * **`SSL_check_chain` only lands its refusal arms.** A non-NULL `x`/`pk` pair reaches
//!   `tls1_check_chain` (`t1_lib.c:3984-4243`), whose signature-algorithm, certificate-parameter,
//!   suite-B and issuer-name checks are the certificate path's and are not landed in this subphase.
//!   The court drives the NULL-connection and NULL-chain arms only, and names the chain arm
//!   `pending` rather than approximating it.
//! * **The GOST rows of `sigalg_lookup_tbl` are omitted.** The admitted authority's default
//!   provider publishes neither the GOST digests nor the GOST key types, so its
//!   `SSL_get1_builtin_sigalgs` never appends them (verified against the authority's own output);
//!   the four rows are not transcribed. A build whose default provider published GOST would make
//!   this module's answer shorter than the authority's, which is a recorded environment dependency
//!   rather than a silent one.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(non_upper_case_globals)] // the constants are the authority's own C macro spellings

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;

use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free};
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_new, EVP_PKEY_set_type};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_pkey, EVP_PKEY_DSA, EVP_PKEY_EC, EVP_PKEY_ED25519,
    EVP_PKEY_ED448, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS,
};
use crate::runtime::err::err_reasons::SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH;
use crate::runtime::err::raise_with;

use crate::asn1::owned::OwnedBlock;
use crate::runtime::mem_coords::SeamFile;
use crate::runtime::obj::{
    NID_dsaWithSHA1, NID_dsa_with_SHA256, NID_ecdsa_with_SHA1, NID_ecdsa_with_SHA224,
    NID_ecdsa_with_SHA256, NID_ecdsa_with_SHA384, NID_ecdsa_with_SHA512, NID_sha1,
    NID_sha1WithRSAEncryption, NID_sha224, NID_sha224WithRSAEncryption, NID_sha256,
    NID_sha256WithRSAEncryption, NID_sha384, NID_sha384WithRSAEncryption, NID_sha512,
    NID_sha512WithRSAEncryption, NID_undef, OBJ_nid2ln, NID_ML_DSA_44, NID_ML_DSA_65,
    NID_ML_DSA_87,
};
use crate::runtime::owned_buf::OwnedBuf;
use crate::ssl::ssl_cert::ssl_security;
use crate::ssl::ssl_ciph_table::{
    SSL_aDSS, SSL_aECDSA, SSL_aPSK, SSL_aRSA, SSL_aSRP, SSL_kDHEPSK, SSL_kECDHE, SSL_kECDHEPSK,
    SSL_kPSK, SSL_kRSAPSK, SSL_kSRP, SslCipher,
};
use crate::ssl::ssl_lib::{SSL_is_dtls, Ssl, SslCtx, SslSession};
use crate::ssl::statem::statem_lib::{ssl_get_min_max_version, ssl_version_cmp};

/// `ERR_LIB_SSL` — `include/openssl/err.h.in:91`.
const ERR_LIB_SSL: c_int = 20;
/// `ERR_R_PASSED_INVALID_ARGUMENT` — `err.h.in:360` (`262 | ERR_RFLAG_COMMON`).
const ERR_R_PASSED_INVALID_ARGUMENT: c_int = 262 | (2 << 18);
/// `OPENSSL_FILE` of this translation unit.
const FILE: *const c_char = c"ssl/t1_lib.c".as_ptr();
const FILE_SEAM: SeamFile = SeamFile::new(c"ssl/t1_lib.c");

/// `TLSEXT_max_fragment_length_DISABLED` — `tls1.h:227`.
const TLSEXT_max_fragment_length_DISABLED: u8 = 0;
/// `TLSEXT_max_fragment_length_512` — `tls1.h:229`.
const TLSEXT_max_fragment_length_512: u8 = 1;
/// `TLSEXT_max_fragment_length_4096` — `tls1.h:232`.
const TLSEXT_max_fragment_length_4096: u8 = 4;
/// `TLSEXT_max_fragment_length_UNSPECIFIED` — `tls1.h:234`.
const TLSEXT_max_fragment_length_UNSPECIFIED: u8 = 255;

/// `IS_MAX_FRAGMENT_LENGTH_EXT_VALID(value)` — `ssl_local.h:293-294`.
fn is_max_fragment_length_ext_valid(value: u8) -> bool {
    (TLSEXT_max_fragment_length_512..=TLSEXT_max_fragment_length_4096).contains(&value)
}

// ---------------------------------------------------------------------------------------------
// Ownership of a scratch buffer
// ---------------------------------------------------------------------------------------------

/// `SIGALG_LOOKUP` — `ssl_local.h:1186-1212`, reduced to the columns the two public readers and
/// the shared-list computation actually observe.
struct SigAlgLookup {
    /// `const char *name`.
    name: &'static str,
    /// `uint16_t sigalg` — the TLS code point.
    sigalg: u16,
    /// `int hash` — `NID_undef` means "no associated digest".
    hash: c_int,
    /// `int sig` — the `EVP_PKEY_*` type.
    sig: c_int,
    /// `int sigandhash` — the combined signature-with-digest NID (`NID_undef` when none).
    sigandhash: c_int,
    /// `int sig_idx` — the certificate slot index (`ssl_cert_info` order).
    sig_idx: usize,
    /// `secbits`, as `sigalg_security_bits` computes it (`SSL_get1_builtin_sigalgs` does not read
    /// it; the security callback of the shared-list walk does).
    sec_bits: c_int,
}

/// `sigalg_lookup_tbl[]` — `ssl/t1_lib.c:1964-2142`, the twenty-six non-GOST rows, in table order.
///
/// The names are the `TLSEXT_SIGALG_*_name` macros (`ssl_local.h:2247-2280`); the hash and key-type
/// columns are read from the same initialiser. The four `#ifndef OPENSSL_NO_GOST` rows are omitted
/// per this module's divergence note.
static SIGALG_LOOKUP_TBL: [SigAlgLookup; 26] = [
    SigAlgLookup {
        name: "ecdsa_secp256r1_sha256",
        sigalg: 0x0403,
        hash: NID_sha256,
        sig: EVP_PKEY_EC,
        sigandhash: NID_ecdsa_with_SHA256,
        sig_idx: 3,
        sec_bits: 128,
    },
    SigAlgLookup {
        name: "ecdsa_secp384r1_sha384",
        sigalg: 0x0503,
        hash: NID_sha384,
        sig: EVP_PKEY_EC,
        sigandhash: NID_ecdsa_with_SHA384,
        sig_idx: 3,
        sec_bits: 192,
    },
    SigAlgLookup {
        name: "ecdsa_secp521r1_sha512",
        sigalg: 0x0603,
        hash: NID_sha512,
        sig: EVP_PKEY_EC,
        sigandhash: NID_ecdsa_with_SHA512,
        sig_idx: 3,
        sec_bits: 256,
    },
    SigAlgLookup {
        name: "ed25519",
        sigalg: 0x0807,
        hash: NID_undef,
        sig: EVP_PKEY_ED25519,
        sigandhash: NID_undef,
        sig_idx: 7,
        sec_bits: 128,
    },
    SigAlgLookup {
        name: "ed448",
        sigalg: 0x0808,
        hash: NID_undef,
        sig: EVP_PKEY_ED448,
        sigandhash: NID_undef,
        sig_idx: 8,
        sec_bits: 224,
    },
    SigAlgLookup {
        name: "ecdsa_sha224",
        sigalg: 0x0303,
        hash: NID_sha224,
        sig: EVP_PKEY_EC,
        sigandhash: NID_ecdsa_with_SHA224,
        sig_idx: 3,
        sec_bits: 112,
    },
    SigAlgLookup {
        name: "ecdsa_sha1",
        sigalg: 0x0203,
        hash: NID_sha1,
        sig: EVP_PKEY_EC,
        sigandhash: NID_ecdsa_with_SHA1,
        sig_idx: 3,
        sec_bits: 64,
    },
    SigAlgLookup {
        name: "ecdsa_brainpoolP256r1tls13_sha256",
        sigalg: 0x081a,
        hash: NID_sha256,
        sig: EVP_PKEY_EC,
        sigandhash: NID_ecdsa_with_SHA256,
        sig_idx: 3,
        sec_bits: 128,
    },
    SigAlgLookup {
        name: "ecdsa_brainpoolP384r1tls13_sha384",
        sigalg: 0x081b,
        hash: NID_sha384,
        sig: EVP_PKEY_EC,
        sigandhash: NID_ecdsa_with_SHA384,
        sig_idx: 3,
        sec_bits: 192,
    },
    SigAlgLookup {
        name: "ecdsa_brainpoolP512r1tls13_sha512",
        sigalg: 0x081c,
        hash: NID_sha512,
        sig: EVP_PKEY_EC,
        sigandhash: NID_ecdsa_with_SHA512,
        sig_idx: 3,
        sec_bits: 256,
    },
    SigAlgLookup {
        name: "rsa_pss_rsae_sha256",
        sigalg: 0x0804,
        hash: NID_sha256,
        sig: EVP_PKEY_RSA_PSS,
        sigandhash: NID_undef,
        sig_idx: 0,
        sec_bits: 128,
    },
    SigAlgLookup {
        name: "rsa_pss_rsae_sha384",
        sigalg: 0x0805,
        hash: NID_sha384,
        sig: EVP_PKEY_RSA_PSS,
        sigandhash: NID_undef,
        sig_idx: 0,
        sec_bits: 192,
    },
    SigAlgLookup {
        name: "rsa_pss_rsae_sha512",
        sigalg: 0x0806,
        hash: NID_sha512,
        sig: EVP_PKEY_RSA_PSS,
        sigandhash: NID_undef,
        sig_idx: 0,
        sec_bits: 256,
    },
    SigAlgLookup {
        name: "rsa_pss_pss_sha256",
        sigalg: 0x0809,
        hash: NID_sha256,
        sig: EVP_PKEY_RSA_PSS,
        sigandhash: NID_undef,
        sig_idx: 1,
        sec_bits: 128,
    },
    SigAlgLookup {
        name: "rsa_pss_pss_sha384",
        sigalg: 0x080a,
        hash: NID_sha384,
        sig: EVP_PKEY_RSA_PSS,
        sigandhash: NID_undef,
        sig_idx: 1,
        sec_bits: 192,
    },
    SigAlgLookup {
        name: "rsa_pss_pss_sha512",
        sigalg: 0x080b,
        hash: NID_sha512,
        sig: EVP_PKEY_RSA_PSS,
        sigandhash: NID_undef,
        sig_idx: 1,
        sec_bits: 256,
    },
    SigAlgLookup {
        name: "rsa_pkcs1_sha256",
        sigalg: 0x0401,
        hash: NID_sha256,
        sig: EVP_PKEY_RSA,
        sigandhash: NID_sha256WithRSAEncryption,
        sig_idx: 0,
        sec_bits: 128,
    },
    SigAlgLookup {
        name: "rsa_pkcs1_sha384",
        sigalg: 0x0501,
        hash: NID_sha384,
        sig: EVP_PKEY_RSA,
        sigandhash: NID_sha384WithRSAEncryption,
        sig_idx: 0,
        sec_bits: 192,
    },
    SigAlgLookup {
        name: "rsa_pkcs1_sha512",
        sigalg: 0x0601,
        hash: NID_sha512,
        sig: EVP_PKEY_RSA,
        sigandhash: NID_sha512WithRSAEncryption,
        sig_idx: 0,
        sec_bits: 256,
    },
    SigAlgLookup {
        name: "rsa_pkcs1_sha224",
        sigalg: 0x0301,
        hash: NID_sha224,
        sig: EVP_PKEY_RSA,
        sigandhash: NID_sha224WithRSAEncryption,
        sig_idx: 0,
        sec_bits: 112,
    },
    SigAlgLookup {
        name: "rsa_pkcs1_sha1",
        sigalg: 0x0201,
        hash: NID_sha1,
        sig: EVP_PKEY_RSA,
        sigandhash: NID_sha1WithRSAEncryption,
        sig_idx: 0,
        sec_bits: 64,
    },
    SigAlgLookup {
        name: "dsa_sha256",
        sigalg: 0x0402,
        hash: NID_sha256,
        sig: EVP_PKEY_DSA,
        sigandhash: NID_dsa_with_SHA256,
        sig_idx: 2,
        sec_bits: 128,
    },
    SigAlgLookup {
        name: "dsa_sha384",
        sigalg: 0x0502,
        hash: NID_sha384,
        sig: EVP_PKEY_DSA,
        sigandhash: NID_undef,
        sig_idx: 2,
        sec_bits: 192,
    },
    SigAlgLookup {
        name: "dsa_sha512",
        sigalg: 0x0602,
        hash: NID_sha512,
        sig: EVP_PKEY_DSA,
        sigandhash: NID_undef,
        sig_idx: 2,
        sec_bits: 256,
    },
    SigAlgLookup {
        name: "dsa_sha224",
        sigalg: 0x0302,
        hash: NID_sha224,
        sig: EVP_PKEY_DSA,
        sigandhash: NID_undef,
        sig_idx: 2,
        sec_bits: 112,
    },
    SigAlgLookup {
        name: "dsa_sha1",
        sigalg: 0x0202,
        hash: NID_sha1,
        sig: EVP_PKEY_DSA,
        sigandhash: NID_dsaWithSHA1,
        sig_idx: 2,
        sec_bits: 64,
    },
];

/// The three provider (`TLS-SIGALG` capability) rows the admitted build's default provider
/// publishes (`providers/common/capabilities.c:315-320`; the ML-DSA entries have no hash, and
/// `ssl_setup_sigalgs` gives them `sig_idx = SSL_PKEY_NUM + i` and a `sigandhash` equal to their
/// own algorithm NID). The authority keeps them in `ctx->sigalg_lookup_cache` after the static
/// rows, so `tls1_lookup_sigalg` resolves them for `SSL_get_sigalgs`.
static PROVIDER_SIGALGS: [SigAlgLookup; 3] = [
    SigAlgLookup {
        name: "mldsa44",
        sigalg: 0x0904,
        hash: NID_undef,
        sig: NID_ML_DSA_44,
        sigandhash: NID_ML_DSA_44,
        sig_idx: 9,
        sec_bits: 128,
    },
    SigAlgLookup {
        name: "mldsa65",
        sigalg: 0x0905,
        hash: NID_undef,
        sig: NID_ML_DSA_65,
        sigandhash: NID_ML_DSA_65,
        sig_idx: 10,
        sec_bits: 192,
    },
    SigAlgLookup {
        name: "mldsa87",
        sigalg: 0x0906,
        hash: NID_undef,
        sig: NID_ML_DSA_87,
        sigandhash: NID_ML_DSA_87,
        sig_idx: 11,
        sec_bits: 256,
    },
];

/// `tls1_lookup_sigalg(ctx, sigalg)` — `ssl/t1_lib.c:2367-2379`, over the static table followed by
/// the provider rows, in the cache order `ssl_setup_sigalgs` builds.
///
/// **Availability is the admitted build's.** `ssl_setup_sigalgs` marks a static row unavailable
/// when its digest or key type is missing and a provider row available for every TLS context; this
/// build's default provider publishes every digest and key type in the static table (the same
/// property `SSL_get1_builtin_sigalgs` observes), so every row resolves. A context created over a
/// different library context whose providers differ would mark fewer rows available; that is a
/// recorded residual of the reduced context cache, not a silent assumption.
fn tls1_lookup_sigalg(sigalg: u16) -> Option<&'static SigAlgLookup> {
    SIGALG_LOOKUP_TBL
        .iter()
        .chain(PROVIDER_SIGALGS.iter())
        .find(|row| row.sigalg == sigalg)
}

/// `int SSL_CTX_set_tlsext_max_fragment_length(SSL_CTX *ctx, uint8_t mode)` —
/// `ssl/t1_lib.c:4750-4760`.
///
/// # Safety
/// `ctx` must be NULL or point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_tlsext_max_fragment_length(
    ctx: *mut SslCtx,
    mode: u8,
) -> c_int {
    if mode != TLSEXT_max_fragment_length_DISABLED && !is_max_fragment_length_ext_valid(mode) {
        // SAFETY: a constant site.
        unsafe {
            raise_with(
                ERR_LIB_SSL,
                SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH,
                FILE,
                4754,
            )
        };
        return 0;
    }
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: `ctx` is non-NULL and live per the caller's contract.
    unsafe { (*ctx).ext_max_fragment_len_mode = mode };
    1
}

/// `int SSL_set_tlsext_max_fragment_length(SSL *ssl, uint8_t mode)` — `ssl/t1_lib.c:4762-4778`.
///
/// # Safety
/// `ssl` must be NULL or point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_tlsext_max_fragment_length(ssl: *mut Ssl, mode: u8) -> c_int {
    if ssl.is_null() {
        return 0;
    }
    if mode != TLSEXT_max_fragment_length_DISABLED && !is_max_fragment_length_ext_valid(mode) {
        // SAFETY: a constant site.
        unsafe {
            raise_with(
                ERR_LIB_SSL,
                SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH,
                FILE,
                4772,
            )
        };
        return 0;
    }
    // SAFETY: `ssl` is non-NULL and live per the caller's contract.
    unsafe { (*ssl).max_fragment_len_mode = mode };
    1
}

/// `uint8_t SSL_SESSION_get_max_fragment_length(const SSL_SESSION *session)` —
/// `ssl/t1_lib.c:4780-4785`.
///
/// # Safety
/// `session` must be NULL or point to a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_get_max_fragment_length(session: *const SslSession) -> u8 {
    if session.is_null() {
        return TLSEXT_max_fragment_length_DISABLED;
    }
    // SAFETY: `session` is non-NULL and live per the caller's contract.
    let mode = unsafe { (*session).max_fragment_len_mode };
    if mode == TLSEXT_max_fragment_length_UNSPECIFIED {
        TLSEXT_max_fragment_length_DISABLED
    } else {
        mode
    }
}

/// `int SSL_get_signature_type_nid(const SSL *s, int *pnid)` — `ssl/t1_lib.c:2825-2836`.
///
/// # Safety
/// `s` must be NULL or live; `pnid` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_signature_type_nid(s: *const Ssl, pnid: *mut c_int) -> c_int {
    if s.is_null() {
        return 0;
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    if unsafe { (*s).sigalg }.is_null() {
        return 0;
    }
    // Unreachable: no unit in this slice sets `s3.tmp.sigalg`.
    if !pnid.is_null() {
        // SAFETY: `pnid` is writable per the contract.
        unsafe { *pnid = NID_undef };
    }
    1
}

/// `int SSL_get_peer_signature_type_nid(const SSL *s, int *pnid)` — `ssl/t1_lib.c:2812-2823`.
///
/// # Safety
/// `s` must be NULL or live; `pnid` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_peer_signature_type_nid(s: *const Ssl, pnid: *mut c_int) -> c_int {
    if s.is_null() {
        return 0;
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    if unsafe { (*s).peer_sigalg }.is_null() {
        return 0;
    }
    // Unreachable: no unit in this slice sets `s3.tmp.peer_sigalg`.
    if !pnid.is_null() {
        // SAFETY: `pnid` is writable per the contract.
        unsafe { *pnid = NID_undef };
    }
    1
}

/// `int SSL_get_sigalgs(SSL *s, int idx, int *psign, int *phash, int *psignhash,
/// unsigned char *rsig, unsigned char *rhash)` — `ssl/t1_lib.c:3599-3634`.
///
/// The stored list is the connection's owned peer list; its length is the allocation's own
/// element count (see [`SigalgsSlot`]), so an index is checked against the block that will be
/// read, never against a separately tracked count. Each scheme is resolved through
/// [`tls1_lookup_sigalg`], which is the authority's cache lookup for the admitted build; an
/// unknown or unavailable code point answers `NID_undef` in all three NID out-parameters, exactly
/// as the authority's `lu == NULL` arm does.
///
/// # Safety
/// `s` must be NULL or live; the out-parameters NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_sigalgs(
    s: *mut Ssl,
    idx: c_int,
    psign: *mut c_int,
    phash: *mut c_int,
    psignhash: *mut c_int,
    rsig: *mut u8,
    rhash: *mut u8,
) -> c_int {
    if s.is_null() {
        return 0;
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract, so its peer pair obeys the pair
    // invariant and the borrow lives only for this block.
    let list = unsafe { (*s).peer_sigalgs() };
    if list.len() > c_int::MAX as usize {
        return 0;
    }
    if idx >= 0 {
        let Some(&val) = list.get(idx as usize) else {
            return 0;
        };
        if !rhash.is_null() {
            // SAFETY: `rhash` is writable per the contract.
            unsafe { *rhash = ((val >> 8) & 0xff) as u8 };
        }
        if !rsig.is_null() {
            // SAFETY: `rsig` is writable per the contract.
            unsafe { *rsig = (val & 0xff) as u8 };
        }
        let lu = tls1_lookup_sigalg(val);
        if !psign.is_null() {
            // SAFETY: `psign` is writable per the contract.
            unsafe { *psign = lu.map_or(NID_undef, |row| row.sig) };
        }
        if !phash.is_null() {
            // SAFETY: `phash` is writable per the contract.
            unsafe { *phash = lu.map_or(NID_undef, |row| row.hash) };
        }
        if !psignhash.is_null() {
            // SAFETY: `psignhash` is writable per the contract.
            unsafe { *psignhash = lu.map_or(NID_undef, |row| row.sigandhash) };
        }
    }
    list.len() as c_int
}

/// `int SSL_get_shared_sigalgs(SSL *s, int idx, int *psign, int *phash, int *psignhash,
/// unsigned char *rsig, unsigned char *rhash)` — `ssl/t1_lib.c:3636-3663`.
///
/// [`tls1_set_shared_sigalgs`] publishes the negotiated list as scheme codes (the authority stores
/// `SIGALG_LOOKUP *`; the representation is private to the connection, and the accessor resolves
/// each code through the same static table). The list is empty until the peer's list has been
/// processed, which is the authority's NULL answer.
///
/// # Safety
/// `s` must be NULL or live; the out-parameters NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_shared_sigalgs(
    s: *mut Ssl,
    idx: c_int,
    psign: *mut c_int,
    phash: *mut c_int,
    psignhash: *mut c_int,
    rsig: *mut u8,
    rhash: *mut u8,
) -> c_int {
    if s.is_null() {
        return 0;
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract, so its shared pair obeys the
    // pair invariant and the borrow lives only for this block.
    let list = unsafe { (*s).shared_sigalgs() };
    if idx < 0 || idx as usize >= list.len() || list.len() > c_int::MAX as usize {
        return 0;
    }
    let code = list[idx as usize];
    let Some(lu) = tls1_lookup_sigalg(code) else {
        // The shared list only contains resolved rows; a corrupt list is refused rather than read.
        return 0;
    };
    if !phash.is_null() {
        // SAFETY: `phash` is writable per the contract.
        unsafe { *phash = lu.hash };
    }
    if !psign.is_null() {
        // SAFETY: `psign` is writable per the contract.
        unsafe { *psign = lu.sig };
    }
    if !psignhash.is_null() {
        // SAFETY: `psignhash` is writable per the contract.
        unsafe { *psignhash = lu.sigandhash };
    }
    if !rsig.is_null() {
        // SAFETY: `rsig` is writable per the contract.
        unsafe { *rsig = (lu.sigalg & 0xff) as u8 };
    }
    if !rhash.is_null() {
        // SAFETY: `rhash` is writable per the contract.
        unsafe { *rhash = ((lu.sigalg >> 8) & 0xff) as u8 };
    }
    list.len() as c_int
}

/// `int SSL_check_chain(SSL *s, X509 *x, EVP_PKEY *pk, STACK_OF(X509) *chain)` —
/// `ssl/t1_lib.c:4260-4268`.
///
/// Only the refusal arms are landed; see this module's divergence note.
///
/// # Safety
/// `s` must be NULL or live.
#[no_mangle]
pub unsafe extern "C" fn SSL_check_chain(
    s: *mut Ssl,
    x: *mut c_void,
    pk: *mut c_void,
    chain: *mut c_void,
) -> c_int {
    let _ = chain;
    if s.is_null() {
        return 0;
    }
    // `tls1_check_chain` (`t1_lib.c:4024`) answers 0 for a NULL `x`/`pk` pair on the `idx == -1`
    // path, which is the whole of the chain arm this subphase lands.
    if x.is_null() || pk.is_null() {
        return 0;
    }
    0
}

/// `char *SSL_get1_builtin_sigalgs(OSSL_LIB_CTX *libctx)` — `ssl/t1_lib.c:2293-2364`.
///
/// Returns an `OPENSSL_malloc`'d, colon-separated list of the sigalg rows whose hash the default
/// provider publishes and whose key type it can set, or NULL when the scratch key cannot be
/// allocated. The caller frees it with `OPENSSL_free`.
///
/// # Safety
/// `libctx` must be NULL or a live library context.
#[no_mangle]
pub unsafe extern "C" fn SSL_get1_builtin_sigalgs(libctx: *mut c_void) -> *mut c_char {
    // SAFETY: `EVP_PKEY_new` takes no preconditions.
    let tmpkey = unsafe { EVP_PKEY_new() };
    if tmpkey.is_null() {
        return ptr::null_mut();
    }

    let mut out = String::new();
    for row in SIGALG_LOOKUP_TBL.iter() {
        let mut enabled = true;

        if row.hash != NID_undef {
            // SAFETY: `libctx` is NULL or live per the contract; `OBJ_nid2ln` returns a static
            // NUL-terminated string for a known NID.
            let md = unsafe { EVP_MD_fetch(libctx, OBJ_nid2ln(row.hash), ptr::null()) };
            if md.is_null() {
                // The hash is unavailable; the authority skips the row.
                continue;
            }
            // SAFETY: `md` is live.
            unsafe { EVP_MD_free(md) };
        }

        // SAFETY: `tmpkey` is live.
        if unsafe { EVP_PKEY_set_type(tmpkey, row.sig) } == 0 {
            continue;
        }
        // SAFETY: `libctx` is NULL or live; `tmpkey` is live.
        let pctx = unsafe { EVP_PKEY_CTX_new_from_pkey(libctx, tmpkey, ptr::null()) };
        if pctx.is_null() {
            enabled = false;
        }
        // SAFETY: `pctx` is NULL or live.
        unsafe { EVP_PKEY_CTX_free(pctx) };

        if enabled {
            if !out.is_empty() {
                out.push(':');
            }
            out.push_str(row.name);
        }
    }

    // SAFETY: `tmpkey` is live.
    unsafe { EVP_PKEY_free(tmpkey) };

    // `OPENSSL_malloc`-equivalent: a `CRYPTO_malloc` block the caller frees with `OPENSSL_free`,
    // exactly as the authority's `OPENSSL_malloc`/`OPENSSL_realloc` buffer is. `OwnedBuf::new`
    // allocates it at the authority's own size/file/line, and `into_raw` hands it to the caller.
    let bytes = out.as_bytes();
    let Some(ret) = OwnedBuf::new(bytes.len() + 1, FILE_SEAM, 2298) else {
        return ptr::null_mut();
    };
    // SAFETY: `ret` is a fresh block of at least `bytes.len() + 1` bytes.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), ret.as_ptr().cast::<u8>(), bytes.len());
        *ret.as_ptr().cast::<u8>().add(bytes.len()) = 0;
    }
    ret.into_raw().cast()
}

// -------------------------------------------------------------------------------------------
// 14.7b — the client-disabled mask trackers (`t1_lib.c`)
//
// `SSL_get1_supported_ciphers` (`ssl_lib.c:3276`) filters a connection's cipher list through
// `ssl_set_client_disabled` and `ssl_cipher_disabled`; both are `t1_lib.c` internals 14.1 recorded
// as the row's blocker. The `s3.tmp.mask_a`/`mask_k`/`min_ver`/`max_ver` words they read are now
// fields on `Ssl`, and the `ssl_get_min_max_version`/`ssl_version_cmp` pair they call is in
// `src/ssl/statem/statem_lib.rs`.
// -------------------------------------------------------------------------------------------

/// `SSL_SECOP_SIGALG_MASK` — `ssl.h:2740` (`14 | SSL_SECOP_OTHER_SIGALG`).
const SSL_SECOP_SIGALG_MASK: c_int = 14 | (5 << 16);
/// `SSL3_VERSION` — `ssl3.h:136`.
const SSL3_VERSION: c_int = 0x0300;
/// `TLS1_VERSION` — `tls1.h:199`.
const TLS1_VERSION: c_int = 0x0301;

/// `void ssl_set_sig_mask(uint32_t *pmask_a, SSL_CONNECTION *s, int op)` —
/// `ssl/t1_lib.c:3395-3423`.
///
/// **Reduced, and recorded here rather than hidden.** The authority walks `tls12_get_psigalgs` and
/// clears an auth-family bit for every supported signature algorithm, consulting `tls1_lookup_sigalg`,
/// `ssl_cert_lookup_by_idx` and `tls12_sigalg_allowed` — the `SIGALG_LOOKUP` table's `sig_idx` and
/// `secbits` columns and the security check, none of which this stratum's `SigAlgLookup` models.
/// This function walks the crate's own `sigalg_lookup_tbl` and clears each auth family that has at
/// least one row. For the admitted build's default table every family (RSA, DSA, ECDSA) has one, so
/// the authority's security-level filtering is not observable at the reachable arms and `*pmask_a`
/// receives the same 0 the authority leaves.
///
/// # Safety
/// `pmask_a` must be a writable `uint32_t`; `s` must be a live connection.
unsafe fn ssl_set_sig_mask(pmask_a: *mut u32, s: *mut Ssl, _op: c_int) {
    let _ = s;
    let mut disabled_mask: u32 = (SSL_aRSA | SSL_aDSS | SSL_aECDSA) as u32;
    for row in SIGALG_LOOKUP_TBL.iter() {
        let amask: u32 = if row.sig == EVP_PKEY_RSA || row.sig == EVP_PKEY_RSA_PSS {
            SSL_aRSA as u32
        } else if row.sig == EVP_PKEY_EC {
            SSL_aECDSA as u32
        } else if row.sig == EVP_PKEY_DSA {
            SSL_aDSS as u32
        } else {
            0
        };
        if amask != 0 {
            disabled_mask &= !amask;
        }
    }
    // SAFETY: `pmask_a` is writable per the caller's contract.
    unsafe { *pmask_a |= disabled_mask };
}

/// `int ssl_set_client_disabled(SSL_CONNECTION *s)` — `ssl/t1_lib.c:2848-2871`.
///
/// # Safety
/// `s` must be a live connection.
pub(crate) unsafe fn ssl_set_client_disabled(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        (*s).mask_a = 0;
        (*s).mask_k = 0;
        ssl_set_sig_mask(&mut (*s).mask_a, s, SSL_SECOP_SIGALG_MASK);
        if ssl_get_min_max_version(s, &mut (*s).min_ver, &mut (*s).max_ver, ptr::null_mut()) != 0 {
            return 0;
        }
        // With PSK there must be a client callback set.
        if (*s).psk_client_callback.is_none() {
            (*s).mask_a |= SSL_aPSK as u32;
            (*s).mask_k |= (SSL_kPSK | SSL_kRSAPSK | SSL_kECDHEPSK | SSL_kDHEPSK) as u32;
        }
        if ((*s).srp_ctx.srp_mask & SSL_kSRP) == 0 {
            (*s).mask_a |= SSL_aSRP as u32;
            (*s).mask_k |= SSL_kSRP as u32;
        }
    }
    1
}

/// `int ssl_cipher_disabled(const SSL_CONNECTION *s, const SSL_CIPHER *c, int op, int ecdhe)` —
/// `ssl/t1_lib.c:2882-2919`.
///
/// Returns 1 when the cipher is disabled, 0 when enabled. The `SSL_IS_QUIC_INT_HANDSHAKE` arm is
/// unreachable for every object this crate builds.
///
/// # Safety
/// `s` must be a live connection; `c` must be a live cipher table row.
pub(crate) unsafe fn ssl_cipher_disabled(
    s: *const Ssl,
    c: *const SslCipher,
    op: c_int,
    ecdhe: c_int,
) -> c_int {
    // SAFETY: `s` and `c` are live per the caller's contract.
    unsafe {
        let dtls = SSL_is_dtls(s) != 0;
        let mut minversion = if dtls { (*c).min_dtls } else { (*c).min_tls };
        let maxversion = if dtls { (*c).max_dtls } else { (*c).max_tls };

        if ((*c).algorithm_mkey & (*s).mask_k) != 0 || ((*c).algorithm_auth & (*s).mask_a) != 0 {
            return 1;
        }
        if (*s).max_ver == 0 {
            return 1;
        }

        // For historical reasons ECDHE is allowed in SSLv3 when we are a client.
        if minversion == TLS1_VERSION
            && ecdhe != 0
            && ((*c).algorithm_mkey & (SSL_kECDHE | SSL_kECDHEPSK) as u32) != 0
        {
            minversion = SSL3_VERSION;
        }

        if ssl_version_cmp(s, minversion, (*s).max_ver) > 0
            || ssl_version_cmp(s, maxversion, (*s).min_ver) < 0
        {
            return 1;
        }

        c_int::from(ssl_security(s, op, (*c).strength_bits, 0, c.cast_mut().cast()) == 0)
    }
}

// ---------------------------------------------------------------------------------------------
// Phase 17.2b — the TLS group list. `ssl_load_groups` (`t1_lib.c:366-372`) drives provider
// capability discovery and then parses `TLS_DEFAULT_GROUP_LIST` (`t1_lib.c:206-209`); this stratum
// has no provider-capability walk, so the constructor below installs the list the admitted
// provider's default resolves to, reduced by the hybrid `X25519MLKEM768` (its key-share KEM is
// 17.2's key-schedule boundary and is named in `extensions_clnt.rs`).
// ---------------------------------------------------------------------------------------------

/// `OSSL_TLS_GROUP_ID_x25519` — `tls1.h`.
pub(crate) const OSSL_TLS_GROUP_ID_x25519: u16 = 29;
/// `OSSL_TLS_GROUP_ID_secp256r1` — `tls1.h`.
pub(crate) const OSSL_TLS_GROUP_ID_secp256r1: u16 = 23;
/// `OSSL_TLS_GROUP_ID_x448` — `tls1.h`.
pub(crate) const OSSL_TLS_GROUP_ID_x448: u16 = 30;
/// `OSSL_TLS_GROUP_ID_secp384r1` — `tls1.h`.
pub(crate) const OSSL_TLS_GROUP_ID_secp384r1: u16 = 24;
/// `OSSL_TLS_GROUP_ID_secp521r1` — `tls1.h`.
pub(crate) const OSSL_TLS_GROUP_ID_secp521r1: u16 = 25;
/// `OSSL_TLS_GROUP_ID_ffdhe2048` — `tls1.h`.
pub(crate) const OSSL_TLS_GROUP_ID_ffdhe2048: u16 = 256;
/// `OSSL_TLS_GROUP_ID_ffdhe3072` — `tls1.h`.
pub(crate) const OSSL_TLS_GROUP_ID_ffdhe3072: u16 = 257;

/// `TLS_DEFAULT_GROUP_LIST` (`t1_lib.c:208-209`) resolved for the admitted provider: `X25519`,
/// `secp256r1`, `X448`, `secp384r1`, `secp521r1`, `ffdhe2048`, `ffdhe3072`.
pub(crate) const DEFAULT_GROUPS: [u16; 7] = [
    OSSL_TLS_GROUP_ID_x25519,
    OSSL_TLS_GROUP_ID_secp256r1,
    OSSL_TLS_GROUP_ID_x448,
    OSSL_TLS_GROUP_ID_secp384r1,
    OSSL_TLS_GROUP_ID_secp521r1,
    OSSL_TLS_GROUP_ID_ffdhe2048,
    OSSL_TLS_GROUP_ID_ffdhe3072,
];

/// The provider key-management algorithm and provider-internal curve name for a TLS1.2 ECDHE
/// group, or `None` when this reduction has no ECDHE implementation for it.
///
/// `tls1_group_id_lookup` (`t1_lib.c:722-732`) answers the same pair from `TLS_GROUP_INFO`; the
/// admitted provider's rows are `capabilities.c:50-93` (`X25519`/`X448` for the X25519 family,
/// `EC` with the curve's provider name for the NIST curves). Only groups whose key agreement the
/// crate already implements are listed: the key exchange reuses `EVP_PKEY_derive`, not new curve
/// arithmetic.
pub(crate) fn tls1_group_id2kex(group_id: u16) -> Option<(&'static CStr, &'static CStr)> {
    match group_id {
        OSSL_TLS_GROUP_ID_x25519 => Some((c"X25519", c"X25519")),
        OSSL_TLS_GROUP_ID_x448 => Some((c"X448", c"X448")),
        OSSL_TLS_GROUP_ID_secp256r1 => Some((c"EC", c"prime256v1")),
        OSSL_TLS_GROUP_ID_secp384r1 => Some((c"EC", c"secp384r1")),
        OSSL_TLS_GROUP_ID_secp521r1 => Some((c"EC", c"secp521r1")),
        _ => None,
    }
}

/// `tls_use_ticket` (`t1_lib.c:2921-2926`), reduced to the `SSL_OP_NO_TICKET` arm.
///
/// The authority also consults the certificate security callback (`SSL_SECOP_TICKET`); this
/// reduction has no default callback (`ssl_security` answers 0 with none installed), so calling
/// it would disable tickets for every connection. The option arm is the observable behaviour a
/// consumer sets with `SSL_OP_NO_TICKET` (`s_client -no_ticket` is a client-side option and does
/// not reach this path).
///
/// # Safety
/// `s` must be a live connection.
pub(crate) unsafe fn tls_use_ticket(s: *const Ssl) -> bool {
    // SAFETY: `s` is live per the contract.
    unsafe { (*s).options & crate::ssl::ssl_ciph_table::SSL_OP_NO_TICKET == 0 }
}

/// `void tls1_get_supported_groups(SSL_CONNECTION *s, const uint16_t **pgroups,`
/// `size_t *pgroupslen)` — `t1_lib.c:784-816`, reduced to the built-in default list or the
/// connection's configured list.
///
/// The `SSL_CTX_set1_groups_list`/`SSL_set1_groups_list` parser installs the connection's list
/// (`tls1_set_groups_list` below); a connection that never called a group setter reaches exactly the
/// authority's default arm.
///
/// # Safety
/// `s` must be NULL or a live connection. The returned slice borrows the connection's
/// `supportedgroups` list (or the static default list); although its type is `'static`, the
/// caller must not use it after any operation that frees or replaces that list or destroys
/// `s` — in practice, only for the duration of the current handshake step.
pub(crate) unsafe fn tls1_get_supported_groups(s: *const Ssl) -> &'static [u16] {
    if !s.is_null() {
        // SAFETY: `s` is live per the contract.
        let (p, n) = unsafe { ((*s).supportedgroups, (*s).supportedgroups_len) };
        if !p.is_null() && n > 0 {
            // SAFETY: the list is owned by the connection for its lifetime; the caller uses the
            // slice only for the duration of the current handshake step.
            return unsafe { core::slice::from_raw_parts(p, n) };
        }
    }
    &DEFAULT_GROUPS
}

/// `uint16_t tls1_nid2group_id(int nid)` — `t1_lib.c:768-781`, the `nid_to_group` table reduced to
/// the groups this provider can negotiate.
pub(crate) fn tls1_nid2group_id(nid: c_int) -> u16 {
    use crate::runtime::obj as o;
    match nid {
        o::NID_X25519 => OSSL_TLS_GROUP_ID_x25519,
        o::NID_X448 => OSSL_TLS_GROUP_ID_x448,
        o::NID_X9_62_prime256v1 => OSSL_TLS_GROUP_ID_secp256r1,
        o::NID_secp384r1 => OSSL_TLS_GROUP_ID_secp384r1,
        o::NID_secp521r1 => OSSL_TLS_GROUP_ID_secp521r1,
        o::NID_secp256k1 => 22,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------------------------
// The peer and shared signature-algorithm list owners
// ---------------------------------------------------------------------------------------------

/// A connection-owned signature-algorithm list: exactly `count` native-endian `u16` schemes in one
/// `CRYPTO_malloc` block.
///
/// The block and its element count are created together, so they cannot disagree: the only ways to
/// obtain a value are [`from_codes`](OwnedSigalgs::from_codes) and
/// [`from_scheme_bytes`](OwnedSigalgs::from_scheme_bytes), each of which allocates for exactly
/// `count` schemes and initialises every slot before the value exists. Until
/// [`SigalgsSlot::replace`] transfers it to a connection, this value is the block's only owner and
/// its `Drop` is the block's single release.
struct OwnedSigalgs {
    block: OwnedBlock<u16>,
    count: usize,
}

impl OwnedSigalgs {
    /// Copy `codes` into a fresh block. `None` (nothing allocated, nothing published) when `codes`
    /// is empty or the block cannot be allocated; the extent is `checked_mul`-guarded inside
    /// [`OwnedBlock::malloc`].
    fn from_codes(codes: &[u16]) -> Option<OwnedSigalgs> {
        if codes.is_empty() {
            return None;
        }
        let block = OwnedBlock::<u16>::malloc(codes.len(), FILE_SEAM, 0)?;
        // SAFETY: `block` is a fresh allocation of exactly `codes.len()` writable `u16`s, and the
        // source is a live slice of the same length that cannot alias the fresh block. Every slot
        // is initialised exactly once through the raw pointer; no typed reference is formed over
        // uninitialised storage.
        unsafe { ptr::copy_nonoverlapping(codes.as_ptr(), block.as_ptr(), codes.len()) };
        Some(OwnedSigalgs {
            block,
            count: codes.len(),
        })
    }

    /// Copy big-endian wire pairs into a fresh block. The caller has established a non-empty, even
    /// length; `None` when the block cannot be allocated.
    fn from_scheme_bytes(schemes: &[u8]) -> Option<OwnedSigalgs> {
        if schemes.is_empty() || !schemes.len().is_multiple_of(2) {
            return None;
        }
        let count = schemes.len() / 2;
        let block = OwnedBlock::<u16>::malloc(count, FILE_SEAM, 0)?;
        for (i, pair) in schemes.as_chunks::<2>().0.iter().enumerate() {
            // SAFETY: `block` names exactly `count` writable `u16`s and `i < count`; the slot was
            // uninitialised until this write, which goes through the raw pointer so no typed
            // reference is formed over uninitialised storage.
            unsafe { block.as_ptr().add(i).write(u16::from_be_bytes(*pair)) };
        }
        Some(OwnedSigalgs { block, count })
    }

    /// The stored schemes. Every slot was initialised by the constructor and `count` is the
    /// allocation's own element count, so the slice never reaches outside the block.
    #[cfg(test)]
    fn as_slice(&self) -> &[u16] {
        // SAFETY: `block` is a live allocation of exactly `count` initialised `u16`s owned by
        // `self`; the returned borrow cannot outlive `self`.
        unsafe { core::slice::from_raw_parts(self.block.as_ptr(), self.count) }
    }
}

/// The transfer boundary between an [`OwnedSigalgs`] and a connection's stored `(ptr, len)` member
/// pair. The pair stays `*mut u16`/`usize` at its authority offset; this handle is the only
/// sanctioned way to move a list in or out, and `Ssl`'s fields are private, so no other code can
/// make the stored extent disagree with the allocation.
pub(crate) struct SigalgsSlot<'a> {
    ptr: &'a mut *mut u16,
    len: &'a mut usize,
}

impl<'a> SigalgsSlot<'a> {
    /// Derive the handle from a connection's member pair.
    ///
    /// # Safety
    ///
    /// `ptr`/`len` are the two member fields of a live connection and currently obey the pair
    /// invariant: `(NULL, 0)`, or a single `CRYPTO_*` block this connection owns exclusively whose
    /// length is exactly `len` elements. The borrow is exclusive for `'a`, so nothing else
    /// publishes to the pair for that time.
    pub(crate) unsafe fn of(ptr: &'a mut *mut u16, len: &'a mut usize) -> SigalgsSlot<'a> {
        SigalgsSlot { ptr, len }
    }

    /// Release the incumbent (if any) and publish `list`.
    ///
    /// `list` was allocated before this call, so a refused allocation leaves the incumbent in
    /// place — exactly `tls1_save_u16`'s ordering (it parses and allocates first, then frees the
    /// old pointer). Reads derive emptiness from `*ptr`, so even the transient `(NULL, old_len)`
    /// produced by [`clear`](SigalgsSlot::clear) reads as empty rather than as a slice.
    ///
    /// Private to this module: the only list values that exist are built here, so the slot's
    /// public surface (`of`/`clear`) cannot install a block whose extent is not its own count.
    fn replace(&mut self, list: OwnedSigalgs) {
        self.clear(FILE, 0);
        let count = list.count;
        // `into_raw` gives up the owner's single release; no allocator call or callback lies
        // between the two publications, so the pair is never observable in a half-updated state.
        *self.ptr = list.block.into_raw();
        *self.len = count;
    }

    /// Release the incumbent through `CRYPTO_free` at `file`/`line` and publish `(NULL, 0)`.
    pub(crate) fn clear(&mut self, file: *const c_char, line: c_int) {
        let old = core::mem::replace(self.ptr, ptr::null_mut());
        *self.len = 0;
        // SAFETY: by the pair invariant the incumbent is NULL or this connection's own single
        // block, whose base pointer is what `CRYPTO_free` releases; NULL is its no-op.
        unsafe { crate::runtime::mem::CRYPTO_free(old.cast(), file, line) };
    }
}

/// The scheme bytes of a `signature_algorithms` extension body (`list_len(2) || scheme(2)...`) as
/// `tls_parse_ctos_sig_algs` accepts them, or `None` when the authority refuses the vector.
///
/// `PACKET_as_length_prefixed_2` (`extensions_srvr.c:308`) requires the length-prefixed vector to
/// consume the **whole** extension body, then `PACKET_remaining != 0` and `tls1_save_u16` require a
/// non-empty, even-length vector. This function is that single acceptance condition: a body
/// shorter than the length word, a zero-length vector, an odd-length vector, a declared vector that
/// runs past the body, or trailing bytes after it all answer `None`. It is shared by the writer
/// ([`tls1_save_peer_sigalgs`]) and the ClientHello parser, so both refuse the same inputs.
pub(crate) fn tls1_peer_sigalgs(body: &[u8]) -> Option<&[u8]> {
    if body.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if list_len == 0 {
        return None;
    }
    // The authority's `PACKET_as_length_prefixed_2` requires the sub-packet to exhaust the body.
    if list_len.checked_add(2)? != body.len() {
        return None;
    }
    let schemes = &body[2..];
    if !schemes.len().is_multiple_of(2) {
        return None;
    }
    Some(schemes)
}

/// `int tls1_save_u16(PACKET *pkt, uint16_t **p, size_t *len)` — `t1_lib.c:3523-3559`, for the
/// `signature_algorithms` vector `tls_parse_ctos_sig_algs` saves (`extensions_srvr.c:303-320`)
/// and the client's `CertificateRequest` reader (`statem_clnt.c:2650-2690`, `:2686`).
///
/// The extension body is `list_len(2) || scheme(2)...`; a zero-length, odd-length, over-long or
/// trailing-byte-bearing vector is refused *before* the incumbent list is released, so a malformed
/// request leaves the previous list intact (the authority parses into the packet before it
/// stores). On success the schemes are stored as native-endian `u16`s — that is the representation
/// `SSL_get_sigalgs` reads — in a `CRYPTO_malloc` block the connection owns and `SSL_free` releases.
///
/// # Safety
/// `s` must be a live connection.
pub(crate) unsafe fn tls1_save_peer_sigalgs(s: *mut Ssl, body: &[u8]) -> c_int {
    let Some(schemes) = tls1_peer_sigalgs(body) else {
        return 0;
    };
    // SAFETY: `s` is live per the caller's contract; `schemes` is the validated vector inside
    // `body`.
    unsafe { tls1_save_peer_sigalgs_raw(s, schemes) }
}

/// The scheme bytes of a `signature_algorithms` vector (`list_len(2)` already stripped), saved
/// exactly as [`tls1_save_peer_sigalgs`] saves them. The TLS1.2 `CertificateRequest` reader has the
/// vector in this shape after `PACKET_get_length_prefixed_2`.
///
/// A refused allocation leaves the incumbent in place (`tls1_save_u16` frees only after the new
/// block exists); a repeated save replaces it, so the previous list is released exactly once.
///
/// # Safety
/// `s` must be a live connection.
pub(crate) unsafe fn tls1_save_peer_sigalgs_raw(s: *mut Ssl, schemes: &[u8]) -> c_int {
    if schemes.is_empty() || !schemes.len().is_multiple_of(2) {
        return 0;
    }
    let Some(list) = OwnedSigalgs::from_scheme_bytes(schemes) else {
        return 0;
    };
    // SAFETY: `s` is live; its peer pair currently obeys the pair invariant (it is `(NULL, 0)` or
    // the connection's own single block, written only through this handle).
    unsafe { (*s).peer_sigalgs_slot().replace(list) };
    1
}

/// Stores `schemes` as the connection's peer signature-algorithm list.
///
/// The authority's default list is what it uses when the peer sent no `signature_algorithms` at
/// all: the client falls back to the list it advertised (`tls1_get_legacy_sigalg` + the
/// `tls12_get_psigalgs(s, 1, ...)` membership test in `tls_choose_sigalg`, `t1_lib.c:4685-4713`;
/// `tls1_set_shared_sigalgs`'s NULL-`peer_sigalgs` arm, `t1_lib.c:3500-3508`). This stores that
/// list so the certificate constructors' scheme check can consult it.
///
/// # Safety
/// `s` must be a live connection.
pub(crate) unsafe fn tls1_save_peer_sigalgs_default(s: *mut Ssl, schemes: &[u16]) -> c_int {
    let Some(list) = OwnedSigalgs::from_codes(schemes) else {
        return 0;
    };
    // SAFETY: `s` is live; its peer pair currently obeys the pair invariant.
    unsafe { (*s).peer_sigalgs_slot().replace(list) };
    1
}

/// `SSL_SECOP_SIGALG_SHARED` — `ssl.h:2736` (`12 | SSL_SECOP_OTHER_SIGALG`).
const SSL_SECOP_SIGALG_SHARED: c_int = 12 | (5 << 16);

/// `SSL_OP_SERVER_PREFERENCE` — `ssl.h:390` (`SSL_OP_BIT(22)`).
const SSL_OP_SERVER_PREFERENCE: u64 = 1 << 22;

/// `ssl_cert_is_disabled(ctx, idx)` — `ssl_local.h`. The reduced certificate never installs a
/// disabled-slot mask (no `SSL_set1_sigalgs`-style setter is wired), so its answer is always 0;
/// the `sig_idx` column is consulted here so the table stays the authority's shape.
fn ssl_cert_is_disabled(_s: *const Ssl, _idx: usize) -> bool {
    false
}

/// `tls12_sigalg_allowed(s, op, lu)` — `t1_lib.c:3317-3393`, over the columns this reduced table
/// models.
///
/// The GOST arm is vacuous (no GOST row is transcribed), `ssl_cert_is_disabled` is all-zero in
/// this build (nothing calls the certificate-disabling setters), and `tls1_suiteb` is always 0
/// (Suite B is not modelled). The security callback is invoked exactly as the authority invokes
/// it, so an application callback sees the shared-list walk.
///
/// # Safety
/// `s` must be a live connection.
unsafe fn tls12_sigalg_allowed(s: *const Ssl, op: c_int, lu: &SigAlgLookup) -> bool {
    // SAFETY: `s` is live per the contract.
    let tls13 = unsafe { (*s).version == crate::ssl::ssl_lib::TLS1_3_VERSION };
    // DSA is not allowed in TLS 1.3.
    if tls13 && lu.sig == EVP_PKEY_DSA {
        return false;
    }
    // A client that could negotiate TLS 1.3 drops DSA and the SHA-1/SHA-224 schemes from the
    // shared walk (`t1_lib.c:3331-3337`).
    // SAFETY: `s` is live.
    // SAFETY: `s` is live.
    if unsafe { (*s).server == 0 }
        // SAFETY: `s` is live.
        && unsafe { SSL_is_dtls(s) == 0 }
        // SAFETY: `s` is live.
        && unsafe { (*s).min_ver } >= crate::ssl::ssl_lib::TLS1_3_VERSION
        && (lu.sig == EVP_PKEY_DSA || lu.hash == NID_sha1 || lu.hash == NID_sha224)
    {
        return false;
    }
    if ssl_cert_is_disabled(s, lu.sig_idx) {
        return false;
    }
    // `SSL_new` always installs the certificate, so the authority never reaches `ssl_security`
    // with a NULL `cert`; a partially constructed test object can. Answer "not allowed" rather
    // than dereferencing NULL: this cannot widen the walk.
    // SAFETY: `s` is live per the contract.
    if unsafe { (*s).cert.is_null() } {
        return false;
    }
    let sigalgstr = [(lu.sigalg >> 8) as u8, lu.sigalg as u8];
    // SAFETY: `s` is live; `sigalgstr` is a live two-byte array passed as the authority's
    // `void *other` for the duration of the callback.
    unsafe {
        crate::ssl::ssl_cert::ssl_security(
            s,
            op,
            lu.sec_bits,
            lu.hash,
            sigalgstr.as_ptr().cast_mut().cast(),
        ) != 0
    }
}

/// `size_t tls12_shared_sigalgs(s, shsig, pref, preflen, allow, allowlen)` — `t1_lib.c:3451-3476`,
/// as scheme codes.
///
/// A preference entry is kept when it resolves to an available row, `tls12_sigalg_allowed`
/// accepts it, and it appears in `allow`; the inner scan `break`s on the first match, so duplicate
/// preference entries produce duplicate shared entries exactly as the authority's counting and
/// filling passes do.
///
/// # Safety
/// `s` must be a live connection.
unsafe fn tls12_shared_sigalgs(s: *const Ssl, pref: &[u16], allow: &[u16]) -> Vec<u16> {
    let mut out = Vec::new();
    for &code in pref {
        let Some(lu) = tls1_lookup_sigalg(code) else {
            continue;
        };
        // SAFETY: `s` is live per the contract.
        if !unsafe { tls12_sigalg_allowed(s, SSL_SECOP_SIGALG_SHARED, lu) } {
            continue;
        }
        if allow.contains(&code) {
            out.push(code);
        }
    }
    out
}

/// `int tls1_set_shared_sigalgs(SSL_CONNECTION *s)` — `t1_lib.c:3478-3521`.
///
/// The preference and allowed lists are the connection's configured default
/// ([`CLIENT_SIGALGS`], the authority's `ctx->tls12_sigalgs` order) and the peer's saved list,
/// swapped when `SSL_OP_SERVER_PREFERENCE` is set. `client_sigalgs`/`conf_sigalgs` and Suite B are
/// not modelled, so the configured list is always the default — a recorded reduction of the same
/// kind `ssl_conf.rs` records for the `sigalgs` commands.
///
/// The peer list is copied before the walk, because the walk invokes the application's security
/// callback: the callback must not be handed a borrow of storage it could re-enter and replace.
/// The incumbent shared list is released only after the new one exists, and the allocation
/// failure answer is the authority's `0`.
///
/// # Safety
/// `s` must be a live connection.
pub(crate) unsafe fn tls1_set_shared_sigalgs(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live per the contract; the returned slice borrows the connection only for
    // this statement.
    let peer: Vec<u16> = unsafe { (*s).peer_sigalgs() }.to_vec();
    let conf: &[u16] = &crate::ssl::statem::extensions_clnt::CLIENT_SIGALGS;
    // SAFETY: `s` is live.
    let server_pref = unsafe { (*s).options } & SSL_OP_SERVER_PREFERENCE != 0;
    let (pref, allow) = if server_pref {
        (conf, peer.as_slice())
    } else {
        (peer.as_slice(), conf)
    };
    // SAFETY: `s` is live.
    let codes = unsafe { tls12_shared_sigalgs(s, pref, allow) };
    if codes.is_empty() {
        // No match (or no peer list): the authority publishes `(NULL, 0)` and answers success.
        // SAFETY: `s` is live; its shared pair currently obeys the pair invariant.
        unsafe { (*s).shared_sigalgs_slot().clear(FILE, 0) };
        return 1;
    }
    let Some(list) = OwnedSigalgs::from_codes(&codes) else {
        // An allocation refusal: the authority answers 0 with the shared list empty. This
        // implementation leaves the incumbent in place (a valid state that the caller's failure
        // path poisons); nothing is published and nothing leaks.
        return 0;
    };
    // SAFETY: `s` is live; its shared pair currently obeys the pair invariant.
    unsafe { (*s).shared_sigalgs_slot().replace(list) };
    1
}

/// `int tls1_process_sigalgs(SSL_CONNECTION *s)` — `t1_lib.c:3573-3598`, reduced to the shared-list
/// computation this module's accessor observes; the authority also derives `valid_flags`, which
/// this reduced certificate path does not model.
///
/// # Safety
/// `s` must be a live connection.
pub(crate) unsafe fn tls1_process_sigalgs(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live per the contract.
    unsafe { tls1_set_shared_sigalgs(s) }
}

/// `uint16_t tls1_group_name2id(SSL_CTX *ctx, const char *name)` — `t1_lib.c:709-719`, reduced to
/// the provider names the admitted group table publishes (`providers/common/capabilities.c:150-260`).
///
/// The authority compares the string case-insensitively against both the TLS name and the
/// provider-internal name, which is why `secp256r1`, `prime256v1` and `P-256` all resolve to the
/// same group. Names outside this reduced table (the deprecated curves and the hybrid KEMs) are
/// unknown here, so an unprefixed use of one fails and a `?`-prefixed one is ignored.
fn tls1_group_name2id(name: &[u8]) -> u16 {
    const NAMES: &[(&[u8], u16)] = &[
        (b"x25519", OSSL_TLS_GROUP_ID_x25519),
        (b"x448", OSSL_TLS_GROUP_ID_x448),
        (b"secp256r1", OSSL_TLS_GROUP_ID_secp256r1),
        (b"prime256v1", OSSL_TLS_GROUP_ID_secp256r1),
        (b"p-256", OSSL_TLS_GROUP_ID_secp256r1),
        (b"secp384r1", OSSL_TLS_GROUP_ID_secp384r1),
        (b"p-384", OSSL_TLS_GROUP_ID_secp384r1),
        (b"secp521r1", OSSL_TLS_GROUP_ID_secp521r1),
        (b"p-521", OSSL_TLS_GROUP_ID_secp521r1),
        (b"secp256k1", 22),
        (b"ffdhe2048", OSSL_TLS_GROUP_ID_ffdhe2048),
        (b"ffdhe3072", OSSL_TLS_GROUP_ID_ffdhe3072),
    ];
    for (n, id) in NAMES {
        if name.eq_ignore_ascii_case(n) {
            return *id;
        }
    }
    0
}

/// `CONF_parse_list`'s `nospc` trimming: leading and trailing ASCII whitespace around an element is
/// removed before the element is interpreted (`crypto/conf/conf_mod.c:739-757`).
fn trim_ascii(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if !first.is_ascii_whitespace() {
            break;
        }
        s = rest;
    }
    while let [rest @ .., last] = s {
        if !last.is_ascii_whitespace() {
            break;
        }
        s = rest;
    }
    s
}

/// One `gid_cb` invocation (`t1_lib.c:1261-1560`): apply the per-group prefixes and add, remove or
/// ignore the group. Returns `None` for the authority's syntax/unknown-group failure.
fn parse_group_element(mut elem: &[u8], out: &mut Vec<u16>) -> Option<()> {
    let mut add_keyshare = false;
    let mut ignore_unknown = false;
    let mut remove_group = false;
    loop {
        match elem.first().copied() {
            // `*` requests a key share for the group. This reduction regenerates its single share
            // from the negotiated group, so the prefix only has to be accepted.
            Some(b'*') => {
                if add_keyshare {
                    return None;
                }
                add_keyshare = true;
                elem = &elem[1..];
            }
            Some(b'?') => {
                if ignore_unknown {
                    return None;
                }
                ignore_unknown = true;
                elem = &elem[1..];
            }
            Some(b'-') => {
                if remove_group {
                    return None;
                }
                remove_group = true;
                elem = &elem[1..];
            }
            // Neither delimiter is a valid prefix for a single group name.
            Some(b'/') | Some(b':') => return None,
            _ => break,
        }
    }
    if elem.is_empty() {
        return None;
    }

    // The `DEFAULT`/`DEFAULT_SUITE_B` pseudo groups expand to a built-in list (`t1_lib.c:1163-1166`).
    // The reduced default omits the hybrid KEM the admitted provider cannot complete.
    if elem.eq_ignore_ascii_case(b"default") {
        if ignore_unknown || remove_group {
            return None;
        }
        for &gid in DEFAULT_GROUPS.iter() {
            if !out.contains(&gid) {
                out.push(gid);
            }
        }
        return Some(());
    }
    if elem.eq_ignore_ascii_case(b"default_suite_b") {
        if ignore_unknown || remove_group {
            return None;
        }
        for &gid in [OSSL_TLS_GROUP_ID_secp256r1, OSSL_TLS_GROUP_ID_secp384r1].iter() {
            if !out.contains(&gid) {
                out.push(gid);
            }
        }
        return Some(());
    }

    let gid = tls1_group_name2id(elem);
    if gid == 0 {
        return if ignore_unknown { Some(()) } else { None };
    }
    if remove_group {
        if let Some(pos) = out.iter().position(|&g| g == gid) {
            out.remove(pos);
        }
    } else if !out.contains(&gid) {
        out.push(gid);
    }
    Some(())
}

/// `tls1_set_groups_list`'s parser (`t1_lib.c:1633-1746`), reduced to the flat supported-groups list.
/// Tuples (`/`) and groups (`:`) are parsed with the authority's separators and whitespace rules; a
/// duplicate group is ignored, an empty element is a syntax error, and an unknown group fails unless
/// it carries `?`.
fn parse_groups_list(input: &[u8]) -> Option<Vec<u16>> {
    let mut out: Vec<u16> = Vec::new();
    let input = trim_ascii(input);
    if input.is_empty() {
        // The authority's `empty_list` arm reports success with a zero-length list.
        return Some(out);
    }
    for tuple in input.split(|b| *b == b'/') {
        let tuple = trim_ascii(tuple);
        if tuple.is_empty() {
            return None;
        }
        for elem in tuple.split(|b| *b == b':') {
            parse_group_element(trim_ascii(elem), &mut out)?;
        }
    }
    Some(out)
}

/// `int tls1_set_groups_list(SSL_CTX *ctx, uint16_t **grpext, size_t *grpextlen, ..., const char *str)`
/// — `t1_lib.c:1633-1746`, reduced to the flat supported-groups list (the key-share and tuple
/// extensions are regenerated from the negotiated group rather than stored).
///
/// # Safety
/// `str` must be NULL or a NUL-terminated C string. When `grpext`/`grpextlen` are non-NULL they
/// must be writable and `*grpext` must be NULL or a block this crate allocated from the `CRYPTO_*`
/// malloc seam that this call exclusively owns.
pub(crate) unsafe fn tls1_set_groups_list(
    grpext: *mut *mut u16,
    grpextlen: *mut usize,
    str: *const c_char,
) -> c_int {
    if str.is_null() {
        return 0;
    }
    // SAFETY: `str` is a NUL-terminated C string per the contract.
    let input = unsafe { CStr::from_ptr(str) }.to_bytes();
    let Some(ids) = parse_groups_list(input) else {
        // SAFETY: a constant site; the authority raises `ERR_R_PASSED_INVALID_ARGUMENT` for both a
        // syntax error and a group it cannot resolve without `?` (`t1_lib.c:1683-1687`).
        unsafe { raise_with(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT, FILE, 1690) };
        return 0;
    };
    if grpext.is_null() || grpextlen.is_null() {
        // The authority's syntax-check arm (`t1_lib.c:1723-1728`).
        return 1;
    }
    let n = ids.len();
    if n == 0 {
        // SAFETY: the pointers are writable per the contract; the previous list is owned here.
        unsafe {
            drop(OwnedBuf::adopt_plain_nullable(
                (*grpext).cast(),
                FILE_SEAM,
                0,
            ));
            *grpext = ptr::null_mut();
            *grpextlen = 0;
        }
        return 1;
    }
    let Some(bytes) = n.checked_mul(core::mem::size_of::<u16>()) else {
        return 0;
    };
    let Some(mem) = OwnedBuf::new(bytes, FILE_SEAM, 0) else {
        return 0;
    };
    for (i, gid) in ids.iter().enumerate() {
        // SAFETY: `mem` is a fresh `n`-element allocation.
        unsafe { *mem.as_ptr().cast::<u16>().add(i) = *gid };
    }
    // SAFETY: `grpext`/`grpextlen` are writable per the contract, and the previous `*grpext` is a
    // plain block this crate allocated that no one else owns.
    unsafe {
        drop(OwnedBuf::adopt_plain_nullable(
            (*grpext).cast(),
            FILE_SEAM,
            0,
        ));
        *grpext = mem.into_raw().cast();
        *grpextlen = n;
    }
    1
}

/// `int tls1_set_groups(uint16_t **grpext, size_t *grpextlen, ... int *groups, size_t ngroups)` —
/// `t1_lib.c:1083-1130`, reduced to the supported-groups list (the key-share and tuple extensions are
/// not modelled; the authority fills them in but this reduction regenerates the share from the
/// chosen group).
///
/// # Safety
/// `groups` must hold `ngroups` readable `int`s; `grpext`/`grpextlen` must be writable.
/// `*grpext` must be NULL or an initialised block allocated from the crate's `CRYPTO_*`
/// malloc seam and exclusively owned by this call (the authority's `OPENSSL_free(*grpext)`).
pub(crate) unsafe fn tls1_set_groups(
    grpext: *mut *mut u16,
    grpextlen: *mut usize,
    groups: *const c_int,
    ngroups: usize,
) -> c_int {
    if ngroups == 0 || groups.is_null() {
        return 0;
    }
    let mut list: [u16; 64] = [0u16; 64];
    if ngroups > list.len() {
        return 0;
    }
    for i in 0..ngroups {
        // SAFETY: `groups` holds `ngroups` ints per the contract.
        let nid = unsafe { *groups.add(i) };
        let id = tls1_nid2group_id(nid);
        if id == 0 || list[..i].contains(&id) {
            return 0;
        }
        list[i] = id;
    }
    let Some(mem) = OwnedBuf::new(ngroups * core::mem::size_of::<u16>(), FILE_SEAM, 0) else {
        return 0;
    };
    for (i, g) in list[..ngroups].iter().enumerate() {
        // SAFETY: `mem` is a fresh `ngroups`-element allocation.
        unsafe { *mem.as_ptr().cast::<u16>().add(i) = *g };
    }
    // SAFETY: `grpext`/`grpextlen` are writable per the contract, and the previous `*grpext` is a
    // plain block this crate allocated that no one else owns.
    unsafe {
        // SAFETY: the pointer is NULL or a live block this frame exclusively owns from the crate's CRYPTO_* seam; NULL is the authority's own no-op `free(NULL)`.
        drop(OwnedBuf::adopt_plain_nullable(
            (*grpext).cast(),
            FILE_SEAM,
            0,
        ));
        *grpext = mem.into_raw().cast();
        *grpextlen = ngroups;
    }
    1
}

// ---------------------------------------------------------------------------------------------
// S58 — the peer/shared signature-algorithm boundary
// ---------------------------------------------------------------------------------------------
#[cfg(test)]
mod t1_lib_sigalgs_tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    use crate::runtime::err::ERR_clear_error;
    use crate::ssl::methods::TLS_method;
    use crate::ssl::ssl_lib::{SSL_CTX_free, SSL_CTX_new, SSL_free, SSL_new};

    const TLS1_2_VERSION: c_int = 0x0303;

    /// A fresh context and connection; the caller releases both.
    fn connection() -> (*mut SslCtx, *mut Ssl) {
        // SAFETY: the constructors take no caller obligations and answer fresh objects owned by
        // this frame; the caller releases them with `SSL_free`/`SSL_CTX_free`.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            let s = SSL_new(ctx);
            assert!(!s.is_null());
            (ctx, s)
        }
    }

    /// A `signature_algorithms` extension body from wire scheme bytes.
    fn body(schemes: &[u8]) -> Vec<u8> {
        let mut out = (schemes.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(schemes);
        out
    }

    /// The safe acceptance rule refuses every malformed shape the authority refuses.
    #[test]
    fn t1_lib_sigalgs_malformed_vectors_are_refused_without_touching_the_incumbent() {
        let _g = crate::test_support::lock_global_state();
        let (ctx, s) = connection();
        // SAFETY: every object is this frame's.
        unsafe {
            assert_eq!(tls1_save_peer_sigalgs(s, &body(&[0x04, 0x03])), 1);
            assert_eq!((*s).peer_sigalgs(), &[0x0403]);

            // Empty body, bare length word, zero length, odd length, over-long declaration,
            // and a declared length that disagrees with the containing extension.
            for malformed in [
                &[][..],
                &[0x00][..],
                &[0x00, 0x00][..],
                &[0x00, 0x03, 0x04, 0x03, 0x00][..],
                &[0xff, 0xfe, 0x04, 0x03][..],
                &[0x00, 0x02, 0x04, 0x03, 0xff][..],
            ] {
                assert!(
                    tls1_peer_sigalgs(malformed).is_none(),
                    "malformed vector accepted: {malformed:02x?}"
                );
                ERR_clear_error();
                assert_eq!(
                    tls1_save_peer_sigalgs(s, malformed),
                    0,
                    "malformed vector saved: {malformed:02x?}"
                );
                assert_eq!(
                    (*s).peer_sigalgs(),
                    &[0x0403],
                    "a refused vector must leave the incumbent list in place"
                );
            }
            SSL_free(s);
            SSL_CTX_free(ctx);
        }
    }

    /// An unknown code point is a valid vector entry: it is stored, counted, and resolves to the
    /// authority's `NID_undef` in all three NID out-parameters.
    #[test]
    fn t1_lib_sigalgs_unknown_code_points_are_stored_and_resolve_to_nid_undef() {
        let _g = crate::test_support::lock_global_state();
        let (ctx, s) = connection();
        // SAFETY: every object is this frame's.
        unsafe {
            assert_eq!(
                tls1_save_peer_sigalgs(s, &body(&[0x04, 0x03, 0xff, 0xff])),
                1
            );
            assert_eq!((*s).peer_sigalgs(), &[0x0403, 0xffff]);

            let (mut sign, mut hash, mut signhash) = (-1, -1, -1);
            let (mut rsig, mut rhash) = (0u8, 0u8);
            assert_eq!(
                SSL_get_sigalgs(
                    s,
                    1,
                    &mut sign,
                    &mut hash,
                    &mut signhash,
                    &mut rsig,
                    &mut rhash
                ),
                2
            );
            assert_eq!((sign, hash, signhash), (NID_undef, NID_undef, NID_undef));
            assert_eq!((rsig, rhash), (0xff, 0xff));
            // An out-of-range index answers 0, as the authority's `idx >= numsigalgs` arm does.
            assert_eq!(
                SSL_get_sigalgs(
                    s,
                    2,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut()
                ),
                0
            );
            SSL_free(s);
            SSL_CTX_free(ctx);
        }
    }

    /// Duplicates are preserved: the stored list is the wire list, not a set.
    #[test]
    fn t1_lib_sigalgs_duplicates_are_preserved() {
        let _g = crate::test_support::lock_global_state();
        let (ctx, s) = connection();
        // SAFETY: every object is this frame's.
        unsafe {
            assert_eq!(
                tls1_save_peer_sigalgs(s, &body(&[0x04, 0x03, 0x04, 0x03])),
                1
            );
            assert_eq!((*s).peer_sigalgs(), &[0x0403, 0x0403]);
            assert_eq!(
                SSL_get_sigalgs(
                    s,
                    -1,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut()
                ),
                2
            );
            SSL_free(s);
            SSL_CTX_free(ctx);
        }
    }

    /// `SSL_get_sigalgs` resolves the authority's table columns for a known peer list (the case
    /// that previously answered `NID_undef` for every row) and for a provider row.
    #[test]
    fn t1_lib_sigalgs_get_sigalgs_matches_the_authority_table() {
        let _g = crate::test_support::lock_global_state();
        let (ctx, s) = connection();
        // SAFETY: every object is this frame's.
        unsafe {
            // 0x0403 ECDSA P-256/SHA-256, 0x0804 RSA-PSS/SHA-256, 0x0201 RSA PKCS#1/SHA-1,
            // 0x0905 ML-DSA-65 (a provider row), and an unknown code point.
            assert_eq!(
                tls1_save_peer_sigalgs(
                    s,
                    &body(&[0x04, 0x03, 0x08, 0x04, 0x02, 0x01, 0x09, 0x05, 0xff, 0xff])
                ),
                1
            );

            let row = |idx: c_int| {
                let (mut sign, mut hash, mut signhash) = (-1, -1, -1);
                let (mut rsig, mut rhash) = (0u8, 0u8);
                assert_eq!(
                    SSL_get_sigalgs(
                        s,
                        idx,
                        &mut sign,
                        &mut hash,
                        &mut signhash,
                        &mut rsig,
                        &mut rhash
                    ),
                    5
                );
                ((sign, hash, signhash), u16::from_be_bytes([rhash, rsig]))
            };

            assert_eq!(
                row(0),
                ((EVP_PKEY_EC, NID_sha256, NID_ecdsa_with_SHA256), 0x0403)
            );
            assert_eq!(row(1), ((EVP_PKEY_RSA_PSS, NID_sha256, NID_undef), 0x0804));
            assert_eq!(
                row(2),
                ((EVP_PKEY_RSA, NID_sha1, NID_sha1WithRSAEncryption), 0x0201)
            );
            assert_eq!(row(3), ((NID_ML_DSA_65, NID_undef, NID_ML_DSA_65), 0x0905));
            assert_eq!(row(4), ((NID_undef, NID_undef, NID_undef), 0xffff));
            SSL_free(s);
            SSL_CTX_free(ctx);
        }
    }

    /// The shared list is the authority's intersection: peer order by default, configured order
    /// under `SSL_OP_SERVER_PREFERENCE`, with unknown and un-offered entries skipped and duplicate
    /// preference entries preserved. Before this change the accessor answered 0 unconditionally.
    #[test]
    fn t1_lib_sigalgs_shared_list_matches_the_authority() {
        let _g = crate::test_support::lock_global_state();
        let (ctx, s) = connection();
        // SAFETY: every object is this frame's.
        unsafe {
            (*s).server = 1;
            (*s).version = TLS1_2_VERSION;
            (*s).min_ver = TLS1_2_VERSION;

            // Peer order wins by default: 0x0503 precedes 0x0403 on the wire.
            assert_eq!(
                tls1_save_peer_sigalgs(s, &body(&[0x05, 0x03, 0x04, 0x03])),
                1
            );
            assert_eq!(tls1_process_sigalgs(s), 1);
            assert_eq!((*s).shared_sigalgs(), &[0x0503, 0x0403]);
            let (mut sign, mut hash, mut signhash) = (-1, -1, -1);
            let (mut rsig, mut rhash) = (0u8, 0u8);
            assert_eq!(
                SSL_get_shared_sigalgs(
                    s,
                    0,
                    &mut sign,
                    &mut hash,
                    &mut signhash,
                    &mut rsig,
                    &mut rhash
                ),
                2
            );
            assert_eq!(
                (sign, hash, signhash),
                (EVP_PKEY_EC, NID_sha384, NID_ecdsa_with_SHA384)
            );
            assert_eq!(u16::from_be_bytes([rhash, rsig]), 0x0503);

            // Unknown and not-configured entries are skipped; duplicates are preserved.
            assert_eq!(
                tls1_save_peer_sigalgs(s, &body(&[0x99, 0x99, 0x04, 0x03, 0x04, 0x03, 0x02, 0x03])),
                1
            );
            assert_eq!(tls1_process_sigalgs(s), 1);
            assert_eq!((*s).shared_sigalgs(), &[0x0403, 0x0403]);

            // Server preference reverses the order to the configured list's.
            (*s).options |= SSL_OP_SERVER_PREFERENCE;
            assert_eq!(
                tls1_save_peer_sigalgs(s, &body(&[0x05, 0x03, 0x04, 0x03])),
                1
            );
            assert_eq!(tls1_process_sigalgs(s), 1);
            assert_eq!((*s).shared_sigalgs(), &[0x0403, 0x0503]);

            // A provider row is part of the configured list and resolves in the accessor.
            (*s).options &= !SSL_OP_SERVER_PREFERENCE;
            assert_eq!(tls1_save_peer_sigalgs(s, &body(&[0x09, 0x05])), 1);
            assert_eq!(tls1_process_sigalgs(s), 1);
            assert_eq!((*s).shared_sigalgs(), &[0x0905]);
            let (mut sign, mut hash, mut signhash) = (-1, -1, -1);
            assert_eq!(
                SSL_get_shared_sigalgs(
                    s,
                    0,
                    &mut sign,
                    &mut hash,
                    &mut signhash,
                    ptr::null_mut(),
                    ptr::null_mut()
                ),
                1
            );
            assert_eq!(
                (sign, hash, signhash),
                (NID_ML_DSA_65, NID_undef, NID_ML_DSA_65)
            );

            // Before any peer list is processed the accessor is in the authority's empty state.
            assert_eq!(
                SSL_get_shared_sigalgs(
                    s,
                    -1,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut()
                ),
                0
            );
            SSL_free(s);
            SSL_CTX_free(ctx);
        }
    }

    /// The owning value's constructors initialise every slot for exactly the stated count.
    #[test]
    fn t1_lib_sigalgs_owned_list_extent_matches_its_allocation() {
        let from_bytes = OwnedSigalgs::from_scheme_bytes(&[0x04, 0x03, 0x05, 0x03]).unwrap();
        assert_eq!(from_bytes.as_slice(), &[0x0403, 0x0503]);
        let from_codes = OwnedSigalgs::from_codes(&[0x0804]).unwrap();
        assert_eq!(from_codes.as_slice(), &[0x0804]);
        assert!(OwnedSigalgs::from_codes(&[]).is_none());
        assert!(OwnedSigalgs::from_scheme_bytes(&[0x04]).is_none());
    }

    /// §16 negative control: the pre-fix rule `body.get(2..2 + list_len)` accepted trailing bytes,
    /// and the instrument must distinguish it from the fixed rule. The printed line is the
    /// recorded output.
    #[test]
    fn t1_lib_sigalgs_negative_control_trailing_bytes() {
        let body = [0x00u8, 0x02, 0x04, 0x03, 0xff];
        let list_len = u16::from_be_bytes([body[0], body[1]]) as usize;
        // The exact predicate the pre-fix `tls1_peer_sigalgs` used.
        let pre_fix_accepts = body.get(2..2 + list_len).is_some();
        let post_fix_accepts = tls1_peer_sigalgs(&body).is_some();
        println!(
            "negative control: pre-fix accepts trailing-byte vector = {pre_fix_accepts}; \
             post-fix = {post_fix_accepts}"
        );
        assert!(pre_fix_accepts, "the pre-fix rule must exhibit the defect");
        assert!(!post_fix_accepts, "the fixed rule must refuse it");
    }

    /// Allocator-injection probe (`scripts/adv-probe.sh`): a refused replacement keeps the
    /// incumbent, and a successful replacement releases the previous block *by address* exactly
    /// once. `#[ignore]`d because it installs the process-global `CRYPTO_set_mem_functions` hook;
    /// it must run alone (`--exact --test-threads=1` with `OPENSSL_RS_ADV_PROBE=1`).
    #[test]
    #[ignore = "installs the process-global allocator hook; run one probe per process"]
    fn t1_lib_sigalgs_repeated_save_releases_the_incumbent_by_address() {
        let _g = crate::test_support::lock_global_state();
        use crate::ssl::adv_alloc::{self, Ev};

        adv_alloc::require_installed();
        adv_alloc::assert_instrument_live();
        let (ctx, s) = connection();
        // SAFETY: every object is this frame's; the hook observes the crate's allocator seam.
        unsafe {
            assert_eq!(tls1_save_peer_sigalgs(s, &body(&[0x04, 0x03])), 1);
            let first = (*s).peer_sigalgs().as_ptr() as usize;
            assert_eq!((*s).peer_sigalgs(), &[0x0403]);

            // A refused two-scheme (4-byte) replacement leaves the incumbent installed and does
            // not release it.
            adv_alloc::reset();
            adv_alloc::arm_any(4);
            assert_eq!(
                tls1_save_peer_sigalgs(s, &body(&[0x04, 0x03, 0x05, 0x03])),
                0
            );
            adv_alloc::disarm_any();
            assert_eq!(
                (*s).peer_sigalgs(),
                &[0x0403],
                "a refused allocation must leave the incumbent in place"
            );
            let events = adv_alloc::events();
            assert!(
                events.iter().any(|e| matches!(
                    e,
                    Ev::Malloc {
                        n: 4,
                        refused: true,
                        ..
                    }
                )),
                "the probe must have observed its intended refusal: {events:?}"
            );
            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e, Ev::Free { p } if *p == first)),
                "the incumbent must not be released on a refused allocation: {events:?}"
            );

            // A successful replacement releases the previous block by address and installs the
            // new one.
            adv_alloc::reset();
            assert_eq!(
                tls1_save_peer_sigalgs(s, &body(&[0x05, 0x03, 0x06, 0x03])),
                1
            );
            let second = (*s).peer_sigalgs().as_ptr() as usize;
            assert_ne!(second, first);
            assert_eq!((*s).peer_sigalgs(), &[0x0503, 0x0603]);
            let events = adv_alloc::events();
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, Ev::Free { p } if *p == first)),
                "the previous block must be released by its address: {events:?}"
            );

            SSL_free(s);
            SSL_CTX_free(ctx);
            adv_alloc::assert_no_double_free();
        }
    }
}
