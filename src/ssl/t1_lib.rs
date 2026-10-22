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
//! * **The sigalg readers.** `SSL_get_sigalgs`, `SSL_get_shared_sigalgs`,
//!   `SSL_get_signature_type_nid` and `SSL_get_peer_signature_type_nid` read the connection's
//!   `s3.tmp.peer_sigalgs`/`shared_sigalgs`/`sigalg`/`peer_sigalg`, all NULL before a handshake, and
//!   so answer the authority's own `0`.
//! * **`SSL_get1_builtin_sigalgs`.** The authority's provider probe: for each row of the static
//!   `sigalg_lookup_tbl` it fetches the hash and sets the key type, appending the row's name when
//!   both succeed. The table is transcribed below with the twenty-six rows the admitted authority's
//!   default provider enables.
//! * **`SSL_check_chain`.** The refusal arms: a NULL connection and a NULL `cert`/`pkey` pair both
//!   answer the authority's `0`.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **The sigalg lookup cache is not loaded, so the sigalg readers only reach their empty state.**
//!   The authority's `SSL_CTX_new_ex` runs `ssl_load_sigalgs` (`t1_lib.c:2200-2289`), which fills
//!   `ctx->sigalg_lookup_cache`; this slice does not, exactly as 14.1's recorded divergence for
//!   `SSL_CTX_new_ex` says. The cache is consulted by `SSL_get_sigalgs`'s per-index
//!   `tls1_lookup_sigalg` (`t1_lib.c:3625`), but every field it would read is NULL until a handshake
//!   populates them, and no handshake runs, so the court observes the empty answer on both sides.
//!   The lookup's name/phash/psignhash arm is therefore stated as `NID_undef` (what an empty cache
//!   answers) and is unreachable.
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

use crate::runtime::mem_coords::SeamFile;
use crate::runtime::obj::{
    NID_sha1, NID_sha224, NID_sha256, NID_sha384, NID_sha512, NID_undef, OBJ_nid2ln,
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

/// `SIGALG_LOOKUP` — `ssl_local.h:1186-1212`, reduced to the three fields `SSL_get1_builtin_sigalgs`
/// reads: the TLS name, the hash NID and the `EVP_PKEY` type.
struct SigAlgLookup {
    /// `const char *name`.
    name: &'static str,
    /// `int hash` — `NID_undef` means "no associated digest".
    hash: c_int,
    /// `int sig` — the `EVP_PKEY_*` type.
    sig: c_int,
}

/// `sigalg_lookup_tbl[]` — `ssl/t1_lib.c:1964-2142`, the twenty-six non-GOST rows, in table order.
///
/// The names are the `TLSEXT_SIGALG_*_name` macros (`ssl_local.h:2247-2280`); the hash and key-type
/// columns are read from the same initialiser. The four `#ifndef OPENSSL_NO_GOST` rows are omitted
/// per this module's divergence note.
static SIGALG_LOOKUP_TBL: [SigAlgLookup; 26] = [
    SigAlgLookup {
        name: "ecdsa_secp256r1_sha256",
        hash: NID_sha256,
        sig: EVP_PKEY_EC,
    },
    SigAlgLookup {
        name: "ecdsa_secp384r1_sha384",
        hash: NID_sha384,
        sig: EVP_PKEY_EC,
    },
    SigAlgLookup {
        name: "ecdsa_secp521r1_sha512",
        hash: NID_sha512,
        sig: EVP_PKEY_EC,
    },
    SigAlgLookup {
        name: "ed25519",
        hash: NID_undef,
        sig: EVP_PKEY_ED25519,
    },
    SigAlgLookup {
        name: "ed448",
        hash: NID_undef,
        sig: EVP_PKEY_ED448,
    },
    SigAlgLookup {
        name: "ecdsa_sha224",
        hash: NID_sha224,
        sig: EVP_PKEY_EC,
    },
    SigAlgLookup {
        name: "ecdsa_sha1",
        hash: NID_sha1,
        sig: EVP_PKEY_EC,
    },
    SigAlgLookup {
        name: "ecdsa_brainpoolP256r1tls13_sha256",
        hash: NID_sha256,
        sig: EVP_PKEY_EC,
    },
    SigAlgLookup {
        name: "ecdsa_brainpoolP384r1tls13_sha384",
        hash: NID_sha384,
        sig: EVP_PKEY_EC,
    },
    SigAlgLookup {
        name: "ecdsa_brainpoolP512r1tls13_sha512",
        hash: NID_sha512,
        sig: EVP_PKEY_EC,
    },
    SigAlgLookup {
        name: "rsa_pss_rsae_sha256",
        hash: NID_sha256,
        sig: EVP_PKEY_RSA_PSS,
    },
    SigAlgLookup {
        name: "rsa_pss_rsae_sha384",
        hash: NID_sha384,
        sig: EVP_PKEY_RSA_PSS,
    },
    SigAlgLookup {
        name: "rsa_pss_rsae_sha512",
        hash: NID_sha512,
        sig: EVP_PKEY_RSA_PSS,
    },
    SigAlgLookup {
        name: "rsa_pss_pss_sha256",
        hash: NID_sha256,
        sig: EVP_PKEY_RSA_PSS,
    },
    SigAlgLookup {
        name: "rsa_pss_pss_sha384",
        hash: NID_sha384,
        sig: EVP_PKEY_RSA_PSS,
    },
    SigAlgLookup {
        name: "rsa_pss_pss_sha512",
        hash: NID_sha512,
        sig: EVP_PKEY_RSA_PSS,
    },
    SigAlgLookup {
        name: "rsa_pkcs1_sha256",
        hash: NID_sha256,
        sig: EVP_PKEY_RSA,
    },
    SigAlgLookup {
        name: "rsa_pkcs1_sha384",
        hash: NID_sha384,
        sig: EVP_PKEY_RSA,
    },
    SigAlgLookup {
        name: "rsa_pkcs1_sha512",
        hash: NID_sha512,
        sig: EVP_PKEY_RSA,
    },
    SigAlgLookup {
        name: "rsa_pkcs1_sha224",
        hash: NID_sha224,
        sig: EVP_PKEY_RSA,
    },
    SigAlgLookup {
        name: "rsa_pkcs1_sha1",
        hash: NID_sha1,
        sig: EVP_PKEY_RSA,
    },
    SigAlgLookup {
        name: "dsa_sha256",
        hash: NID_sha256,
        sig: EVP_PKEY_DSA,
    },
    SigAlgLookup {
        name: "dsa_sha384",
        hash: NID_sha384,
        sig: EVP_PKEY_DSA,
    },
    SigAlgLookup {
        name: "dsa_sha512",
        hash: NID_sha512,
        sig: EVP_PKEY_DSA,
    },
    SigAlgLookup {
        name: "dsa_sha224",
        hash: NID_sha224,
        sig: EVP_PKEY_DSA,
    },
    SigAlgLookup {
        name: "dsa_sha1",
        hash: NID_sha1,
        sig: EVP_PKEY_DSA,
    },
];

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
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    let (psig, numsigalgs) = unsafe { ((*s).peer_sigalgs, (*s).peer_sigalgslen) };
    if psig.is_null() || numsigalgs > c_int::MAX as usize {
        return 0;
    }
    if idx >= 0 {
        if idx as usize >= numsigalgs {
            return 0;
        }
        // SAFETY: `idx` is in range of the `numsigalgs`-long array `psig`.
        let val = unsafe { *psig.add(idx as usize) };
        if !rhash.is_null() {
            // SAFETY: `rhash` is writable per the contract.
            unsafe { *rhash = ((val >> 8) & 0xff) as u8 };
        }
        if !rsig.is_null() {
            // SAFETY: `rsig` is writable per the contract.
            unsafe { *rsig = (val & 0xff) as u8 };
        }
        // `tls1_lookup_sigalg`'s cache is not loaded (see the module divergence note), so an
        // empty cache is what this arm would answer; it is unreachable because `peer_sigalgs` is
        // NULL in every state this slice can reach.
        if !psign.is_null() {
            // SAFETY: `psign` is writable per the contract.
            unsafe { *psign = NID_undef };
        }
        if !phash.is_null() {
            // SAFETY: `phash` is writable per the contract.
            unsafe { *phash = NID_undef };
        }
        if !psignhash.is_null() {
            // SAFETY: `psignhash` is writable per the contract.
            unsafe { *psignhash = NID_undef };
        }
    }
    numsigalgs as c_int
}

/// `int SSL_get_shared_sigalgs(SSL *s, int idx, int *psign, int *phash, int *psignhash,
/// unsigned char *rsig, unsigned char *rhash)` — `ssl/t1_lib.c:3636-3663`.
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
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    let (shsigalgs, len) = unsafe { ((*s).shared_sigalgs, (*s).shared_sigalgslen) };
    if shsigalgs.is_null() || idx < 0 || idx as usize >= len || len > c_int::MAX as usize {
        return 0;
    }
    // Unreachable: no unit in this slice sets `shared_sigalgs`.
    if !phash.is_null() {
        // SAFETY: `phash` is writable per the contract.
        unsafe { *phash = NID_undef };
    }
    if !psign.is_null() {
        // SAFETY: `psign` is writable per the contract.
        unsafe { *psign = NID_undef };
    }
    if !psignhash.is_null() {
        // SAFETY: `psignhash` is writable per the contract.
        unsafe { *psignhash = NID_undef };
    }
    if !rsig.is_null() {
        // SAFETY: `rsig` is writable per the contract.
        unsafe { *rsig = 0 };
    }
    if !rhash.is_null() {
        // SAFETY: `rhash` is writable per the contract.
        unsafe { *rhash = 0 };
    }
    len as c_int
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

/// `int tls1_save_u16(PACKET *pkt, uint16_t **p, size_t *len)` — `t1_lib.c:3490-3517`, for the
/// `signature_algorithms` vector `tls_parse_ctos_sig_algs` saves (`extensions_srvr.c:303-320`)
/// and the client's `CertificateRequest` reader (`statem_clnt.c:2650-2690`, `:2686`).
///
/// The extension body is `list_len(2) || scheme(2)...`; a zero-length or odd list, or one whose
/// declared length runs past the body, is refused *before* the incumbent list is released, so a
/// malformed request leaves the previous list intact (the authority parses into the packet before
/// it stores). On success the schemes are stored as native-endian `u16`s — that is the
/// representation `SSL_get_sigalgs` reads — in a `CRYPTO_malloc` block this connection owns and
/// `SSL_free` releases.
///
/// # Safety
/// `s` must be a live connection.
pub(crate) unsafe fn tls1_save_peer_sigalgs(s: *mut Ssl, body: &[u8]) -> c_int {
    if body.len() < 2 {
        return 0;
    }
    let list_len = ((body[0] as usize) << 8) | body[1] as usize;
    if list_len == 0 || 2 + list_len > body.len() {
        return 0;
    }
    // SAFETY: the declared vector is inside `body`.
    unsafe { tls1_save_peer_sigalgs_raw(s, &body[2..2 + list_len]) }
}

/// The scheme bytes of a `signature_algorithms` vector (`list_len(2)` already stripped), saved
/// exactly as [`tls1_save_peer_sigalgs`] saves them. The TLS1.2 `CertificateRequest` reader has
/// the vector in this shape after `PACKET_get_length_prefixed_2`.
///
/// # Safety
/// `s` must be a live connection.
pub(crate) unsafe fn tls1_save_peer_sigalgs_raw(s: *mut Ssl, schemes: &[u8]) -> c_int {
    if schemes.is_empty() || !schemes.len().is_multiple_of(2) {
        return 0;
    }
    let count = schemes.len() / 2;
    // SAFETY: `s` is live; the block is the connection's own.
    let p = unsafe { alloc_peer_sigalgs(s, count) };
    if p.is_null() {
        return 0;
    }
    // SAFETY: `p` is `count * size_of::<u16>()` writable bytes from `CRYPTO_malloc` (maximally
    // aligned), so it is a valid `count`-element `u16` slice; this frame is its only writer.
    let out = unsafe { core::slice::from_raw_parts_mut(p, count) };
    for (slot, pair) in out.iter_mut().zip(schemes.as_chunks::<2>().0) {
        *slot = u16::from_be_bytes(*pair);
    }
    1
}

/// Stores `schemes` as the connection's peer signature-algorithm list.
///
/// The authority's default list is what it uses when the peer sent no `signature_algorithms` at
/// all: the client falls back to the list it advertised (`tls1_get_legacy_sigalg` + the
/// `tls12_get_psigalgs(s, 1, ...)` membership test in `tls_choose_sigalg`, `t1_lib.c:4685-4713`;
/// `tls1_set_shared_sigalgs`'s NULL-`peer_sigalgs` arm, `t1_lib.c:3490-3509`). This stores that
/// list so the certificate constructors' scheme check can consult it.
///
/// # Safety
/// `s` must be a live connection.
pub(crate) unsafe fn tls1_save_peer_sigalgs_default(s: *mut Ssl, schemes: &[u16]) -> c_int {
    if schemes.is_empty() {
        return 0;
    }
    // SAFETY: `s` is live; the block is the connection's own.
    let p = unsafe { alloc_peer_sigalgs(s, schemes.len()) };
    if p.is_null() {
        return 0;
    }
    // SAFETY: `p` is `schemes.len()` writable `u16`s; this frame is its only writer.
    let out = unsafe { core::slice::from_raw_parts_mut(p, schemes.len()) };
    out.copy_from_slice(schemes);
    1
}

/// Releases the incumbent peer list and answers a writable block for `count` schemes, publishing
/// it as the connection's own. NULL on a refused allocation; the checked multiply is what refuses
/// an impossible extent before anything is released.
///
/// # Safety
/// `s` must be a live connection.
unsafe fn alloc_peer_sigalgs(s: *mut Ssl, count: usize) -> *mut u16 {
    use crate::runtime::mem::{CRYPTO_free, CRYPTO_malloc};
    let Some(bytes) = count.checked_mul(core::mem::size_of::<u16>()) else {
        return ptr::null_mut();
    };
    // SAFETY: `s` is live; the incumbent (if any) is this connection's own block.
    unsafe {
        CRYPTO_free((*s).peer_sigalgs.cast(), FILE, 0);
        (*s).peer_sigalgs = ptr::null_mut();
        (*s).peer_sigalgslen = 0;
    }
    // SAFETY: no preconditions; the refusal arm leaves the connection's list empty.
    let p = unsafe { CRYPTO_malloc(bytes, FILE, 0) }.cast::<u16>();
    if p.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `s` is live; `p` is the block just allocated for `count` schemes.
    unsafe {
        (*s).peer_sigalgs = p;
        (*s).peer_sigalgslen = count;
    }
    p
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
