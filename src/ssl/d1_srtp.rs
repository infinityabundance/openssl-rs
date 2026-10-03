//! Phase 14.8 — `ssl/d1_srtp.c`: the DTLS-SRTP profile surface.
//!
//! The four rows the plan gives this unit: `SSL_CTX_set_tlsext_use_srtp`, `SSL_set_tlsext_use_srtp`,
//! `SSL_get_srtp_profiles` and `SSL_get_selected_srtp_profile`. The twelve-profile table
//! (`d1_srtp.c:23-73`), the `:`-separated name parser and the duplicate/unknown refusals are
//! transcribed by name and id from `srtp.h`.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **`IS_QUIC_METHOD` is always false here.** `SSL_CTX_set_tlsext_use_srtp` returns 1 early for a
//!   QUIC method; this crate builds no QUIC method (`OSSL_QUIC_*` are Phase 15's), so the arm is
//!   unreachable and the setter always runs the parser, as the authority does for a non-QUIC
//!   method.
//! * **`SSL_get_selected_srtp_profile` is always NULL before a handshake.** The negotiated profile
//!   is set by the `use_srtp` extension during a handshake; no arm of `RT-DTLS` has one.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_ulong, c_void};

use crate::ffi::guard_ffi;
use crate::runtime::err::raise_with;
use crate::runtime::stack::{
    OPENSSL_sk_find, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_push, OpenSslStack,
};
use crate::ssl::ssl_lib::{SSL_is_quic, Ssl, SslCtx};

/// `OPENSSL_FILE` of this translation unit.
const FILE: *const c_char = c"ssl/d1_srtp.c".as_ptr();

/// `ERR_LIB_SSL` — `err.h.in:91`.
const ERR_LIB_SSL: c_int = 20;
/// `SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES` — `sslerr.h:266`.
const SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES: c_int = 362;
/// `SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST` — `sslerr.h:58`.
const SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST: c_int = 353;
/// `SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE` — `sslerr.h:268`.
const SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE: c_int = 364;

/// `struct srtp_protection_profile_st` — `ssl.h:244-247`.
#[repr(C)]
pub struct SrtpProtectionProfile {
    /// `const char *name`.
    pub name: *const c_char,
    /// `unsigned long id`.
    pub id: c_ulong,
}

// SAFETY: the profile table is a process-lifetime `static` of `(name, id)` pairs; both fields are
// plain data and the only pointer is to a `'static` C string that is never written. Sharing the
// records across threads therefore introduces no data race.
unsafe impl Sync for SrtpProtectionProfile {}

/// One row of `srtp_known_profiles` — `d1_srtp.c:23-73`.
const fn profile(name: *const c_char, id: c_ulong) -> SrtpProtectionProfile {
    SrtpProtectionProfile { name, id }
}

/// `static const SRTP_PROTECTION_PROFILE srtp_known_profiles[]` — `d1_srtp.c:23-73`. The authority's
/// trailing `{ 0 }` terminator is not stored: the lookups below iterate a fixed-length slice by
/// name, and no code here walks a sentinel.
static SRTP_KNOWN_PROFILES: [SrtpProtectionProfile; 12] = [
    profile(c"SRTP_AES128_CM_SHA1_80".as_ptr(), 0x0001),
    profile(c"SRTP_AES128_CM_SHA1_32".as_ptr(), 0x0002),
    profile(c"SRTP_AEAD_AES_128_GCM".as_ptr(), 0x0007),
    profile(c"SRTP_AEAD_AES_256_GCM".as_ptr(), 0x0008),
    profile(
        c"SRTP_DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM".as_ptr(),
        0x0009,
    ),
    profile(
        c"SRTP_DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM".as_ptr(),
        0x000A,
    ),
    profile(c"SRTP_ARIA_128_CTR_HMAC_SHA1_80".as_ptr(), 0x000B),
    profile(c"SRTP_ARIA_128_CTR_HMAC_SHA1_32".as_ptr(), 0x000C),
    profile(c"SRTP_ARIA_256_CTR_HMAC_SHA1_80".as_ptr(), 0x000D),
    profile(c"SRTP_ARIA_256_CTR_HMAC_SHA1_32".as_ptr(), 0x000E),
    profile(c"SRTP_AEAD_ARIA_128_GCM".as_ptr(), 0x000F),
    profile(c"SRTP_AEAD_ARIA_256_GCM".as_ptr(), 0x0010),
];

/// `find_profile_by_name` — `d1_srtp.c:75-92`.
fn find_profile_by_name(name: &[u8]) -> Option<&'static SrtpProtectionProfile> {
    for p in SRTP_KNOWN_PROFILES.iter() {
        // SAFETY: every entry's `name` is a process-lifetime NUL-terminated C string.
        let known = unsafe { core::ffi::CStr::from_ptr(p.name) }.to_bytes();
        if known.len() == name.len() && known == name {
            return Some(p);
        }
    }
    None
}

/// Raise `ERR_raise(ERR_LIB_SSL, reason)` at `ssl/d1_srtp.c:line`.
///
/// # Safety
/// Nothing beyond the FFI contract: the error state is thread-local.
unsafe fn raise_ssl(reason: c_int, line: c_int) {
    // SAFETY: `FILE` is a static NUL-terminated string and `reason` one of this file's constants.
    unsafe { raise_with(ERR_LIB_SSL, reason, FILE, line) };
}

/// `ssl_ctx_make_profiles` — `d1_srtp.c:94-141`.
///
/// # Safety
/// `profiles_string` must be a NUL-terminated string; `out` must point at a writable
/// `STACK_OF(SRTP_PROTECTION_PROFILE) *` slot.
unsafe fn ssl_ctx_make_profiles(
    profiles_string: *const c_char,
    out: *mut *mut OpenSslStack,
) -> c_int {
    // SAFETY: `profiles_string` is NUL-terminated per the caller's contract.
    let bytes = unsafe { core::ffi::CStr::from_ptr(profiles_string) }.to_bytes();
    // SAFETY: a fresh stack with no comparator, exactly `sk_SRTP_PROTECTION_PROFILE_new_null()`.
    let sk = OPENSSL_sk_new_null();
    if sk.is_null() {
        // SAFETY: a constant site.
        unsafe { raise_ssl(SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES, 104) };
        return 1;
    }
    let mut rest = bytes;
    loop {
        let (segment, has_colon) = match rest.iter().position(|&b| b == b':') {
            Some(i) => (&rest[..i], true),
            None => (rest, false),
        };
        match find_profile_by_name(segment) {
            Some(p) => {
                let ptr = p as *const SrtpProtectionProfile as *const c_void;
                // SAFETY: `sk` is live; `ptr` is a static profile.
                if unsafe { OPENSSL_sk_find(sk, ptr) } >= 0 {
                    // SAFETY: a constant site.
                    unsafe { raise_ssl(SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST, 115) };
                    // SAFETY: `sk` is live and owns no elements.
                    unsafe { OPENSSL_sk_free(sk) };
                    return 1;
                }
                // SAFETY: `sk` is live; `ptr` is a static profile.
                if unsafe { OPENSSL_sk_push(sk, ptr) } == 0 {
                    // SAFETY: a constant site.
                    unsafe { raise_ssl(SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES, 121) };
                    // SAFETY: `sk` is live and owns no elements.
                    unsafe { OPENSSL_sk_free(sk) };
                    return 1;
                }
            }
            None => {
                // SAFETY: a constant site.
                unsafe { raise_ssl(SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE, 125) };
                // SAFETY: `sk` is live and owns no elements.
                unsafe { OPENSSL_sk_free(sk) };
                return 1;
            }
        }
        if has_colon {
            rest = &rest[segment.len() + 1..];
        } else {
            break;
        }
    }
    // SAFETY: `out` is writable and `sk` is live.
    unsafe {
        OPENSSL_sk_free(*out);
        *out = sk;
    }
    0
}

/// `int SSL_CTX_set_tlsext_use_srtp(SSL_CTX *ctx, const char *profiles)` — `ssl/d1_srtp.c:143-149`.
///
/// # Safety
/// `ctx` must point to a live context; `profiles` a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_tlsext_use_srtp(
    ctx: *mut SslCtx,
    profiles: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        // `IS_QUIC_METHOD(ctx->method)` is unreachable for the methods this crate builds (see the
        // module header). `ctx` is live per the caller's contract.
        // SAFETY: `ctx` is live.
        unsafe { ssl_ctx_make_profiles(profiles, &mut (*ctx).srtp_profiles) }
    })
}

/// `int SSL_set_tlsext_use_srtp(SSL *s, const char *profiles)` — `ssl/d1_srtp.c:151-159`.
///
/// # Safety
/// `s` must be NULL or a live connection; `profiles` a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_tlsext_use_srtp(s: *mut Ssl, profiles: *const c_char) -> c_int {
    guard_ffi(1, || {
        if s.is_null() {
            return 1;
        }
        // SAFETY: `s` is non-NULL and live.
        if unsafe { SSL_is_quic(s) } != 0 {
            return 1;
        }
        // SAFETY: `s` is live.
        unsafe { ssl_ctx_make_profiles(profiles, &mut (*s).srtp_profiles) }
    })
}

/// `STACK_OF(SRTP_PROTECTION_PROFILE) *SSL_get_srtp_profiles(SSL *s)` — `ssl/d1_srtp.c:161-174`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_srtp_profiles(s: *mut Ssl) -> *mut OpenSslStack {
    guard_ffi(core::ptr::null_mut(), || {
        if s.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: `s` is non-NULL and live.
        if unsafe { SSL_is_quic(s) } != 0 {
            return core::ptr::null_mut();
        }
        // SAFETY: `s` is live.
        let own = unsafe { (*s).srtp_profiles };
        if !own.is_null() {
            return own;
        }
        // SAFETY: `s` is live.
        let ctx = unsafe { (*s).ctx };
        if !ctx.is_null() {
            // SAFETY: `ctx` is live.
            let from_ctx = unsafe { (*ctx).srtp_profiles };
            if !from_ctx.is_null() {
                return from_ctx;
            }
        }
        core::ptr::null_mut()
    })
}

/// `SRTP_PROTECTION_PROFILE *SSL_get_selected_srtp_profile(SSL *s)` — `ssl/d1_srtp.c:176-184`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_selected_srtp_profile(s: *mut Ssl) -> *mut SrtpProtectionProfile {
    guard_ffi(core::ptr::null_mut(), || {
        if s.is_null() {
            return core::ptr::null_mut();
        }
        // SAFETY: `s` is non-NULL and live.
        if unsafe { SSL_is_quic(s) } != 0 {
            return core::ptr::null_mut();
        }
        // SAFETY: `s` is live.
        unsafe { (*s).srtp_profile as *mut SrtpProtectionProfile }
    })
}
