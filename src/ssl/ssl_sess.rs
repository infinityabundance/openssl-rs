//! Phase 14.7 — `ssl/ssl_sess.c`: the session object, the session cache, the callback setters and
//! the PEM session codec.
//!
//! The 65 exports the plan names for this unit. The session object's lifecycle
//! (`SSL_SESSION_new`/`_free`/`_up_ref`/`_dup`), its accessors, the per-context internal cache
//! (`SSL_CTX_add_session`/`_remove_session`/`_flush_sessions_ex` and the callback setters), the
//! connection's session selection (`SSL_get_session`/`SSL_get1_session`/`SSL_set_session`) and the
//! four PEM entry points the `IMPLEMENT_PEM_rw` macro generates at `ssl_sess.c:1523`.
//!
//! ## The cache is an `OpenSslStack`, and the divergence is recorded
//!
//! The authority keys an `LHASH_OF(SSL_SESSION)` on `(ssl_version, session_id)` (`ssl_lib.c:3854`,
//! `:3877`) and keeps a `calc_timeout`-ordered doubly linked list for eviction. This crate stores
//! the sessions in an `OpenSslStack` and searches it linearly, comparing the same two fields; the
//! observable cache controls (add/remove/flush returns and the callbacks each invokes) are the
//! authority's. **Eviction and flushing process the stack in insertion order, not
//! `calc_timeout` order** — no court arm depends on the eviction order, and the divergence is
//! recorded here rather than hidden. The per-session `prev`/`next`/`owner` fields exist but only
//! `owner` is maintained (the list is not modelled).
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **`time`/`timeout`/`calc_timeout` are seconds.** See `src/ssl/ssl_lib.rs`: every reader
//!   converts to `time_t`, so the codec and the accessors agree.
//! * **`ssl_generate_session_id` and `ssl_get_new_session` are not landed.** They are internal to
//!   `ssl_sess.c` and drive the handshake; no exported row names them, and the handshake is not
//!   driven. `SSL_SESSION_new` itself is landed whole.
//! * **`ssl_session_dup_intern` copies the parsed fields but not `early_secret`'s length** — the
//!   authority `memcpy`s the first `offsetof(SSL_SESSION, prev)` bytes, which includes it; this
//!   crate copies the field explicitly, so the result is the same.
//! * **`SSL_CTX_sess_set_new_cb`'s callback is stored but never invoked.** Nothing this crate
//!   builds completes a handshake, so the "new session" trigger is unreachable.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::evp::pkey::EVP_PKEY_up_ref;
use crate::ffi::guard_ffi;
use crate::runtime::err::raise_with;
use crate::runtime::ex_data::{
    CRYPTO_dup_ex_data, CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data,
    CRYPTO_set_ex_data, CRYPTO_EX_INDEX_SSL_SESSION,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_memdup, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::stack::{
    OPENSSL_sk_delete, OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push,
    OPENSSL_sk_value,
};
use crate::runtime::thread::{
    CRYPTO_THREAD_read_lock, CRYPTO_THREAD_unlock, CRYPTO_THREAD_write_lock,
};
use crate::ssl::ssl_asn1::{d2i_SSL_SESSION, i2d_SSL_SESSION};
use crate::ssl::ssl_init::OPENSSL_init_ssl;
use crate::ssl::ssl_lib::{
    ClientCertCb, GenCookieCb, GenStatelessCookieCb, GetSessionCb, InfoCb, NewSessionCb,
    RemoveSessionCb, Ssl, SslCtx, SslSession, TlsSessionTicketExt, VerifyCookieCb,
    VerifyStatelessCookieCb, SSL_MAX_SID_CTX_LENGTH, SSL_MAX_SSL_SESSION_ID_LENGTH,
    TLS13_MAX_RESUMPTION_PSK_LENGTH,
};
use crate::ssl::ssl_lib::{SSL_is_quic, SSL_set_ssl_method};
use crate::ssl::statem::statem::{SSL_in_before, SSL_in_init};
use crate::x509::t_x509::OSSL_STACK_OF_X509_free;
use crate::x509::x509_set::X509_up_ref;
use crate::x509::x_x509::{X509_free, X509};

/// `OPENSSL_FILE` of this translation unit.
const FILE: *const c_char = c"ssl/ssl_sess.c".as_ptr();
/// `ERR_LIB_SSL` — `include/openssl/err.h.in:91`.
const ERR_LIB_SSL: c_int = 20;
/// `SSL_R_SSL_SESSION_ID_TOO_LONG` — `sslerr.h:296`.
const SSL_R_SSL_SESSION_ID_TOO_LONG: c_int = 408;
/// `SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG` — `sslerr.h:294`.
const SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG: c_int = 273;
/// `SSL_SESS_CACHE_UPDATE_TIME` — `ssl.h:721`.
const SSL_SESS_CACHE_UPDATE_TIME: c_long = 0x0400;
/// `TLSEXT_max_fragment_length_UNSPECIFIED` — `tls1.h:234`.
const TLSEXT_MAX_FRAGMENT_LENGTH_UNSPECIFIED: u8 = 255;
/// `X509_V_OK` is the value `ssl_get_new_session` installs; that internal function is not
/// landed, so the constant is named for the record only.
#[allow(dead_code)]
const X509_V_OK: c_long = 0;
/// `TLS1_VERSION` — `tls1.h`.
const TLS1_VERSION: c_int = 0x0301;
/// `OPENSSL_INIT_LOAD_SSL_STRINGS` — `ssl.h:2827`.
const OPENSSL_INIT_LOAD_SSL_STRINGS: u64 = 0x0020_0000;
/// `SSL_MAX_MASTER_KEY_LENGTH` — `ssl.h`.
const SSL_MAX_MASTER_KEY_LENGTH: usize = 48;
/// `SSL_SENT_SHUTDOWN` — `ssl.h:932`.
const SSL_SENT_SHUTDOWN: c_int = 1;
/// `PEM_STRING_SSL_SESSION` — `pem.h:53`.
const PEM_STRING_SSL_SESSION: *const c_char = c"SSL SESSION PARAMETERS".as_ptr();

/// `CRYPTO_UP_REF` — the relaxed fetch-add the authority's header defines.
fn up_ref(refs: &AtomicI32) -> c_int {
    refs.fetch_add(1, Ordering::Relaxed) + 1
}

/// `CRYPTO_DOWN_REF` — the release fetch-sub the authority's header defines.
fn down_ref(refs: &AtomicI32) -> c_int {
    refs.fetch_sub(1, Ordering::Release) - 1
}

/// `ERR_raise(ERR_LIB_SSL, reason)` at `ssl/ssl_sess.c:line`.
fn raise_ssl(reason: c_int, line: c_int) {
    // SAFETY: thread-local error state.
    unsafe { raise_with(ERR_LIB_SSL, reason, FILE, line) };
}

/// `CRYPTO_EX_INDEX_SSL_SESSION`'s `CRYPTO_new_ex_data` wrapper over a raw session.
///
/// # Safety
/// `ss` must be a live session whose `ex_data` is unused.
unsafe fn session_new_ex_data(ss: *mut SslSession) -> c_int {
    // SAFETY: `ss` is live per the contract.
    unsafe { CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL_SESSION, ss.cast(), &mut (*ss).ex_data) }
}

/// `void ssl_session_calculate_timeout(SSL_SESSION *ss)` — `ssl/ssl_sess.c:48-51`.
///
/// # Safety
/// `ss` must be a live session.
pub(crate) unsafe fn ssl_session_calculate_timeout(ss: *mut SslSession) {
    // SAFETY: `ss` is live per the contract.
    unsafe { (*ss).calc_timeout = (*ss).time.wrapping_add((*ss).timeout) };
}

/// `static ossl_inline int sess_timedout(OSSL_TIME t, SSL_SESSION *ss)` — `ssl/ssl_sess.c:30-33`.
///
/// # Safety
/// `ss` must be a live session.
unsafe fn sess_timedout(t: u64, ss: *const SslSession) -> bool {
    // SAFETY: `ss` is live per the contract.
    t > unsafe { (*ss).calc_timeout }
}

/// `static ossl_inline int timeoutcmp(SSL_SESSION *a, SSL_SESSION *b)` — `ssl/ssl_sess.c:39-42`.
///
/// Kept for the record: the authority uses it to order the linked list, which this crate's
/// stack-based cache does not model (see the module header).
///
/// # Safety
/// Both pointers must be live sessions.
#[allow(dead_code)]
unsafe fn timeoutcmp(a: *const SslSession, b: *const SslSession) -> c_int {
    // SAFETY: both are live per the contract.
    let (x, y) = unsafe { ((*a).calc_timeout, (*b).calc_timeout) };
    if x < y {
        -1
    } else if x > y {
        1
    } else {
        0
    }
}

/// `SSL_SESSION *SSL_SESSION_new(void)` — `ssl/ssl_sess.c:102-130`.
///
/// # Safety
/// No precondition; the returned session is owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_new() -> *mut SslSession {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the initialisation options are a constant; `settings` is NULL.
        if unsafe { OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, ptr::null()) } == 0 {
            return ptr::null_mut();
        }
        // SAFETY: `CRYPTO_zalloc` is this crate's own allocator and returns a zeroed block or NULL.
        let ss = CRYPTO_zalloc(core::mem::size_of::<SslSession>(), FILE, 109).cast::<SslSession>();
        if ss.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `ss` is a fresh zeroed allocation.
        unsafe {
            (*ss).max_fragment_len_mode = TLSEXT_MAX_FRAGMENT_LENGTH_UNSPECIFIED;
            (*ss).verify_result = 1;
            (*ss).timeout = 60 * 5 + 4;
            (*ss).time = time_now_secs();
            ssl_session_calculate_timeout(ss);
            (*ss).references = AtomicI32::new(1);
        }
        // SAFETY: `ss` is live and its `ex_data` is zeroed.
        if unsafe { session_new_ex_data(ss) } == 0 {
            // SAFETY: `ss` is live and owned here.
            unsafe { CRYPTO_free(ss.cast(), FILE, 121) };
            return ptr::null_mut();
        }
        ss
    })
}

/// Seconds since the epoch, the authority's `ossl_time_now` at second resolution.
fn time_now_secs() -> u64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => 0,
    }
}

/// `static SSL_SESSION *ssl_session_dup_intern(const SSL_SESSION *src, int ticket)` —
/// `ssl/ssl_sess.c:136-266`.
///
/// # Safety
/// `src` must be a live session; the returned session is owned by the caller.
unsafe fn ssl_session_dup_intern(src: *const SslSession, ticket: c_int) -> *mut SslSession {
    // SAFETY: `src` is live per the contract.
    let s = unsafe { &*src };
    // SAFETY: `CRYPTO_zalloc` is this crate's own allocator and returns a zeroed block or NULL.
    let dest = CRYPTO_zalloc(core::mem::size_of::<SslSession>(), FILE, 140).cast::<SslSession>();
    if dest.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `dest` is a fresh zeroed allocation; copy the value fields, leave every pointer NULL
    // until it is successfully re-created below (the authority's `memcpy` up to `prev`).
    unsafe {
        (*dest).ssl_version = s.ssl_version;
        (*dest).master_key_length = s.master_key_length;
        (*dest).early_secret = s.early_secret;
        (*dest).master_key = s.master_key;
        (*dest).session_id_length = s.session_id_length;
        (*dest).session_id = s.session_id;
        (*dest).sid_ctx_length = s.sid_ctx_length;
        (*dest).sid_ctx = s.sid_ctx;
        (*dest).not_resumable = s.not_resumable;
        (*dest).verify_result = s.verify_result;
        (*dest).time = s.time;
        (*dest).timeout = s.timeout;
        (*dest).calc_timeout = s.calc_timeout;
        (*dest).compress_meth = s.compress_meth;
        (*dest).cipher = s.cipher;
        (*dest).cipher_id = s.cipher_id;
        (*dest).kex_group = s.kex_group;
        (*dest).flags = s.flags;
        (*dest).ext_tick_lifetime_hint = s.ext_tick_lifetime_hint;
        (*dest).ext_tick_age_add = s.ext_tick_age_add;
        (*dest).ext_max_early_data = s.ext_max_early_data;
        (*dest).max_fragment_len_mode = s.max_fragment_len_mode;
        (*dest).references = AtomicI32::new(1);
    }
    // SAFETY: `dest` is live with a zeroed `ex_data`.
    if unsafe { session_new_ex_data(dest) } == 0 {
        // SAFETY: `dest` is owned here.
        unsafe { CRYPTO_free(dest.cast(), FILE, 181) };
        return ptr::null_mut();
    }

    // SAFETY: every step mirrors the authority's `goto err` ladder.
    unsafe {
        if !s.peer.is_null() {
            if X509_up_ref(s.peer) == 0 {
                SSL_SESSION_free(dest);
                return ptr::null_mut();
            }
            (*dest).peer = s.peer;
        }
        if !s.peer_chain.is_null() {
            (*dest).peer_chain = crate::x509::x509_cmp::X509_chain_up_ref(s.peer_chain);
            if (*dest).peer_chain.is_null() {
                SSL_SESSION_free(dest);
                return ptr::null_mut();
            }
        }
        if !s.peer_rpk.is_null() {
            if EVP_PKEY_up_ref(s.peer_rpk.cast::<crate::evp::pkey::EvpPkey>()) == 0 {
                SSL_SESSION_free(dest);
                return ptr::null_mut();
            }
            (*dest).peer_rpk = s.peer_rpk;
        }
        if !s.psk_identity_hint.is_null() {
            (*dest).psk_identity_hint = CRYPTO_strdup(s.psk_identity_hint, FILE, 210);
            if (*dest).psk_identity_hint.is_null() {
                SSL_SESSION_free(dest);
                return ptr::null_mut();
            }
        }
        if !s.psk_identity.is_null() {
            (*dest).psk_identity = CRYPTO_strdup(s.psk_identity, FILE, 215);
            if (*dest).psk_identity.is_null() {
                SSL_SESSION_free(dest);
                return ptr::null_mut();
            }
        }
        if CRYPTO_dup_ex_data(
            CRYPTO_EX_INDEX_SSL_SESSION,
            &mut (*dest).ex_data,
            &s.ex_data as *const _ as *mut _,
        ) == 0
        {
            SSL_SESSION_free(dest);
            return ptr::null_mut();
        }
        if !s.ext_hostname.is_null() {
            (*dest).ext_hostname = CRYPTO_strdup(s.ext_hostname, FILE, 227);
            if (*dest).ext_hostname.is_null() {
                SSL_SESSION_free(dest);
                return ptr::null_mut();
            }
        }
        if ticket != 0 && !s.ext_tick.is_null() {
            (*dest).ext_tick = CRYPTO_memdup(s.ext_tick.cast(), s.ext_ticklen, FILE, 233).cast();
            if (*dest).ext_tick.is_null() {
                SSL_SESSION_free(dest);
                return ptr::null_mut();
            }
            (*dest).ext_ticklen = s.ext_ticklen;
        } else {
            (*dest).ext_tick_lifetime_hint = 0;
            (*dest).ext_ticklen = 0;
        }
        if !s.ext_alpn_selected.is_null() {
            (*dest).ext_alpn_selected = CRYPTO_memdup(
                s.ext_alpn_selected.cast(),
                s.ext_alpn_selected_len,
                FILE,
                243,
            )
            .cast();
            if (*dest).ext_alpn_selected.is_null() {
                SSL_SESSION_free(dest);
                return ptr::null_mut();
            }
            (*dest).ext_alpn_selected_len = s.ext_alpn_selected_len;
        }
        if !s.srp_username.is_null() {
            (*dest).srp_username = CRYPTO_strdup(s.srp_username, FILE, 250);
            if (*dest).srp_username.is_null() {
                SSL_SESSION_free(dest);
                return ptr::null_mut();
            }
        }
        if !s.ticket_appdata.is_null() {
            (*dest).ticket_appdata =
                CRYPTO_memdup(s.ticket_appdata.cast(), s.ticket_appdata_len, FILE, 257).cast();
            if (*dest).ticket_appdata.is_null() {
                SSL_SESSION_free(dest);
                return ptr::null_mut();
            }
            (*dest).ticket_appdata_len = s.ticket_appdata_len;
        }
    }
    dest
}

/// `SSL_SESSION *SSL_SESSION_dup(const SSL_SESSION *src)` — `ssl/ssl_sess.c:268-271`.
///
/// # Safety
/// `src` must be a live session; the returned session is owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_dup(src: *const SslSession) -> *mut SslSession {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: forwarded per the caller's contract.
        unsafe { ssl_session_dup_intern(src, 1) }
    })
}

/// `SSL_SESSION *ssl_session_dup(const SSL_SESSION *src, int ticket)` — `ssl/ssl_sess.c:279-287`.
///
/// The internal duplicate `SSL_dup` reaches; that entry point is still open, so this is named for
/// the record.
///
/// # Safety
/// `src` must be a live session; the returned session is owned by the caller.
#[allow(dead_code)]
pub(crate) unsafe fn ssl_session_dup(src: *const SslSession, ticket: c_int) -> *mut SslSession {
    // SAFETY: forwarded per the caller's contract.
    let sess = unsafe { ssl_session_dup_intern(src, ticket) };
    if !sess.is_null() {
        // SAFETY: `sess` is a fresh session owned here.
        unsafe { (*sess).not_resumable = 0 };
    }
    sess
}

/// `void SSL_SESSION_free(SSL_SESSION *ss)` — `ssl/ssl_sess.c:899-931`.
///
/// # Safety
/// `ss` must be NULL or a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_free(ss: *mut SslSession) {
    guard_ffi((), || {
        if ss.is_null() {
            return;
        }
        // SAFETY: `ss` is live per the caller's contract.
        let i = down_ref(unsafe { &(*ss).references });
        if i > 0 {
            return;
        }
        // SAFETY: the count reached zero, so `ss` is owned here.
        unsafe {
            CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_SESSION, ss.cast(), &mut (*ss).ex_data);
            // `OPENSSL_cleanse` of the master key and session id.
            ptr::write_bytes(
                (*ss).master_key.as_mut_ptr(),
                0,
                TLS13_MAX_RESUMPTION_PSK_LENGTH,
            );
            ptr::write_bytes(
                (*ss).session_id.as_mut_ptr(),
                0,
                SSL_MAX_SSL_SESSION_ID_LENGTH,
            );
            X509_free((*ss).peer);
            crate::evp::pkey::EVP_PKEY_free((*ss).peer_rpk.cast());
            OSSL_STACK_OF_X509_free((*ss).peer_chain);
            CRYPTO_free((*ss).ext_hostname.cast(), FILE, 918);
            CRYPTO_free((*ss).ext_tick.cast(), FILE, 919);
            CRYPTO_free((*ss).psk_identity_hint.cast(), FILE, 921);
            CRYPTO_free((*ss).psk_identity.cast(), FILE, 922);
            CRYPTO_free((*ss).srp_username.cast(), FILE, 925);
            CRYPTO_free((*ss).ext_alpn_selected.cast(), FILE, 927);
            CRYPTO_free((*ss).ticket_appdata.cast(), FILE, 928);
            CRYPTO_free(ss.cast(), FILE, 930);
        }
    })
}

/// `int SSL_SESSION_up_ref(SSL_SESSION *ss)` — `ssl/ssl_sess.c:933-943`.
///
/// # Safety
/// `ss` must be a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_up_ref(ss: *mut SslSession) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ss` is live per the caller's contract.
        let i = unsafe { up_ref(&(*ss).references) };
        if i <= 0 {
            return 0;
        }
        if i > 1 {
            1
        } else {
            0
        }
    })
}

// -------------------------------------------------------------------------------------------
// The internal session cache
// -------------------------------------------------------------------------------------------

/// Compare two sessions the way `ssl_session_cmp` (`ssl_lib.c:3877`) does, on `ssl_version` and
/// the session id.
///
/// # Safety
/// Both pointers must be live sessions.
unsafe fn session_cmp(a: *const SslSession, b: *const SslSession) -> bool {
    // SAFETY: both are live per the contract.
    unsafe {
        if (*a).ssl_version != (*b).ssl_version {
            return false;
        }
        if (*a).session_id_length != (*b).session_id_length {
            return false;
        }
        let n = (*a).session_id_length;
        if n == 0 {
            return true;
        }
        let pa = (*a).session_id.as_ptr();
        let pb = (*b).session_id.as_ptr();
        if pa == pb {
            return true;
        }
        for i in 0..n {
            if *pa.add(i) != *pb.add(i) {
                return false;
            }
        }
        true
    }
}

/// The authority's `lh_SSL_SESSION_retrieve(ctx->sessions, c)`.
///
/// # Safety
/// `ctx` must be a live context; `c` a live session.
unsafe fn cache_find(ctx: *mut SslCtx, c: *const SslSession) -> *mut SslSession {
    // SAFETY: `ctx` is live per the contract.
    let st = unsafe { (*ctx).sessions };
    if st.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `st` is the live cache stack.
    let n = unsafe { OPENSSL_sk_num(st) };
    for i in 0..n {
        // SAFETY: the index is in range.
        let s = unsafe { OPENSSL_sk_value(st, i).cast::<SslSession>() };
        // SAFETY: both pointers are live sessions (the entry is non-NULL and `c` is the caller's).
        if !s.is_null() && unsafe { session_cmp(s, c) } {
            return s;
        }
    }
    ptr::null_mut()
}

/// Remove a session from the cache stack and return its index, or -1.
///
/// # Safety
/// `ctx` must be a live context; `s` the session to delete.
unsafe fn cache_delete_ptr(ctx: *mut SslCtx, s: *mut SslSession) -> c_int {
    // SAFETY: `ctx` is live per the contract.
    let st = unsafe { (*ctx).sessions };
    if st.is_null() {
        return -1;
    }
    // SAFETY: `st` is the live cache stack.
    let n = unsafe { OPENSSL_sk_num(st) };
    for i in 0..n {
        // SAFETY: the index is in range.
        if unsafe { OPENSSL_sk_value(st, i).cast::<SslSession>() } == s {
            // SAFETY: the index is in range.
            unsafe { OPENSSL_sk_delete(st, i) };
            return i;
        }
    }
    -1
}

/// `static SSL_SESSION *remove_session_locked(SSL_CTX *ctx, SSL_SESSION *c)` —
/// `ssl/ssl_sess.c:884-897`.
///
/// # Safety
/// `ctx` must be a live context; `c` a live session.
unsafe fn remove_session_locked(ctx: *mut SslCtx, c: *mut SslSession) -> *mut SslSession {
    let mut r: *mut SslSession = ptr::null_mut();
    // SAFETY: `c` is NULL or live per the contract.
    if !c.is_null() && unsafe { (*c).session_id_length } != 0 {
        // SAFETY: `ctx`/`c` are live per the contract.
        r = unsafe { cache_find(ctx, c) };
        if !r.is_null() {
            // SAFETY: `r` is the cached session.
            unsafe { cache_delete_ptr(ctx, r) };
        }
        // SAFETY: `c` is live.
        unsafe { (*c).not_resumable = 1 };
    }
    r
}

/// `int SSL_CTX_add_session(SSL_CTX *ctx, SSL_SESSION *c)` — `ssl/ssl_sess.c:749-856`.
///
/// # Safety
/// `ctx` must be a live context; `c` a live session (borrowed; the cache takes a reference).
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_add_session(ctx: *mut SslCtx, c: *mut SslSession) -> c_int {
    guard_ffi(0, || {
        if ctx.is_null() || c.is_null() {
            return 0;
        }
        // SAFETY: `c` is live.
        if unsafe { SSL_SESSION_up_ref(c) } == 0 {
            return 0;
        }
        // SAFETY: `ctx` is live.
        if unsafe { CRYPTO_THREAD_write_lock((*ctx).lock) } == 0 {
            // SAFETY: `c` is live.
            unsafe { SSL_SESSION_free(c) };
            return 0;
        }
        // SAFETY: `ctx` and `c` are live per the caller's contract.
        let mut existing: *mut SslSession = unsafe { cache_find(ctx, c) };
        if !existing.is_null() && existing != c {
            // In the cache under the same key but a different object: drop the old one.
            // SAFETY: `existing` is live.
            unsafe {
                cache_delete_ptr(ctx, existing);
                SSL_SESSION_free(existing);
            }
            existing = ptr::null_mut();
        }
        if existing.is_null() {
            // The authority updates the last-used time when `SSL_SESS_CACHE_UPDATE_TIME` is set
            // (`ssl_sess.c:798-801`).
            // SAFETY: `ctx`/`c` are live per the caller's contract.
            unsafe {
                if (*ctx).session_cache_mode & SSL_SESS_CACHE_UPDATE_TIME != 0 {
                    (*c).time = time_now_secs();
                    ssl_session_calculate_timeout(c);
                }
            }
        }
        // The authority's `lh_SSL_SESSION_insert` returns an existing entry with the same key, or
        // NULL when the session is new; the `retrieve == NULL` OOM arm is unobservable here.
        let ret;
        if existing.is_null() {
            ret = 1;
            // SAFETY: `ctx` is live and its cache is this context's own.
            unsafe {
                if (*ctx).sessions.is_null() {
                    (*ctx).sessions = OPENSSL_sk_new_null();
                }
                // Eviction: the authority drops the oldest until it is under the size cap. This
                // crate processes insertion order where the authority processes timeout order.
                while (*ctx).session_cache_size > 0
                    && OPENSSL_sk_num((*ctx).sessions) as usize >= (*ctx).session_cache_size
                {
                    let r = remove_session_locked(
                        ctx,
                        OPENSSL_sk_value((*ctx).sessions, 0).cast::<SslSession>(),
                    );
                    if r.is_null() {
                        break;
                    }
                    if let Some(cb) = (*ctx).remove_session_cb {
                        cb(ctx, r);
                    }
                    SSL_SESSION_free(r);
                }
                OPENSSL_sk_push((*ctx).sessions, c.cast());
                (*c).owner = ctx;
            }
        } else {
            // SAFETY: `c` is live; `existing == c`.
            unsafe { SSL_SESSION_free(c) };
            ret = 0;
        }
        // SAFETY: `ctx` is live.
        unsafe { CRYPTO_THREAD_unlock((*ctx).lock) };
        ret
    })
}

/// `int SSL_CTX_remove_session(SSL_CTX *ctx, SSL_SESSION *c)` — `ssl/ssl_sess.c:858-877`.
///
/// # Safety
/// `ctx` must be a live context; `c` a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_remove_session(ctx: *mut SslCtx, c: *mut SslSession) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx`/`c` are live per the caller's contract.
        unsafe {
            if c.is_null() || (*c).session_id_length == 0 {
                return 0;
            }
            if ctx.is_null() || CRYPTO_THREAD_write_lock((*ctx).lock) == 0 {
                return 0;
            }
            let r = remove_session_locked(ctx, c);
            CRYPTO_THREAD_unlock((*ctx).lock);
            if let Some(cb) = (*ctx).remove_session_cb {
                cb(ctx, c);
            }
            SSL_SESSION_free(r);
            if r.is_null() {
                0
            } else {
                1
            }
        }
    })
}

/// `void SSL_CTX_flush_sessions_ex(SSL_CTX *s, time_t t)` — `ssl/ssl_sess.c:1265-1310`.
///
/// # Safety
/// `s` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_flush_sessions_ex(s: *mut SslCtx, t: i64) {
    guard_ffi((), || {
        if s.is_null() {
            return;
        }
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            if CRYPTO_THREAD_write_lock((*s).lock) == 0 {
                return;
            }
            let mut removed: Vec<*mut SslSession> = Vec::new();
            let st = (*s).sessions;
            if !st.is_null() {
                // Walk newest-to-oldest so the surviving prefix's order is preserved.
                let n = OPENSSL_sk_num(st);
                let mut i = n - 1;
                while i >= 0 {
                    let current = OPENSSL_sk_value(st, i).cast::<SslSession>();
                    if !current.is_null() && (t == 0 || sess_timedout(t as u64, current)) {
                        OPENSSL_sk_delete(st, i);
                        (*current).not_resumable = 1;
                        removed.push(current);
                    }
                    i -= 1;
                }
            }
            CRYPTO_THREAD_unlock((*s).lock);
            for current in removed {
                if let Some(cb) = (*s).remove_session_cb {
                    cb(s, current);
                }
                SSL_SESSION_free(current);
            }
        }
    })
}

/// `void SSL_CTX_flush_sessions(SSL_CTX *s, long t)` — `ssl/ssl_sess.c:1259-1262`.
///
/// # Safety
/// `s` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_flush_sessions(s: *mut SslCtx, t: c_long) {
    guard_ffi((), || {
        // SAFETY: forwarded per the caller's contract.
        // SAFETY: forwarded per the caller's contract.
        unsafe { SSL_CTX_flush_sessions_ex(s, t) };
    })
}

/// Release a context's session cache (`SSL_CTX_free`'s cache teardown).
///
/// # Safety
/// `ctx` must be a live context whose cache is no longer shared.
pub(crate) unsafe fn ssl_ctx_session_cache_free(ctx: *mut SslCtx) {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let st = (*ctx).sessions;
        if st.is_null() {
            return;
        }
        let n = OPENSSL_sk_num(st);
        for i in 0..n {
            SSL_SESSION_free(OPENSSL_sk_value(st, i).cast::<SslSession>());
        }
        OPENSSL_sk_free(st);
        (*ctx).sessions = ptr::null_mut();
    }
}

// -------------------------------------------------------------------------------------------
// Accessors
// -------------------------------------------------------------------------------------------

/// `SSL_SESSION *SSL_get_session(const SSL *ssl)` — `ssl/ssl_sess.c:62-71`.
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_session(ssl: *const Ssl) -> *mut SslSession {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `ssl` is NULL or live per the caller's contract.
        unsafe {
            if ssl.is_null() || SSL_is_quic(ssl) != 0 {
                return ptr::null_mut();
            }
            (*ssl).session
        }
    })
}

/// `SSL_SESSION *SSL_get1_session(SSL *ssl)` — `ssl/ssl_sess.c:73-90`.
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get1_session(ssl: *mut Ssl) -> *mut SslSession {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `ssl` is NULL or live per the caller's contract.
        unsafe {
            if ssl.is_null() || CRYPTO_THREAD_read_lock((*ssl).lock) == 0 {
                return ptr::null_mut();
            }
            let mut sess = SSL_get_session(ssl);
            if !sess.is_null() && SSL_SESSION_up_ref(sess) == 0 {
                sess = ptr::null_mut();
            }
            CRYPTO_THREAD_unlock((*ssl).lock);
            sess
        }
    })
}

/// `int SSL_set_session(SSL *s, SSL_SESSION *session)` — `ssl/ssl_sess.c:945-970`.
///
/// # Safety
/// `s` must be NULL or a live connection; `session` NULL or a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_session(s: *mut Ssl, session: *mut SslSession) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is NULL or live per the caller's contract.
        unsafe {
            if s.is_null() || SSL_is_quic(s) != 0 {
                return 0;
            }
            if !session.is_null() && SSL_SESSION_up_ref(session) == 0 {
                return 0;
            }
            ssl_clear_bad_session(s);
            if (*s).defltmeth != (*s).method && SSL_set_ssl_method(s, (*s).defltmeth) == 0 {
                SSL_SESSION_free(session);
                return 0;
            }
            if !session.is_null() {
                (*s).verify_result = (*session).verify_result;
            }
            SSL_SESSION_free((*s).session);
            (*s).session = session;
            1
        }
    })
}

/// `int ssl_clear_bad_session(SSL_CONNECTION *s)` — `ssl/ssl_sess.c:1312-1319`.
///
/// # Safety
/// `s` must be a live connection.
pub(crate) unsafe fn ssl_clear_bad_session(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live per the contract.
    unsafe {
        if !(*s).session.is_null()
            && ((*s).shutdown & SSL_SENT_SHUTDOWN) == 0
            && !(SSL_in_init(s) != 0 || SSL_in_before(s) != 0)
        {
            SSL_CTX_remove_session((*s).session_ctx, (*s).session);
            1
        } else {
            0
        }
    }
}

/// `SSL_SESSION *SSL_SESSION_set_ex_data(SSL_SESSION *s, int idx, void *arg)` — `ssl_sess.c:92`.
///
/// # Safety
/// `s` must be a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_set_ex_data(
    s: *mut SslSession,
    idx: c_int,
    arg: *mut c_void,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe { CRYPTO_set_ex_data(&mut (*s).ex_data, idx, arg) }
    })
}

/// `void *SSL_SESSION_get_ex_data(const SSL_SESSION *s, int idx)` — `ssl_sess.c:97`.
///
/// # Safety
/// `s` must be a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_get_ex_data(s: *const SslSession, idx: c_int) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe { CRYPTO_get_ex_data(&(*s).ex_data, idx) }
    })
}

/// `const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *s, unsigned int *len)` —
/// `ssl_sess.c:289-294`.
///
/// # Safety
/// `s` must be a live session; `len` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_get_id(s: *const SslSession, len: *mut c_uint) -> *const u8 {
    guard_ffi(ptr::null(), || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            if !len.is_null() {
                *len = (*s).session_id_length as c_uint;
            }
            (*s).session_id.as_ptr()
        }
    })
}

/// `const unsigned char *SSL_SESSION_get0_id_context(const SSL_SESSION *s, unsigned int *len)` —
/// `ssl_sess.c:296-302`.
///
/// # Safety
/// `s` must be a live session; `len` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_get0_id_context(
    s: *const SslSession,
    len: *mut c_uint,
) -> *const u8 {
    guard_ffi(ptr::null(), || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            if !len.is_null() {
                *len = (*s).sid_ctx_length as c_uint;
            }
            (*s).sid_ctx.as_ptr()
        }
    })
}

/// `unsigned int SSL_SESSION_get_compress_id(const SSL_SESSION *s)` — `ssl_sess.c:304-307`.
///
/// # Safety
/// `s` must be a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_get_compress_id(s: *const SslSession) -> c_uint {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).compress_meth }
    })
}

/// `int SSL_SESSION_set1_id(SSL_SESSION *s, const unsigned char *sid, unsigned int sid_len)` —
/// `ssl_sess.c:972-984`.
///
/// # Safety
/// `s` must be a live session; `sid` readable for `sid_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_set1_id(
    s: *mut SslSession,
    sid: *const u8,
    sid_len: c_uint,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            if sid_len as usize > SSL_MAX_SSL_SESSION_ID_LENGTH {
                raise_ssl(SSL_R_SSL_SESSION_ID_TOO_LONG, 976);
                return 0;
            }
            (*s).session_id_length = sid_len as usize;
            if sid != (*s).session_id.as_ptr() && sid_len > 0 {
                ptr::copy_nonoverlapping(sid, (*s).session_id.as_mut_ptr(), sid_len as usize);
            }
            1
        }
    })
}

/// `long SSL_SESSION_set_timeout(SSL_SESSION *s, long t)` — `ssl_sess.c:986-1004`.
///
/// # Safety
/// `s` must be NULL or a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_set_timeout(s: *mut SslSession, t: c_long) -> c_long {
    guard_ffi(0, || {
        // SAFETY: `s` is NULL or live per the caller's contract.
        unsafe {
            if s.is_null() || t < 0 {
                return 0;
            }
            if !(*s).owner.is_null() {
                if CRYPTO_THREAD_write_lock((*(*s).owner).lock) == 0 {
                    return 0;
                }
                (*s).timeout = t as u64;
                ssl_session_calculate_timeout(s);
                CRYPTO_THREAD_unlock((*(*s).owner).lock);
            } else {
                (*s).timeout = t as u64;
                ssl_session_calculate_timeout(s);
            }
            1
        }
    })
}

/// `long SSL_SESSION_get_timeout(const SSL_SESSION *s)` — `ssl_sess.c:1006-1011`.
///
/// # Safety
/// `s` must be NULL or a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_get_timeout(s: *const SslSession) -> c_long {
    guard_ffi(0, || {
        // SAFETY: `s` is NULL or live per the caller's contract.
        unsafe {
            if s.is_null() {
                0
            } else {
                (*s).timeout as c_long
            }
        }
    })
}

/// `long SSL_SESSION_get_time(const SSL_SESSION *s)` — `ssl_sess.c:1014-1017`.
///
/// # Safety
/// `s` must be NULL or a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_get_time(s: *const SslSession) -> c_long {
    guard_ffi(0, || {
        // SAFETY: forwarded per the caller's contract.
        unsafe { SSL_SESSION_get_time_ex(s) as c_long }
    })
}

/// `time_t SSL_SESSION_get_time_ex(const SSL_SESSION *s)` — `ssl_sess.c:1020-1025`.
///
/// # Safety
/// `s` must be NULL or a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_get_time_ex(s: *const SslSession) -> i64 {
    guard_ffi(0, || {
        // SAFETY: `s` is NULL or live per the caller's contract.
        unsafe {
            if s.is_null() {
                0
            } else {
                (*s).time as i64
            }
        }
    })
}

/// `time_t SSL_SESSION_set_time_ex(SSL_SESSION *s, time_t t)` — `ssl_sess.c:1027-1045`.
///
/// # Safety
/// `s` must be NULL or a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_set_time_ex(s: *mut SslSession, t: i64) -> i64 {
    guard_ffi(0, || {
        // SAFETY: `s` is NULL or live per the caller's contract.
        unsafe {
            if s.is_null() {
                return 0;
            }
            if !(*s).owner.is_null() {
                if CRYPTO_THREAD_write_lock((*(*s).owner).lock) == 0 {
                    return 0;
                }
                (*s).time = t as u64;
                ssl_session_calculate_timeout(s);
                CRYPTO_THREAD_unlock((*(*s).owner).lock);
            } else {
                (*s).time = t as u64;
                ssl_session_calculate_timeout(s);
            }
            t
        }
    })
}

/// `long SSL_SESSION_set_time(SSL_SESSION *s, long t)` — `ssl_sess.c:1048-1051`.
///
/// # Safety
/// `s` must be NULL or a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_set_time(s: *mut SslSession, t: c_long) -> c_long {
    guard_ffi(0, || {
        // SAFETY: forwarded per the caller's contract.
        // SAFETY: forwarded per the caller's contract.
        unsafe { SSL_SESSION_set_time_ex(s, t) as c_long }
    })
}

/// `int SSL_SESSION_get_protocol_version(const SSL_SESSION *s)` — `ssl_sess.c:1054-1057`.
///
/// # Safety
/// `s` must be a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_get_protocol_version(s: *const SslSession) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).ssl_version }
    })
}

/// `int SSL_SESSION_set_protocol_version(SSL_SESSION *s, int version)` — `ssl_sess.c:1059-1063`.
///
/// # Safety
/// `s` must be a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_set_protocol_version(
    s: *mut SslSession,
    version: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).ssl_version = version };
        1
    })
}

/// `const SSL_CIPHER *SSL_SESSION_get0_cipher(const SSL_SESSION *s)` — `ssl_sess.c:1065-1068`.
///
/// # Safety
/// `s` must be a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_get0_cipher(
    s: *const SslSession,
) -> *const crate::ssl::ssl_ciph_table::SslCipher {
    guard_ffi(ptr::null(), || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).cipher }
    })
}

/// `int SSL_SESSION_set_cipher(SSL_SESSION *s, const SSL_CIPHER *cipher)` — `ssl_sess.c:1070-1074`.
///
/// # Safety
/// `s` must be a live session; `cipher` NULL or a static cipher.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_set_cipher(
    s: *mut SslSession,
    cipher: *const crate::ssl::ssl_ciph_table::SslCipher,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).cipher = cipher };
        1
    })
}

/// `const char *SSL_SESSION_get0_hostname(const SSL_SESSION *s)` — `ssl_sess.c:1076-1079`.
///
/// # Safety
/// `s` must be a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_get0_hostname(s: *const SslSession) -> *const c_char {
    guard_ffi(ptr::null(), || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).ext_hostname }
    })
}

/// `int SSL_SESSION_set1_hostname(SSL_SESSION *s, const char *hostname)` — `ssl_sess.c:1081-1091`.
///
/// # Safety
/// `s` must be a live session; `hostname` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_set1_hostname(
    s: *mut SslSession,
    hostname: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            CRYPTO_free((*s).ext_hostname.cast(), FILE, 1083);
            if hostname.is_null() {
                (*s).ext_hostname = ptr::null_mut();
                return 1;
            }
            (*s).ext_hostname = CRYPTO_strdup(hostname, FILE, 1088);
            if (*s).ext_hostname.is_null() {
                0
            } else {
                1
            }
        }
    })
}

/// `int SSL_SESSION_has_ticket(const SSL_SESSION *s)` — `ssl_sess.c:1093-1096`.
///
/// # Safety
/// `s` must be a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_has_ticket(s: *const SslSession) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            if (*s).ext_ticklen > 0 {
                1
            } else {
                0
            }
        }
    })
}

/// `unsigned long SSL_SESSION_get_ticket_lifetime_hint(const SSL_SESSION *s)` —
/// `ssl_sess.c:1098-1101`.
///
/// # Safety
/// `s` must be a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_get_ticket_lifetime_hint(s: *const SslSession) -> c_ulong {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).ext_tick_lifetime_hint }
    })
}

/// `void SSL_SESSION_get0_ticket(const SSL_SESSION *s, const unsigned char **tick, size_t *len)` —
/// `ssl_sess.c:1103-1109`.
///
/// # Safety
/// `s` must be a live session; `len` writable; `tick` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_get0_ticket(
    s: *const SslSession,
    tick: *mut *const u8,
    len: *mut usize,
) {
    guard_ffi((), || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            *len = (*s).ext_ticklen;
            if !tick.is_null() {
                *tick = (*s).ext_tick;
            }
        }
    })
}

/// `uint32_t SSL_SESSION_get_max_early_data(const SSL_SESSION *s)` — `ssl_sess.c:1111-1114`.
///
/// # Safety
/// `s` must be a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_get_max_early_data(s: *const SslSession) -> u32 {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).ext_max_early_data }
    })
}

/// `int SSL_SESSION_set_max_early_data(SSL_SESSION *s, uint32_t max_early_data)` —
/// `ssl_sess.c:1116-1121`.
///
/// # Safety
/// `s` must be a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_set_max_early_data(s: *mut SslSession, max: u32) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).ext_max_early_data = max };
        1
    })
}

/// `void SSL_SESSION_get0_alpn_selected(const SSL_SESSION *s, const unsigned char **alpn,
/// size_t *len)` — `ssl_sess.c:1123-1129`.
///
/// # Safety
/// `s` must be a live session; `alpn`/`len` writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_get0_alpn_selected(
    s: *const SslSession,
    alpn: *mut *const u8,
    len: *mut usize,
) {
    guard_ffi((), || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            *alpn = (*s).ext_alpn_selected;
            *len = (*s).ext_alpn_selected_len;
        }
    })
}

/// `int SSL_SESSION_set1_alpn_selected(SSL_SESSION *s, const unsigned char *alpn, size_t len)` —
/// `ssl_sess.c:1131-1148`.
///
/// # Safety
/// `s` must be a live session; `alpn` NULL or readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_set1_alpn_selected(
    s: *mut SslSession,
    alpn: *const u8,
    len: usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            CRYPTO_free((*s).ext_alpn_selected.cast(), FILE, 1134);
            if alpn.is_null() || len == 0 {
                (*s).ext_alpn_selected = ptr::null_mut();
                (*s).ext_alpn_selected_len = 0;
                return 1;
            }
            (*s).ext_alpn_selected = CRYPTO_memdup(alpn.cast(), len, FILE, 1140).cast();
            if (*s).ext_alpn_selected.is_null() {
                (*s).ext_alpn_selected_len = 0;
                return 0;
            }
            (*s).ext_alpn_selected_len = len;
            1
        }
    })
}

/// `X509 *SSL_SESSION_get0_peer(SSL_SESSION *s)` — `ssl_sess.c:1150-1153`.
///
/// # Safety
/// `s` must be a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_get0_peer(s: *mut SslSession) -> *mut X509 {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).peer }
    })
}

/// `EVP_PKEY *SSL_SESSION_get0_peer_rpk(SSL_SESSION *s)` — `ssl_sess.c:1155-1158`.
///
/// # Safety
/// `s` must be a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_get0_peer_rpk(s: *mut SslSession) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).peer_rpk }
    })
}

/// `int SSL_SESSION_set1_id_context(SSL_SESSION *s, const unsigned char *sid_ctx,
/// unsigned int sid_ctx_len)` — `ssl_sess.c:1160-1172`.
///
/// # Safety
/// `s` must be a live session; `sid_ctx` readable for `sid_ctx_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_set1_id_context(
    s: *mut SslSession,
    sid_ctx: *const u8,
    sid_ctx_len: c_uint,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            if sid_ctx_len as usize > SSL_MAX_SID_CTX_LENGTH {
                raise_ssl(SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG, 1164);
                return 0;
            }
            (*s).sid_ctx_length = sid_ctx_len as usize;
            if sid_ctx != (*s).sid_ctx.as_ptr() {
                ptr::copy_nonoverlapping(sid_ctx, (*s).sid_ctx.as_mut_ptr(), sid_ctx_len as usize);
            }
            1
        }
    })
}

/// `int SSL_SESSION_is_resumable(const SSL_SESSION *s)` — `ssl_sess.c:1174-1182`.
///
/// # Safety
/// `s` must be a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_is_resumable(s: *const SslSession) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            if (*s).not_resumable == 0 && ((*s).session_id_length > 0 || (*s).ext_ticklen > 0) {
                1
            } else {
                0
            }
        }
    })
}

/// `long SSL_CTX_set_timeout(SSL_CTX *s, long t)` — `ssl_sess.c:1184-1193`.
///
/// # Safety
/// `s` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_timeout(s: *mut SslCtx, t: c_long) -> c_long {
    guard_ffi(0, || {
        // SAFETY: `s` is NULL or live per the caller's contract.
        unsafe {
            if s.is_null() {
                return 0;
            }
            let l = (*s).session_timeout as c_long;
            (*s).session_timeout = t as u64;
            l
        }
    })
}

/// `long SSL_CTX_get_timeout(const SSL_CTX *s)` — `ssl_sess.c:1195-1200`.
///
/// # Safety
/// `s` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_timeout(s: *const SslCtx) -> c_long {
    guard_ffi(0, || {
        // SAFETY: `s` is NULL or live per the caller's contract.
        unsafe {
            if s.is_null() {
                0
            } else {
                (*s).session_timeout as c_long
            }
        }
    })
}

/// `int SSL_set_session_secret_cb(SSL *s, tls_session_secret_cb_fn cb, void *arg)` —
/// `ssl_sess.c:1202-1214`.
///
/// # Safety
/// `s` must be a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_session_secret_cb(
    s: *mut Ssl,
    cb: Option<crate::ssl::ssl_lib::SessionSecretCb>,
    arg: *mut c_void,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            if s.is_null() || SSL_is_quic(s) != 0 {
                return 0;
            }
            (*s).session_secret_cb = cb;
            (*s).session_secret_cb_arg = arg;
            1
        }
    })
}

/// `int SSL_set_session_ticket_ext_cb(SSL *s, tls_session_ticket_ext_cb_fn cb, void *arg)` —
/// `ssl_sess.c:1216-1227`.
///
/// # Safety
/// `s` must be a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_session_ticket_ext_cb(
    s: *mut Ssl,
    cb: Option<crate::ssl::ssl_lib::SessionTicketExtCb>,
    arg: *mut c_void,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            if s.is_null() || SSL_is_quic(s) != 0 {
                return 0;
            }
            (*s).session_ticket_cb = cb;
            (*s).session_ticket_cb_arg = arg;
            1
        }
    })
}

/// `int SSL_set_session_ticket_ext(SSL *s, void *ext_data, int ext_len)` — `ssl_sess.c:1229-1256`.
///
/// # Safety
/// `s` must be a live connection; `ext_data` NULL or readable for `ext_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_session_ticket_ext(
    s: *mut Ssl,
    ext_data: *mut c_void,
    ext_len: c_int,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            if s.is_null() || SSL_is_quic(s) != 0 {
                return 0;
            }
            if (*s).version >= TLS1_VERSION {
                CRYPTO_free((*s).session_ticket.cast(), FILE, 1237);
                (*s).session_ticket = ptr::null_mut();
                let base = core::mem::size_of::<TlsSessionTicketExt>() + ext_len.max(0) as usize;
                // SAFETY: a raw allocation of the authority's size.
                let st = CRYPTO_zalloc(base, FILE, 1239).cast::<TlsSessionTicketExt>();
                if st.is_null() {
                    return 0;
                }
                if !ext_data.is_null() {
                    (*st).length = ext_len as u16;
                    let data = st
                        .cast::<u8>()
                        .add(core::mem::size_of::<TlsSessionTicketExt>());
                    (*st).data = data.cast();
                    ptr::copy_nonoverlapping(ext_data.cast::<u8>(), data, ext_len as usize);
                } else {
                    (*st).length = 0;
                    (*st).data = ptr::null_mut();
                }
                (*s).session_ticket = st;
                return 1;
            }
            0
        }
    })
}

// -------------------------------------------------------------------------------------------
// The callback setters and their getters
// -------------------------------------------------------------------------------------------

/// `void SSL_CTX_sess_set_new_cb(SSL_CTX *ctx, int (*cb)(SSL *, SSL_SESSION *))` —
/// `ssl_sess.c:1401-1405`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_sess_set_new_cb(ctx: *mut SslCtx, cb: Option<NewSessionCb>) {
    guard_ffi((), || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).new_session_cb = cb };
    })
}

/// `int (*SSL_CTX_sess_get_new_cb(SSL_CTX *ctx))(SSL *, SSL_SESSION *)` — `ssl_sess.c:1407`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_sess_get_new_cb(ctx: *mut SslCtx) -> Option<NewSessionCb> {
    guard_ffi(None, || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).new_session_cb }
    })
}

/// `void SSL_CTX_sess_set_remove_cb(SSL_CTX *ctx, void (*cb)(SSL_CTX *, SSL_SESSION *))` —
/// `ssl_sess.c:1412-1416`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_sess_set_remove_cb(ctx: *mut SslCtx, cb: Option<RemoveSessionCb>) {
    guard_ffi((), || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).remove_session_cb = cb };
    })
}

/// `void (*SSL_CTX_sess_get_remove_cb(SSL_CTX *ctx))(SSL_CTX *, SSL_SESSION *)` — `ssl_sess.c:1418`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_sess_get_remove_cb(ctx: *mut SslCtx) -> Option<RemoveSessionCb> {
    guard_ffi(None, || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).remove_session_cb }
    })
}

/// `void SSL_CTX_sess_set_get_cb(SSL_CTX *ctx, SSL_SESSION *(*cb)(SSL *, const unsigned char *,
/// int, int *))` — `ssl_sess.c:1424-1430`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_sess_set_get_cb(ctx: *mut SslCtx, cb: Option<GetSessionCb>) {
    guard_ffi((), || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).get_session_cb = cb };
    })
}

/// `SSL_SESSION *(*SSL_CTX_sess_get_get_cb(SSL_CTX *ctx))(SSL *, const unsigned char *, int,
/// int *)` — `ssl_sess.c:1432-1439`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_sess_get_get_cb(ctx: *mut SslCtx) -> Option<GetSessionCb> {
    guard_ffi(None, || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).get_session_cb }
    })
}

/// `void SSL_CTX_set_info_callback(SSL_CTX *ctx, void (*cb)(const SSL *, int, int))` —
/// `ssl_sess.c:1441-1445`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_info_callback(ctx: *mut SslCtx, cb: Option<InfoCb>) {
    guard_ffi((), || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).info_callback = cb };
    })
}

/// `void (*SSL_CTX_get_info_callback(SSL_CTX *ctx))(const SSL *, int, int)` — `ssl_sess.c:1447`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_info_callback(ctx: *mut SslCtx) -> Option<InfoCb> {
    guard_ffi(None, || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).info_callback }
    })
}

/// `void SSL_CTX_set_client_cert_cb(SSL_CTX *ctx, int (*cb)(SSL *, X509 **, EVP_PKEY **))` —
/// `ssl_sess.c:1453-1458`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_client_cert_cb(ctx: *mut SslCtx, cb: Option<ClientCertCb>) {
    guard_ffi((), || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).client_cert_cb = cb };
    })
}

/// `int (*SSL_CTX_get_client_cert_cb(SSL_CTX *ctx))(SSL *, X509 **, EVP_PKEY **)` —
/// `ssl_sess.c:1460-1464`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_client_cert_cb(ctx: *mut SslCtx) -> Option<ClientCertCb> {
    guard_ffi(None, || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).client_cert_cb }
    })
}

/// `void SSL_CTX_set_cookie_generate_cb(SSL_CTX *ctx, int (*cb)(SSL *, unsigned char *,
/// unsigned int *))` — `ssl_sess.c:1466-1472`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_cookie_generate_cb(ctx: *mut SslCtx, cb: Option<GenCookieCb>) {
    guard_ffi((), || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).app_gen_cookie_cb = cb };
    })
}

/// `void SSL_CTX_set_cookie_verify_cb(SSL_CTX *ctx, int (*cb)(SSL *, const unsigned char *,
/// unsigned int))` — `ssl_sess.c:1474-1480`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_cookie_verify_cb(
    ctx: *mut SslCtx,
    cb: Option<VerifyCookieCb>,
) {
    guard_ffi((), || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).app_verify_cookie_cb = cb };
    })
}

/// `void SSL_CTX_set_stateless_cookie_generate_cb(SSL_CTX *ctx, int (*cb)(SSL *, unsigned char *,
/// size_t *))` — `ssl_sess.c:1505-1512`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_stateless_cookie_generate_cb(
    ctx: *mut SslCtx,
    cb: Option<GenStatelessCookieCb>,
) {
    guard_ffi((), || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).gen_stateless_cookie_cb = cb };
    })
}

/// `void SSL_CTX_set_stateless_cookie_verify_cb(SSL_CTX *ctx, int (*cb)(SSL *,
/// const unsigned char *, size_t))` — `ssl_sess.c:1514-1521`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_stateless_cookie_verify_cb(
    ctx: *mut SslCtx,
    cb: Option<VerifyStatelessCookieCb>,
) {
    guard_ffi((), || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).verify_stateless_cookie_cb = cb };
    })
}

/// `int SSL_SESSION_set1_ticket_appdata(SSL_SESSION *ss, const void *data, size_t len)` —
/// `ssl_sess.c:1482-1496`.
///
/// # Safety
/// `ss` must be a live session; `data` NULL or readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_set1_ticket_appdata(
    ss: *mut SslSession,
    data: *const c_void,
    len: usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ss` is live per the caller's contract.
        unsafe {
            CRYPTO_free((*ss).ticket_appdata.cast(), FILE, 1484);
            (*ss).ticket_appdata_len = 0;
            if data.is_null() || len == 0 {
                (*ss).ticket_appdata = ptr::null_mut();
                return 1;
            }
            (*ss).ticket_appdata = CRYPTO_memdup(data, len, FILE, 1490).cast();
            if !(*ss).ticket_appdata.is_null() {
                (*ss).ticket_appdata_len = len;
                return 1;
            }
            0
        }
    })
}

/// `int SSL_SESSION_get0_ticket_appdata(SSL_SESSION *ss, void **data, size_t *len)` —
/// `ssl_sess.c:1498-1503`.
///
/// # Safety
/// `ss` must be a live session; `data`/`len` writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_get0_ticket_appdata(
    ss: *mut SslSession,
    data: *mut *mut c_void,
    len: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ss` is live per the caller's contract.
        unsafe {
            *data = (*ss).ticket_appdata.cast();
            *len = (*ss).ticket_appdata_len;
            1
        }
    })
}

// -------------------------------------------------------------------------------------------
// The PEM codec the IMPLEMENT_PEM_rw macro generates at ssl_sess.c:1523
// -------------------------------------------------------------------------------------------

/// `d2i_of_void` thunk over `d2i_SSL_SESSION`.
///
/// # Safety
/// As `d2i_SSL_SESSION`.
unsafe extern "C" fn d2i_session_void(
    a: *mut *mut c_void,
    pp: *mut *const u8,
    len: c_long,
) -> *mut c_void {
    // SAFETY: forwarded per the caller's contract.
    unsafe { d2i_SSL_SESSION(a.cast::<*mut SslSession>(), pp, len).cast() }
}

/// `i2d_of_void` thunk over `i2d_SSL_SESSION`.
///
/// # Safety
/// As `i2d_SSL_SESSION`.
unsafe extern "C" fn i2d_session_void(a: *const c_void, pp: *mut *mut u8) -> c_int {
    // SAFETY: forwarded per the caller's contract.
    unsafe { i2d_SSL_SESSION(a.cast::<SslSession>(), pp) }
}

/// `SSL_SESSION *PEM_read_bio_SSL_SESSION(BIO *bp, SSL_SESSION **x, pem_password_cb *cb,
/// void *u)` — `ssl_sess.c:1523`'s `IMPLEMENT_PEM_rw`.
///
/// # Safety
/// `bp` must be a live readable BIO; `x` writable; `cb`/`u` as the PEM layer.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_bio_SSL_SESSION(
    bp: *mut crate::runtime::bio::Bio,
    x: *mut *mut SslSession,
    cb: Option<crate::ssl::ssl_lib::PemPasswordCb>,
    u: *mut c_void,
) -> *mut SslSession {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: forwarded per the caller's contract.
        unsafe {
            crate::pem::pem_oth::PEM_ASN1_read_bio(
                d2i_session_void,
                PEM_STRING_SSL_SESSION,
                bp,
                x.cast(),
                cb,
                u,
            )
            .cast()
        }
    })
}

/// `int PEM_write_bio_SSL_SESSION(BIO *bp, const SSL_SESSION *x)` — `ssl_sess.c:1523`.
///
/// # Safety
/// `bp` must be a live writable BIO; `x` NULL or a live session.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_bio_SSL_SESSION(
    bp: *mut crate::runtime::bio::Bio,
    x: *const SslSession,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: forwarded per the caller's contract.
        unsafe {
            crate::pem::pem_lib::PEM_ASN1_write_bio(
                Some(i2d_session_void),
                PEM_STRING_SSL_SESSION,
                bp,
                x.cast(),
                ptr::null(),
                ptr::null(),
                0,
                None,
                ptr::null_mut(),
            )
        }
    })
}

/// `SSL_SESSION *PEM_read_SSL_SESSION(FILE *fp, SSL_SESSION **x, pem_password_cb *cb, void *u)` —
/// `ssl_sess.c:1523`.
///
/// # Safety
/// `fp` must be a live readable stream; `x` writable.
#[no_mangle]
pub unsafe extern "C" fn PEM_read_SSL_SESSION(
    fp: *mut c_void,
    x: *mut *mut SslSession,
    cb: Option<crate::ssl::ssl_lib::PemPasswordCb>,
    u: *mut c_void,
) -> *mut SslSession {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: forwarded per the caller's contract.
        unsafe {
            crate::pem::pem_lib::PEM_ASN1_read(
                d2i_session_void,
                PEM_STRING_SSL_SESSION,
                fp,
                x.cast(),
                cb,
                u,
            )
            .cast()
        }
    })
}

/// `int PEM_write_SSL_SESSION(FILE *fp, const SSL_SESSION *x)` — `ssl_sess.c:1523`.
///
/// # Safety
/// `fp` must be a live writable stream; `x` NULL or a live session.
#[no_mangle]
pub unsafe extern "C" fn PEM_write_SSL_SESSION(fp: *mut c_void, x: *const SslSession) -> c_int {
    guard_ffi(0, || {
        // SAFETY: forwarded per the caller's contract.
        unsafe {
            crate::pem::pem_lib::PEM_ASN1_write(
                Some(i2d_session_void),
                PEM_STRING_SSL_SESSION,
                fp,
                x.cast(),
                ptr::null(),
                ptr::null(),
                0,
                None,
                ptr::null_mut(),
            )
        }
    })
}

// The four PEM entry points forward through the PEM layer; no trailing placeholder.
const _: () = {
    assert!(SSL_MAX_MASTER_KEY_LENGTH <= TLS13_MAX_RESUMPTION_PSK_LENGTH);
};
