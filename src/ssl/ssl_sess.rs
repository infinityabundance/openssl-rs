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
//! * **Removal callbacks run outside the context cache lock.** The authority invokes
//!   `remove_session_cb` while holding `ctx->lock` from both `SSL_CTX_add_session`'s eviction arm
//!   and `SSL_CTX_flush_sessions` (`ssl_sess.c:784-790`, `:1292-1298`). `ctx->lock` is not
//!   recursive, so an application callback that re-enters `SSL_CTX_add_session` or
//!   `SSL_CTX_remove_session` fails (or deadlocks against a plain `pthread_rwlock_t`). Every
//!   cache entry is detached first, the lock is released, and only then is the callback invoked
//!   with the entry's cache reference still owned here; re-entrant mutation therefore sees a
//!   consistent cache. This is a deliberate safety correction, recorded rather than hidden; the
//!   callback's arguments, order, and count are unchanged.
//! * **Automatic flushing is modelled** (`ssl_lib.c:4766-4782`): unless
//!   `SSL_SESS_CACHE_NO_AUTO_CLEAR` is set, `ssl_update_cache` flushes the context's cache when
//!   the good-connection counter's low byte is `0xff`, using the counter value from before the
//!   caller's own increment, exactly as the authority does.
//!
//! ## Reference ownership is structural (S57)
//!
//! Every cache-held or lookup-acquired reference is a non-`Copy` [`SessionRef`] guard: it is
//! acquired once, released exactly once by `Drop`, and can leave the guard only through an
//! explicit transfer ([`SessionRef::into_raw`]) to the cache stack or to an accepting callback.
//! A refused write lock, a refused `sk_push` or a refusing callback therefore unwinds a partially
//! acquired reference exactly once instead of relying on hand-written release sequencing.
//!
//! The lookup key is a [`SessionKey`] value containing only the three compared fields. It replaces
//! the previous zero-initialised `SSL_SESSION` scratch object, so no storage is reinterpreted as a
//! session and the key's validity no longer depends on every — present or future — field of
//! `SSL_SESSION` being zero-valid (AGENTS §2).
//!
//! ### Concurrency: what is established and what is not
//!
//! The *reference lifetime* is established: `lookup_sess_in_cache` holds the context's **read**
//! lock across the find and the `SSL_SESSION_up_ref`, and every cache mutation
//! (`SSL_CTX_add_session`, `SSL_CTX_remove_session`, `SSL_CTX_flush_sessions_ex`) holds the
//! **write** lock, so the cache's reference cannot be released between the find and the acquire.
//! After the unlock the returned guard is the caller's own reference and survives any later
//! eviction or flush.
//!
//! What is **not** established, and is recorded rather than asserted: eviction, removal and
//! flushing write the session's non-atomic bookkeeping fields (`not_resumable`, `owner`) under
//! the write lock, while a thread that already owns a reference reads them without any lock.
//! Those accesses are a data race in the Rust memory model (and formally in C too); the authority
//! has the same structure. Making them sound needs a design change (atomic fields or protecting
//! every reader), which S57 does not make; no lock is added that the authority does not take.
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **`time`/`timeout`/`calc_timeout` are seconds.** See `src/ssl/ssl_lib.rs`: every reader
//!   converts to `time_t`, so the codec and the accessors agree.
//! * **`ssl_generate_session_id`, `ssl_get_new_session`, `ssl_get_prev_session`, `lookup_sess_in_cache`
//!   and `ssl_update_cache` are landed** (Phase 17): they drive the TLS1.2 handshake session. The
//!   TLS1.3 arms are the reduced ones `tls13_client_create_session` already provided.
//! * **The TLS1.2 NewSessionTicket is stateful, not the authority's stateless blob.** The authority
//!   encrypts an `i2d_SSL_SESSION` under the context ticket key and reconstructs the session by
//!   decrypting it (`construct_stateless_ticket`/`tls_decrypt_ticket`). This crate mints an opaque
//!   64-byte ticket, caches the server session under `SHA256(ticket)` (the same id the client
//!   computes at `statem_clnt.c:2851-2872`), and resumes by the internal-cache lookup. The client-
//!   observable shape is the authority's (`session.id` is `SHA256(ticket)`, `has_ticket` true, the
//!   lifetime hint is the session timeout); the ticket bytes themselves and `SSL_CTX_sess_number`
//!   after a handshake differ. No court compares the TLS1.2 ticket wire. **TLS1.3 tickets are the
//!   authority's stateless form** (`construct_stateless_ticket`/`tls13_decrypt_ticket`,
//!   `statem_srvr.rs`), encrypted through the application's `ticket_key_cb`, so TLS1.3 resumption
//!   works across nginx workers exactly as the authority's; the client-side `pre_shared_key`
//!   offering remains a boundary (a candidate client stores the ticket but a subsequent connect
//!   falls back to a full handshake).
//! * **`ssl_session_dup_intern` copies the parsed fields but not `early_secret`'s length** — the
//!   authority `memcpy`s the first `offsetof(SSL_SESSION, prev)` bytes, which includes it; this
//!   crate copies the field explicitly, so the result is the same.
//! * **`SSL_CTX_sess_set_new_cb`'s callback is stored and invoked** by `ssl_update_cache` once a
//!   handshake completes (Phase 17).
//!
//! ## Ownership: the session block is an [`OwnedCtx`] whose `Drop` is `SSL_SESSION_free`'s body
//!
//! The `SSL_SESSION` blocks this unit allocates ([`SSL_SESSION_new`] and `ssl_session_dup_intern`)
//! are owned here: each stays a `CRYPTO_zalloc` at `size_of::<SslSession>()` on the crate's
//! allocator seam and its release stays a `CRYPTO_free` at the authority's own line, so a
//! caller-installed `CRYPTO_set_mem_functions` hook observes the allocation and its release exactly
//! as it observes the authority's; only the *ownership* is the handle. `Drop` runs the authority's
//! own `SSL_SESSION_free` body ([`CtxDestroy::destroy_body`]) followed by the block release, so the
//! constructor, the duplicate's `goto err` ladder and [`SSL_SESSION_free`] no longer walk a release
//! by hand. The block itself is the session's stable address, handed out and taken back by the
//! exported ABI.
//!
//! **The session's object-owned member buffers are mediated by handles.** The C strings
//! `ext_hostname`, `psk_identity_hint`, `psk_identity` and `srp_username` and the `(ptr, len)`
//! blobs `ext_tick`/`ext_ticklen`, `ext_alpn_selected`/`ext_alpn_selected_len` and
//! `ticket_appdata`/`ticket_appdata_len` are owned by the session and reached only through
//! [`crate::ssl::ssl_lib::MemberCStrSlot`], [`crate::ssl::ssl_lib::MemberBufSlot`] and the
//! `SslSession` readers (`ssl_lib.rs`). The fields are private there, so every read, write and
//! release is compile-time-confinable to one place; see `MEMBER-BUFFER-MODEL.md`. (The connection's
//! variable-sized `session_ticket` block is a `Ssl` member and remains outside this conversion,
//! exactly as in the authority.)
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::evp::pkey::EVP_PKEY_up_ref;
use crate::ffi::guard_ffi;
use crate::runtime::bio::owned::{CtxDestroy, OwnedCtx};
use crate::runtime::err::raise_with;
use crate::runtime::ex_data::{
    CRYPTO_dup_ex_data, CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data,
    CRYPTO_set_ex_data, CRYPTO_EX_INDEX_SSL_SESSION,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_memdup, CRYPTO_zalloc};
use crate::runtime::mem_coords::SeamFile;
use crate::runtime::owned_str::OwnedCStr;
use crate::runtime::refcount::{down_ref, up_ref, DownRef};
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
    ClientCertCb, GenCookieCb, GenStatelessCookieCb, GenerateSessionIdCb, GetSessionCb, InfoCb,
    NewSessionCb, RemoveSessionCb, Ssl, SslCtx, SslSession, TlsSessionTicketExt, VerifyCookieCb,
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
const FILE_SEAM: SeamFile = SeamFile::new(c"ssl/ssl_sess.c");
/// `ERR_LIB_SSL` — `include/openssl/err.h.in:91`.
const ERR_LIB_SSL: c_int = 20;
/// `SSL_R_SSL_SESSION_ID_TOO_LONG` — `sslerr.h:296`.
const SSL_R_SSL_SESSION_ID_TOO_LONG: c_int = 408;
/// `SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG` — `sslerr.h:294`.
const SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG: c_int = 273;
/// `SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED` — `sslerr.h:261`.
const SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED: c_int = 277;
/// `SSL_R_SSL_SESSION_ID_CALLBACK_FAILED` — `sslerr.h:292`.
const SSL_R_SSL_SESSION_ID_CALLBACK_FAILED: c_int = 301;
/// `SSL_R_SSL_SESSION_ID_HAS_BAD_LENGTH` — `sslerr.h:295`.
const SSL_R_SSL_SESSION_ID_HAS_BAD_LENGTH: c_int = 303;
/// `SSL_R_UNSUPPORTED_SSL_VERSION` — `sslerr.h:362`.
const SSL_R_UNSUPPORTED_SSL_VERSION: c_int = 259;
/// `ERR_R_INTERNAL_ERROR` — `err.h:356`.
const ERR_R_INTERNAL_ERROR: c_int = 259 | (3 << 18);
/// `ERR_R_MALLOC_FAILURE` — `err.h:354`.
const ERR_R_MALLOC_FAILURE: c_int = 256 | (3 << 18);
/// `TLS1_FLAGS_RECEIVED_EXTMS` — `ssl3.h:300`.
const TLS1_FLAGS_RECEIVED_EXTMS: u64 = 0x0200;
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

// ---------------------------------------------------------------------------------------------
// Ownership of the session block, reclaimed from `SSL_SESSION_free`'s own body
// ---------------------------------------------------------------------------------------------

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
        // The session block, allocated through the crate's allocator seam; `Drop` is its single
        // release on the refusal below and `into_raw` hands it out on success. `ss` is the block's
        // stable address.
        let Some(ss_owner) = OwnedCtx::<SslSession>::zalloc_at(FILE_SEAM, 109, FILE_SEAM, 930)
        else {
            return ptr::null_mut();
        };
        let ss = ss_owner.as_ptr();
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
            // The refusal releases the block it built: returning drops `ss_owner`. (`CRYPTO_new_ex_data`
            // answers 1 for this valid class, so the authority's bare block release at
            // `ssl_sess.c:121`, which is not the destructor, is unreachable here.)
            return ptr::null_mut();
        }
        ss_owner.into_raw()
    })
}

/// Seconds since the epoch, the authority's `ossl_time_now` at second resolution.
pub(crate) fn time_now_secs() -> u64 {
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
    // The session block, allocated through the crate's allocator seam; `Drop` is its single release
    // on every refusal below and `into_raw` hands it out on success. `dest` is the block's stable
    // address, and the authority's `goto err` ladder reaches its destructor (`SSL_SESSION_free`),
    // which is `OwnedCtx`'s `Drop`.
    let Some(dest_owner) = OwnedCtx::<SslSession>::zalloc_at(FILE_SEAM, 140, FILE_SEAM, 930) else {
        return ptr::null_mut();
    };
    let dest = dest_owner.as_ptr();
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
        // The refusal releases the block it built: returning drops `dest_owner`. (`CRYPTO_new_ex_data`
        // answers 1 for this valid class, so the authority's bare block release at `ssl_sess.c:181`
        // is unreachable here.)
        return ptr::null_mut();
    }

    // SAFETY: every step mirrors the authority's `goto err` ladder. Each refusal returns and lets
    // `dest_owner`'s `Drop` run the authority's own `SSL_SESSION_free` body, release what the
    // ladder built, and release the block -- exactly the `err:` the authority's ladder reaches.
    unsafe {
        if !s.peer.is_null() {
            if X509_up_ref(s.peer) == 0 {
                return ptr::null_mut();
            }
            (*dest).peer = s.peer;
        }
        if !s.peer_chain.is_null() {
            (*dest).peer_chain = crate::x509::x509_cmp::X509_chain_up_ref(s.peer_chain);
            if (*dest).peer_chain.is_null() {
                return ptr::null_mut();
            }
        }
        if !s.peer_rpk.is_null() {
            if EVP_PKEY_up_ref(s.peer_rpk.cast::<crate::evp::pkey::EvpPkey>()) == 0 {
                return ptr::null_mut();
            }
            (*dest).peer_rpk = s.peer_rpk;
        }
        let hint = s.psk_identity_hint();
        if !hint.is_null() {
            // SAFETY: `hint` is NUL-terminated; the seam answers a fresh block.
            let Some(dup) = OwnedCStr::dup(hint, FILE_SEAM, 210) else {
                return ptr::null_mut();
            };
            // SAFETY: `dest` is freshly zeroed, so its `psk_identity_hint` is empty.
            let empty = (*dest).psk_identity_hint_slot().assume_empty();
            empty.store(dup);
        }
        let identity = s.psk_identity();
        if !identity.is_null() {
            // SAFETY: `identity` is NUL-terminated; the seam answers a fresh block.
            let Some(dup) = OwnedCStr::dup(identity, FILE_SEAM, 215) else {
                return ptr::null_mut();
            };
            // SAFETY: `dest`'s `psk_identity` member is empty.
            let empty = (*dest).psk_identity_slot().assume_empty();
            empty.store(dup);
        }
        if CRYPTO_dup_ex_data(
            CRYPTO_EX_INDEX_SSL_SESSION,
            &mut (*dest).ex_data,
            &s.ex_data as *const _ as *mut _,
        ) == 0
        {
            return ptr::null_mut();
        }
        let hostname = s.ext_hostname();
        if !hostname.is_null() {
            // SAFETY: `hostname` is NUL-terminated; the seam answers a fresh block.
            let Some(dup) = OwnedCStr::dup(hostname, FILE_SEAM, 227) else {
                return ptr::null_mut();
            };
            // SAFETY: `dest` is freshly zeroed, so its `ext_hostname` is empty.
            let empty = (*dest).ext_hostname_slot().assume_empty();
            empty.store(dup);
        }
        if ticket != 0 && !s.ext_tick().0.is_null() {
            let (tick_ptr, tick_len) = s.ext_tick();
            let dup = CRYPTO_memdup(tick_ptr.cast(), tick_len, FILE, 233).cast::<u8>();
            if dup.is_null() {
                return ptr::null_mut();
            }
            // SAFETY: `dup` is this call's fresh block of `tick_len` bytes; `dest`'s member is empty.
            (*dest).ext_tick_slot().store(dup, tick_len);
        } else {
            // `dest` is fresh (`{ext_tick, ext_ticklen} == (NULL, 0)`) and this arm stores nothing,
            // so the member is already the authority's post-`ext_ticklen = 0` state.
            (*dest).ext_tick_lifetime_hint = 0;
        }
        let (alpn_ptr, alpn_len) = s.ext_alpn_selected();
        if !alpn_ptr.is_null() {
            let dup = CRYPTO_memdup(alpn_ptr.cast(), alpn_len, FILE, 243).cast::<u8>();
            if dup.is_null() {
                return ptr::null_mut();
            }
            // SAFETY: `dup` is this call's fresh block of `alpn_len` bytes; `dest`'s member is empty.
            (*dest).ext_alpn_selected_slot().store(dup, alpn_len);
        }
        let srp = s.srp_username();
        if !srp.is_null() {
            // SAFETY: `srp` is NUL-terminated; the seam answers a fresh block.
            let Some(dup) = OwnedCStr::dup(srp, FILE_SEAM, 250) else {
                return ptr::null_mut();
            };
            // SAFETY: `dest`'s `srp_username` member is empty.
            let empty = (*dest).srp_username_slot().assume_empty();
            empty.store(dup);
        }
        let (appdata_ptr, appdata_len) = s.ticket_appdata();
        if !appdata_ptr.is_null() {
            let dup = CRYPTO_memdup(appdata_ptr.cast(), appdata_len, FILE, 257).cast::<u8>();
            if dup.is_null() {
                return ptr::null_mut();
            }
            // SAFETY: `dup` is this call's fresh block of `appdata_len` bytes; `dest`'s member is
            // empty.
            (*dest).ticket_appdata_slot().store(dup, appdata_len);
        }
    }
    // The block and the fields it holds are the caller's now.
    dest_owner.into_raw()
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
        // SAFETY: the C-ABI caller guarantees `ss` is live and owns the one reference this
        // free releases (the caller's obligation); on `Last` this frame is the unique
        // destructor runner.
        match unsafe { down_ref(&(*ss).references) } {
            DownRef::Last => {}
            DownRef::Remaining | DownRef::Retired => return,
        }
        // SAFETY: this call claimed the last reference (`1 -> REF_DESTROYING`), so `ss` is owned
        // here; `from_raw` reclaims it (NULL is a no-op) and `Drop` runs the authority's own
        // `SSL_SESSION_free` body followed by the block release.
        unsafe { drop(OwnedCtx::<SslSession>::from_raw_at(ss, FILE_SEAM, 930)) };
    })
}

/// The authority's `SSL_SESSION_free` body, without the block release [`OwnedCtx`]'s `Drop`
/// performs.
// SAFETY: (a) holds: `destroy_body` is `SSL_SESSION_free` minus the block -- the ex-data, the
// master key/id cleanse, the peer, CRL, peer_rpk and peer_chain references and the object-owned
// member buffers, each releaser NULL-tolerant, never the enclosing block. (b) holds: an all-zero
// session has every member NULL/zero, so the body is the authority's own all-empty teardown -- what
// the safe `OwnedCtx::zalloc_at` leans on.
unsafe impl CtxDestroy for SslSession {
    /// # Safety
    /// `ptr` is a live session whose reference count has reached zero and which this file owns.
    unsafe fn destroy_body(ptr: *mut SslSession) {
        // SAFETY: `ptr` is live per the contract; each field is NULL or owned, exactly as the
        // authority's `SSL_SESSION_free` walks it.
        unsafe {
            CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_SESSION, ptr.cast(), &mut (*ptr).ex_data);
            // `OPENSSL_cleanse` of the master key and session id.
            ptr::write_bytes(
                (*ptr).master_key.as_mut_ptr(),
                0,
                TLS13_MAX_RESUMPTION_PSK_LENGTH,
            );
            ptr::write_bytes(
                (*ptr).session_id.as_mut_ptr(),
                0,
                SSL_MAX_SSL_SESSION_ID_LENGTH,
            );
            X509_free((*ptr).peer);
            crate::evp::pkey::EVP_PKEY_free((*ptr).peer_rpk.cast());
            OSSL_STACK_OF_X509_free((*ptr).peer_chain);
            // The session's object-owned C-string and blob member buffers: each is released exactly
            // once here through its validated handle, at the authority's own `file`/`line`. A NULL
            // incumbent is `CRYPTO_free`'s own no-op. The release order is the authority's.
            (*ptr).ext_hostname_slot().clear(FILE_SEAM, 918);
            (*ptr).ext_tick_slot().clear(FILE, 919);
            (*ptr).psk_identity_hint_slot().clear(FILE_SEAM, 921);
            (*ptr).psk_identity_slot().clear(FILE_SEAM, 922);
            (*ptr).srp_username_slot().clear(FILE_SEAM, 925);
            (*ptr).ext_alpn_selected_slot().clear(FILE, 927);
            (*ptr).ticket_appdata_slot().clear(FILE, 928);
        }
    }
}

/// `int SSL_SESSION_up_ref(SSL_SESSION *ss)` — `ssl/ssl_sess.c:933-943`.
///
/// # Safety
/// `ss` must be a live session.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_up_ref(ss: *mut SslSession) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the C-ABI caller guarantees `ss` is live and holds the reference this
        // call acts for (a caller obligation, not something this wrapper can check); this
        // call acquires exactly one new reference for the caller.
        unsafe { up_ref(&(*ss).references) }
    })
}

// -------------------------------------------------------------------------------------------
// The internal session cache
// -------------------------------------------------------------------------------------------

/// The `(ssl_version, session_id)` lookup key of `ssl_session_cmp` (`ssl_lib.c:3877`).
///
/// **This is a key, not a session.** The previous technique fabricated a whole `SslSession` with
/// `core::mem::zeroed()` and relied on every present and future field being valid when zero. That
/// is a property of the *whole type*, not of the three fields the comparator reads, so a later
/// structure change could silently invalidate it (AGENTS §2: zeroed storage is not automatically a
/// valid `T`). This type contains exactly the compared fields, is written field-by-field by
/// [`SessionKey::from_id`], and is never reinterpreted as a session.
struct SessionKey {
    ssl_version: c_int,
    session_id_length: usize,
    session_id: [u8; SSL_MAX_SSL_SESSION_ID_LENGTH],
}

impl SessionKey {
    /// The key of a live session (the comparator's operand when removing or replacing).
    ///
    /// # Safety
    /// `session` must be a live session.
    unsafe fn of_session(session: *const SslSession) -> SessionKey {
        // SAFETY: `session` is live per the contract.
        unsafe {
            SessionKey {
                ssl_version: (*session).ssl_version,
                session_id_length: (*session).session_id_length,
                session_id: (*session).session_id,
            }
        }
    }

    /// The key for a lookup by id. The id is truncated to the session-id width exactly as the
    /// comparator would; every field is written here, so the value is valid by construction.
    fn from_id(ssl_version: c_int, id: &[u8]) -> SessionKey {
        let n = id.len().min(SSL_MAX_SSL_SESSION_ID_LENGTH);
        let mut session_id = [0u8; SSL_MAX_SSL_SESSION_ID_LENGTH];
        session_id[..n].copy_from_slice(&id[..n]);
        SessionKey {
            ssl_version,
            session_id_length: n,
            session_id,
        }
    }

    /// `ssl_session_cmp` against a live session.
    ///
    /// # Safety
    /// `session` must be a live session.
    unsafe fn matches(&self, session: *const SslSession) -> bool {
        // SAFETY: `session` is live per the contract.
        unsafe {
            if (*session).ssl_version != self.ssl_version
                || (*session).session_id_length != self.session_id_length
            {
                return false;
            }
            // A stored length wider than the array cannot describe a well-formed session; the
            // authority's `memcmp` would read past `session_id`. Refuse to compare rather than
            // reproduce that out-of-bounds read.
            if self.session_id_length > SSL_MAX_SSL_SESSION_ID_LENGTH {
                return false;
            }
            // SAFETY: `self.session_id_length` is at most the array width and the session's own
            // stored length compares equal, so both sides name an in-bounds prefix.
            core::slice::from_raw_parts((*session).session_id.as_ptr(), self.session_id_length)
                == &self.session_id[..self.session_id_length]
        }
    }
}

/// One owned `SSL_SESSION` reference in this module's cache lifecycle.
///
/// The guard is neither `Copy` nor `Clone`: a reference is acquired (or adopted from a detached
/// cache entry) exactly once and `Drop` releases it exactly once. Every early return — a refused
/// lock, a refused `sk_push`, a refused callback — simply lets the guard drop, so a partially
/// acquired reference cannot leak; a reference transferred to the cache stack or to an accepting
/// callback is moved out with [`SessionRef::into_raw`], so the guard cannot release it again. The
/// exported `SSL_SESSION_free`/`SSL_SESSION_up_ref` ABI is unchanged.
struct SessionRef {
    session: ptr::NonNull<SslSession>,
}

impl SessionRef {
    /// Acquire one new reference with `SSL_SESSION_up_ref`, or `None` when the object refuses
    /// (retired or destroying).
    ///
    /// # Safety
    /// `session` must be a live session whose positive reference count is published.
    unsafe fn acquire(session: *mut SslSession) -> Option<SessionRef> {
        if session.is_null() {
            return None;
        }
        // SAFETY: `session` is live per the contract; success transfers exactly one new
        // reference to this guard.
        if unsafe { SSL_SESSION_up_ref(session) } == 0 {
            return None;
        }
        Some(SessionRef {
            // SAFETY: the NULL case returned above; `up_ref` succeeded, so the object is live.
            session: unsafe { ptr::NonNull::new_unchecked(session) },
        })
    }

    /// Adopt the single reference a cache entry held before that entry left the cache's
    /// bookkeeping.
    ///
    /// # Safety
    /// `session` must be non-NULL, live, and the caller must have removed its entry from the
    /// cache stack in this critical section (or be releasing that stack) without handing the
    /// entry's reference to any other owner. This guard becomes its sole releaser.
    unsafe fn adopt_cache_entry(session: *mut SslSession) -> SessionRef {
        // The contract, not this debug-only check, carries the invariant; a release build may
        // not rely on it.
        debug_assert!(!session.is_null());
        SessionRef {
            // SAFETY: non-NULL per the contract.
            session: unsafe { ptr::NonNull::new_unchecked(session) },
        }
    }

    /// The borrowed pointer; the session stays owned by this guard.
    fn as_ptr(&self) -> *mut SslSession {
        self.session.as_ptr()
    }

    /// Transfer the reference to a new owner: the cache stack that accepted the push, or an
    /// application callback that reported it keeps the reference.
    fn into_raw(self) -> *mut SslSession {
        let p = self.session.as_ptr();
        core::mem::forget(self);
        p
    }
}

impl Drop for SessionRef {
    fn drop(&mut self) {
        // SAFETY: this guard owns exactly one reference (each constructor transfers one) and
        // `Drop` runs once; `SSL_SESSION_free` releases exactly that reference.
        unsafe { SSL_SESSION_free(self.session.as_ptr()) };
    }
}

/// The authority's `lh_SSL_SESSION_retrieve(ctx->sessions, key)`.
///
/// # Safety
/// `ctx` must be a live context; `key` names the session to find.
unsafe fn cache_find(ctx: *mut SslCtx, key: &SessionKey) -> *mut SslSession {
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
        // SAFETY: a cache entry is a live session (the slot is non-NULL for a pushed entry).
        if !s.is_null() && unsafe { key.matches(s) } {
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
            // The authority's `SSL_SESSION_list_remove` clears the cache back-pointer
            // (`ssl_sess.c:1349`). The session may outlive the context through an independent
            // reference, so leaving `owner` pointing at the context is a dangling reference.
            // SAFETY: `s` is live per the contract.
            unsafe { (*s).owner = ptr::null_mut() };
            return i;
        }
    }
    -1
}

/// `static SSL_SESSION *remove_session_locked(SSL_CTX *ctx, SSL_SESSION *c)` —
/// `ssl/ssl_sess.c:884-897`.
///
/// Returns the detached entry's cache reference as a guard. The caller holds the write lock and
/// must release the guard **after** unlocking (a last-reference release can run application
/// `ex_data` destructors).
///
/// # Safety
/// `ctx` must be a live context whose write lock this thread holds; `c` a live session.
unsafe fn remove_session_locked(ctx: *mut SslCtx, c: *mut SslSession) -> Option<SessionRef> {
    let mut r = None;
    // SAFETY: `c` is NULL or live per the contract.
    if !c.is_null() && unsafe { (*c).session_id_length } != 0 {
        // SAFETY: `c` is live.
        let key = unsafe { SessionKey::of_session(c) };
        // SAFETY: `ctx` is live per the contract.
        let found = unsafe { cache_find(ctx, &key) };
        if !found.is_null() {
            // SAFETY: `found` is the live cache entry.
            if unsafe { cache_delete_ptr(ctx, found) } >= 0 {
                // SAFETY: the entry's cache reference was just detached from the stack; this
                // guard becomes its sole releaser.
                r = Some(unsafe { SessionRef::adopt_cache_entry(found) });
            }
        }
        // SAFETY: `c` is live.
        unsafe { (*c).not_resumable = 1 };
    }
    r
}

/// `int SSL_CTX_add_session(SSL_CTX *ctx, SSL_SESSION *c)` — `ssl/ssl_sess.c:749-856`.
///
/// The insert is **failure-atomic**: the session is pushed before any incumbent is replaced or
/// evicted, so a refused push (`OPENSSL_sk_new_null`/`OPENSSL_sk_push` failure) leaves the cache
/// exactly as it was, including an incumbent with the same key. Every detached entry owns exactly
/// one reference — the cache's — which is released here, outside the lock, after the removal
/// callback has run (module header).
///
/// # Safety
/// `ctx` must be a live context; `c` a live session (borrowed; the cache takes a reference).
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_add_session(ctx: *mut SslCtx, c: *mut SslSession) -> c_int {
    guard_ffi(0, || {
        if ctx.is_null() || c.is_null() {
            return 0;
        }
        // The cache's prospective reference. Every early return below lets this guard drop,
        // which releases exactly the reference this call acquired — including the lock-refusal
        // arm, where the reference is acquired before the lock can refuse.
        // SAFETY: `c` is live per the caller's contract.
        let Some(cache_ref) = (unsafe { SessionRef::acquire(c) }) else {
            return 0;
        };
        // SAFETY: `ctx` is live.
        if unsafe { CRYPTO_THREAD_write_lock((*ctx).lock) } == 0 {
            // `cache_ref` drops: the partially acquired reference is released exactly once.
            return 0;
        }
        // The authority replaces an incumbent with the same key and updates the last-used time
        // whenever `SSL_SESS_CACHE_UPDATE_TIME` is set (`ssl_sess.c:798-801`), before the
        // new/replacement decision.
        // SAFETY: `ctx` and `c` are live per the caller's contract.
        unsafe {
            if (*ctx).session_cache_mode & SSL_SESS_CACHE_UPDATE_TIME != 0 {
                (*c).time = time_now_secs();
                ssl_session_calculate_timeout(c);
            }
        }
        // SAFETY: `c` is live.
        let key = unsafe { SessionKey::of_session(c) };
        // SAFETY: `ctx` is live.
        let existing = unsafe { cache_find(ctx, &key) };
        let mut ret = 0;
        // `cache_ref` stays owned until it is either transferred to the stack (successful push)
        // or released after the unlock. `replaced` is the previous object under this key
        // (`lh_SSL_SESSION_insert`'s return); the authority releases it *without* a
        // `remove_session_cb`. `evicted` entries are the size-cap removals, which do run the
        // callback. Both carry the detached cache reference in a guard, so each is released
        // exactly once and only after the lock is gone.
        let mut cache_ref = Some(cache_ref);
        let mut replaced: Option<SessionRef> = None;
        let mut evicted: Vec<SessionRef> = Vec::new();
        if existing == c {
            // Already cached: the reference acquired at entry is redundant (`ret` stays 0, as the
            // authority's `s == c` arm does). It is released after the lock is dropped below.
        } else {
            // Insert first. Nothing below this point can refuse, so a refusal here is the only
            // failure path and it has not touched the cache.
            // SAFETY: `ctx` is live and its cache is this context's own.
            let pushed = unsafe {
                if (*ctx).sessions.is_null() {
                    (*ctx).sessions = OPENSSL_sk_new_null();
                }
                !(*ctx).sessions.is_null() && OPENSSL_sk_push((*ctx).sessions, c.cast()) != 0
            };
            if pushed {
                // The stack now owns the reference acquired at entry; hand it over so the guard
                // cannot release it a second time.
                if let Some(r) = cache_ref.take() {
                    let _ = r.into_raw();
                }
                // SAFETY: `ctx`/`c`/`existing` are live, and `existing` (when non-NULL) is the
                // cache's entry under the same key.
                unsafe {
                    (*c).owner = ctx;
                    ret = 1;
                    if !existing.is_null() && cache_delete_ptr(ctx, existing) >= 0 {
                        // SAFETY: the incumbent's cache reference was just detached.
                        replaced = Some(SessionRef::adopt_cache_entry(existing));
                    }
                    // Evict the oldest entries until the cache is at its configured limit. The
                    // entry just pushed is the newest, so it is never index 0 while another
                    // entry is present.
                    loop {
                        let cap = (*ctx).session_cache_size;
                        let num = OPENSSL_sk_num((*ctx).sessions);
                        if cap == 0 || num <= 0 || num as usize <= cap {
                            break;
                        }
                        let tail = OPENSSL_sk_value((*ctx).sessions, 0).cast::<SslSession>();
                        let Some(r) = remove_session_locked(ctx, tail) else {
                            break;
                        };
                        (*ctx).stats.sess_cache_full.fetch_add(1, Ordering::Relaxed);
                        evicted.push(r);
                    }
                }
            }
        }
        // SAFETY: `ctx` is live and this thread holds its write lock.
        unsafe { CRYPTO_THREAD_unlock((*ctx).lock) };
        // Every release below happens outside the lock: an application `remove_session_cb` may
        // re-enter the cache, and a last-reference release may run the session's `ex_data`
        // destructors, which are application callbacks too.
        drop(cache_ref);
        drop(replaced);
        // Snapshot the callback (it is a plain function pointer) so the loop never re-reads the
        // context after a callback that retires it.
        // SAFETY: `ctx` is live here; the caller holds a context reference.
        let cb = unsafe { (*ctx).remove_session_cb };
        for r in evicted {
            if let Some(cb) = cb {
                // SAFETY: `cb` is the application's registered `remove_session_cb` and `ctx`/`r`
                // are live (the callback's own contract; `r` stays owned by this guard for the
                // call's duration).
                unsafe { cb(ctx, r.as_ptr()) };
            }
            drop(r);
        }
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
            let removed = remove_session_locked(ctx, c);
            CRYPTO_THREAD_unlock((*ctx).lock);
            if let Some(cb) = (*ctx).remove_session_cb {
                cb(ctx, c);
            }
            // `removed` owns the detached cache reference; it is released exactly once here,
            // after the callback and outside the lock.
            let ret = if removed.is_some() { 1 } else { 0 };
            drop(removed);
            ret
        }
    })
}

/// `void SSL_CTX_flush_sessions_ex(SSL_CTX *s, time_t t)` — `ssl/ssl_sess.c:1265-1310`.
///
/// A negative `t` expires nothing: the authority's `sess_timedout((time_t)t, ...)` compares signed
/// values, so only `t == 0` (flush everything) or a positive cutoff selects entries. The walk is
/// insertion order (module header), so it cannot stop at the first live entry as the authority's
/// timeout-ordered list does.
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
            let mut removed: Vec<SessionRef> = Vec::new();
            let st = (*s).sessions;
            if !st.is_null() {
                // Walk newest-to-oldest so the surviving prefix's order is preserved.
                let n = OPENSSL_sk_num(st);
                let mut i = n - 1;
                while i >= 0 {
                    let current = OPENSSL_sk_value(st, i).cast::<SslSession>();
                    if !current.is_null() && (t == 0 || (t > 0 && sess_timedout(t as u64, current)))
                    {
                        OPENSSL_sk_delete(st, i);
                        (*current).not_resumable = 1;
                        // `SSL_SESSION_list_remove` clears the cache back-pointer
                        // (`ssl_sess.c:1349`); a caller-held reference outlives the context.
                        (*current).owner = ptr::null_mut();
                        // SAFETY: the entry was just deleted from the live stack; this guard
                        // becomes the sole releaser of its cache reference.
                        removed.push(SessionRef::adopt_cache_entry(current));
                    }
                    i -= 1;
                }
            }
            CRYPTO_THREAD_unlock((*s).lock);
            // Snapshot the callback: an application callback is free to re-enter the cache, and
            // snapshotting keeps this loop from re-reading the context after an adversarial
            // callback retired the last reference to it.
            let cb = (*s).remove_session_cb;
            for current in removed {
                if let Some(cb) = cb {
                    cb(s, current.as_ptr());
                }
                // The guard releases the detached cache reference exactly once, after the
                // callback and outside the lock.
                drop(current);
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

/// Release a context's session-cache container (`SSL_CTX_free`'s `lh_SSL_SESSION_free`).
///
/// [`crate::ssl::ssl_sess::SSL_CTX_flush_sessions_ex`] has already removed every entry and
/// invoked `remove_session_cb` while the context was live, so this is normally just the
/// container release. An entry a callback re-added during the flush is released here **without**
/// a callback: that matches the authority's `lh_SSL_SESSION_free` being a container-only free
/// (the authority would leak such an entry; releasing it is the safe divergence, not a double
/// release, because the cache reference is the one dropped).
///
/// # Safety
/// `ctx` must be a live context whose cache is no longer shared and whose `ex_data` has been
/// released (no callback runs here).
pub(crate) unsafe fn ssl_ctx_session_cache_free(ctx: *mut SslCtx) {
    // SAFETY: `ctx` is live per the contract.
    unsafe {
        let st = (*ctx).sessions;
        if st.is_null() {
            return;
        }
        let n = OPENSSL_sk_num(st);
        let mut removed: Vec<SessionRef> = Vec::new();
        for i in 0..n {
            let session = OPENSSL_sk_value(st, i).cast::<SslSession>();
            if !session.is_null() {
                // `SSL_CTX_flush_sessions_ex` removes each cache entry from the list before the
                // context is released, so a session still held by an application has no owner.
                (*session).owner = ptr::null_mut();
                // SAFETY: the container is released below, so the entry's cache reference is
                // leaving the cache's bookkeeping; this guard is its sole releaser.
                removed.push(SessionRef::adopt_cache_entry(session));
            }
        }
        OPENSSL_sk_free(st);
        (*ctx).sessions = ptr::null_mut();
        // Release every remaining cache reference exactly once. No callback runs here (the
        // context's `ex_data` is already gone, so this is the container-only free).
        drop(removed);
    }
}

// -------------------------------------------------------------------------------------------
// Phase 17 — the handshake session (`ssl/ssl_sess.c`'s `ssl_get_new_session`, the server's
// `ssl_get_prev_session`, and `ssl_update_cache`)
// -------------------------------------------------------------------------------------------

/// `SSL3_VERSION` — `ssl3.h`.
const SSL3_VERSION: c_int = 0x0300;
/// `TLS1_1_VERSION` — `tls1.h`.
const TLS1_1_VERSION: c_int = 0x0302;
/// `TLS1_2_VERSION` — `tls1.h`.
const TLS1_2_VERSION: c_int = 0x0303;
/// `SSL3_SSL_SESSION_ID_LENGTH` — `ssl3.h` (32).
const SSL3_SSL_SESSION_ID_LENGTH: usize = 32;
/// `SSL_SESS_CACHE_CLIENT` — `ssl.h:711`.
pub(crate) const SSL_SESS_CACHE_CLIENT: c_long = 0x0001;
/// `SSL_SESS_CACHE_SERVER` — `ssl.h:713`.
pub(crate) const SSL_SESS_CACHE_SERVER: c_long = 0x0002;
/// `SSL_SESS_CACHE_NO_INTERNAL_STORE` — `ssl.h:715`.
const SSL_SESS_CACHE_NO_INTERNAL_STORE: c_long = 0x0200;
/// `SSL_SESS_CACHE_NO_AUTO_CLEAR` — `ssl.h:714`.
const SSL_SESS_CACHE_NO_AUTO_CLEAR: c_long = 0x0080;
/// `SSL_VERIFY_PEER` — `ssl.h`.
const SSL_VERIFY_PEER: c_int = 0x01;

/// `static int def_generate_session_id(SSL *ssl, unsigned char *id, unsigned int *id_len)` —
/// `ssl/ssl_sess.c:321-346`, reduced to the RAND arm (no FUZZING retry).
///
/// # Safety
/// `ssl` must be NULL or a live connection; `id` writable for `*id_len`; `id_len` writable.
unsafe extern "C" fn def_generate_session_id(
    ssl: *mut Ssl,
    id: *mut u8,
    id_len: *mut c_uint,
) -> c_int {
    let _ = ssl;
    // SAFETY: `id`/`id_len` are the caller's per the contract.
    unsafe {
        if id_len.is_null() || crate::rand::rand_lib::RAND_bytes(id, *id_len as c_int) <= 0 {
            return 0;
        }
    }
    1
}

/// `int ssl_generate_session_id(SSL_CONNECTION *s, SSL_SESSION *ss)` — `ssl/ssl_sess.c:348-433`,
/// reduced at the callback selection and the `SSL_has_matching_session_id` conflict check.
///
/// # Safety
/// `s` must be a live connection; `ss` a live session.
pub(crate) unsafe fn ssl_generate_session_id(s: *mut Ssl, ss: *mut SslSession) -> c_int {
    // SAFETY: `s`/`ss` are live per the contract.
    unsafe {
        match (*s).version {
            SSL3_VERSION
            | TLS1_VERSION
            | TLS1_1_VERSION
            | TLS1_2_VERSION
            | crate::ssl::ssl_lib::TLS1_3_VERSION => {
                (*ss).session_id_length = SSL3_SSL_SESSION_ID_LENGTH;
            }
            _ => {
                raise_ssl(SSL_R_UNSUPPORTED_SSL_VERSION, 366);
                return 0;
            }
        }
        // The RFC5077 arm: when the server will issue a stateless ticket, the session id is empty.
        if (*s).ext_ticket_expected != 0 {
            (*ss).session_id_length = 0;
            return 1;
        }
        let mut cb: Option<GenerateSessionIdCb> = None;
        if let Some(c) = (*s).generate_session_id {
            cb = Some(c);
        } else if !(*s).session_ctx.is_null() {
            if let Some(c) = (*(*s).session_ctx).generate_session_id {
                cb = Some(c);
            }
        }
        let cb = cb.unwrap_or(def_generate_session_id);
        ptr::write_bytes((*ss).session_id.as_mut_ptr(), 0, (*ss).session_id_length);
        let mut tmp = (*ss).session_id_length as c_uint;
        if cb(s, (*ss).session_id.as_mut_ptr(), &mut tmp) == 0 {
            raise_ssl(SSL_R_SSL_SESSION_ID_CALLBACK_FAILED, 410);
            return 0;
        }
        if tmp == 0 || tmp as usize > (*ss).session_id_length {
            raise_ssl(SSL_R_SSL_SESSION_ID_HAS_BAD_LENGTH, 420);
            return 0;
        }
        (*ss).session_id_length = tmp as usize;
    }
    1
}

/// `int ssl_get_new_session(SSL_CONNECTION *s, int session)` — `ssl/ssl_sess.c:435-489`.
///
/// # Safety
/// `s` must be a live connection.
pub(crate) unsafe fn ssl_get_new_session(s: *mut Ssl, session: c_int) -> c_int {
    // SAFETY: `s` is live per the contract.
    let ss = unsafe { SSL_SESSION_new() };
    if ss.is_null() {
        // SAFETY: `s` is live.
        raise_ssl(ERR_R_MALLOC_FAILURE, 442);
        return 0;
    }
    // SAFETY: `s`/`ss` are live per the contract.
    unsafe {
        let ctx = (*s).session_ctx;
        let timeout = if ctx.is_null() || (*ctx).session_timeout == 0 {
            (*(*s).method).timeout_secs
        } else {
            (*ctx).session_timeout
        };
        (*ss).timeout = timeout;
        ssl_session_calculate_timeout(ss);

        SSL_SESSION_free((*s).session);
        (*s).session = ptr::null_mut();

        if session != 0 {
            if (*s).version == crate::ssl::ssl_lib::TLS1_3_VERSION {
                (*ss).session_id_length = 0;
            } else if ssl_generate_session_id(s, ss) == 0 {
                SSL_SESSION_free(ss);
                return 0;
            }
        } else {
            (*ss).session_id_length = 0;
        }

        if (*s).sid_ctx_length as usize > SSL_MAX_SID_CTX_LENGTH {
            raise_ssl(ERR_R_INTERNAL_ERROR, 475);
            SSL_SESSION_free(ss);
            return 0;
        }
        let n = (*s).sid_ctx_length as usize;
        core::ptr::copy_nonoverlapping(
            core::ptr::addr_of!((*s).sid_ctx).cast::<u8>(),
            core::ptr::addr_of_mut!((*ss).sid_ctx).cast::<u8>(),
            n,
        );
        (*ss).sid_ctx_length = n;
        (*s).session = ss;
        (*ss).ssl_version = (*s).version;
        (*ss).verify_result = X509_V_OK;
        if (*s).s3_flags & TLS1_FLAGS_RECEIVED_EXTMS != 0 {
            (*ss).flags |= crate::ssl::ssl_lib::SSL_SESS_FLAG_EXTMS;
        }
    }
    1
}

/// `SSL_SESSION *lookup_sess_in_cache(SSL_CONNECTION *s, const unsigned char *sess_id,`
/// `size_t sess_id_len)` — `ssl/ssl_sess.c:491-566`, reduced to the internal stack lookup (the
/// external `get_session_cb` arm is not exercised). Returns a session with one reference owned by
/// the caller, or `None`.
///
/// # Safety
/// `s` must be a live connection; `sess_id` a readable slice.
unsafe fn lookup_sess_in_cache(s: *mut Ssl, sess_id: &[u8]) -> Option<SessionRef> {
    // SAFETY: `s` is live per the contract.
    unsafe {
        let ctx = (*s).session_ctx;
        if ctx.is_null() {
            return None;
        }
        // A key value built from the compared fields — not a zeroed `SSL_SESSION` (AGENTS §2).
        let key = SessionKey::from_id((*s).version, sess_id);
        if CRYPTO_THREAD_read_lock((*ctx).lock) == 0 {
            return None;
        }
        let found = cache_find(ctx, &key);
        // The read lock excludes the write lock every eviction/removal/flush takes, so the
        // cache's reference cannot be released between the find and this acquire. The guard is
        // the caller's own reference and survives any later eviction after the unlock.
        let ret = if found.is_null() {
            None
        } else {
            // SAFETY: `found` is a live cache entry while the read lock is held.
            SessionRef::acquire(found)
        };
        CRYPTO_THREAD_unlock((*ctx).lock);
        if found.is_null() {
            (*ctx).stats.sess_miss.fetch_add(1, Ordering::Relaxed);
        }
        ret
    }
}

/// `int ssl_get_prev_session(SSL_CONNECTION *s, CLIENTHELLO_MSG *hello)` — `ssl/ssl_sess.c:585-747`.
///
/// This crate's TLS1.2 tickets are stateful: the server records the session under
/// `SHA256(ticket)` and looks it up by the client-offered session id, which the client sets to
/// that same hash (`tls_process_new_session_ticket`, `statem_clnt.c:2851`). The authority's
/// stateless-ticket decrypt path is recorded as a divergence in the module header. Returns 1 on a
/// hit (with `s->session` and `s->hit` side effects left to the caller), 0 on a miss.
///
/// # Safety
/// `s` must be a live connection; `session_id`/`ticket` are readable slices.
pub(crate) unsafe fn ssl_get_prev_session(
    s: *mut Ssl,
    session_id: &[u8],
    ticket_ext_present: bool,
) -> c_int {
    // SAFETY: `s` is live per the contract.
    unsafe {
        // `tls_get_ticket_from_client` clears the flag first (`t1_lib.c:3000`) and only re-arms
        // it when the client offered `session_ticket` and tickets are enabled
        // (`t1_lib.c:2996-3010`).
        (*s).ext_ticket_expected = 0;
        let ticket_expected =
            c_int::from(ticket_ext_present && crate::ssl::t1_lib::tls_use_ticket(s));
        if session_id.is_empty() {
            // No session looked up: the server will issue a fresh ticket and session.
            (*s).ext_ticket_expected = ticket_expected;
            return 0;
        }
        let ctx = (*s).session_ctx;
        // `ret` owns one reference from the lookup; every rejection below drops it exactly once
        // (immediately, or on the return), and the accepted path transfers it to `s->session`.
        let mut ret = lookup_sess_in_cache(s, session_id);
        if ret.is_none() {
            (*s).ext_ticket_expected = ticket_expected;
            return 0;
        }
        // Version consistency (`ssl_sess.c:641`).
        if ret
            .as_ref()
            .is_some_and(|r| (*r.as_ptr()).ssl_version != (*s).version)
        {
            ret = None;
        }
        // `sid_ctx` consistency (`ssl_sess.c:644`).
        if let Some(r) = &ret {
            let p = r.as_ptr();
            let rn = (*p).sid_ctx_length;
            let sn = (*s).sid_ctx_length as usize;
            let same = if rn != sn {
                false
            } else if rn == 0 {
                true
            } else {
                let a =
                    core::slice::from_raw_parts(core::ptr::addr_of!((*p).sid_ctx).cast::<u8>(), rn);
                let b =
                    core::slice::from_raw_parts(core::ptr::addr_of!((*s).sid_ctx).cast::<u8>(), rn);
                a == b
            };
            if !same {
                ret = None;
            }
        }
        if ret.is_none() {
            (*s).ext_ticket_expected = ticket_expected;
            return 0;
        }
        if (*s).verify_mode & SSL_VERIFY_PEER != 0 && (*s).sid_ctx_length == 0 {
            raise_ssl(SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED, 665);
            return -1;
        }
        if let Some(r) = &ret {
            if sess_timedout(time_now_secs(), r.as_ptr()) {
                (*ctx).stats.sess_timeout.fetch_add(1, Ordering::Relaxed);
                SSL_CTX_remove_session(ctx, r.as_ptr());
                (*s).ext_ticket_expected = ticket_expected;
                return 0;
            }
        }
        // The explicit offered/embedded id match (`ssl_sess.c:717-723`).
        if let Some(r) = &ret {
            let p = r.as_ptr();
            if (*p).session_id_length != session_id.len() || {
                let a = core::slice::from_raw_parts(
                    core::ptr::addr_of!((*p).session_id).cast::<u8>(),
                    session_id.len(),
                );
                a != session_id
            } {
                ret = None;
            }
        }
        let Some(r) = ret else {
            (*s).ext_ticket_expected = ticket_expected;
            return 0;
        };
        (*ctx).stats.sess_hit.fetch_add(1, Ordering::Relaxed);
        let accepted = r.as_ptr();
        (*s).verify_result = (*accepted).verify_result;
        SSL_SESSION_free((*s).session);
        (*s).session = accepted;
        // The connection now owns the lookup's reference.
        let _ = r.into_raw();
    }
    1
}

/// `void ssl_update_cache(SSL_CONNECTION *s, int mode)` — `ssl/ssl_lib.c:4712-4783`.
///
/// The internal-store, `new_session_cb` and automatic-flush arms. The auto-flush trigger matches
/// the authority: when auto-clear is enabled and `(session_cache_mode & mode) == mode`, the counter
/// for this side is read *before* the caller increments it and a low byte of `0xff` flushes the
/// cache with the current time. TLS1.3 cache updates use their own path, so the authority's
/// `SSL_IS_TLS13(s)` sub-conditions are out of this call's scope.
///
/// # Safety
/// `s` must be a live connection with its session set.
pub(crate) unsafe fn ssl_update_cache(s: *mut Ssl, mode: c_long) {
    // SAFETY: `s` is live per the contract.
    unsafe {
        let sess = (*s).session;
        // The authority dereferences `s->session` unconditionally; a NULL here is undefined there
        // and is a no-op here (the accessor family's NULL discipline).
        if sess.is_null() || (*sess).session_id_length == 0 {
            return;
        }
        if (*s).server != 0
            && (*sess).sid_ctx_length == 0
            && (*s).verify_mode & SSL_VERIFY_PEER != 0
        {
            return;
        }
        let ctx = (*s).session_ctx;
        if ctx.is_null() {
            return;
        }
        let i = (*ctx).session_cache_mode;
        // `not_resumable` is an additional guard over the authority's test: a session the cache
        // has already retired must not be re-inserted by a finishing handshake.
        if (i & mode) != 0 && (*s).hit == 0 && (*sess).not_resumable == 0 {
            if (i & SSL_SESS_CACHE_NO_INTERNAL_STORE) == 0 {
                SSL_CTX_add_session(ctx, sess);
            }
            if let Some(cb) = (*ctx).new_session_cb {
                // The authority gives the callback its own reference and takes it back only when
                // the callback refuses (`ssl_lib.c:4746-4755`). The guard makes that transfer
                // structural: a refusal (0) drops the reference exactly once; acceptance moves
                // it to the callback, which then owns it.
                // SAFETY: `sess` is live through the connection's reference.
                if let Some(extra) = SessionRef::acquire(sess) {
                    // SAFETY: `cb` is the registered callback; `s`/`sess` are live per the
                    // callback's own contract.
                    if cb(s, sess) == 0 {
                        // `extra` drops here.
                    } else {
                        let _ = extra.into_raw();
                    }
                }
            }
        }
        // `ssl_lib.c:4766-4782`. The caller increments the good-connection counter after this
        // call, so the comparison is against the pre-increment value, exactly as the authority
        // reads it.
        if (i & SSL_SESS_CACHE_NO_AUTO_CLEAR) == 0 && (i & mode) == mode {
            let stat = if mode & SSL_SESS_CACHE_CLIENT != 0 {
                &(*ctx).stats.sess_connect_good
            } else {
                &(*ctx).stats.sess_accept_good
            };
            if stat.load(Ordering::Relaxed) & 0xff == 0xff {
                SSL_CTX_flush_sessions_ex(ctx, time_now_secs() as i64);
            }
        }
    }
}

// -------------------------------------------------------------------------------------------
// Accessors
// -------------------------------------------------------------------------------------------

// ## NULL safety
//
// The authority defines a NULL answer only for the time accessors
// (`SSL_SESSION_get_time[_ex]`, `SSL_SESSION_get_timeout`, the matching setters) and
// dereferences NULL in the rest. Every accessor below answers a neutral value from a NULL
// session instead: a NULL reaching a reader is a defect in the caller or in
// `SSL_get_session` (the sslscan 2.1.5 crash), and reproducing the authority's dereference
// would be undefined behaviour (AGENTS §17). Defined, non-NULL inputs keep the authority's
// exact answer; the deviation exists only for the input the authority leaves undefined.

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
        if s.is_null() {
            return ptr::null_mut();
        }
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
        if s.is_null() {
            if !len.is_null() {
                // SAFETY: `len` is NULL or writable per the caller's contract.
                unsafe { *len = 0 };
            }
            return ptr::null();
        }
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
        if s.is_null() {
            if !len.is_null() {
                // SAFETY: `len` is NULL or writable per the caller's contract.
                unsafe { *len = 0 };
            }
            return ptr::null();
        }
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
        if s.is_null() {
            return 0;
        }
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
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            if sid_len as usize > SSL_MAX_SSL_SESSION_ID_LENGTH {
                raise_ssl(SSL_R_SSL_SESSION_ID_TOO_LONG, 976);
                return 0;
            }
            (*s).session_id_length = sid_len as usize;
            if sid != (*s).session_id.as_ptr() && sid_len > 0 {
                // `memmove` semantics: the C contract only requires `sid` to be readable for
                // `sid_len` bytes, and a partially overlapping pointer into `session_id` satisfies
                // it. The authority's `memcpy` makes that overlap UB (AGENTS §17); the copy is
                // otherwise the authority's in-place result.
                ptr::copy(sid, (*s).session_id.as_mut_ptr(), sid_len as usize);
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
        if s.is_null() {
            return 0;
        }
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
        if s.is_null() {
            return 0;
        }
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
        if s.is_null() {
            return ptr::null();
        }
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
        if s.is_null() {
            return 0;
        }
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
        if s.is_null() {
            return ptr::null();
        }
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).ext_hostname() }
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
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live per the caller's contract and its `ext_hostname` member obeys the
        // member-buffer invariant.
        let mut slot = unsafe { (*s).ext_hostname_slot() };
        if hostname.is_null() {
            // A NULL argument leaves the member unset after releasing the incumbent, as the
            // authority does at `ssl_sess.c:1083-1086`.
            slot.clear(FILE_SEAM, 1083);
            return 1;
        }
        // Duplicate **before** releasing the incumbent: `hostname` may be the pointer
        // `SSL_SESSION_get0_hostname` handed out, i.e. this very member. The authority frees the
        // member first (`ssl_sess.c:1083`) and then calls `OPENSSL_strdup` on the caller's pointer
        // (`:1088`), which is a use-after-free for that caller; this ordering is the §17 UB
        // elimination recorded as D563. The release still happens at the same authority site.
        // SAFETY: `hostname` is NUL-terminated per the caller's contract.
        let dup = unsafe { OwnedCStr::dup(hostname, FILE_SEAM, 1088) };
        let empty = slot.clear(FILE_SEAM, 1083);
        match dup {
            Some(dup) => {
                empty.store(dup);
                1
            }
            None => 0,
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
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            if (*s).ext_tick().1 > 0 {
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
        if s.is_null() {
            return 0;
        }
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
        if s.is_null() {
            // SAFETY: `len` is writable and `tick` is NULL or writable per the caller's contract.
            unsafe {
                *len = 0;
                if !tick.is_null() {
                    *tick = ptr::null();
                }
            }
            return;
        }
        // SAFETY: `s` is live per the caller's contract.
        let (tick_ptr, tick_len) = unsafe { (*s).ext_tick() };
        // SAFETY: `len` is writable and `tick` is NULL or writable, per the caller's contract.
        unsafe {
            *len = tick_len;
            if !tick.is_null() {
                *tick = tick_ptr;
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
        if s.is_null() {
            return 0;
        }
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
        if s.is_null() {
            return 0;
        }
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
        if s.is_null() {
            // SAFETY: `alpn` and `len` are writable per the caller's contract.
            unsafe {
                *alpn = ptr::null();
                *len = 0;
            }
            return;
        }
        // SAFETY: `s` is live per the caller's contract.
        let (alpn_ptr, alpn_len) = unsafe { (*s).ext_alpn_selected() };
        // SAFETY: `alpn` and `len` are writable per the caller's contract.
        unsafe {
            *alpn = alpn_ptr;
            *len = alpn_len;
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
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live per the caller's contract and its `ext_alpn_selected` member obeys
        // the blob member-buffer invariant.
        let mut slot = unsafe { (*s).ext_alpn_selected_slot() };
        if alpn.is_null() || len == 0 {
            // The authority clears the pair on this arm (`ssl_sess.c:1134-1138`).
            slot.clear(FILE, 1134);
            return 1;
        }
        // Duplicate before releasing the incumbent: `alpn` may be the pointer
        // `SSL_SESSION_get0_alpn_selected` handed out, i.e. this very member. The authority frees
        // first (`ssl_sess.c:1134`) and then calls `OPENSSL_memdup` on the caller's pointer
        // (`:1140`), which is a use-after-free for that caller; this ordering is the §17 UB
        // elimination recorded as D563. A refused duplicate still clears, matching the authority's
        // post-failure `(NULL, 0)` state.
        // SAFETY: `alpn` is readable for `len` bytes per the caller's contract.
        let dup = unsafe { CRYPTO_memdup(alpn.cast(), len, FILE, 1140).cast::<u8>() };
        slot.clear(FILE, 1134);
        if dup.is_null() {
            0
        } else {
            // SAFETY: `dup` is this call's fresh block of `len` bytes; the member is empty.
            unsafe { slot.store(dup, len) };
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
        if s.is_null() {
            return ptr::null_mut();
        }
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
        if s.is_null() {
            return ptr::null_mut();
        }
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
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            if sid_ctx_len as usize > SSL_MAX_SID_CTX_LENGTH {
                raise_ssl(SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG, 1164);
                return 0;
            }
            (*s).sid_ctx_length = sid_ctx_len as usize;
            if sid_ctx != (*s).sid_ctx.as_ptr() {
                // As `SSL_SESSION_set1_id`: a source partially overlapping `sid_ctx` is readable
                // under the stated contract, so use memmove rather than reproduce `memcpy`'s
                // overlap UB (AGENTS §17).
                ptr::copy(sid_ctx, (*s).sid_ctx.as_mut_ptr(), sid_ctx_len as usize);
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
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            if (*s).not_resumable == 0 && ((*s).session_id_length > 0 || (*s).ext_tick().1 > 0) {
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
                // A negative `ext_len` is undefined in the authority: signed/unsigned wrap in
                // `sizeof(*st) + ext_len` can yield a small allocation, followed by an oversized
                // copy. This crate refuses with `0` before allocating (AGENTS §17 UB elimination,
                // not an authority success/failure result); the checked add likewise refuses an
                // overflowing size.
                let Ok(ext_len) = usize::try_from(ext_len) else {
                    return 0;
                };
                let Some(base) = core::mem::size_of::<TlsSessionTicketExt>().checked_add(ext_len)
                else {
                    return 0;
                };
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
                    ptr::copy_nonoverlapping(ext_data.cast::<u8>(), data, ext_len);
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
        if ss.is_null() {
            return 0;
        }
        // SAFETY: `ss` is live per the caller's contract and its `ticket_appdata` member obeys the
        // blob member-buffer invariant.
        let mut slot = unsafe { (*ss).ticket_appdata_slot() };
        if data.is_null() || len == 0 {
            // The authority clears the pair on this arm (`ssl_sess.c:1484-1489`).
            slot.clear(FILE, 1484);
            return 1;
        }
        // Duplicate before releasing the incumbent: `data` may be the pointer
        // `SSL_SESSION_get0_ticket_appdata` handed out, i.e. this very member. The authority frees
        // first (`ssl_sess.c:1484`) and then calls `OPENSSL_memdup` on the caller's pointer
        // (`:1490`), which is a use-after-free for that caller; this ordering is the §17 UB
        // elimination recorded as D563. A refused duplicate still clears, matching the authority's
        // post-failure `(NULL, 0)` state.
        // SAFETY: `data` is readable for `len` bytes per the caller's contract.
        let dup = unsafe { CRYPTO_memdup(data, len, FILE, 1490).cast::<u8>() };
        slot.clear(FILE, 1484);
        if dup.is_null() {
            0
        } else {
            // SAFETY: `dup` is this call's fresh block of `len` bytes; the member is empty.
            unsafe { slot.store(dup, len) };
            1
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
        if ss.is_null() {
            // SAFETY: `data` and `len` are writable per the caller's contract.
            unsafe {
                *data = ptr::null_mut();
                *len = 0;
            }
            return 0;
        }
        // SAFETY: `ss` is live per the caller's contract.
        let (appdata_ptr, appdata_len) = unsafe { (*ss).ticket_appdata() };
        // SAFETY: `data` and `len` are writable per the caller's contract.
        unsafe {
            *data = appdata_ptr.cast_mut().cast();
            *len = appdata_len;
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

#[cfg(test)]
mod refcount_reentrancy_tests {
    #![allow(clippy::panic)]

    use super::*;
    use crate::runtime::ex_data::{CRYPTO_get_ex_new_index, CryptoExData};
    use core::sync::atomic::AtomicUsize;

    static REENTER_TARGET: AtomicUsize = AtomicUsize::new(0);
    static REENTER_CALLS: AtomicUsize = AtomicUsize::new(0);

    /// An application `CRYPTO_EX_free` callback that re-enters `SSL_SESSION_free` with the
    /// same session. It is ignored for every other session.
    unsafe extern "C" fn session_reenter_free(
        obj: *mut c_void,
        _ptr: *mut c_void,
        _ad: *mut CryptoExData,
        _idx: c_int,
        _argl: c_long,
        _argp: *mut c_void,
    ) {
        if obj as usize == REENTER_TARGET.load(Ordering::Relaxed) {
            REENTER_CALLS.fetch_add(1, Ordering::Relaxed);
            // SAFETY: `obj` is the live session this callback was invoked for, and the outer
            // `SSL_SESSION_free` is still inside its destructor body.
            unsafe { SSL_SESSION_free(obj.cast::<SslSession>()) };
        }
    }

    struct ResetTarget;
    impl Drop for ResetTarget {
        fn drop(&mut self) {
            REENTER_TARGET.store(0, Ordering::Relaxed);
        }
    }

    /// A re-entrant `SSL_SESSION_free` from the session's own ex-data free callback must be a
    /// defined no-op: the last releaser has already installed `REF_DESTROYING`.
    #[test]
    fn session_free_reentrancy_is_defined_noop() {
        REENTER_CALLS.store(0, Ordering::Relaxed);
        let idx = CRYPTO_get_ex_new_index(
            CRYPTO_EX_INDEX_SSL_SESSION,
            0,
            ptr::null_mut(),
            None,
            None,
            Some(session_reenter_free),
        );
        assert!(idx > 0);

        // SAFETY: `SSL_SESSION_new` takes no arguments and returns a fresh session or NULL.
        let session = unsafe { SSL_SESSION_new() };
        assert!(!session.is_null());
        let _reset = ResetTarget;
        REENTER_TARGET.store(session as usize, Ordering::Relaxed);

        // SAFETY: `session` is live and `idx` is the index registered above.
        let set = unsafe { SSL_SESSION_set_ex_data(session, idx, session.cast()) };
        assert_eq!(set, 1);
        // SAFETY: this call retires the session's only reference; the callback re-enters it.
        unsafe { SSL_SESSION_free(session) };

        assert_eq!(REENTER_CALLS.load(Ordering::Relaxed), 1);
    }
}

/// The session's `owner` is a cache back-pointer, not an owning reference. Every path that
/// removes the session from the cache must clear it (the authority's `SSL_SESSION_list_remove`,
/// `ssl_sess.c:1349`), or a session held independently of the context would retain a pointer
/// into the freed `SSL_CTX` and `SSL_SESSION_set_timeout` would dereference it.
#[cfg(test)]
mod alias_ownership_tests {
    #![allow(clippy::panic)]

    use super::*;
    use crate::ssl::methods::TLS_method;
    use crate::ssl::ssl_lib::{SSL_CTX_free, SSL_CTX_new};
    use core::sync::atomic::AtomicUsize;

    static REMOVE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static OBSERVED_CTX: AtomicUsize = AtomicUsize::new(0);
    static OBSERVED_EX_DATA: AtomicUsize = AtomicUsize::new(0);
    static OBSERVED_SESSION: AtomicUsize = AtomicUsize::new(0);
    static OBSERVED_INDEX: AtomicI32 = AtomicI32::new(-1);

    /// The teardown-time `remove_session_cb`. It reads the context's ex_data through the public
    /// getter: that is the authority's ticket-#212 ordering contract, and it is what a regression
    /// that freed `ex_data` before the flush would break (the getter would answer NULL).
    unsafe extern "C" fn record_remove_session(ctx: *mut SslCtx, session: *mut SslSession) {
        REMOVE_CALLS.fetch_add(1, Ordering::Relaxed);
        OBSERVED_CTX.store(ctx as usize, Ordering::Relaxed);
        OBSERVED_SESSION.store(session as usize, Ordering::Relaxed);
        let idx = OBSERVED_INDEX.load(Ordering::Relaxed);
        // SAFETY: `ctx` is live for the duration of the authority's remove_session_cb, and `idx`
        // was registered by the test before the callback was installed.
        let data = unsafe { crate::ssl::ssl_lib::SSL_CTX_get_ex_data(ctx, idx) };
        OBSERVED_EX_DATA.store(data as usize, Ordering::Relaxed);
    }

    fn session_refs(session: *const SslSession) -> i32 {
        // SAFETY: `session` is a live session in every caller.
        unsafe { (*session).references.load(Ordering::Relaxed) }
    }

    fn new_cached_session(ctx: *mut SslCtx) -> *mut SslSession {
        // SAFETY: no arguments; the returned session is owned here.
        let session = unsafe { SSL_SESSION_new() };
        assert!(!session.is_null());
        // SAFETY: `session` and `ctx` are live. A non-zero id is required for cache removal.
        unsafe {
            (*session).session_id_length = 4;
            (&mut (*session).session_id)[..4].copy_from_slice(b"test");
            assert_eq!(SSL_CTX_add_session(ctx, session), 1);
            assert_eq!((*session).owner, ctx);
        }
        assert_eq!(session_refs(session), 2);
        session
    }

    #[test]
    fn removed_session_does_not_retain_a_context_back_pointer() {
        // SAFETY: process-lifetime method table; the constructor returns an owned context.
        let ctx = unsafe { SSL_CTX_new(TLS_method()) };
        assert!(!ctx.is_null());
        let session = new_cached_session(ctx);

        // SAFETY: both pointers are live and the session is in `ctx`'s cache.
        assert_eq!(unsafe { SSL_CTX_remove_session(ctx, session) }, 1);
        // SAFETY: `session` survives through this frame's reference.
        assert!(unsafe { (*session).owner }.is_null());
        assert_eq!(session_refs(session), 1);

        // SAFETY: this releases the caller's remaining session reference.
        unsafe { SSL_SESSION_free(session) };
        // SAFETY: the context still has the caller's reference.
        unsafe { SSL_CTX_free(ctx) };
    }

    #[test]
    fn flushed_session_does_not_retain_a_context_back_pointer() {
        // SAFETY: process-lifetime method table; the constructor returns an owned context.
        let ctx = unsafe { SSL_CTX_new(TLS_method()) };
        assert!(!ctx.is_null());
        let session = new_cached_session(ctx);

        // SAFETY: both pointers are live; a timestamp of 0 flushes every cached session.
        unsafe { SSL_CTX_flush_sessions_ex(ctx, 0) };
        // SAFETY: `session` survives through this frame's reference.
        assert!(unsafe { (*session).owner }.is_null());
        assert_eq!(session_refs(session), 1);

        // SAFETY: this releases the caller's remaining session reference.
        unsafe { SSL_SESSION_free(session) };
        // SAFETY: the context still has the caller's reference.
        unsafe { SSL_CTX_free(ctx) };
    }

    #[test]
    fn context_free_flushes_the_cache_and_runs_remove_session_cb_while_ex_data_is_live() {
        // SAFETY: process-lifetime method table; the constructor returns an owned context.
        let ctx = unsafe { SSL_CTX_new(TLS_method()) };
        assert!(!ctx.is_null());
        let session = new_cached_session(ctx);

        // SAFETY: the class/index registration has no object preconditions.
        let idx = crate::runtime::ex_data::CRYPTO_get_ex_new_index(
            crate::runtime::ex_data::CRYPTO_EX_INDEX_SSL_CTX,
            0,
            ptr::null_mut(),
            None,
            None,
            None,
        );
        assert!(idx > 0);
        let sentinel = 0x5EED_5EEDusize;
        // SAFETY: `ctx` is live and `idx` names a registered slot.
        let set =
            unsafe { crate::ssl::ssl_lib::SSL_CTX_set_ex_data(ctx, idx, sentinel as *mut c_void) };
        assert_eq!(set, 1);
        OBSERVED_INDEX.store(idx, Ordering::Relaxed);
        REMOVE_CALLS.store(0, Ordering::Relaxed);
        OBSERVED_EX_DATA.store(0, Ordering::Relaxed);
        OBSERVED_SESSION.store(0, Ordering::Relaxed);
        // SAFETY: `ctx` is live and the callback is a process-lifetime function.
        unsafe { SSL_CTX_sess_set_remove_cb(ctx, Some(record_remove_session)) };

        // SAFETY: this retires the context's only reference. `SSL_CTX_free` must flush the cache
        // (invoking the callback) before `ex_data`, the members and the lock are released.
        unsafe { SSL_CTX_free(ctx) };

        assert_eq!(REMOVE_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(OBSERVED_CTX.load(Ordering::Relaxed), ctx as usize);
        assert_eq!(
            OBSERVED_EX_DATA.load(Ordering::Relaxed),
            sentinel,
            "the callback must observe live ex_data"
        );
        assert_ne!(OBSERVED_SESSION.load(Ordering::Relaxed), 0);
        // The flush released the cache's reference; this frame's remains, and the session no
        // longer points at the retired context.
        assert_eq!(session_refs(session), 1);
        // SAFETY: `session` is live through this frame's reference.
        assert!(unsafe { (*session).owner }.is_null());
        // SAFETY: this releases the caller's remaining reference.
        unsafe { SSL_SESSION_free(session) };
    }

    #[test]
    fn context_free_clears_the_back_pointer_of_a_surviving_session() {
        // SAFETY: process-lifetime method table; the constructor returns an owned context.
        let ctx = unsafe { SSL_CTX_new(TLS_method()) };
        assert!(!ctx.is_null());
        let session = new_cached_session(ctx);

        // SAFETY: this retires the context, releasing the cache's reference. The session is
        // still alive through this frame's reference.
        unsafe { SSL_CTX_free(ctx) };
        // SAFETY: `session` is live and must no longer point at the freed context.
        assert!(unsafe { (*session).owner }.is_null());
        assert_eq!(session_refs(session), 1);

        // This reader dereferences `owner->lock`; before the fix it read freed memory.
        // SAFETY: `session` is live and unowned by any context now.
        assert_eq!(unsafe { SSL_SESSION_set_timeout(session, 42) }, 1);
        // SAFETY: `session` is live and unowned by any context now.
        assert_eq!(unsafe { SSL_SESSION_get_timeout(session) }, 42);

        // SAFETY: this releases the caller's remaining reference.
        unsafe { SSL_SESSION_free(session) };
    }
}

// OB-3 obligation (b): execute every shared `CtxDestroy` body on an all-zero block.
#[cfg(test)]
crate::runtime::bio::zero_state::zero_state_sweep!(SslSession => zero_state_sweep_ssl_session);

/// Adversarial self-aliasing probes (`adv-probe.sh`, §16).
#[cfg(test)]
mod adv_probe {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::ssl::adv_alloc::{self, Ev};

    /// The duplicate must be allocated **before** the incumbent is released. On the old order the
    /// release precedes the allocation; with poison-on-free the duplicate then reads zeros.
    fn assert_duplicate_precedes_release(ev: &[Ev], released: usize) {
        let first_malloc = ev.iter().position(|e| matches!(e, Ev::Malloc { .. }));
        let release = ev
            .iter()
            .position(|e| matches!(e, Ev::Free { p } if *p == released));
        assert!(first_malloc.is_some(), "no allocation was observed: {ev:?}");
        assert!(release.is_some(), "the incumbent was not released: {ev:?}");
        assert!(
            first_malloc < release,
            "the copy must be allocated before the incumbent is released: {ev:?}"
        );
    }

    /// Each of the three setters must survive being handed the pointer its own getter answered.
    #[test]
    #[ignore = "requires OPENSSL_RS_ADV_PROBE=1; run scripts/adv-probe.sh (--ignored, one process per probe)"]
    fn self_aliasing_session_setters_copy_before_clearing() {
        let _g = crate::test_support::lock_global_state();
        adv_alloc::require_installed();
        adv_alloc::assert_instrument_live();

        // SAFETY: no arguments; the returned session is owned by this frame.
        let s = unsafe { SSL_SESSION_new() };
        assert!(!s.is_null(), "SSL_SESSION_new must succeed");

        // --- hostname -----------------------------------------------------------------------
        let name = c"example.test";
        // SAFETY: `s` is live and `name` is NUL-terminated.
        assert_eq!(unsafe { SSL_SESSION_set1_hostname(s, name.as_ptr()) }, 1);
        // SAFETY: `s` is live.
        let original = unsafe { SSL_SESSION_get0_hostname(s) };
        assert!(!original.is_null());
        adv_alloc::reset();
        adv_alloc::arm_poison_on_free();
        // SAFETY: `s` is live and `original` is NUL-terminated (it names the member itself).
        assert_eq!(unsafe { SSL_SESSION_set1_hostname(s, original) }, 1);
        adv_alloc::disarm_poison_on_free();
        // SAFETY: `s` is live.
        let after = unsafe { SSL_SESSION_get0_hostname(s) };
        assert!(!after.is_null());
        assert_eq!(
            // SAFETY: `after` is a live NUL-terminated member.
            unsafe { core::ffi::CStr::from_ptr(after) }.to_bytes(),
            b"example.test",
            "an aliasing hostname setter must preserve the value"
        );
        assert_duplicate_precedes_release(&adv_alloc::events(), original as usize);

        // --- ALPN ---------------------------------------------------------------------------
        let alpn = b"h2";
        assert_eq!(
            // SAFETY: `s` is live and `alpn` is readable for two bytes.
            unsafe { SSL_SESSION_set1_alpn_selected(s, alpn.as_ptr(), alpn.len()) },
            1
        );
        let mut original_ptr: *const u8 = core::ptr::null();
        let mut original_len = 0usize;
        // SAFETY: `s` is live and both out-params are writable.
        unsafe { SSL_SESSION_get0_alpn_selected(s, &mut original_ptr, &mut original_len) };
        assert!(!original_ptr.is_null());
        adv_alloc::reset();
        adv_alloc::arm_poison_on_free();
        assert_eq!(
            // SAFETY: `s` is live; `original_ptr` is readable for `original_len` bytes (it is the
            // member itself).
            unsafe { SSL_SESSION_set1_alpn_selected(s, original_ptr, original_len) },
            1
        );
        adv_alloc::disarm_poison_on_free();
        let mut after_ptr: *const u8 = core::ptr::null();
        let mut after_len = 0usize;
        // SAFETY: `s` is live and both out-params are writable.
        unsafe { SSL_SESSION_get0_alpn_selected(s, &mut after_ptr, &mut after_len) };
        assert!(!after_ptr.is_null());
        assert_eq!(
            // SAFETY: `after_ptr` is readable for `after_len` bytes.
            unsafe { core::slice::from_raw_parts(after_ptr, after_len) },
            alpn.as_slice(),
            "an aliasing ALPN setter must preserve the value"
        );
        assert_duplicate_precedes_release(&adv_alloc::events(), original_ptr as usize);

        // --- ticket application data --------------------------------------------------------
        let appdata = b"abcd";
        assert_eq!(
            // SAFETY: `s` is live and `appdata` is readable for four bytes.
            unsafe { SSL_SESSION_set1_ticket_appdata(s, appdata.as_ptr().cast(), appdata.len()) },
            1
        );
        let mut original_ptr: *mut c_void = core::ptr::null_mut();
        let mut original_len = 0usize;
        assert_eq!(
            // SAFETY: `s` is live and both out-params are writable.
            unsafe { SSL_SESSION_get0_ticket_appdata(s, &mut original_ptr, &mut original_len) },
            1
        );
        assert!(!original_ptr.is_null());
        adv_alloc::reset();
        adv_alloc::arm_poison_on_free();
        assert_eq!(
            // SAFETY: `s` is live; `original_ptr` is readable for `original_len` bytes (it is the
            // member itself).
            unsafe { SSL_SESSION_set1_ticket_appdata(s, original_ptr, original_len) },
            1
        );
        adv_alloc::disarm_poison_on_free();
        let mut after_ptr: *mut c_void = core::ptr::null_mut();
        let mut after_len = 0usize;
        assert_eq!(
            // SAFETY: `s` is live and both out-params are writable.
            unsafe { SSL_SESSION_get0_ticket_appdata(s, &mut after_ptr, &mut after_len) },
            1
        );
        assert!(!after_ptr.is_null());
        assert_eq!(
            // SAFETY: `after_ptr` is readable for `after_len` bytes.
            unsafe { core::slice::from_raw_parts(after_ptr.cast::<u8>(), after_len) },
            appdata.as_slice(),
            "an aliasing ticket-appdata setter must preserve the value"
        );
        assert_duplicate_precedes_release(&adv_alloc::events(), original_ptr as usize);

        // SAFETY: `s` is live and this releases this frame's reference.
        unsafe { SSL_SESSION_free(s) };
        adv_alloc::assert_no_double_free();
    }
}

// -------------------------------------------------------------------------------------------
// §16 control: overlapping session-id sources
// -------------------------------------------------------------------------------------------
//
// The setter contracts require only that the source be readable for the given length. A pointer
// into the destination array itself satisfies that, so the copy must have memmove semantics; the
// authority's `memcpy` is undefined for a partial overlap (AGENTS §17).
#[cfg(test)]
mod session_id_alias_tests {
    use super::*;

    #[test]
    fn partially_overlapping_session_id_and_context_sources_are_copied_safely() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: no arguments; the returned session is owned by this frame.
        let s = unsafe { SSL_SESSION_new() };
        assert!(!s.is_null(), "SSL_SESSION_new must succeed");

        // SAFETY: `s` is live; each source is readable for the stated length.
        unsafe {
            let id = [1u8, 2, 3, 4, 5, 6, 7, 8];
            assert_eq!(SSL_SESSION_set1_id(s, id.as_ptr(), id.len() as c_uint), 1);
            // Source starts one byte into the destination: the seven copied bytes shift left.
            let overlap = (*s).session_id.as_ptr().add(1);
            assert_eq!(SSL_SESSION_set1_id(s, overlap, 7), 1);
            assert_eq!(
                &(&(*s).session_id)[..8],
                &[2, 3, 4, 5, 6, 7, 8, 8],
                "a partially overlapping id source must be copied with memmove semantics"
            );

            let ctx = [9u8, 10, 11, 12, 13];
            assert_eq!(
                SSL_SESSION_set1_id_context(s, ctx.as_ptr(), ctx.len() as c_uint),
                1
            );
            let overlap = (*s).sid_ctx.as_ptr().add(1);
            assert_eq!(SSL_SESSION_set1_id_context(s, overlap, 4), 1);
            assert_eq!(
                &(&(*s).sid_ctx)[..4],
                &[10, 11, 12, 13],
                "a partially overlapping id-context source must be copied safely"
            );

            SSL_SESSION_free(s);
        }
    }
}

/// NULL-input safety for the whole accessor family. The authority dereferences NULL in most of
/// these (`ssl_sess.c`), which is undefined behaviour; every accessor here instead answers a
/// neutral value. This is the shape sslscan 2.1.5 reached: `SSL_get_session` answered NULL and
/// `SSL_SESSION_get_compress_id` faulted on it.
#[cfg(test)]
mod null_accessor_tests {
    #![allow(clippy::panic)]

    use super::*;

    #[test]
    fn every_session_accessor_answers_a_neutral_value_for_null() {
        let _g = crate::test_support::lock_global_state();
        let n: *const SslSession = core::ptr::null();
        let m: *mut SslSession = core::ptr::null_mut();
        // SAFETY: every call passes a NULL session, which each accessor now accepts; all
        // out-parameters are this frame's own variables.
        unsafe {
            assert_eq!(SSL_SESSION_get_compress_id(n), 0);
            assert_eq!(SSL_SESSION_get_protocol_version(n), 0);
            assert_eq!(SSL_SESSION_get_max_early_data(n), 0);
            assert_eq!(SSL_SESSION_get_ticket_lifetime_hint(n), 0);
            assert_eq!(SSL_SESSION_has_ticket(n), 0);
            assert_eq!(SSL_SESSION_is_resumable(n), 0);
            assert_eq!(SSL_SESSION_get_time(n), 0);
            assert_eq!(SSL_SESSION_get_time_ex(n), 0);
            assert_eq!(SSL_SESSION_get_timeout(n), 0);
            assert!(SSL_SESSION_get0_cipher(n).is_null());
            assert!(SSL_SESSION_get0_hostname(n).is_null());
            assert!(SSL_SESSION_get0_peer(m).is_null());
            assert!(SSL_SESSION_get0_peer_rpk(m).is_null());
            assert!(SSL_SESSION_get_ex_data(n, 0).is_null());

            let mut len = 7u32;
            assert!(SSL_SESSION_get_id(n, &mut len).is_null());
            assert_eq!(len, 0);
            len = 7;
            assert!(SSL_SESSION_get0_id_context(n, &mut len).is_null());
            assert_eq!(len, 0);

            let mut tick: *const u8 = core::ptr::NonNull::dangling().as_ptr();
            let mut tick_len = 7usize;
            SSL_SESSION_get0_ticket(n, &mut tick, &mut tick_len);
            assert!(tick.is_null());
            assert_eq!(tick_len, 0);

            let mut alpn: *const u8 = core::ptr::NonNull::dangling().as_ptr();
            let mut alpn_len = 7usize;
            SSL_SESSION_get0_alpn_selected(n, &mut alpn, &mut alpn_len);
            assert!(alpn.is_null());
            assert_eq!(alpn_len, 0);

            let mut appdata: *mut c_void = core::ptr::NonNull::dangling().as_ptr();
            let mut appdata_len = 7usize;
            assert_eq!(
                SSL_SESSION_get0_ticket_appdata(m, &mut appdata, &mut appdata_len),
                0
            );
            assert!(appdata.is_null());
            assert_eq!(appdata_len, 0);

            assert_eq!(SSL_SESSION_set_protocol_version(m, 0x0304), 0);
            assert_eq!(SSL_SESSION_set_max_early_data(m, 1), 0);
            assert_eq!(SSL_SESSION_set_cipher(m, core::ptr::null()), 0);
            assert_eq!(SSL_SESSION_set1_hostname(m, core::ptr::null()), 0);
            assert_eq!(SSL_SESSION_set1_id(m, core::ptr::null(), 0), 0);
            assert_eq!(SSL_SESSION_set1_id_context(m, core::ptr::null(), 0), 0);
            assert_eq!(SSL_SESSION_set1_alpn_selected(m, core::ptr::null(), 0), 0);
            assert_eq!(SSL_SESSION_set1_ticket_appdata(m, core::ptr::null(), 0), 0);
            assert_eq!(SSL_SESSION_set_time_ex(m, 0), 0);
            assert_eq!(SSL_SESSION_set_timeout(m, 1), 0);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// S30 — session-cache lifecycle
// ---------------------------------------------------------------------------------------------
//
// Bounded, deterministic controls for the ownership model: growth past the configured limit,
// expiration, re-entrant removal callbacks, address-identified single release, the
// automatic-flush trigger, and end-to-end TLS1.2 resumption with `SSL_OP_NO_TICKET`.
#[cfg(test)]
mod cache_lifecycle_tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::evp::legacy_sha::EVP_sha256;
    use crate::evp::pkey::{openssl_rs_evp_pkey_q_keygen, EVP_PKEY_free, EvpPkey};
    use crate::runtime::bio::{bss_mem::BIO_s_mem, BIO_new, BIO_read, BIO_write, Bio};
    use crate::runtime::ex_data::{CRYPTO_get_ex_new_index, CryptoExData};
    use crate::ssl::methods::TLS_method;
    use crate::ssl::ssl_ciph_table::SSL_OP_NO_TICKET;
    use crate::ssl::ssl_lib::{
        SSL_CTX_ctrl, SSL_CTX_free, SSL_CTX_new, SSL_CTX_set_cipher_list, SSL_CTX_set_options,
        SSL_CTX_set_verify, SSL_do_handshake, SSL_free, SSL_new, SSL_session_reused,
        SSL_set_accept_state, SSL_set_bio, SSL_set_connect_state,
    };
    use crate::ssl::ssl_rsa::{SSL_CTX_use_PrivateKey, SSL_CTX_use_certificate};
    use crate::x509::x509_set::{
        X509_set_issuer_name, X509_set_pubkey, X509_set_subject_name, X509_set_version,
    };
    use crate::x509::x509_vfy::X509_gmtime_adj;
    use crate::x509::x509name::X509_NAME_add_entry_by_txt;
    use crate::x509::x_all::X509_sign;
    use crate::x509::x_name::{X509_NAME_free, X509_NAME_new};
    use crate::x509::x_x509::{X509_free, X509_new, X509};
    use core::sync::atomic::AtomicUsize;

    const TLS1_2_VERSION_CODE: c_int = 0x0303;
    const SSL_CTRL_SET_SESS_CACHE_SIZE: c_int = 42;
    const SSL_CTRL_SESS_NUMBER: c_int = 20;
    const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
    const SSL_CTRL_SET_MAX_PROTO_VERSION: c_int = 124;
    const DEFAULT_CACHE_SIZE: c_long = 1024 * 20;

    // --- shared helpers ---------------------------------------------------------------------

    fn cache_len(ctx: *mut SslCtx) -> c_int {
        // SAFETY: `ctx` is live in every caller; a NULL cache reads as empty.
        unsafe {
            if (*ctx).sessions.is_null() {
                0
            } else {
                OPENSSL_sk_num((*ctx).sessions)
            }
        }
    }

    fn session_refs(session: *const SslSession) -> i32 {
        // SAFETY: `session` is live in every caller.
        unsafe { (*session).references.load(Ordering::Relaxed) }
    }

    /// A fresh TLS1.2 session carrying `id`, owned by the caller.
    fn new_session(id: &[u8]) -> *mut SslSession {
        assert!(id.len() <= SSL_MAX_SSL_SESSION_ID_LENGTH);
        // SAFETY: no arguments; the returned session is owned here.
        let session = unsafe { SSL_SESSION_new() };
        assert!(!session.is_null(), "SSL_SESSION_new must succeed");
        // SAFETY: `session` is live and owned here.
        unsafe {
            (*session).ssl_version = TLS1_2_VERSION_CODE;
            (*session).session_id_length = id.len();
            (&mut (*session).session_id)[..id.len()].copy_from_slice(id);
        }
        session
    }

    /// Whether an entry with `id` is in the context's cache. Uses the same key-only probe as
    /// `lookup_sess_in_cache`, so nothing is inserted or released.
    fn cache_has(ctx: *mut SslCtx, id: &[u8]) -> bool {
        let key = SessionKey::from_id(TLS1_2_VERSION_CODE, id);
        // SAFETY: `ctx` is live in every caller.
        unsafe { !cache_find(ctx, &key).is_null() }
    }

    // --- growth past the configured limit ---------------------------------------------------

    static EVICT_CALLS: AtomicUsize = AtomicUsize::new(0);
    static EVICT_LAST: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_eviction(_ctx: *mut SslCtx, session: *mut SslSession) {
        EVICT_CALLS.fetch_add(1, Ordering::Relaxed);
        EVICT_LAST.store(session as usize, Ordering::Relaxed);
    }

    #[test]
    fn ssl_sess_growth_past_limit_evicts_the_oldest_entry() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object below is created, used and released in this frame.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            assert_eq!(
                SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_SIZE, 2, ptr::null_mut()),
                DEFAULT_CACHE_SIZE
            );

            let a = new_session(b"aaaa");
            let b = new_session(b"bbbb");
            let c = new_session(b"cccc");
            assert_eq!(SSL_CTX_add_session(ctx, a), 1);
            assert_eq!(SSL_CTX_add_session(ctx, b), 1);
            assert_eq!(cache_len(ctx), 2);
            assert!(cache_has(ctx, b"aaaa") && cache_has(ctx, b"bbbb"));

            EVICT_CALLS.store(0, Ordering::Relaxed);
            EVICT_LAST.store(0, Ordering::Relaxed);
            SSL_CTX_sess_set_remove_cb(ctx, Some(record_eviction));
            assert_eq!(SSL_CTX_add_session(ctx, c), 1);

            assert_eq!(
                cache_len(ctx),
                2,
                "the cache must stay at its configured size"
            );
            assert!(!cache_has(ctx, b"aaaa"), "the oldest entry must be evicted");
            assert!(cache_has(ctx, b"bbbb") && cache_has(ctx, b"cccc"));
            assert_eq!(EVICT_CALLS.load(Ordering::Relaxed), 1);
            assert_eq!(EVICT_LAST.load(Ordering::Relaxed), a as usize);
            assert_eq!(session_refs(a), 1, "only the caller's reference remains");
            assert_eq!((*a).owner, ptr::null_mut());
            assert_eq!((*ctx).stats.sess_cache_full.load(Ordering::Relaxed), 1);
            assert_eq!(
                SSL_CTX_ctrl(ctx, SSL_CTRL_SESS_NUMBER, 0, ptr::null_mut()),
                2
            );

            SSL_SESSION_free(a);
            SSL_SESSION_free(b);
            SSL_SESSION_free(c);
            SSL_CTX_free(ctx);
        }
    }

    // --- expiration -------------------------------------------------------------------------

    #[test]
    fn ssl_sess_expiration_removes_the_session_and_lookup_misses() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object below is created, used and released in this frame.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            let s = new_session(b"exp1");
            (*s).time = 1;
            (*s).timeout = 1;
            ssl_session_calculate_timeout(s);
            assert_eq!(SSL_CTX_add_session(ctx, s), 1);
            assert_eq!(cache_len(ctx), 1);

            // The authority compares signed time values: a negative cutoff expires nothing.
            SSL_CTX_flush_sessions_ex(ctx, -1);
            assert_eq!(
                cache_len(ctx),
                1,
                "a negative cutoff must not expire sessions"
            );

            EVICT_CALLS.store(0, Ordering::Relaxed);
            EVICT_LAST.store(0, Ordering::Relaxed);
            SSL_CTX_sess_set_remove_cb(ctx, Some(record_eviction));
            SSL_CTX_flush_sessions_ex(ctx, time_now_secs() as i64);

            assert_eq!(cache_len(ctx), 0);
            assert_eq!(EVICT_CALLS.load(Ordering::Relaxed), 1);
            assert_eq!(EVICT_LAST.load(Ordering::Relaxed), s as usize);
            assert_eq!(session_refs(s), 1);
            assert!((*s).owner.is_null());

            // A subsequent lookup by the same id misses.
            let ssl = SSL_new(ctx);
            assert!(!ssl.is_null());
            (*ssl).version = TLS1_2_VERSION_CODE;
            let miss = lookup_sess_in_cache(ssl, b"exp1");
            assert!(miss.is_none(), "a flushed session must not be found");
            assert_eq!((*ctx).stats.sess_miss.load(Ordering::Relaxed), 1);

            SSL_free(ssl);
            SSL_SESSION_free(s);
            SSL_CTX_free(ctx);
        }
    }

    // --- a removal callback that re-enters the cache -----------------------------------------

    static CB_CALLS: AtomicUsize = AtomicUsize::new(0);
    static CB_LOCK_FREE: AtomicUsize = AtomicUsize::new(0);
    static CB_ADD_RESULT: AtomicI32 = AtomicI32::new(-1);
    static CB_REMOVE_RESULT: AtomicI32 = AtomicI32::new(-1);
    static CB_NEW: AtomicUsize = AtomicUsize::new(0);
    static CB_REMOVE: AtomicUsize = AtomicUsize::new(0);
    static CB_CTX: AtomicUsize = AtomicUsize::new(0);

    /// True when this thread can take and release `ctx`'s write lock, i.e. no cache lock is held
    /// by the caller. This is the detector the canary below exercises.
    fn cache_lock_is_free(ctx: *mut SslCtx) -> bool {
        // SAFETY: `ctx` is live in every caller and this thread does not already hold the lock in
        // the fixed flow; if it does, `CRYPTO_THREAD_write_lock` reports it instead of deadlocking.
        unsafe {
            if CRYPTO_THREAD_write_lock((*ctx).lock) == 0 {
                false
            } else {
                CRYPTO_THREAD_unlock((*ctx).lock);
                true
            }
        }
    }

    unsafe extern "C" fn reenter_on_remove(ctx: *mut SslCtx, _session: *mut SslSession) {
        let call = CB_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
        CB_CTX.store(ctx as usize, Ordering::Relaxed);
        if cache_lock_is_free(ctx) {
            CB_LOCK_FREE.fetch_add(1, Ordering::Relaxed);
        }
        // Only the outermost invocation re-enters, so the nested eviction this insert causes
        // cannot recurse without bound.
        if call == 1 {
            let remove = CB_REMOVE.load(Ordering::Relaxed) as *mut SslSession;
            if !remove.is_null() {
                // SAFETY: `remove` is a live session owned by the test and `ctx` is the live
                // context the authority passes to a removal callback.
                let removed = unsafe { SSL_CTX_remove_session(ctx, remove) };
                CB_REMOVE_RESULT.store(removed, Ordering::Relaxed);
            }
            let new = CB_NEW.load(Ordering::Relaxed) as *mut SslSession;
            if !new.is_null() {
                // SAFETY: `new` is a live session owned by the test and `ctx` is the live context
                // the authority passes to a removal callback.
                let added = unsafe { SSL_CTX_add_session(ctx, new) };
                CB_ADD_RESULT.store(added, Ordering::Relaxed);
            }
        }
    }

    #[test]
    fn ssl_sess_remove_callback_reentrant_insert_does_not_corrupt_the_cache() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object below is created, used and released in this frame.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            assert_eq!(
                SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_SIZE, 2, ptr::null_mut()),
                DEFAULT_CACHE_SIZE
            );
            let a = new_session(b"r001");
            let b = new_session(b"r002");
            let c = new_session(b"r003");
            let fresh = new_session(b"r004");

            CB_CALLS.store(0, Ordering::Relaxed);
            CB_LOCK_FREE.store(0, Ordering::Relaxed);
            CB_ADD_RESULT.store(-1, Ordering::Relaxed);
            CB_REMOVE_RESULT.store(-1, Ordering::Relaxed);
            CB_CTX.store(0, Ordering::Relaxed);
            CB_NEW.store(fresh as usize, Ordering::Relaxed);
            CB_REMOVE.store(0, Ordering::Relaxed);
            SSL_CTX_sess_set_remove_cb(ctx, Some(reenter_on_remove));

            assert_eq!(SSL_CTX_add_session(ctx, a), 1);
            assert_eq!(SSL_CTX_add_session(ctx, b), 1);
            // Evicts `a`; the callback inserts `fresh`, which evicts `b`.
            assert_eq!(SSL_CTX_add_session(ctx, c), 1);

            let calls = CB_CALLS.load(Ordering::Relaxed);
            assert!(
                calls >= 2,
                "expected the eviction chain, saw {calls} callbacks"
            );
            assert_eq!(
                CB_ADD_RESULT.load(Ordering::Relaxed),
                1,
                "the callback's insert must succeed"
            );
            assert_eq!(
                CB_LOCK_FREE.load(Ordering::Relaxed),
                calls,
                "no removal callback may run under the cache lock"
            );
            assert_eq!(CB_CTX.load(Ordering::Relaxed), ctx as usize);

            assert_eq!(cache_len(ctx), 2);
            assert!(cache_has(ctx, b"r003") && cache_has(ctx, b"r004"));
            assert!(!cache_has(ctx, b"r001") && !cache_has(ctx, b"r002"));
            assert_eq!((*a).owner, ptr::null_mut());
            assert_eq!((*b).owner, ptr::null_mut());
            assert_eq!((*fresh).owner, ctx);
            assert_eq!(session_refs(a), 1);
            assert_eq!(session_refs(b), 1);
            assert_eq!(
                session_refs(fresh),
                2,
                "the frame's reference and the cache's"
            );

            CB_NEW.store(0, Ordering::Relaxed);
            SSL_SESSION_free(a);
            SSL_SESSION_free(b);
            SSL_SESSION_free(c);
            SSL_SESSION_free(fresh);
            SSL_CTX_free(ctx);
        }
    }

    /// A removal callback that re-enters with `SSL_CTX_remove_session` and then with
    /// `SSL_CTX_add_session`: both mutations must succeed and leave a consistent cache.
    #[test]
    fn ssl_sess_remove_callback_reentrant_remove_does_not_corrupt_the_cache() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object below is created, used and released in this frame.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            assert_eq!(
                SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_SIZE, 2, ptr::null_mut()),
                DEFAULT_CACHE_SIZE
            );
            let a = new_session(b"x001");
            let b = new_session(b"x002");
            let c = new_session(b"x003");
            let fresh = new_session(b"x004");

            CB_CALLS.store(0, Ordering::Relaxed);
            CB_LOCK_FREE.store(0, Ordering::Relaxed);
            CB_ADD_RESULT.store(-1, Ordering::Relaxed);
            CB_REMOVE_RESULT.store(-1, Ordering::Relaxed);
            CB_CTX.store(0, Ordering::Relaxed);
            CB_NEW.store(fresh as usize, Ordering::Relaxed);
            CB_REMOVE.store(b as usize, Ordering::Relaxed);
            SSL_CTX_sess_set_remove_cb(ctx, Some(reenter_on_remove));

            assert_eq!(SSL_CTX_add_session(ctx, a), 1);
            assert_eq!(SSL_CTX_add_session(ctx, b), 1);
            // Evicts `a`; the callback removes `b` and inserts `fresh`.
            assert_eq!(SSL_CTX_add_session(ctx, c), 1);

            let calls = CB_CALLS.load(Ordering::Relaxed);
            assert_eq!(calls, 2, "the eviction and the callback's own removal");
            assert_eq!(
                CB_REMOVE_RESULT.load(Ordering::Relaxed),
                1,
                "the callback's remove must succeed"
            );
            assert_eq!(
                CB_ADD_RESULT.load(Ordering::Relaxed),
                1,
                "the callback's insert must succeed"
            );
            assert_eq!(
                CB_LOCK_FREE.load(Ordering::Relaxed),
                calls,
                "no removal callback may run under the cache lock"
            );
            assert_eq!(CB_CTX.load(Ordering::Relaxed), ctx as usize);

            assert_eq!(cache_len(ctx), 2);
            assert!(cache_has(ctx, b"x003") && cache_has(ctx, b"x004"));
            assert!(!cache_has(ctx, b"x001") && !cache_has(ctx, b"x002"));
            assert!((*a).owner.is_null() && (*b).owner.is_null());
            assert_eq!((*fresh).owner, ctx);
            assert_eq!(session_refs(a), 1);
            assert_eq!(session_refs(b), 1);
            assert_eq!(session_refs(fresh), 2);

            CB_NEW.store(0, Ordering::Relaxed);
            CB_REMOVE.store(0, Ordering::Relaxed);
            SSL_SESSION_free(a);
            SSL_SESSION_free(b);
            SSL_SESSION_free(c);
            SSL_SESSION_free(fresh);
            SSL_CTX_free(ctx);
        }
    }

    /// Negative control (§16): the instrument used by the test above must report a held cache lock
    /// as "not free". The pre-fix code invoked `remove_session_cb` while holding `ctx->lock`; that
    /// is exactly the state this canary constructs.
    #[test]
    fn ssl_sess_canary_detects_a_removal_callback_under_the_cache_lock() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: `ctx` is created and released here.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());

            // Simulate the pre-fix callback context: this thread holds the write lock.
            assert_eq!(CRYPTO_THREAD_write_lock((*ctx).lock), 1);
            let pre_fix = cache_lock_is_free(ctx);
            assert_eq!(CRYPTO_THREAD_unlock((*ctx).lock), 1);
            // The fixed flow runs the callback after unlocking.
            let fixed = cache_lock_is_free(ctx);

            println!(
                "ssl_sess canary: callback-under-lock probe = {pre_fix} (must be false), \
                 callback-after-unlock probe = {fixed} (must be true)"
            );
            assert!(
                !pre_fix,
                "the negative control must fire on the pre-fix callback-under-lock state"
            );
            assert!(fixed, "the fixed state must be observed as lock-free");

            SSL_CTX_free(ctx);
        }
    }

    // --- released exactly once, by address ---------------------------------------------------

    static RELEASED_TARGET: AtomicUsize = AtomicUsize::new(0);
    static RELEASED_COUNT: AtomicUsize = AtomicUsize::new(0);
    /// The ex-data index this probe owns. Each test registers its own index, but
    /// `CRYPTO_free_ex_data` calls **every** registered free function, so the probe must
    /// ignore the instances registered by the other tests.
    static RELEASED_INDEX: AtomicI32 = AtomicI32::new(-1);

    unsafe extern "C" fn record_release(
        obj: *mut c_void,
        _ptr: *mut c_void,
        _ad: *mut CryptoExData,
        idx: c_int,
        _argl: c_long,
        _argp: *mut c_void,
    ) {
        let target = RELEASED_TARGET.load(Ordering::Relaxed);
        if target != 0 && obj as usize == target && idx == RELEASED_INDEX.load(Ordering::Relaxed) {
            RELEASED_COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn ssl_sess_inserted_looked_up_and_removed_session_is_released_exactly_once() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object below is created, used and released in this frame.
        unsafe {
            let idx = CRYPTO_get_ex_new_index(
                CRYPTO_EX_INDEX_SSL_SESSION,
                0,
                ptr::null_mut(),
                None,
                None,
                Some(record_release),
            );
            assert!(idx > 0);
            RELEASED_INDEX.store(idx, Ordering::Relaxed);

            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            let s = new_session(b"once");
            assert_eq!(SSL_CTX_add_session(ctx, s), 1);
            assert_eq!(session_refs(s), 2, "caller plus cache");

            let ssl = SSL_new(ctx);
            assert!(!ssl.is_null());
            (*ssl).version = TLS1_2_VERSION_CODE;
            let got = lookup_sess_in_cache(ssl, b"once").expect("the cache lookup must hit");
            assert_eq!(
                got.as_ptr(),
                s,
                "the lookup must answer the cached object by address"
            );
            assert_eq!(session_refs(s), 3, "caller, cache and lookup");

            SSL_SESSION_free(s);
            assert_eq!(session_refs(got.as_ptr()), 2);
            assert_eq!(SSL_CTX_remove_session(ctx, got.as_ptr()), 1);
            assert_eq!(
                session_refs(got.as_ptr()),
                1,
                "removal drops only the cache's reference"
            );

            RELEASED_COUNT.store(0, Ordering::Relaxed);
            RELEASED_TARGET.store(got.as_ptr() as usize, Ordering::Relaxed);
            // Dropping the guard releases the lookup's reference: the last one.
            drop(got);
            assert_eq!(
                RELEASED_COUNT.load(Ordering::Relaxed),
                1,
                "the block at this address must be released exactly once"
            );
            RELEASED_TARGET.store(0, Ordering::Relaxed);

            SSL_free(ssl);
            SSL_CTX_free(ctx);
        }
    }

    // --- automatic flush --------------------------------------------------------------------

    #[test]
    fn ssl_sess_auto_flush_fires_on_the_authority_counter_value() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object below is created, used and released in this frame.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            assert_eq!(
                (*ctx).session_cache_mode & SSL_SESS_CACHE_SERVER,
                SSL_SESS_CACHE_SERVER
            );
            let old = new_session(b"old!");
            (*old).time = 1;
            (*old).timeout = 1;
            ssl_session_calculate_timeout(old);
            assert_eq!(SSL_CTX_add_session(ctx, old), 1);

            let ssl = SSL_new(ctx);
            assert!(!ssl.is_null());
            (*ssl).version = TLS1_2_VERSION_CODE;
            (*ssl).server = 1;
            (*ssl).hit = 0;
            (*ssl).verify_mode = 0;
            // The connection owns this reference; `SSL_free` releases it.
            let current = new_session(b"cur!");
            (*ssl).session = current;

            (*ctx).stats.sess_accept_good.store(0xfe, Ordering::Relaxed);
            ssl_update_cache(ssl, SSL_SESS_CACHE_SERVER);
            assert_eq!(cache_len(ctx), 2, "0xfe must not trigger the flush");
            assert_eq!((*old).owner, ctx, "the expired entry is still cached");

            (*ctx).stats.sess_accept_good.store(0xff, Ordering::Relaxed);
            ssl_update_cache(ssl, SSL_SESS_CACHE_SERVER);
            assert_eq!(cache_len(ctx), 1, "only the current session remains");
            assert!((*old).owner.is_null(), "the expired entry must be flushed");
            assert!(cache_has(ctx, b"cur!"));
            assert!(!cache_has(ctx, b"old!"));
            assert_eq!(
                (*ctx).stats.sess_accept_good.load(Ordering::Relaxed),
                0xff,
                "ssl_update_cache must not increment the counter"
            );

            SSL_free(ssl);
            SSL_CTX_free(ctx);
            SSL_SESSION_free(old);
        }
    }

    // --- S57: the reference guard, a reentrant/refusing new_session_cb, and replacement --------

    static NEW_CB_CALLS: AtomicUsize = AtomicUsize::new(0);
    static NEW_CB_LOCK_FREE: AtomicUsize = AtomicUsize::new(0);
    static NEW_CB_ACCEPTED: AtomicUsize = AtomicUsize::new(0);
    static NEW_CB_RESULT: AtomicI32 = AtomicI32::new(1);
    static NEW_CB_ADD_TARGET: AtomicUsize = AtomicUsize::new(0);
    static NEW_CB_ADD_RESULT: AtomicI32 = AtomicI32::new(-1);

    fn reset_new_cb(result: c_int, add_target: *mut SslSession) {
        NEW_CB_CALLS.store(0, Ordering::Relaxed);
        NEW_CB_LOCK_FREE.store(0, Ordering::Relaxed);
        NEW_CB_ACCEPTED.store(0, Ordering::Relaxed);
        NEW_CB_RESULT.store(result, Ordering::Relaxed);
        NEW_CB_ADD_TARGET.store(add_target as usize, Ordering::Relaxed);
        NEW_CB_ADD_RESULT.store(-1, Ordering::Relaxed);
    }

    /// A `new_session_cb` that can re-enter the cache, accept or refuse the reference it is
    /// offered, and reports whether it observed the cache lock as free.
    unsafe extern "C" fn reenter_on_new(ssl: *mut Ssl, session: *mut SslSession) -> c_int {
        NEW_CB_CALLS.fetch_add(1, Ordering::Relaxed);
        let ctx = if ssl.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: `ssl` is live per the callback's contract.
            unsafe { (*ssl).session_ctx }
        };
        if !ctx.is_null() && cache_lock_is_free(ctx) {
            NEW_CB_LOCK_FREE.fetch_add(1, Ordering::Relaxed);
        }
        let target = NEW_CB_ADD_TARGET.load(Ordering::Relaxed) as *mut SslSession;
        if !target.is_null() && !ctx.is_null() {
            // SAFETY: `target` is a live test-owned session and `ctx` is the callback's context.
            let added = unsafe { SSL_CTX_add_session(ctx, target) };
            NEW_CB_ADD_RESULT.store(added, Ordering::Relaxed);
        }
        let result = NEW_CB_RESULT.load(Ordering::Relaxed);
        if result != 0 {
            // The caller transfers its extra reference to an accepting callback, which owns it.
            NEW_CB_ACCEPTED.fetch_add(1, Ordering::Relaxed);
            // SAFETY: `session` is live and this callback owns the reference just transferred.
            unsafe { SSL_SESSION_free(session) };
        }
        result
    }

    /// A server connection holding `session`, ready for `ssl_update_cache`.
    fn server_conn(ctx: *mut SslCtx, session: *mut SslSession) -> *mut Ssl {
        // SAFETY: `ctx` is live in every caller; the returned connection is owned here.
        unsafe {
            let ssl = SSL_new(ctx);
            assert!(!ssl.is_null());
            (*ssl).server = 1;
            (*ssl).hit = 0;
            (*ssl).verify_mode = 0;
            (*ssl).session = session;
            ssl
        }
    }

    /// A reentrant `new_session_cb` must run outside the cache lock and be able to mutate the
    /// cache (the S30 fix covered `remove_session_cb` only).
    #[test]
    fn ssl_sess_reentrant_new_session_cb_mutates_an_unlocked_cache() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object below is created, used and released in this frame.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            let current = new_session(b"n001");
            let other = new_session(b"n002");
            let ssl = server_conn(ctx, current);

            reset_new_cb(1, other);
            SSL_CTX_sess_set_new_cb(ctx, Some(reenter_on_new));
            ssl_update_cache(ssl, SSL_SESS_CACHE_SERVER);

            assert_eq!(NEW_CB_CALLS.load(Ordering::Relaxed), 1);
            assert_eq!(
                NEW_CB_LOCK_FREE.load(Ordering::Relaxed),
                1,
                "new_session_cb must run outside the cache lock"
            );
            assert_eq!(
                NEW_CB_ADD_RESULT.load(Ordering::Relaxed),
                1,
                "the callback's re-entrant add must succeed"
            );
            assert_eq!(NEW_CB_ACCEPTED.load(Ordering::Relaxed), 1);
            assert_eq!(cache_len(ctx), 2);
            assert!(cache_has(ctx, b"n001") && cache_has(ctx, b"n002"));
            assert_eq!(session_refs(current), 2, "connection and cache");
            assert_eq!(session_refs(other), 2, "test and cache");

            SSL_CTX_sess_set_new_cb(ctx, None);
            reset_new_cb(1, ptr::null_mut());
            SSL_free(ssl);
            SSL_SESSION_free(other);
            SSL_CTX_free(ctx);
        }
    }

    /// A `new_session_cb` that refuses (returns 0) must neither insert nor remove, and the extra
    /// reference offered to it must be released exactly once (refs stay at connection + cache).
    #[test]
    fn ssl_sess_refusing_new_session_cb_leaves_the_cache_unchanged() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object below is created, used and released in this frame.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            let current = new_session(b"n003");
            let ssl = server_conn(ctx, current);

            reset_new_cb(0, ptr::null_mut());
            SSL_CTX_sess_set_new_cb(ctx, Some(reenter_on_new));
            ssl_update_cache(ssl, SSL_SESS_CACHE_SERVER);

            assert_eq!(NEW_CB_CALLS.load(Ordering::Relaxed), 1);
            assert_eq!(NEW_CB_LOCK_FREE.load(Ordering::Relaxed), 1);
            assert_eq!(
                NEW_CB_ACCEPTED.load(Ordering::Relaxed),
                0,
                "a refusing callback must not take the reference"
            );
            assert_eq!(
                cache_len(ctx),
                1,
                "the refused callback must not change the cache"
            );
            assert!(cache_has(ctx, b"n003"));
            assert_eq!((*current).owner, ctx);
            assert_eq!(
                session_refs(current),
                2,
                "connection and cache; the refused extra was released exactly once"
            );

            SSL_CTX_sess_set_new_cb(ctx, None);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
        }
    }

    /// A lookup reference held while the cached entry is replaced by a different object under the
    /// same key must remain a valid, independently owned session.
    #[test]
    fn ssl_sess_lookup_reference_survives_cache_replacement() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object below is created, used and released in this frame.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            let first = new_session(b"same");
            assert_eq!(SSL_CTX_add_session(ctx, first), 1);
            let ssl = SSL_new(ctx);
            assert!(!ssl.is_null());
            (*ssl).version = TLS1_2_VERSION_CODE;

            // The lookup is in flight: this guard is the connection's reference while the
            // cache's entry is replaced.
            let held = lookup_sess_in_cache(ssl, b"same").expect("the cache lookup must hit");
            assert_eq!(held.as_ptr(), first);
            assert_eq!(session_refs(first), 3, "test, cache and lookup");

            let replacement = new_session(b"same");
            assert_eq!(SSL_CTX_add_session(ctx, replacement), 1);

            assert_eq!(session_refs(first), 2, "test and lookup");
            assert!((*first).owner.is_null());
            let key = SessionKey::from_id(TLS1_2_VERSION_CODE, b"same");
            assert_eq!(cache_find(ctx, &key), replacement);
            // The in-flight object is still usable at its own address.
            assert_eq!((*held.as_ptr()).session_id_length, 4);
            assert_eq!(&(&(*held.as_ptr()).session_id)[..4], b"same");

            drop(held);
            assert_eq!(session_refs(first), 1);
            SSL_SESSION_free(first);
            SSL_SESSION_free(replacement);
            SSL_CTX_free(ctx);
            SSL_free(ssl);
        }
    }

    /// The reference acquired before the write lock can refuse it must be released exactly once.
    /// The address-identity destructor probe proves no extra reference leaked.
    #[test]
    fn ssl_sess_refused_add_releases_the_partially_acquired_reference_once() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object below is created, used and released in this frame.
        unsafe {
            let idx = CRYPTO_get_ex_new_index(
                CRYPTO_EX_INDEX_SSL_SESSION,
                0,
                ptr::null_mut(),
                None,
                None,
                Some(record_release),
            );
            assert!(idx > 0);
            RELEASED_INDEX.store(idx, Ordering::Relaxed);

            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            let s = new_session(b"rf01");

            // The reference is acquired before the write lock can refuse it: this thread already
            // holds the non-recursive lock, which the crate reports as failure.
            assert_eq!(CRYPTO_THREAD_write_lock((*ctx).lock), 1);
            let ret = SSL_CTX_add_session(ctx, s);
            assert_eq!(CRYPTO_THREAD_unlock((*ctx).lock), 1);

            assert_eq!(ret, 0, "the refused lock must refuse the insert");
            assert_eq!(
                session_refs(s),
                1,
                "the partially acquired reference was released"
            );
            assert_eq!(cache_len(ctx), 0);
            assert!((*s).owner.is_null());

            RELEASED_COUNT.store(0, Ordering::Relaxed);
            RELEASED_TARGET.store(s as usize, Ordering::Relaxed);
            SSL_SESSION_free(s);
            assert_eq!(
                RELEASED_COUNT.load(Ordering::Relaxed),
                1,
                "no extra reference may leak: the block is released exactly once"
            );
            RELEASED_TARGET.store(0, Ordering::Relaxed);

            SSL_CTX_free(ctx);
        }
    }

    /// The scratch key is a key-only value, not a zero-initialised `SSL_SESSION`. It must compare
    /// exactly the authority's fields, truncate at the array width, and refuse an over-wide stored
    /// length instead of reading out of bounds.
    #[test]
    fn ssl_sess_lookup_uses_a_key_value_not_a_zeroed_session() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object below is created, used and released in this frame.
        unsafe {
            let ctx = SSL_CTX_new(TLS_method());
            assert!(!ctx.is_null());
            let a = new_session(b"key1");
            assert_eq!(SSL_CTX_add_session(ctx, a), 1);

            let key = SessionKey::from_id(TLS1_2_VERSION_CODE, b"key1");
            assert_eq!(cache_find(ctx, &key), a);
            assert!(cache_find(ctx, &SessionKey::from_id(TLS1_2_VERSION_CODE, b"key2")).is_null());
            assert!(
                cache_find(ctx, &SessionKey::from_id(TLS1_2_VERSION_CODE + 1, b"key1")).is_null(),
                "ssl_version is part of the key"
            );

            let overlong = [0x5au8; SSL_MAX_SSL_SESSION_ID_LENGTH + 7];
            let long_key = SessionKey::from_id(TLS1_2_VERSION_CODE, &overlong);
            assert_eq!(long_key.session_id_length, SSL_MAX_SSL_SESSION_ID_LENGTH);
            assert_eq!(
                &long_key.session_id[..],
                &overlong[..SSL_MAX_SSL_SESSION_ID_LENGTH]
            );
            assert!(key.matches(a));

            // A corrupt over-wide length is refused rather than read out of bounds (the
            // authority's `memcmp` would run past `session_id`; AGENTS §17).
            (*a).session_id_length = SSL_MAX_SSL_SESSION_ID_LENGTH + 1;
            assert!(!long_key.matches(a));
            (*a).session_id_length = 4;

            assert_eq!(
                SessionKey::from_id(TLS1_2_VERSION_CODE, b"").session_id_length,
                0,
                "an empty id is a length-0 key, as in the authority's comparator"
            );

            SSL_SESSION_free(a);
            SSL_CTX_free(ctx);
        }
    }

    /// Negative control (§16): the address-identity probe used above must detect the pre-fix
    /// behaviour — a partial acquisition whose refusal path returns without the matching release.
    #[test]
    fn ssl_sess_canary_detects_an_unreleased_partial_acquisition() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: `s` is created and released here; the second `SSL_SESSION_free` releases the
        // simulated extra reference, so nothing is leaked at the end of the test.
        unsafe {
            let idx = CRYPTO_get_ex_new_index(
                CRYPTO_EX_INDEX_SSL_SESSION,
                0,
                ptr::null_mut(),
                None,
                None,
                Some(record_release),
            );
            assert!(idx > 0);
            RELEASED_INDEX.store(idx, Ordering::Relaxed);
            let s = SSL_SESSION_new();
            assert!(!s.is_null());
            RELEASED_COUNT.store(0, Ordering::Relaxed);
            RELEASED_TARGET.store(s as usize, Ordering::Relaxed);

            // The pre-fix shape: acquire, then release only the caller's reference. The block
            // stays live, so the destructor probe must stay silent.
            assert_eq!(SSL_SESSION_up_ref(s), 1);
            assert_eq!(session_refs(s), 2);
            SSL_SESSION_free(s);
            let detected = RELEASED_COUNT.load(Ordering::Relaxed) == 0;
            println!(
                "ssl_sess canary: unreleased-partial-acquisition probe = {detected} (must be true); \
                 refs after releasing one of two = {} (must be 1)",
                session_refs(s)
            );
            assert!(
                detected,
                "the address-identity probe must detect the skipped release"
            );
            assert_eq!(session_refs(s), 1);

            // Clean up the simulated leaked reference; the probe fires exactly once.
            SSL_SESSION_free(s);
            assert_eq!(RELEASED_COUNT.load(Ordering::Relaxed), 1);
            RELEASED_TARGET.store(0, Ordering::Relaxed);
        }
    }

    // --- end-to-end TLS1.2 resumption with SSL_OP_NO_TICKET -----------------------------------

    struct HsPair {
        c: *mut Ssl,
        s: *mut Ssl,
        c_r: *mut Bio,
        c_w: *mut Bio,
        s_r: *mut Bio,
        s_w: *mut Bio,
    }

    /// A self-signed RSA identity for the server.
    ///
    /// # Safety
    /// The returned objects are owned by the caller.
    unsafe fn rsa_identity() -> (*mut EvpPkey, *mut X509) {
        use crate::asn1::layout::MBSTRING_UTF8;
        use crate::asn1::prim::ASN1_INTEGER_set;
        // SAFETY: constructors below answer fresh objects owned by this frame.
        unsafe {
            let pkey = openssl_rs_evp_pkey_q_keygen(
                ptr::null_mut(),
                ptr::null(),
                c"RSA".as_ptr(),
                1,
                2048,
                ptr::null(),
            );
            assert!(!pkey.is_null(), "an RSA key must be generatable");
            let x = X509_new();
            let name = X509_NAME_new();
            assert!(!x.is_null() && !name.is_null());
            assert_eq!(
                X509_NAME_add_entry_by_txt(
                    name,
                    c"CN".as_ptr(),
                    MBSTRING_UTF8,
                    c"ssl-sess.test".as_ptr().cast::<u8>(),
                    13,
                    -1,
                    0,
                ),
                1
            );
            assert_eq!(X509_set_version(x, 2), 1);
            assert_eq!(ASN1_INTEGER_set(&mut (*x).cert_info.serialNumber, 1), 1);
            assert_eq!(X509_set_subject_name(x, name), 1);
            assert_eq!(X509_set_issuer_name(x, name), 1);
            (*x).cert_info.validity.notBefore = X509_gmtime_adj(ptr::null_mut(), 0);
            (*x).cert_info.validity.notAfter = X509_gmtime_adj(ptr::null_mut(), 86_400);
            assert!(!(*x).cert_info.validity.notBefore.is_null());
            assert!(!(*x).cert_info.validity.notAfter.is_null());
            assert_eq!(X509_set_pubkey(x, pkey), 1);
            assert!(X509_sign(x, pkey, EVP_sha256()) > 0, "signing must succeed");
            X509_NAME_free(name);
            (pkey, x)
        }
    }

    /// # Safety
    /// `cctx`/`sctx` are live and outlive the returned pair.
    unsafe fn new_hs_pair(cctx: *mut SslCtx, sctx: *mut SslCtx) -> HsPair {
        // SAFETY: every constructor below answers a fresh object owned by this frame.
        unsafe {
            let c = SSL_new(cctx);
            let s = SSL_new(sctx);
            assert!(!c.is_null() && !s.is_null());
            SSL_set_connect_state(c);
            SSL_set_accept_state(s);
            let c_r = BIO_new(BIO_s_mem());
            let c_w = BIO_new(BIO_s_mem());
            let s_r = BIO_new(BIO_s_mem());
            let s_w = BIO_new(BIO_s_mem());
            assert!(!c_r.is_null() && !c_w.is_null() && !s_r.is_null() && !s_w.is_null());
            SSL_set_bio(c, c_r, c_w);
            SSL_set_bio(s, s_r, s_w);
            HsPair {
                c,
                s,
                c_r,
                c_w,
                s_r,
                s_w,
            }
        }
    }

    /// # Safety
    /// `from`/`to` are live memory BIOs.
    unsafe fn drain(from: *mut Bio, to: *mut Bio) {
        let mut buf = [0u8; 8192];
        loop {
            // SAFETY: `buf` is writable; `from` is live.
            let n = unsafe { BIO_read(from, buf.as_mut_ptr().cast(), buf.len() as c_int) };
            if n <= 0 {
                break;
            }
            // SAFETY: `buf[..n]` is readable; `to` is live.
            let w = unsafe { BIO_write(to, buf.as_ptr().cast(), n) };
            if w != n {
                break;
            }
        }
    }

    /// # Safety
    /// `p` is a live pair from [`new_hs_pair`].
    unsafe fn drive(p: &HsPair) -> (bool, bool) {
        let mut client_ok = false;
        let mut server_ok = false;
        for _ in 0..128 {
            // SAFETY: both connections are live for the duration of the pair.
            let client_ret = unsafe { SSL_do_handshake(p.c) };
            // SAFETY: both connections are live for the duration of the pair.
            let server_ret = unsafe { SSL_do_handshake(p.s) };
            client_ok |= client_ret == 1;
            server_ok |= server_ret == 1;
            // SAFETY: the four BIOs are live until `free_hs_pair`.
            unsafe {
                drain(p.c_w, p.s_r);
                drain(p.s_w, p.c_r);
            }
            if client_ok && server_ok {
                break;
            }
            // SAFETY: `p.s` is live.
            if unsafe { crate::ssl::statem::statem::ossl_statem_in_error(p.s) } != 0 {
                break;
            }
        }
        (client_ok, server_ok)
    }

    /// # Safety
    /// `p` is a live pair that has not been freed.
    unsafe fn free_hs_pair(p: HsPair) {
        // SAFETY: each connection owns its two BIOs.
        unsafe {
            SSL_free(p.c);
            SSL_free(p.s);
        }
    }

    #[test]
    fn ssl_sess_tls12_resumption_without_tickets_reuses_the_session_id() {
        let _g = crate::test_support::lock_global_state();
        // SAFETY: every object below is created, used and released in this frame.
        unsafe {
            let (pkey, cert) = rsa_identity();
            let cctx = SSL_CTX_new(TLS_method());
            let sctx = SSL_CTX_new(TLS_method());
            assert!(!cctx.is_null() && !sctx.is_null());
            for ctx in [cctx, sctx] {
                assert_eq!(
                    SSL_CTX_ctrl(
                        ctx,
                        SSL_CTRL_SET_MIN_PROTO_VERSION,
                        TLS1_2_VERSION_CODE as c_long,
                        ptr::null_mut()
                    ),
                    1
                );
                assert_eq!(
                    SSL_CTX_ctrl(
                        ctx,
                        SSL_CTRL_SET_MAX_PROTO_VERSION,
                        TLS1_2_VERSION_CODE as c_long,
                        ptr::null_mut()
                    ),
                    1
                );
                assert_eq!(
                    SSL_CTX_set_cipher_list(ctx, c"ECDHE-RSA-AES128-GCM-SHA256".as_ptr()),
                    1
                );
                assert!(SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET) & SSL_OP_NO_TICKET != 0);
            }
            SSL_CTX_set_verify(cctx, 0, None);
            assert_eq!(SSL_CTX_use_certificate(sctx, cert), 1);
            assert_eq!(SSL_CTX_use_PrivateKey(sctx, pkey), 1);
            EVP_PKEY_free(pkey);
            X509_free(cert);

            // Both connections of the first pair stay live until after the resumption: `SSL_free`
            // on a completed, un-shutdown connection calls `ssl_clear_bad_session`, which removes
            // its session from the context cache.
            let first = new_hs_pair(cctx, sctx);
            let (ok_c1, ok_s1) = drive(&first);
            assert!(
                ok_c1 && ok_s1,
                "the initial TLS1.2 handshake must complete (client={ok_c1}, server={ok_s1})"
            );
            let saved = SSL_get1_session(first.c);
            assert!(!saved.is_null());
            let mut id_len = 0u32;
            let id_ptr = SSL_SESSION_get_id(saved, &mut id_len);
            assert_eq!(
                id_len, 32,
                "a ticketless TLS1.2 session carries a full session id"
            );
            let first_id = core::slice::from_raw_parts(id_ptr, id_len as usize).to_vec();
            assert_eq!(
                SSL_SESSION_has_ticket(saved),
                0,
                "SSL_OP_NO_TICKET must suppress the ticket"
            );
            assert_eq!(
                SSL_CTX_ctrl(sctx, SSL_CTRL_SESS_NUMBER, 0, ptr::null_mut()),
                1,
                "the server must retain the session in its internal cache"
            );

            let second = new_hs_pair(cctx, sctx);
            assert_eq!(SSL_set_session(second.c, saved), 1);
            let (ok_c2, ok_s2) = drive(&second);
            assert!(
                ok_c2 && ok_s2,
                "the resumed TLS1.2 handshake must complete (client={ok_c2}, server={ok_s2})"
            );
            assert_eq!(SSL_session_reused(second.c), 1, "the client must resume");
            assert_eq!(
                SSL_session_reused(second.s),
                1,
                "the server must resume from its internal cache"
            );
            let resumed = SSL_get_session(second.c);
            assert!(!resumed.is_null());
            let mut rid_len = 0u32;
            let rid_ptr = SSL_SESSION_get_id(resumed, &mut rid_len);
            assert_eq!(rid_len, id_len);
            assert_eq!(
                core::slice::from_raw_parts(rid_ptr, rid_len as usize),
                first_id.as_slice(),
                "the resumed session must carry the same session id"
            );

            SSL_SESSION_free(saved);
            free_hs_pair(second);
            free_hs_pair(first);
            SSL_CTX_free(cctx);
            SSL_CTX_free(sctx);
        }
    }
}
