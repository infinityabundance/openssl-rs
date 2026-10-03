//! Phase 14.1 — `ssl/ssl_lib.c`: the `SSL_CTX`/`SSL` object model (Slice 1).
//!
//! The landing, its slice record and its measured divergences are documented in `src/ssl/mod.rs`.
//! This file is the code: the `SSL_CTX` and `SSL` structures, the allocation/free/refcount
//! lifecycles, the ex-data and security-attribute blocks, the option/mode/verify/quiet/shutdown
//! accessors and their control dispatch, the callback setters, the BIO plumbing, the version and
//! state readers, and the read/write/handshake entry guards.
//!
//! The structures are opaque to a consumer, so their field order is this crate's own rather than
//! the authority's; `#[repr(C)]` is kept because the pointers cross the FFI boundary.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::ffi::guard_ffi;
use crate::runtime::bio::bss_sock::BIO_s_socket;
use crate::runtime::bio::{
    BIO_ctrl, BIO_find_type, BIO_free_all, BIO_int_ctrl, BIO_method_type, BIO_new, BIO_next,
    BIO_pop, BIO_push, BIO_up_ref, Bio, BIO_C_GET_FD, BIO_C_SET_FD, BIO_NOCLOSE,
    BIO_TYPE_DESCRIPTOR,
};
use crate::runtime::err::{raise_with, ERR_peek_error};
use crate::runtime::ex_data::{
    CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data, CRYPTO_set_ex_data, CryptoExData,
    CRYPTO_EX_INDEX_SSL, CRYPTO_EX_INDEX_SSL_CTX,
};
use crate::runtime::mem::{CRYPTO_free, CRYPTO_strdup, CRYPTO_zalloc};
use crate::runtime::thread::{CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CryptoRwlock};
use crate::x509::x509_lu::{X509Store, X509_STORE_free, X509_STORE_new, X509_STORE_up_ref};
use crate::x509::x509_vpm::{
    X509VerifyParam, X509_VERIFY_PARAM_free, X509_VERIFY_PARAM_get_depth,
    X509_VERIFY_PARAM_inherit, X509_VERIFY_PARAM_new, X509_VERIFY_PARAM_set1,
    X509_VERIFY_PARAM_set_depth,
};

/// `OPENSSL_FILE` of this translation unit, used on allocation and `ERR_raise` sites.
const FILE: *const c_char = c"ssl/ssl_lib.c".as_ptr();

/// `ERR_LIB_SSL` — `include/openssl/err.h.in:91`.
const ERR_LIB_SSL: c_int = 20;
/// `SSL_R_NULL_SSL_METHOD_PASSED` — `sslerr.h:221`.
const SSL_R_NULL_SSL_METHOD_PASSED: c_int = 196;
/// `SSL_R_NULL_SSL_CTX` — `sslerr.h:220`.
const SSL_R_NULL_SSL_CTX: c_int = 195;
/// `SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION` — `sslerr.h:286`.
const SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION: c_int = 228;
/// `SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG` — `sslerr.h:294`.
const SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG: c_int = 273;
/// `SSL_R_BAD_LENGTH` — `sslerr.h:46`.
const SSL_R_BAD_LENGTH: c_int = 271;
/// `SSL_R_UNINITIALIZED` — `sslerr.h:340`.
const SSL_R_UNINITIALIZED: c_int = 276;
/// `SSL_R_CONNECTION_TYPE_NOT_SET` — `sslerr.h:84`.
const SSL_R_CONNECTION_TYPE_NOT_SET: c_int = 144;
/// `SSL_R_NO_METHOD_SPECIFIED` — `sslerr.h:202`.
const SSL_R_NO_METHOD_SPECIFIED: c_int = 188;

/// `ssl_security_default_callback` — the level check the certificate's `sec_cb` is initialised
/// to (`ssl_cert.c:83`).
///
/// Slice 1 stores the pointer so `SSL_CTX_get_security_callback`'s default matches the
/// authority's non-NULL answer; the callback's body is the certificate path's (14.7) and it is
/// never invoked here.
unsafe extern "C" fn ssl_security_default_callback(
    _s: *const Ssl,
    _ctx: *const SslCtx,
    _op: c_int,
    _bits: c_int,
    _nid: c_int,
    _other: *mut c_void,
    _ex: *mut c_void,
) -> c_int {
    1
}

/// `TLS_ANY_VERSION` — `include/openssl/tls1.h:40`.
pub const TLS_ANY_VERSION: c_int = 0x10000;
/// `TLS1_3_VERSION` — `include/openssl/tls1.h`.
pub const TLS1_3_VERSION: c_int = 0x0304;
/// `TLS_MAX_VERSION_INTERNAL` — `ssl_local.h`: `tls1_clear` installs it for an any-version method.
const TLS_MAX_VERSION_INTERNAL: c_int = TLS1_3_VERSION;
/// `DTLS1_VERSION_MAJOR` — `include/openssl/dtls1.h`.
#[allow(dead_code)] // retained for the version-family readers a later slice adds
const DTLS1_VERSION_MAJOR: c_int = 0xFE;

/// `SSL_MAX_SID_CTX_LENGTH` — `ssl.h:64`.
const SSL_MAX_SID_CTX_LENGTH: usize = 32;
/// `SSL_MAX_CERT_LIST_DEFAULT` — `ssl.h:692`.
const SSL_MAX_CERT_LIST_DEFAULT: usize = 1024 * 100;
/// `SSL_SESSION_CACHE_MAX_SIZE_DEFAULT` — `ssl.h:694`.
const SSL_SESSION_CACHE_MAX_SIZE_DEFAULT: usize = 1024 * 20;
/// `SSL_SESS_CACHE_SERVER` — `ssl.h:713`.
const SSL_SESS_CACHE_SERVER: c_long = 0x0002;
/// `SSL_MODE_AUTO_RETRY` — `ssl.h:508`.
const SSL_MODE_AUTO_RETRY: c_uint = 0x0000_0004;
/// `SSL_OP_NO_COMPRESSION` — `ssl.h:394`; `SSL_OP_BIT(17)`.
const SSL_OP_NO_COMPRESSION: u64 = 1 << 17;
/// `SSL_OP_ENABLE_MIDDLEBOX_COMPAT` — `ssl.h:403`; `SSL_OP_BIT(20)`.
const SSL_OP_ENABLE_MIDDLEBOX_COMPAT: u64 = 1 << 20;
/// `SSL_MAX_PIPELINES` — `ssl.h:71`.
const SSL_MAX_PIPELINES: c_long = 32;
/// `SSL3_RT_MAX_PLAIN_LENGTH` — `ssl3.h:177`.
const SSL3_RT_MAX_PLAIN_LENGTH: c_long = 16384;

/// `SSL_CTRL_SET_MSG_CALLBACK` — `ssl.h:1285`.
const SSL_CTRL_SET_MSG_CALLBACK: c_int = 15;
/// `SSL_CTRL_SET_MSG_CALLBACK_ARG` — `ssl.h:1286`.
const SSL_CTRL_SET_MSG_CALLBACK_ARG: c_int = 16;
/// `SSL_CTRL_GET_RI_SUPPORT` — `ssl.h:1344`.
const SSL_CTRL_GET_RI_SUPPORT: c_int = 76;
/// `SSL_CTRL_GET_RAW_CIPHERLIST` — `ssl.h:1368`.
const SSL_CTRL_GET_RAW_CIPHERLIST: c_int = 110;
/// `SSL_CTRL_GET_EXTMS_SUPPORT` — `ssl.h:1376`.
const SSL_CTRL_GET_EXTMS_SUPPORT: c_int = 122;
/// `SSL_CTRL_MODE` — `ssl.h:1302`.
const SSL_CTRL_MODE: c_int = 33;
/// `SSL_CTRL_GET_READ_AHEAD` — `ssl.h:1303`.
const SSL_CTRL_GET_READ_AHEAD: c_int = 40;
/// `SSL_CTRL_SET_READ_AHEAD` — `ssl.h:1304`.
const SSL_CTRL_SET_READ_AHEAD: c_int = 41;
/// `SSL_CTRL_SET_SESS_CACHE_SIZE` — `ssl.h:1305`.
const SSL_CTRL_SET_SESS_CACHE_SIZE: c_int = 42;
/// `SSL_CTRL_GET_SESS_CACHE_SIZE` — `ssl.h:1306`.
const SSL_CTRL_GET_SESS_CACHE_SIZE: c_int = 43;
/// `SSL_CTRL_SET_SESS_CACHE_MODE` — `ssl.h:1307`.
const SSL_CTRL_SET_SESS_CACHE_MODE: c_int = 44;
/// `SSL_CTRL_GET_SESS_CACHE_MODE` — `ssl.h:1308`.
const SSL_CTRL_GET_SESS_CACHE_MODE: c_int = 45;
/// `SSL_CTRL_GET_MAX_CERT_LIST` — `ssl.h:1309`.
const SSL_CTRL_GET_MAX_CERT_LIST: c_int = 50;
/// `SSL_CTRL_SET_MAX_CERT_LIST` — `ssl.h:1310`.
const SSL_CTRL_SET_MAX_CERT_LIST: c_int = 51;
/// `SSL_CTRL_SET_MAX_SEND_FRAGMENT` — `ssl.h:1311`.
const SSL_CTRL_SET_MAX_SEND_FRAGMENT: c_int = 52;
/// `SSL_CTRL_CLEAR_MODE` — `ssl.h:1345`.
const SSL_CTRL_CLEAR_MODE: c_int = 78;
/// `SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB` — `ssl.h:1346`.
const SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB: c_int = 79;
/// `SSL_CTRL_CERT_FLAGS` — `ssl.h:1357`.
const SSL_CTRL_CERT_FLAGS: c_int = 99;
/// `SSL_CTRL_CLEAR_CERT_FLAGS` — `ssl.h:1358`.
const SSL_CTRL_CLEAR_CERT_FLAGS: c_int = 100;
/// `SSL_CTRL_SET_SPLIT_SEND_FRAGMENT` — `ssl.h:1379`.
const SSL_CTRL_SET_SPLIT_SEND_FRAGMENT: c_int = 125;
/// `SSL_CTRL_SET_MAX_PIPELINES` — `ssl.h:1380`.
const SSL_CTRL_SET_MAX_PIPELINES: c_int = 126;
/// `SSL_CTRL_SET_MIN_PROTO_VERSION` — `ssl.h:1377` (the setter is `ssl_set_version_bound`,
/// 14.5's, so it stays on this switch's fall-through).
#[allow(dead_code)]
const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
/// `SSL_CTRL_GET_MIN_PROTO_VERSION` — `ssl.h:1384`.
const SSL_CTRL_GET_MIN_PROTO_VERSION: c_int = 130;
/// `SSL_CTRL_SET_MAX_PROTO_VERSION` — `ssl.h:1378` (as the min setter).
#[allow(dead_code)]
const SSL_CTRL_SET_MAX_PROTO_VERSION: c_int = 124;
/// `SSL_CTRL_GET_MAX_PROTO_VERSION` — `ssl.h:1385`.
const SSL_CTRL_GET_MAX_PROTO_VERSION: c_int = 131;

/// `SSL_NOTHING` — `ssl.h:932`.
const SSL_NOTHING: c_int = 1;
/// `SSL_READING` — `ssl.h:934`.
const SSL_READING: c_int = 3;
/// `SSL_WRITING` — `ssl.h:933`.
const SSL_WRITING: c_int = 2;
/// `SSL_ERROR_NONE` — `ssl.h:1258`.
const SSL_ERROR_NONE: c_int = 0;
/// `SSL_ERROR_SSL` — `ssl.h:1259`.
const SSL_ERROR_SSL: c_int = 1;
/// `SSL_ERROR_SYSCALL` — `ssl.h:1263`.
const SSL_ERROR_SYSCALL: c_int = 5;

/// `TLS_CIPHER_LEN` — `ssl_local.h`: the two-byte cipher-suite coordinate.
const TLS_CIPHER_LEN: c_int = 2;

/// `SSL_TYPE_SSL_CONNECTION` — the ordinary connection type.
const SSL_TYPE_SSL_CONNECTION: c_int = 0;
/// `SSL_TYPE_QUIC_CONNECTION` — a QUIC connection, never produced by this slice.
const SSL_TYPE_QUIC_CONNECTION: c_int = 1;
/// `SSL_TYPE_QUIC_XSO` — a QUIC stream object, never produced by this slice.
const SSL_TYPE_QUIC_XSO: c_int = 2;

/// `X509_V_OK` — `include/openssl/x509_vfy.h`.
const X509_V_OK: c_long = 0;

// -------------------------------------------------------------------------------------------
// Method table (pulled forward from 14.2 for the one constructor the court needs)
// -------------------------------------------------------------------------------------------

/// `struct ssl_method_st` — `ssl_local.h:405-442`, reduced to the fields this slice reads.
///
/// The authority's table is a function-pointer block; Slice 1 reads only `version` and the
/// default timeout (`get_timeout`, `tls1_default_timeout` -> 2 hours). The rest of the table is
/// 14.2's, so the field is kept as a plain scalar here rather than as the authority's callbacks.
#[repr(C)]
pub struct SslMethod {
    /// `int version` — the default protocol version the method installs.
    pub version: c_int,
    /// `unsigned flags` — `SSL_METHOD_*`.
    pub flags: c_uint,
    /// `uint64_t mask` — the option bit the method is disabled by.
    pub mask: u64,
    /// `get_timeout()` in seconds; `tls1_default_timeout` is `60 * 60 * 2`.
    pub timeout_secs: u64,
    /// `ssl3_enc->enc_flags & SSL_ENC_FLAG_DTLS` — the method's datagram family (14.2's table).
    pub dtls: bool,
    /// `method->ssl_accept != ssl_undefined_function` — the default role `SSL_new` installs
    /// (`ssl_lib.c:917`).
    pub default_server: bool,
}

// -------------------------------------------------------------------------------------------
// CERT — the per-context/per-connection certificate container (a reduced `ssl_cert_st`)
// -------------------------------------------------------------------------------------------

/// `struct cert_pkey` — `ssl_local.h`, reduced to the two accessors this slice reads.
#[repr(C)]
pub struct CertKey {
    /// `X509 *x509` — the leaf certificate, NULL until a loader runs (14.7).
    pub x509: *mut c_void,
    /// `EVP_PKEY *privatekey` — the leaf key, NULL until a loader runs (14.7).
    pub privatekey: *mut c_void,
}

/// `struct ssl_cert_st` — `ssl_local.h`, reduced to the fields Slice 1 reads.
#[repr(C)]
pub struct Cert {
    /// `CERT_PKEY *key` — the active leaf certificate/key pair.
    pub key: CertKey,
    /// `int sec_level` — the security level (`SSL_[CTX_]set/get_security_level`).
    pub sec_level: c_int,
    /// `int (*sec_cb)(...)` — the security callback.
    pub sec_cb: Option<SecurityCb>,
    /// `void *sec_ex` — the security callback's ex-data slot.
    pub sec_ex: *mut c_void,
    /// `unsigned long cert_flags` — the `SSL_CTRL_CERT_FLAGS` bitmask.
    pub cert_flags: c_long,
    /// `int (*cert_cb)(SSL *, void *)` — the certificate callback (`SSL_CTX_set_cert_cb`).
    #[allow(dead_code)]
    // stored for the setter's contract; read by the certificate path (14.7)
    pub cert_cb: Option<CertCb>,
    /// The certificate callback's argument.
    #[allow(dead_code)] // as `cert_cb`
    pub cert_cb_arg: *mut c_void,
}

/// A context's or a connection's certificate container, freshly allocated and empty.
///
/// # Safety
/// The returned pointer is a live, zeroed `Cert` with the authority's security-level default
/// (`ssl_cert.c:84`'s `OPENSSL_TLS_SECURITY_LEVEL` = 2); the caller owns it.
unsafe fn cert_new() -> *mut Cert {
    // SAFETY: `CRYPTO_zalloc` returns either NULL or a zeroed block of the requested size.
    let c = CRYPTO_zalloc(core::mem::size_of::<Cert>(), FILE, 0).cast::<Cert>();
    if !c.is_null() {
        // SAFETY: `c` is a fresh zeroed allocation.
        unsafe {
            (*c).sec_level = 2;
            (*c).sec_cb = Some(ssl_security_default_callback);
        }
    }
    c
}

/// Release a certificate container.
///
/// # Safety
/// `c` must be NULL or a live `Cert` previously returned by [`cert_new`].
unsafe fn cert_free(c: *mut Cert) {
    if !c.is_null() {
        // SAFETY: `c` is a live `Cert` per the caller's contract.
        unsafe { CRYPTO_free(c.cast(), FILE, 0) };
    }
}

/// Copy the security-attribute half of a certificate container (the authority's `ssl_cert_dup`
/// copies `sec_level`/`sec_cb`/`sec_ex`/`cert_flags`; the leaf key is 14.7's).
///
/// # Safety
/// `to` must be a live `Cert`; `from` must be NULL or a live `Cert`.
unsafe fn cert_copy_security(to: *mut Cert, from: *const Cert) {
    if from.is_null() {
        return;
    }
    // SAFETY: both pointers are live per the caller's contract.
    let (f, t) = unsafe { (&*from, &mut *to) };
    t.sec_level = f.sec_level;
    t.sec_cb = f.sec_cb;
    t.sec_ex = f.sec_ex;
    t.cert_flags = f.cert_flags;
    t.key.x509 = f.key.x509;
    t.key.privatekey = f.key.privatekey;
}

// -------------------------------------------------------------------------------------------
// SSL_CTX and SSL
// -------------------------------------------------------------------------------------------

/// `struct ssl_ctx_st` — `ssl_local.h:793`, reduced to the fields Slice 1 reads or writes.
#[repr(C)]
pub struct SslCtx {
    /// `CRYPTO_REF_COUNT references` — the context's reference count.
    pub references: AtomicI32,
    /// `CRYPTO_RWLOCK *lock` — the context-wide lock.
    pub lock: *mut CryptoRwlock,
    /// `const SSL_METHOD *method` — the method the context was built from.
    pub method: *const SslMethod,
    /// `OSSL_LIB_CTX *libctx` — the library context, stored verbatim.
    pub libctx: *mut c_void,
    /// `char *propq` — the property query, owned.
    pub propq: *mut c_char,
    /// `int min_proto_version`.
    pub min_proto_version: c_int,
    /// `int max_proto_version`.
    pub max_proto_version: c_int,
    /// `uint32_t mode` — `SSL_MODE_*`.
    pub mode: c_uint,
    /// `long session_cache_mode` — `SSL_SESS_CACHE_*`.
    pub session_cache_mode: c_long,
    /// `size_t session_cache_size`.
    pub session_cache_size: usize,
    /// `OSSL_TIME session_timeout`, in seconds (the authority stores nanoseconds; no reader here).
    pub session_timeout: u64,
    /// `size_t max_cert_list`.
    pub max_cert_list: usize,
    /// `int verify_mode` — `SSL_VERIFY_*`.
    pub verify_mode: c_int,
    /// `uint64_t options` — `SSL_OP_*`.
    pub options: u64,
    /// `int quiet_shutdown`.
    pub quiet_shutdown: c_int,
    /// `int read_ahead`.
    pub read_ahead: c_int,
    /// `size_t max_send_fragment`.
    pub max_send_fragment: usize,
    /// `size_t split_send_fragment`.
    pub split_send_fragment: usize,
    /// `size_t max_pipelines`.
    pub max_pipelines: usize,
    /// `size_t default_read_buf_len` — 14.4's `SSL_CTX_set_default_read_buffer_len` would set it.
    pub default_read_buf_len: usize,
    /// `size_t num_tickets`.
    pub num_tickets: usize,
    /// `uint32_t max_early_data`.
    pub max_early_data: u32,
    /// `uint32_t recv_max_early_data`.
    pub recv_max_early_data: u32,
    /// `unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH]`.
    pub sid_ctx: [u8; SSL_MAX_SID_CTX_LENGTH],
    /// `unsigned int sid_ctx_length`.
    pub sid_ctx_length: c_uint,
    /// `CRYPTO_EX_DATA ex_data`.
    pub ex_data: CryptoExData,
    /// `X509_STORE *cert_store`.
    pub cert_store: *mut X509Store,
    /// `X509_VERIFY_PARAM *param`.
    pub param: *mut X509VerifyParam,
    /// `CERT *cert`.
    pub cert: *mut Cert,
    /// `pem_password_cb *default_passwd_callback`.
    pub default_passwd_callback: Option<PemPasswordCb>,
    /// `void *default_passwd_callback_userdata`.
    pub default_passwd_callback_userdata: *mut c_void,
    /// `int (*default_verify_callback)(int, X509_STORE_CTX *)`.
    pub default_verify_callback: Option<VerifyCb>,
    /// `int (*app_verify_callback)(X509_STORE_CTX *, void *)`.
    #[allow(dead_code)] // stored for the setter's contract; read by the verify path (14.7)
    pub app_verify_callback: Option<AppVerifyCb>,
    /// `void *app_verify_arg`.
    #[allow(dead_code)] // as `app_verify_callback`
    pub app_verify_arg: *mut c_void,
    /// `void (*msg_callback)(...)`.
    pub msg_callback: Option<MsgCb>,
    /// `void *msg_callback_arg`.
    pub msg_callback_arg: *mut c_void,
    /// `SSL_client_hello_cb_fn client_hello_cb`.
    #[allow(dead_code)]
    // stored for the setter's contract; read by the ClientHello path (14.5)
    pub client_hello_cb: Option<ClientHelloCb>,
    /// `void *client_hello_cb_arg`.
    #[allow(dead_code)] // as `client_hello_cb`
    pub client_hello_cb_arg: *mut c_void,
    /// `SSL_CTX_keylog_cb_func keylog_callback`.
    pub keylog_callback: Option<KeylogCb>,
    /// `SSL_async_callback_fn async_cb`.
    #[allow(dead_code)] // stored for the setter's contract; read by the async path (14.5)
    pub async_cb: Option<AsyncCb>,
    /// `void *async_cb_arg`.
    #[allow(dead_code)] // as `async_cb`
    pub async_cb_arg: *mut c_void,
    /// `int (*not_resumable_session_cb)(SSL *, int)`.
    #[allow(dead_code)] // stored for the setter's contract; read by the session path (14.7)
    pub not_resumable_session_cb: Option<NotResumableCb>,
    /// `size_t (*record_padding_cb)(SSL *, int, size_t, void *)`.
    #[allow(dead_code)] // stored for the setter's contract; read by the record layer (14.4)
    pub record_padding_cb: Option<RecordPaddingCb>,
    /// `void *record_padding_arg`.
    pub record_padding_arg: *mut c_void,
    /// `SSL_CTX_alpn_select_cb_func alpn_select_cb`.
    #[allow(dead_code)] // stored for the setter's contract; read by the ALPN path (14.5)
    pub alpn_select_cb: Option<AlpnSelectCb>,
    /// `void *alpn_select_cb_arg`.
    #[allow(dead_code)] // as `alpn_select_cb`
    pub alpn_select_cb_arg: *mut c_void,
    /// `SSL_session_ticket_key_cb session_ticket_cb`.
    #[allow(dead_code)] // stored for the setter's contract; read by the ticket path (14.7)
    pub session_ticket_cb: Option<SessionTicketCb>,
    /// `void *session_ticket_cb_arg`.
    #[allow(dead_code)] // as `session_ticket_cb`
    pub session_ticket_cb_arg: *mut c_void,
    /// `SSL_allow_early_data_cb_fn allow_early_data_cb`.
    #[allow(dead_code)] // stored for the setter's contract; read by the early-data path (14.5)
    pub allow_early_data_cb: Option<AllowEarlyDataCb>,
    /// `void *allow_early_data_cb_data`.
    #[allow(dead_code)] // as `allow_early_data_cb`
    pub allow_early_data_cb_data: *mut c_void,
    /// `SSL_new_pending_conn_cb new_pending_conn_cb`.
    #[allow(dead_code)] // stored for the setter's contract; read by the pending-conn path (15)
    pub new_pending_conn_cb: Option<NewPendingConnCb>,
    /// `void *new_pending_conn_cb_arg`.
    #[allow(dead_code)] // as `new_pending_conn_cb`
    pub new_pending_conn_cb_arg: *mut c_void,
    /// `SSL_psk_client_cb_func psk_client_callback`.
    #[allow(dead_code)] // stored for the setter's contract; read by the PSK path (14.7)
    pub psk_client_callback: Option<PskClientCb>,
    /// `SSL_psk_server_cb_func psk_server_callback`.
    #[allow(dead_code)] // as `psk_client_callback`
    pub psk_server_callback: Option<PskServerCb>,
    /// `SSL_psk_find_session_cb_func psk_find_session_cb`.
    #[allow(dead_code)] // as `psk_client_callback`
    pub psk_find_session_cb: Option<PskFindSessionCb>,
    /// `SSL_psk_use_session_cb_func psk_use_session_cb`.
    #[allow(dead_code)] // as `psk_client_callback`
    pub psk_use_session_cb: Option<PskUseSessionCb>,
    /// `GEN_SESSION_CB generate_session_id`.
    #[allow(dead_code)] // stored for the setter's contract; read by the session path (14.7)
    pub generate_session_id: Option<GenerateSessionIdCb>,
}

/// `struct ssl_st` — `ssl_local.h`, carrying the `SSL_CONNECTION` fields Slice 1 reads.
#[repr(C)]
pub struct Ssl {
    /// `CRYPTO_REF_COUNT references`.
    pub references: AtomicI32,
    /// `CRYPTO_RWLOCK *lock`.
    pub lock: *mut CryptoRwlock,
    /// `SSL_CTX *ctx` — the context the connection was allocated from (a strong reference).
    pub ctx: *mut SslCtx,
    /// `const SSL_METHOD *method`.
    pub method: *const SslMethod,
    /// `const SSL_METHOD *defltmeth`.
    pub defltmeth: *const SslMethod,
    /// `int type` — `SSL_TYPE_*`.
    pub type_: c_int,
    /// `int version` — the negotiated/installed protocol version.
    pub version: c_int,
    /// `int client_version`.
    pub client_version: c_int,
    /// `uint64_t options`.
    pub options: u64,
    /// `int min_proto_version`.
    pub min_proto_version: c_int,
    /// `int max_proto_version`.
    pub max_proto_version: c_int,
    /// `uint32_t mode`.
    pub mode: c_uint,
    /// `size_t max_cert_list`.
    pub max_cert_list: usize,
    /// `size_t num_tickets`.
    pub num_tickets: usize,
    /// `uint32_t max_early_data`.
    pub max_early_data: u32,
    /// `uint32_t recv_max_early_data`.
    pub recv_max_early_data: u32,
    /// `int quiet_shutdown`.
    pub quiet_shutdown: c_int,
    /// `int shutdown` — `SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN`.
    pub shutdown: c_int,
    /// `int verify_mode`.
    pub verify_mode: c_int,
    /// `int (*verify_callback)(int, X509_STORE_CTX *)`.
    pub verify_callback: Option<VerifyCb>,
    /// `long verify_result`.
    pub verify_result: c_long,
    /// `unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH]`.
    pub sid_ctx: [u8; SSL_MAX_SID_CTX_LENGTH],
    /// `unsigned int sid_ctx_length`.
    pub sid_ctx_length: c_uint,
    /// `int rwstate` — `SSL_NOTHING`/`SSL_READING`/`SSL_WRITING`.
    pub rwstate: c_int,
    /// `int server` — set by `SSL_set_accept_state`, 14.5's path.
    pub server: c_int,
    /// `int hit` — set on session resumption, 14.7's path.
    pub hit: c_int,
    /// `size_t max_send_fragment`.
    pub max_send_fragment: usize,
    /// `size_t split_send_fragment`.
    pub split_send_fragment: usize,
    /// `size_t max_pipelines`.
    pub max_pipelines: usize,
    /// `size_t default_read_buf_len`.
    pub default_read_buf_len: usize,
    /// `int read_ahead`.
    pub read_ahead: c_int,
    /// `CRYPTO_EX_DATA ex_data`.
    pub ex_data: CryptoExData,
    /// `X509_VERIFY_PARAM *param`.
    pub param: *mut X509VerifyParam,
    /// `CERT *cert`.
    pub cert: *mut Cert,
    /// `BIO *rbio`.
    pub rbio: *mut Bio,
    /// `BIO *wbio`.
    pub wbio: *mut Bio,
    /// `BIO *bbio` — the write-buffering filter, NULL in this slice (14.4).
    pub bbio: *mut Bio,
    /// `int (*handshake_func)(SSL *)` — NULL until `SSL_set_accept_state`/`_connect_state`
    /// (14.5).
    pub handshake_func: Option<HandshakeFn>,
    /// `pem_password_cb *default_passwd_callback`.
    pub default_passwd_callback: Option<PemPasswordCb>,
    /// `void *default_passwd_callback_userdata`.
    pub default_passwd_callback_userdata: *mut c_void,
    /// `void (*info_callback)(const SSL *, int, int)`.
    pub info_callback: Option<InfoCb>,
    /// `void (*msg_callback)(...)`.
    pub msg_callback: Option<MsgCb>,
    /// `void *msg_callback_arg`.
    pub msg_callback_arg: *mut c_void,
    /// `int (*not_resumable_session_cb)(SSL *, int)`.
    #[allow(dead_code)] // stored for the setter's contract; read by the session path (14.7)
    pub not_resumable_session_cb: Option<NotResumableCb>,
    /// `size_t (*record_padding_cb)(SSL *, int, size_t, void *)`.
    #[allow(dead_code)] // stored for the setter's contract; read by the record layer (14.4)
    pub record_padding_cb: Option<RecordPaddingCb>,
    /// `void *record_padding_arg`.
    pub record_padding_arg: *mut c_void,
    /// `SSL_async_callback_fn async_cb`.
    #[allow(dead_code)] // stored for the setter's contract; read by the async path (14.5)
    pub async_cb: Option<AsyncCb>,
    /// `void *async_cb_arg`.
    #[allow(dead_code)] // as `async_cb`
    pub async_cb_arg: *mut c_void,
    /// `SSL_allow_early_data_cb_fn allow_early_data_cb`.
    #[allow(dead_code)] // stored for the setter's contract; read by the early-data path (14.5)
    pub allow_early_data_cb: Option<AllowEarlyDataCb>,
    /// `void *allow_early_data_cb_data`.
    #[allow(dead_code)] // as `allow_early_data_cb`
    pub allow_early_data_cb_data: *mut c_void,
    /// `SSL_psk_client_cb_func psk_client_callback`.
    #[allow(dead_code)] // stored for the setter's contract; read by the PSK path (14.7)
    pub psk_client_callback: Option<PskClientCb>,
    /// `SSL_psk_server_cb_func psk_server_callback`.
    #[allow(dead_code)] // as `psk_client_callback`
    pub psk_server_callback: Option<PskServerCb>,
    /// `SSL_psk_find_session_cb_func psk_find_session_cb`.
    #[allow(dead_code)] // as `psk_client_callback`
    pub psk_find_session_cb: Option<PskFindSessionCb>,
    /// `SSL_psk_use_session_cb_func psk_use_session_cb`.
    #[allow(dead_code)] // as `psk_client_callback`
    pub psk_use_session_cb: Option<PskUseSessionCb>,
    /// `GEN_SESSION_CB generate_session_id`.
    #[allow(dead_code)] // stored for the setter's contract; read by the session path (14.7)
    pub generate_session_id: Option<GenerateSessionIdCb>,
    /// `unsigned char client_random[32]` — the record layer's; zero here.
    pub client_random: [u8; 32],
    /// `unsigned char server_random[32]` — the record layer's; zero here.
    pub server_random: [u8; 32],
}

// -------------------------------------------------------------------------------------------
// Callback type aliases (their arities are the authority's; Slice 1 stores and returns them)
// -------------------------------------------------------------------------------------------

/// `pem_password_cb` — `evp.h`.
pub type PemPasswordCb = unsafe extern "C" fn(*mut c_char, c_int, c_int, *mut c_void) -> c_int;
/// `int (*)(int, X509_STORE_CTX *)` — the verify callback.
pub type VerifyCb = unsafe extern "C" fn(c_int, *mut c_void) -> c_int;
/// `int (*)(X509_STORE_CTX *, void *)` — the application verify callback.
pub type AppVerifyCb = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
/// `void (*)(const SSL *, int, int)` — the info callback.
pub type InfoCb = unsafe extern "C" fn(*const Ssl, c_int, c_int);
/// `void (*)(int, int, int, const void *, size_t, SSL *, void *)` — the message callback.
pub type MsgCb =
    unsafe extern "C" fn(c_int, c_int, c_int, *const c_void, usize, *mut Ssl, *mut c_void);
/// `SSL_client_hello_cb_fn` — `ssl.h:1965`.
pub type ClientHelloCb = unsafe extern "C" fn(*mut Ssl, *mut c_int, *mut c_void) -> c_int;
/// `int (*)(SSL *, void *)` — the certificate callback.
pub type CertCb = unsafe extern "C" fn(*mut Ssl, *mut c_void) -> c_int;
/// `SSL_CTX_keylog_cb_func` — `ssl.h:960`.
pub type KeylogCb = unsafe extern "C" fn(*const Ssl, *const c_char);
/// `SSL_async_callback_fn` — `ssl.h:348`.
pub type AsyncCb = unsafe extern "C" fn(*mut Ssl, *mut c_void) -> c_int;
/// `int (*)(SSL *, int)` — the not-resumable-session callback.
pub type NotResumableCb = unsafe extern "C" fn(*mut Ssl, c_int) -> c_int;
/// `int (*)(const SSL *, const SSL_CTX *, int, int, int, void *, void *)` — the security callback.
pub type SecurityCb = unsafe extern "C" fn(
    *const Ssl,
    *const SslCtx,
    c_int,
    c_int,
    c_int,
    *mut c_void,
    *mut c_void,
) -> c_int;
/// `size_t (*)(SSL *, int, size_t, void *)` — the record-padding callback.
pub type RecordPaddingCb = unsafe extern "C" fn(*mut Ssl, c_int, usize, *mut c_void) -> usize;
/// `SSL_CTX_alpn_select_cb_func` — `ssl.h:844`.
pub type AlpnSelectCb = unsafe extern "C" fn(
    *mut Ssl,
    *mut *const u8,
    *mut u8,
    *const u8,
    c_uint,
    *mut c_void,
) -> c_int;
/// `SSL_session_ticket_key_cb` — `ssl.h`.
pub type SessionTicketCb =
    unsafe extern "C" fn(*mut Ssl, *mut c_void, *mut c_void, *mut c_void) -> c_int;
/// `SSL_allow_early_data_cb_fn` — `ssl.h:2892`.
pub type AllowEarlyDataCb = unsafe extern "C" fn(*mut Ssl, *mut c_void) -> c_int;
/// `SSL_new_pending_conn_cb` — `ssl.h`.
pub type NewPendingConnCb = unsafe extern "C" fn(*mut Ssl, *mut c_void) -> c_int;
/// `SSL_psk_client_cb_func` — `ssl.h:863`.
pub type PskClientCb =
    unsafe extern "C" fn(*mut Ssl, *const c_char, *mut c_char, c_uint, *mut u8, c_uint) -> c_uint;
/// `SSL_psk_server_cb_func` — `ssl.h:872`.
pub type PskServerCb = unsafe extern "C" fn(*mut Ssl, *const c_char, *mut u8, c_uint) -> c_uint;
/// `SSL_psk_find_session_cb_func` — `ssl.h:885` (the `SSL_SESSION **` parameter is opaque).
pub type PskFindSessionCb =
    unsafe extern "C" fn(*mut Ssl, *const u8, usize, *mut *mut c_void) -> c_int;
/// `SSL_psk_use_session_cb_func` — `ssl.h:889` (the `EVP_MD`/`SSL_SESSION` parameters are opaque).
pub type PskUseSessionCb = unsafe extern "C" fn(*mut Ssl, *const c_void, *mut *mut c_void) -> c_int;
/// `GEN_SESSION_CB` — `ssl.h:708`.
pub type GenerateSessionIdCb = unsafe extern "C" fn(*mut Ssl, *mut u8, *mut c_uint) -> c_int;
/// `int (*)(SSL *)` — a handshake entry, the shape `SSL_CONNECTION.handshake_func` stores.
pub type HandshakeFn = unsafe extern "C" fn(*mut Ssl) -> c_int;

// -------------------------------------------------------------------------------------------
// Small helpers
// -------------------------------------------------------------------------------------------

/// Raise `ERR_raise(ERR_LIB_SSL, reason)` at `ssl/ssl_lib.c:line`.
///
/// # Safety
/// Nothing beyond the FFI contract: the error state is thread-local.
unsafe fn raise_ssl(reason: c_int, line: c_int) {
    // SAFETY: `FILE` is a static NUL-terminated string and `reason` is one of this file's
    // constants; `raise_with` writes the thread-local error queue only.
    unsafe { raise_with(ERR_LIB_SSL, reason, FILE, line) };
}

/// `CRYPTO_UP_REF(&refs, &i)` — the relaxed fetch-add the authority's header defines.
fn up_ref(refs: &AtomicI32) -> c_int {
    refs.fetch_add(1, Ordering::Relaxed) + 1
}

/// `CRYPTO_DOWN_REF(&refs, &i)` — the release fetch-sub the authority's header defines.
fn down_ref(refs: &AtomicI32) -> c_int {
    refs.fetch_sub(1, Ordering::Release) - 1
}

/// `SSL_CONNECTION_IS_DTLS(sc)` — `ssl_local.h:257`, read from the method's enc-flag.
///
/// # Safety
/// `s` must be NULL or a live `Ssl`.
unsafe fn is_dtls(s: *const Ssl) -> bool {
    if s.is_null() {
        return false;
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    let m = unsafe { (*s).method };
    if m.is_null() {
        return false;
    }
    // SAFETY: `m` is the live method table `s` was built from.
    unsafe { (*m).dtls }
}

/// `IS_QUIC(s)` — this slice never produces a QUIC object, so the type is the only test.
///
/// # Safety
/// `s` must be NULL or a live `Ssl`.
unsafe fn is_quic(s: *const Ssl) -> bool {
    if s.is_null() {
        return false;
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    let t = unsafe { (*s).type_ };
    t == SSL_TYPE_QUIC_CONNECTION || t == SSL_TYPE_QUIC_XSO
}

// -------------------------------------------------------------------------------------------
// Lifecycle
// -------------------------------------------------------------------------------------------

/// `SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth)` — `ssl/ssl_lib.c:4333-4336`.
///
/// # Safety
/// `meth` must be NULL or a live method table; the returned context is owned by the caller and
/// must be released with [`SSL_CTX_free`].
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_new(meth: *const SslMethod) -> *mut SslCtx {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: forwarded per the caller's contract.
        unsafe { SSL_CTX_new_ex(ptr::null_mut(), ptr::null(), meth) }
    })
}

/// `SSL_CTX *SSL_CTX_new_ex(OSSL_LIB_CTX *libctx, const char *propq, const SSL_METHOD *meth)` —
/// `ssl/ssl_lib.c:3989-4331`.
///
/// The allocation and the observable defaults are the authority's; the cipher/group/sigalg loading
/// that `ssl_lib.c:4074-4105` performs is withheld because those units are 14.3's and 14.5's. See
/// the divergence note in `src/ssl/mod.rs`.
///
/// # Safety
/// `meth` must be NULL or a live method table; `propq` must be NULL or a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_new_ex(
    libctx: *mut c_void,
    propq: *const c_char,
    meth: *const SslMethod,
) -> *mut SslCtx {
    guard_ffi(ptr::null_mut(), || {
        if meth.is_null() {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_NULL_SSL_METHOD_PASSED, 4001) };
            return ptr::null_mut();
        }

        // SAFETY: a zeroed block of this size is a valid initial `SslCtx` image.
        let ret = CRYPTO_zalloc(core::mem::size_of::<SslCtx>(), FILE, 4014).cast::<SslCtx>();
        if ret.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `ret` is a fresh zeroed allocation; every write below is to it.
        unsafe {
            (*ret).references = AtomicI32::new(1);
            (*ret).lock = CRYPTO_THREAD_lock_new();
            if (*ret).lock.is_null() {
                SSL_CTX_free(ret);
                return ptr::null_mut();
            }
            (*ret).libctx = libctx;
            if !propq.is_null() {
                (*ret).propq = CRYPTO_strdup(propq, FILE, 4040);
                if (*ret).propq.is_null() {
                    SSL_CTX_free(ret);
                    return ptr::null_mut();
                }
            }
            (*ret).method = meth;
            (*ret).mode = SSL_MODE_AUTO_RETRY;
            (*ret).session_cache_mode = SSL_SESS_CACHE_SERVER;
            (*ret).session_cache_size = SSL_SESSION_CACHE_MAX_SIZE_DEFAULT;
            // The authority assigns `meth->get_timeout()`; this slice stores the same seconds.
            (*ret).session_timeout = (*meth).timeout_secs;
            (*ret).max_cert_list = SSL_MAX_CERT_LIST_DEFAULT;
            (*ret).verify_mode = 0;

            (*ret).param = X509_VERIFY_PARAM_new();
            if (*ret).param.is_null() {
                SSL_CTX_free(ret);
                return ptr::null_mut();
            }
            (*ret).cert_store = X509_STORE_new();
            if (*ret).cert_store.is_null() {
                SSL_CTX_free(ret);
                return ptr::null_mut();
            }
            (*ret).cert = cert_new();
            if (*ret).cert.is_null() {
                SSL_CTX_free(ret);
                return ptr::null_mut();
            }
            if CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ret.cast(), &mut (*ret).ex_data) == 0 {
                SSL_CTX_free(ret);
                return ptr::null_mut();
            }

            (*ret).max_send_fragment = SSL3_RT_MAX_PLAIN_LENGTH as usize;
            (*ret).split_send_fragment = SSL3_RT_MAX_PLAIN_LENGTH as usize;
            // `ssl_lib.c:4220`: compression off by default, TLSv1.3 middlebox compat on.
            (*ret).options |= SSL_OP_NO_COMPRESSION | SSL_OP_ENABLE_MIDDLEBOX_COMPAT;
            (*ret).max_early_data = 0;
            (*ret).recv_max_early_data = SSL3_RT_MAX_PLAIN_LENGTH as u32;
            (*ret).num_tickets = 2;
        }
        ret
    })
}

/// `int SSL_CTX_up_ref(SSL_CTX *ctx)` — `ssl/ssl_lib.c:4338-4348`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_up_ref(ctx: *mut SslCtx) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `ctx` is live.
        let i = up_ref(unsafe { &(*ctx).references });
        if i <= 0 {
            0
        } else {
            c_int::from(i > 1)
        }
    })
}

/// `void SSL_CTX_free(SSL_CTX *ctx)` — `ssl/ssl_lib.c:4350-4468`.
///
/// # Safety
/// `ctx` must be NULL or a live context whose references are being released.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_free(ctx: *mut SslCtx) {
    guard_ffi((), || {
        if ctx.is_null() {
            return;
        }
        // SAFETY: the caller guarantees `ctx` is live.
        let i = down_ref(unsafe { &(*ctx).references });
        if i > 0 {
            return;
        }
        // SAFETY: the count reached zero, so this is the last reference and `ctx` is owned here.
        unsafe {
            X509_VERIFY_PARAM_free((*ctx).param);
            CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ctx.cast(), &mut (*ctx).ex_data);
            X509_STORE_free((*ctx).cert_store);
            cert_free((*ctx).cert);
            CRYPTO_THREAD_lock_free((*ctx).lock);
            CRYPTO_free((*ctx).propq.cast(), FILE, 4458);
            CRYPTO_free(ctx.cast(), FILE, 4467);
        }
    })
}

/// `SSL *SSL_new(SSL_CTX *ctx)` — `ssl/ssl_lib.c:690-701`.
///
/// # Safety
/// `ctx` must be NULL or a live context; the returned connection is owned by the caller.
#[no_mangle]
pub unsafe extern "C" fn SSL_new(ctx: *mut SslCtx) -> *mut Ssl {
    guard_ffi(ptr::null_mut(), || {
        if ctx.is_null() {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_NULL_SSL_CTX, 693) };
            return ptr::null_mut();
        }
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if unsafe { (*ctx).method }.is_null() {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION, 697) };
            return ptr::null_mut();
        }
        // SAFETY: `ctx` is non-NULL and live; its method was checked above.
        let method = unsafe { (*ctx).method };
        // SAFETY: a zeroed block of this size is a valid initial `Ssl` image.
        let s = CRYPTO_zalloc(core::mem::size_of::<Ssl>(), FILE, 731).cast::<Ssl>();
        if s.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `s` is a fresh zeroed allocation; every write below is to it.
        unsafe {
            (*s).references = AtomicI32::new(1);
            (*s).lock = CRYPTO_THREAD_lock_new();
            if (*s).lock.is_null() || SSL_CTX_up_ref(ctx) == 0 {
                CRYPTO_THREAD_lock_free((*s).lock);
                CRYPTO_free(s.cast(), FILE, 731);
                return ptr::null_mut();
            }
            (*s).ctx = ctx;
            (*s).method = method;
            (*s).defltmeth = method;
            (*s).type_ = SSL_TYPE_SSL_CONNECTION;
            // `tls1_clear` (`t1_lib.c:137-140`) installs `TLS_MAX_VERSION_INTERNAL` for an
            // any-version method, and `ossl_ssl_connection_reset` (`ssl_lib.c:607-608`) sets the
            // client version to the method's own version; the fresh connection therefore reports
            // `SSL_version == TLS1_3_VERSION` and `SSL_client_version == TLS_ANY_VERSION`.
            (*s).version = if (*method).version == TLS_ANY_VERSION {
                TLS_MAX_VERSION_INTERNAL
            } else {
                (*method).version
            };
            (*s).client_version = (*method).version;
            (*s).server = c_int::from((*method).default_server);
            (*s).rwstate = SSL_NOTHING;

            if CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL, s.cast(), &mut (*s).ex_data) == 0 {
                SSL_CTX_free(ctx);
                CRYPTO_THREAD_lock_free((*s).lock);
                CRYPTO_free(s.cast(), FILE, 731);
                return ptr::null_mut();
            }

            // `ssl_lib.c:731-971` copies the connection's configuration from the context.
            (*s).options = (*ctx).options;
            (*s).min_proto_version = (*ctx).min_proto_version;
            (*s).max_proto_version = (*ctx).max_proto_version;
            (*s).mode = (*ctx).mode;
            (*s).max_cert_list = (*ctx).max_cert_list;
            (*s).num_tickets = (*ctx).num_tickets;
            (*s).max_early_data = (*ctx).max_early_data;
            (*s).recv_max_early_data = (*ctx).recv_max_early_data;
            (*s).quiet_shutdown = (*ctx).quiet_shutdown;
            (*s).read_ahead = (*ctx).read_ahead;
            (*s).max_send_fragment = (*ctx).max_send_fragment;
            (*s).split_send_fragment = (*ctx).split_send_fragment;
            (*s).max_pipelines = (*ctx).max_pipelines;
            (*s).default_read_buf_len = (*ctx).default_read_buf_len;
            (*s).verify_mode = (*ctx).verify_mode;
            (*s).verify_result = X509_V_OK;
            (*s).sid_ctx = (*ctx).sid_ctx;
            (*s).sid_ctx_length = (*ctx).sid_ctx_length;
            (*s).default_passwd_callback = (*ctx).default_passwd_callback;
            (*s).default_passwd_callback_userdata = (*ctx).default_passwd_callback_userdata;
            (*s).verify_callback = (*ctx).default_verify_callback;
            (*s).msg_callback = (*ctx).msg_callback;
            (*s).msg_callback_arg = (*ctx).msg_callback_arg;
            (*s).not_resumable_session_cb = (*ctx).not_resumable_session_cb;
            (*s).record_padding_arg = (*ctx).record_padding_arg;
            (*s).async_cb = (*ctx).async_cb;
            (*s).async_cb_arg = (*ctx).async_cb_arg;
            (*s).psk_client_callback = (*ctx).psk_client_callback;
            (*s).psk_server_callback = (*ctx).psk_server_callback;
            (*s).psk_find_session_cb = (*ctx).psk_find_session_cb;
            (*s).psk_use_session_cb = (*ctx).psk_use_session_cb;
            (*s).generate_session_id = (*ctx).generate_session_id;

            (*s).param = X509_VERIFY_PARAM_new();
            if (*s).param.is_null() {
                SSL_free(s);
                return ptr::null_mut();
            }
            X509_VERIFY_PARAM_inherit((*s).param, (*ctx).param);

            (*s).cert = cert_new();
            if (*s).cert.is_null() {
                SSL_free(s);
                return ptr::null_mut();
            }
            cert_copy_security((*s).cert, (*ctx).cert);
        }
        s
    })
}

/// `int SSL_up_ref(SSL *s)` — `ssl/ssl_lib.c:1018-1028`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_up_ref(s: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `s` is live.
        let i = up_ref(unsafe { &(*s).references });
        if i <= 0 {
            0
        } else {
            c_int::from(i > 1)
        }
    })
}

/// `void SSL_free(SSL *s)` — `ssl/ssl_lib.c:1422-1443`.
///
/// # Safety
/// `s` must be NULL or a live connection whose references are being released.
#[no_mangle]
pub unsafe extern "C" fn SSL_free(s: *mut Ssl) {
    guard_ffi((), || {
        if s.is_null() {
            return;
        }
        // SAFETY: the caller guarantees `s` is live.
        let i = down_ref(unsafe { &(*s).references });
        if i > 0 {
            return;
        }
        // SAFETY: the count reached zero, so this is the last reference and `s` is owned here.
        unsafe {
            BIO_free_all((*s).wbio);
            BIO_free_all((*s).rbio);
            X509_VERIFY_PARAM_free((*s).param);
            cert_free((*s).cert);
            CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL, s.cast(), &mut (*s).ex_data);
            SSL_CTX_free((*s).ctx);
            CRYPTO_THREAD_lock_free((*s).lock);
            CRYPTO_free(s.cast(), FILE, 1442);
        }
    })
}

/// `SSL_CTX *SSL_get_SSL_CTX(const SSL *ssl)` — `ssl/ssl_lib.c:5487-5490`.
///
/// # Safety
/// `ssl` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_SSL_CTX(ssl: *const Ssl) -> *mut SslCtx {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the caller guarantees `ssl` is live.
        unsafe { (*ssl).ctx }
    })
}

/// `const SSL_METHOD *SSL_CTX_get_ssl_method(const SSL_CTX *ctx)` — `ssl/ssl_lib.c:4785-4788`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_ssl_method(ctx: *const SslCtx) -> *const SslMethod {
    guard_ffi(ptr::null(), || {
        // SAFETY: the caller guarantees `ctx` is live.
        unsafe { (*ctx).method }
    })
}

/// `const SSL_METHOD *SSL_get_ssl_method(const SSL *s)` — `ssl/ssl_lib.c:4790-4793`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_ssl_method(s: *const Ssl) -> *const SslMethod {
    guard_ffi(ptr::null(), || {
        // SAFETY: the caller guarantees `s` is live.
        unsafe { (*s).method }
    })
}

/// `int SSL_set_ssl_method(SSL *s, const SSL_METHOD *meth)` — `ssl/ssl_lib.c:4795-4824`.
///
/// The authority re-runs the method's `ssl_deinit`/`ssl_init` when the version changes; those are
/// `s3_lib.c` (14.2), so this slice records the new pointer and reports the authority's success.
///
/// # Safety
/// `s` must point to a live connection; `meth` must be a live method table.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_ssl_method(s: *mut Ssl, meth: *const SslMethod) -> c_int {
    guard_ffi(0, || {
        if s.is_null() || meth.is_null() {
            return 0;
        }
        // SAFETY: `s` is non-NULL and live.
        if unsafe { (*s).type_ } != SSL_TYPE_SSL_CONNECTION && unsafe { (*s).method } != meth {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).method = meth };
        1
    })
}

/// `int SSL_is_dtls(const SSL *s)` — `ssl/ssl_lib.c:978-991`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_is_dtls(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if unsafe { is_quic(s) } {
            return 0;
        }
        // SAFETY: `s` is NULL or live.
        c_int::from(unsafe { is_dtls(s) })
    })
}

/// `int SSL_is_tls(const SSL *s)` — `ssl/ssl_lib.c:993-1006`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_is_tls(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if unsafe { is_quic(s) } {
            return 0;
        }
        // SAFETY: `s` is NULL or live.
        c_int::from(!unsafe { is_dtls(s) })
    })
}

/// `int SSL_is_quic(const SSL *s)` — `ssl/ssl_lib.c:1008-1011`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_is_quic(s: *const Ssl) -> c_int {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi(0, || c_int::from(unsafe { is_quic(s) }))
}

/// `long SSL_get_default_timeout(const SSL *s)` — `ssl/ssl_lib.c:2228-2231`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_default_timeout(s: *const Ssl) -> c_long {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `s` is live.
        unsafe { (*(*s).method).timeout_secs as c_long }
    })
}

/// `int SSL_clear(SSL *s)` — `ssl/ssl_lib.c:567-575`.
///
/// The authority's body is `s->method->ssl_reset(s)` after the NULL-method check; that reset is
/// `ossl_ssl_connection_reset` (`ssl_lib.c:577-660`), which reaches the record layer (`14.4`) and
/// the state machine (`14.5`). Slice 1 performs the guard and reports the reset's own success.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_clear(s: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is non-NULL and live.
        if unsafe { (*s).method }.is_null() {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_NO_METHOD_SPECIFIED, 570) };
            return 0;
        }
        1
    })
}

// -------------------------------------------------------------------------------------------
// Ex-data and the security attribute block
// -------------------------------------------------------------------------------------------

/// `int SSL_set_ex_data(SSL *s, int idx, void *arg)` — `ssl/ssl_lib.c:5734-5737`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_ex_data(s: *mut Ssl, idx: c_int, arg: *mut c_void) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live and `ex_data` is its initialised block.
        unsafe { CRYPTO_set_ex_data(&mut (*s).ex_data, idx, arg) }
    })
}

/// `void *SSL_get_ex_data(const SSL *s, int idx)` — `ssl/ssl_lib.c:5739-5742`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_ex_data(s: *const Ssl, idx: c_int) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `s` is live and `ex_data` is its initialised block.
        unsafe { CRYPTO_get_ex_data(&(*s).ex_data, idx) }
    })
}

/// `int SSL_CTX_set_ex_data(SSL_CTX *s, int idx, void *arg)` — `ssl/ssl_lib.c:5744-5747`.
///
/// # Safety
/// `s` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_ex_data(
    ctx: *mut SslCtx,
    idx: c_int,
    arg: *mut c_void,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live and `ex_data` is its initialised block.
        unsafe { CRYPTO_set_ex_data(&mut (*ctx).ex_data, idx, arg) }
    })
}

/// `void *SSL_CTX_get_ex_data(const SSL_CTX *s, int idx)` — `ssl/ssl_lib.c:5749-5752`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_ex_data(ctx: *const SslCtx, idx: c_int) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `ctx` is live and `ex_data` is its initialised block.
        unsafe { CRYPTO_get_ex_data(&(*ctx).ex_data, idx) }
    })
}

/// `void SSL_set0_security_ex_data(SSL *s, void *ex)` — `ssl/ssl_lib.c:6203-6211`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set0_security_ex_data(s: *mut Ssl, ex: *mut c_void) {
    guard_ffi((), || {
        if s.is_null() {
            return;
        }
        // SAFETY: `s` is live and `cert` is its container.
        unsafe {
            if !(*s).cert.is_null() {
                (*(*s).cert).sec_ex = ex;
            }
        }
    })
}

/// `void *SSL_get0_security_ex_data(const SSL *s)` — `ssl/ssl_lib.c:6213-6221`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_security_ex_data(s: *const Ssl) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() || unsafe { (*s).cert }.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `s` and its `cert` are live.
        unsafe { (*(*s).cert).sec_ex }
    })
}

/// `void SSL_CTX_set0_security_ex_data(SSL_CTX *ctx, void *ex)` — `ssl/ssl_lib.c:6251-6254`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set0_security_ex_data(ctx: *mut SslCtx, ex: *mut c_void) {
    guard_ffi((), || {
        // SAFETY: `ctx` and its `cert` are live.
        unsafe {
            if !(*ctx).cert.is_null() {
                (*(*ctx).cert).sec_ex = ex;
            }
        }
    })
}

/// `void *SSL_CTX_get0_security_ex_data(const SSL_CTX *ctx)` — `ssl/ssl_lib.c:6256-6259`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get0_security_ex_data(ctx: *const SslCtx) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if ctx.is_null() || unsafe { (*ctx).cert }.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `ctx` and its `cert` are live.
        unsafe { (*(*ctx).cert).sec_ex }
    })
}

/// `void SSL_set_security_level(SSL *s, int level)` — `ssl/ssl_lib.c:6157-6165`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_security_level(s: *mut Ssl, level: c_int) {
    guard_ffi((), || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() || unsafe { (*s).cert }.is_null() {
            return;
        }
        // SAFETY: `s` and its `cert` are live.
        unsafe { (*(*s).cert).sec_level = level };
    })
}

/// `int SSL_get_security_level(const SSL *s)` — `ssl/ssl_lib.c:6167-6175`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_security_level(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() || unsafe { (*s).cert }.is_null() {
            return 0;
        }
        // SAFETY: `s` and its `cert` are live.
        unsafe { (*(*s).cert).sec_level }
    })
}

/// `void SSL_CTX_set_security_level(SSL_CTX *ctx, int level)` — `ssl/ssl_lib.c:6223-6226`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_security_level(ctx: *mut SslCtx, level: c_int) {
    guard_ffi((), || {
        // SAFETY: `ctx` and its `cert` are live.
        unsafe { (*(*ctx).cert).sec_level = level };
    })
}

/// `int SSL_CTX_get_security_level(const SSL_CTX *ctx)` — `ssl/ssl_lib.c:6228-6231`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_security_level(ctx: *const SslCtx) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` and its `cert` are live.
        unsafe { (*(*ctx).cert).sec_level }
    })
}

/// `void SSL_set_security_callback(SSL *s, ...)` — `ssl/ssl_lib.c:6177-6188`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_security_callback(s: *mut Ssl, cb: Option<SecurityCb>) {
    guard_ffi((), || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() || unsafe { (*s).cert }.is_null() {
            return;
        }
        // SAFETY: `s` and its `cert` are live.
        unsafe { (*(*s).cert).sec_cb = cb };
    })
}

/// `int (*SSL_get_security_callback(const SSL *s))(...)` — `ssl/ssl_lib.c:6190-6201`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_security_callback(s: *const Ssl) -> Option<SecurityCb> {
    guard_ffi(None, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() || unsafe { (*s).cert }.is_null() {
            return None;
        }
        // SAFETY: `s` and its `cert` are live.
        unsafe { (*(*s).cert).sec_cb }
    })
}

/// `void SSL_CTX_set_security_callback(SSL_CTX *ctx, ...)` — `ssl/ssl_lib.c:6233-6239`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_security_callback(ctx: *mut SslCtx, cb: Option<SecurityCb>) {
    guard_ffi((), || {
        // SAFETY: `ctx` and its `cert` are live.
        unsafe { (*(*ctx).cert).sec_cb = cb };
    })
}

/// `int (*SSL_CTX_get_security_callback(const SSL_CTX *ctx))(...)` — `ssl/ssl_lib.c:6241-6249`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_security_callback(ctx: *const SslCtx) -> Option<SecurityCb> {
    guard_ffi(None, || {
        // SAFETY: `ctx` and its `cert` are live.
        unsafe { (*(*ctx).cert).sec_cb }
    })
}

// -------------------------------------------------------------------------------------------
// Options, mode, verify, quiet-shutdown, shutdown, read-ahead, verify params
// -------------------------------------------------------------------------------------------

/// `uint64_t SSL_CTX_get_options(const SSL_CTX *ctx)` — `ssl/ssl_lib.c:6261-6264`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_options(ctx: *const SslCtx) -> u64 {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi(0, || unsafe { (*ctx).options })
}

/// `uint64_t SSL_CTX_set_options(SSL_CTX *ctx, uint64_t op)` — `ssl/ssl_lib.c:6281-6284`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_options(ctx: *mut SslCtx, op: u64) -> u64 {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live.
        unsafe {
            (*ctx).options |= op;
            (*ctx).options
        }
    })
}

/// `uint64_t SSL_CTX_clear_options(SSL_CTX *ctx, uint64_t op)` — `ssl/ssl_lib.c:6313-6316`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_clear_options(ctx: *mut SslCtx, op: u64) -> u64 {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live.
        unsafe {
            (*ctx).options &= !op;
            (*ctx).options
        }
    })
}

/// `uint64_t SSL_get_options(const SSL *s)` — `ssl/ssl_lib.c:6266-6279`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_options(s: *const Ssl) -> u64 {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).options }
    })
}

/// `uint64_t SSL_set_options(SSL *s, uint64_t op)` — `ssl/ssl_lib.c:6286-6311`.
///
/// The authority also propagates the value to the record layer's method
/// (`sc->rlayer.{rrlmethod,wrlmethod}->set_options`); that is 14.4's and is not modelled here.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_options(s: *mut Ssl, op: u64) -> u64 {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe {
            (*s).options |= op;
            (*s).options
        }
    })
}

/// `uint64_t SSL_clear_options(SSL *s, uint64_t op)` — `ssl/ssl_lib.c:6318-6342`.
///
/// As [`SSL_set_options`], the record-layer propagation is 14.4's.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_clear_options(s: *mut Ssl, op: u64) -> u64 {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe {
            (*s).options &= !op;
            (*s).options
        }
    })
}

/// `int SSL_CTX_get_verify_mode(const SSL_CTX *ctx)` — `ssl/ssl_lib.c:1860-1863`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_verify_mode(ctx: *const SslCtx) -> c_int {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi(0, || unsafe { (*ctx).verify_mode })
}

/// `int SSL_CTX_get_verify_depth(const SSL_CTX *ctx)` — `ssl/ssl_lib.c:1865-1868`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_verify_depth(ctx: *const SslCtx) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` and its `param` are live.
        unsafe { X509_VERIFY_PARAM_get_depth((*ctx).param) }
    })
}

/// `int (*SSL_CTX_get_verify_callback(const SSL_CTX *ctx))(int, X509_STORE_CTX *)` —
/// `ssl/ssl_lib.c:1870-1873`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_verify_callback(ctx: *const SslCtx) -> Option<VerifyCb> {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi(None, || unsafe { (*ctx).default_verify_callback })
}

/// `void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, int (*cb)(int, X509_STORE_CTX *))` —
/// `ssl/ssl_lib.c:4538-4543`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_verify(ctx: *mut SslCtx, mode: c_int, cb: Option<VerifyCb>) {
    guard_ffi((), || {
        // SAFETY: `ctx` is live.
        unsafe {
            (*ctx).verify_mode = mode;
            (*ctx).default_verify_callback = cb;
        }
    })
}

/// `void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth)` — `ssl/ssl_lib.c:4545-4548`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_verify_depth(ctx: *mut SslCtx, depth: c_int) {
    guard_ffi((), || {
        // SAFETY: `ctx` and its `param` are live.
        unsafe { X509_VERIFY_PARAM_set_depth((*ctx).param, depth) };
    })
}

/// `void SSL_CTX_set_cert_verify_callback(SSL_CTX *ctx, int (*cb)(X509_STORE_CTX *, void *), void *arg)`
/// — `ssl/ssl_lib.c:4530-4536`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_cert_verify_callback(
    ctx: *mut SslCtx,
    cb: Option<AppVerifyCb>,
    arg: *mut c_void,
) {
    guard_ffi((), || {
        // SAFETY: `ctx` is live.
        unsafe {
            (*ctx).app_verify_callback = cb;
            (*ctx).app_verify_arg = arg;
        }
    })
}

/// `int SSL_get_verify_mode(const SSL *s)` — `ssl/ssl_lib.c:1830-1838`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_verify_mode(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).verify_mode }
    })
}

/// `int SSL_get_verify_depth(const SSL *s)` — `ssl/ssl_lib.c:1840-1848`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_verify_depth(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` and its `param` are live.
        unsafe { X509_VERIFY_PARAM_get_depth((*s).param) }
    })
}

/// `int (*SSL_get_verify_callback(const SSL *s))(int, X509_STORE_CTX *)` — `ssl/ssl_lib.c:1850-1858`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_verify_callback(s: *const Ssl) -> Option<VerifyCb> {
    guard_ffi(None, || {
        if s.is_null() {
            return None;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).verify_callback }
    })
}

/// `void SSL_set_verify(SSL *s, int mode, int (*callback)(int, X509_STORE_CTX *))` —
/// `ssl/ssl_lib.c:1875-1886`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_verify(s: *mut Ssl, mode: c_int, callback: Option<VerifyCb>) {
    guard_ffi((), || {
        if s.is_null() {
            return;
        }
        // SAFETY: `s` is live.
        unsafe {
            (*s).verify_mode = mode;
            if callback.is_some() {
                (*s).verify_callback = callback;
            }
        }
    })
}

/// `void SSL_set_verify_depth(SSL *s, int depth)` — `ssl/ssl_lib.c:1888-1896`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_verify_depth(s: *mut Ssl, depth: c_int) {
    guard_ffi((), || {
        if s.is_null() {
            return;
        }
        // SAFETY: `s` and its `param` are live.
        unsafe { X509_VERIFY_PARAM_set_depth((*s).param, depth) };
    })
}

/// `void SSL_CTX_set_quiet_shutdown(SSL_CTX *ctx, int mode)` — `ssl/ssl_lib.c:5398-5401`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_quiet_shutdown(ctx: *mut SslCtx, mode: c_int) {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi((), || unsafe { (*ctx).quiet_shutdown = mode })
}

/// `int SSL_CTX_get_quiet_shutdown(const SSL_CTX *ctx)` — `ssl/ssl_lib.c:5403-5406`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_quiet_shutdown(ctx: *const SslCtx) -> c_int {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi(0, || unsafe { (*ctx).quiet_shutdown })
}

/// `void SSL_set_quiet_shutdown(SSL *s, int mode)` — `ssl/ssl_lib.c:5408-5417`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_quiet_shutdown(s: *mut Ssl, mode: c_int) {
    guard_ffi((), || {
        if s.is_null() {
            return;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).quiet_shutdown = mode };
    })
}

/// `int SSL_get_quiet_shutdown(const SSL *s)` — `ssl/ssl_lib.c:5419-5428`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_quiet_shutdown(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).quiet_shutdown }
    })
}

/// `void SSL_set_shutdown(SSL *s, int mode)` — `ssl/ssl_lib.c:5430-5439`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_shutdown(s: *mut Ssl, mode: c_int) {
    guard_ffi((), || {
        if s.is_null() {
            return;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).shutdown = mode };
    })
}

/// `int SSL_get_shutdown(const SSL *s)` — `ssl/ssl_lib.c:5441-5455`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_shutdown(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).shutdown }
    })
}

/// `int SSL_get_read_ahead(const SSL *s)` — `ssl/ssl_lib.c:1916-1924`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_read_ahead(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).read_ahead }
    })
}

/// `void SSL_set_read_ahead(SSL *s, int yes)` — `ssl/ssl_lib.c:1898-1914`.
///
/// The authority also propagates the flag to the record-layer method (`set_options`), which is
/// 14.4's.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_read_ahead(s: *mut Ssl, yes: c_int) {
    guard_ffi((), || {
        if s.is_null() {
            return;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).read_ahead = yes };
    })
}

/// `X509_VERIFY_PARAM *SSL_CTX_get0_param(SSL_CTX *ctx)` — `ssl/ssl_lib.c:1397-1400`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get0_param(ctx: *mut SslCtx) -> *mut X509VerifyParam {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi(ptr::null_mut(), || unsafe { (*ctx).param })
}

/// `X509_VERIFY_PARAM *SSL_get0_param(SSL *ssl)` — `ssl/ssl_lib.c:1402-1410`.
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_param(ssl: *mut Ssl) -> *mut X509VerifyParam {
    guard_ffi(ptr::null_mut(), || {
        if ssl.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `ssl` is live.
        unsafe { (*ssl).param }
    })
}

/// `int SSL_CTX_set1_param(SSL_CTX *ctx, X509_VERIFY_PARAM *vpm)` — `ssl/ssl_lib.c:1382-1385`.
///
/// # Safety
/// `ctx` must point to a live context; `vpm` must be NULL or a live verify-param block.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set1_param(ctx: *mut SslCtx, vpm: *mut X509VerifyParam) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` and its `param` are live; `vpm` is per the caller's contract.
        unsafe { X509_VERIFY_PARAM_set1((*ctx).param, vpm) }
    })
}

/// `int SSL_set1_param(SSL *ssl, X509_VERIFY_PARAM *vpm)` — `ssl/ssl_lib.c:1387-1395`.
///
/// # Safety
/// `ssl` must be NULL or a live connection; `vpm` must be NULL or a live verify-param block.
#[no_mangle]
pub unsafe extern "C" fn SSL_set1_param(ssl: *mut Ssl, vpm: *mut X509VerifyParam) -> c_int {
    guard_ffi(0, || {
        if ssl.is_null() {
            return 0;
        }
        // SAFETY: `ssl` and its `param` are live; `vpm` is per the caller's contract.
        unsafe { X509_VERIFY_PARAM_set1((*ssl).param, vpm) }
    })
}

/// `void SSL_set_verify_result(SSL *ssl, long arg)` — `ssl/ssl_lib.c:5662-5670`.
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_verify_result(ssl: *mut Ssl, arg: c_long) {
    guard_ffi((), || {
        if ssl.is_null() {
            return;
        }
        // SAFETY: `ssl` is live.
        unsafe { (*ssl).verify_result = arg };
    })
}

/// `long SSL_get_verify_result(const SSL *ssl)` — `ssl/ssl_lib.c:5672-5680`.
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_verify_result(ssl: *const Ssl) -> c_long {
    guard_ffi(0, || {
        if ssl.is_null() {
            return 0;
        }
        // SAFETY: `ssl` is live.
        unsafe { (*ssl).verify_result }
    })
}

// -------------------------------------------------------------------------------------------
// The control surface
// -------------------------------------------------------------------------------------------

/// `long SSL_ctrl(SSL *s, int cmd, long larg, void *parg)` — `ssl/ssl_lib.c:2943-2946`, via
/// `ossl_ctrl_internal` (`:2948-3074`).
///
/// For a command outside the explicit switch the authority falls through to `method->ssl_ctrl`
/// (`ssl3_ctrl`, 14.2); this slice returns 0, its documented fall-through divergence.
///
/// # Safety
/// `s` must be NULL or a live connection; `parg` must be valid for `cmd`'s interpretation.
#[no_mangle]
pub unsafe extern "C" fn SSL_ctrl(
    s: *mut Ssl,
    cmd: c_int,
    larg: c_long,
    parg: *mut c_void,
) -> c_long {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live for the whole dispatch.
        let sc = unsafe { &mut *s };
        match cmd {
            SSL_CTRL_GET_READ_AHEAD => sc.read_ahead as c_long,
            SSL_CTRL_SET_READ_AHEAD => {
                let old = sc.read_ahead as c_long;
                sc.read_ahead = larg as c_int;
                old
            }
            SSL_CTRL_MODE => {
                sc.mode |= larg as c_uint;
                sc.mode as c_long
            }
            SSL_CTRL_CLEAR_MODE => {
                sc.mode &= !(larg as c_uint);
                sc.mode as c_long
            }
            SSL_CTRL_GET_MAX_CERT_LIST => sc.max_cert_list as c_long,
            SSL_CTRL_SET_MAX_CERT_LIST => {
                if larg < 0 {
                    0
                } else {
                    let old = sc.max_cert_list as c_long;
                    sc.max_cert_list = larg as usize;
                    old
                }
            }
            SSL_CTRL_SET_MAX_SEND_FRAGMENT => {
                // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
                if !(512..=SSL3_RT_MAX_PLAIN_LENGTH).contains(&larg) {
                    0
                } else {
                    sc.max_send_fragment = larg as usize;
                    if sc.max_send_fragment < sc.split_send_fragment {
                        sc.split_send_fragment = sc.max_send_fragment;
                    }
                    1
                }
            }
            SSL_CTRL_SET_SPLIT_SEND_FRAGMENT => {
                if larg <= 0 || larg as usize > sc.max_send_fragment {
                    0
                } else {
                    sc.split_send_fragment = larg as usize;
                    1
                }
            }
            SSL_CTRL_SET_MAX_PIPELINES => {
                // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
                if !(1..=SSL_MAX_PIPELINES).contains(&larg) {
                    0
                } else {
                    sc.max_pipelines = larg as usize;
                    1
                }
            }
            // `sc->s3.send_connection_binding`, with no connection binding installed.
            SSL_CTRL_GET_RI_SUPPORT => 0,
            SSL_CTRL_CERT_FLAGS => {
                // SAFETY: `cert` is live for a live connection.
                let c = unsafe { &mut *sc.cert };
                c.cert_flags |= larg;
                c.cert_flags
            }
            SSL_CTRL_CLEAR_CERT_FLAGS => {
                // SAFETY: `cert` is live for a live connection.
                let c = unsafe { &mut *sc.cert };
                c.cert_flags &= !larg;
                c.cert_flags
            }
            SSL_CTRL_GET_RAW_CIPHERLIST => {
                // `SSL_CTRL_GET_RAW_CIPHERLIST`: no raw cipher list is installed (14.3).
                if parg.is_null() {
                    TLS_CIPHER_LEN as c_long
                } else {
                    0
                }
            }
            SSL_CTRL_GET_EXTMS_SUPPORT => -1, // no session, so the authority answers -1.
            SSL_CTRL_GET_MIN_PROTO_VERSION => sc.min_proto_version as c_long,
            SSL_CTRL_GET_MAX_PROTO_VERSION => sc.max_proto_version as c_long,
            _ => 0,
        }
    })
}

/// `long SSL_callback_ctrl(SSL *s, int cmd, void (*fp)(void))` — `ssl/ssl_lib.c:3076-3079`.
///
/// `SSL_CTRL_SET_MSG_CALLBACK` is the one command `ssl3_callback_ctrl` redirects to the connection;
/// the remaining commands are 14.2's.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_callback_ctrl(
    s: *mut Ssl,
    cmd: c_int,
    fp: Option<unsafe extern "C" fn()>,
) -> c_long {
    guard_ffi(0, || {
        // SAFETY: `s` is live.
        match cmd {
            SSL_CTRL_SET_MSG_CALLBACK => {
                // SAFETY: `s` is live; a `void (*)(void)` and this call's callback are both
                // pointer-sized, and only the stored bits are ever compared or returned.
                unsafe {
                    (*s).msg_callback = fp.map(|f| core::mem::transmute::<_, MsgCb>(f));
                }
                1
            }
            SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB => {
                // SAFETY: as above.
                unsafe {
                    (*s).not_resumable_session_cb =
                        fp.map(|f| core::mem::transmute::<_, NotResumableCb>(f));
                }
                1
            }
            _ => 0,
        }
    })
}

/// `long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)` — `ssl/ssl_lib.c:3097-3214`.
///
/// As [`SSL_ctrl`], the authority's fall-through is `method->ssl_ctx_ctrl` (`ssl3_ctx_ctrl`, 14.2)
/// and this slice returns 0.
///
/// # Safety
/// `ctx` must be NULL or a live context; `parg` must be valid for `cmd`'s interpretation.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_ctrl(
    ctx: *mut SslCtx,
    cmd: c_int,
    larg: c_long,
    parg: *mut c_void,
) -> c_long {
    guard_ffi(0, || {
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `ctx` is live for the whole dispatch.
        let c = unsafe { &mut *ctx };
        match cmd {
            SSL_CTRL_GET_READ_AHEAD => c.read_ahead as c_long,
            SSL_CTRL_SET_READ_AHEAD => {
                let old = c.read_ahead as c_long;
                c.read_ahead = larg as c_int;
                old
            }
            SSL_CTRL_SET_MSG_CALLBACK_ARG => {
                c.msg_callback_arg = parg;
                1
            }
            SSL_CTRL_GET_MAX_CERT_LIST => c.max_cert_list as c_long,
            SSL_CTRL_SET_MAX_CERT_LIST => {
                if larg < 0 {
                    0
                } else {
                    let old = c.max_cert_list as c_long;
                    c.max_cert_list = larg as usize;
                    old
                }
            }
            SSL_CTRL_SET_SESS_CACHE_SIZE => {
                if larg < 0 {
                    0
                } else {
                    let old = c.session_cache_size as c_long;
                    c.session_cache_size = larg as usize;
                    old
                }
            }
            SSL_CTRL_GET_SESS_CACHE_SIZE => c.session_cache_size as c_long,
            SSL_CTRL_SET_SESS_CACHE_MODE => {
                let old = c.session_cache_mode;
                c.session_cache_mode = larg;
                old
            }
            SSL_CTRL_GET_SESS_CACHE_MODE => c.session_cache_mode,
            SSL_CTRL_MODE => {
                c.mode |= larg as c_uint;
                c.mode as c_long
            }
            SSL_CTRL_CLEAR_MODE => {
                c.mode &= !(larg as c_uint);
                c.mode as c_long
            }
            SSL_CTRL_SET_MAX_SEND_FRAGMENT => {
                // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
                if !(512..=SSL3_RT_MAX_PLAIN_LENGTH).contains(&larg) {
                    0
                } else {
                    c.max_send_fragment = larg as usize;
                    if c.max_send_fragment < c.split_send_fragment {
                        c.split_send_fragment = c.max_send_fragment;
                    }
                    1
                }
            }
            SSL_CTRL_SET_SPLIT_SEND_FRAGMENT => {
                if larg <= 0 || larg as usize > c.max_send_fragment {
                    0
                } else {
                    c.split_send_fragment = larg as usize;
                    1
                }
            }
            SSL_CTRL_SET_MAX_PIPELINES => {
                // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
                if !(1..=SSL_MAX_PIPELINES).contains(&larg) {
                    0
                } else {
                    c.max_pipelines = larg as usize;
                    1
                }
            }
            SSL_CTRL_CERT_FLAGS => {
                // SAFETY: `cert` is live for a live context.
                let cert = unsafe { &mut *c.cert };
                cert.cert_flags |= larg;
                cert.cert_flags
            }
            SSL_CTRL_CLEAR_CERT_FLAGS => {
                // SAFETY: `cert` is live for a live context.
                let cert = unsafe { &mut *c.cert };
                cert.cert_flags &= !larg;
                cert.cert_flags
            }
            SSL_CTRL_GET_MIN_PROTO_VERSION => c.min_proto_version as c_long,
            SSL_CTRL_GET_MAX_PROTO_VERSION => c.max_proto_version as c_long,
            _ => 0,
        }
    })
}

/// `long SSL_CTX_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp)(void))` — `ssl/ssl_lib.c:3216-3228`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_callback_ctrl(
    ctx: *mut SslCtx,
    cmd: c_int,
    fp: Option<unsafe extern "C" fn()>,
) -> c_long {
    guard_ffi(0, || match cmd {
        SSL_CTRL_SET_MSG_CALLBACK => {
            // SAFETY: `ctx` is live; the same callback-pointer argument as `SSL_callback_ctrl`.
            unsafe {
                (*ctx).msg_callback = fp.map(|f| core::mem::transmute::<_, MsgCb>(f));
            }
            1
        }
        _ => 0,
    })
}

// -------------------------------------------------------------------------------------------
// Session-id context, generator, tickets and early data
// -------------------------------------------------------------------------------------------

/// `int SSL_CTX_set_session_id_context(SSL_CTX *ctx, const unsigned char *sid_ctx, unsigned int len)`
/// — `ssl/ssl_lib.c:1030-1041`.
///
/// # Safety
/// `ctx` must point to a live context; `sid_ctx` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_session_id_context(
    ctx: *mut SslCtx,
    sid_ctx: *const u8,
    sid_ctx_len: c_uint,
) -> c_int {
    guard_ffi(0, || {
        if sid_ctx_len as usize > SSL_MAX_SID_CTX_LENGTH {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG, 1034) };
            return 0;
        }
        // SAFETY: `ctx` is live; `sid_ctx` holds `sid_ctx_len` bytes per the caller.
        unsafe {
            (*ctx).sid_ctx_length = sid_ctx_len;
            ptr::copy_nonoverlapping(sid_ctx, (*ctx).sid_ctx.as_mut_ptr(), sid_ctx_len as usize);
        }
        1
    })
}

/// `int SSL_set_session_id_context(SSL *ssl, const unsigned char *sid_ctx, unsigned int len)` —
/// `ssl/ssl_lib.c:1043-1059`.
///
/// # Safety
/// `ssl` must be NULL or a live connection; `sid_ctx` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_session_id_context(
    ssl: *mut Ssl,
    sid_ctx: *const u8,
    sid_ctx_len: c_uint,
) -> c_int {
    guard_ffi(0, || {
        if ssl.is_null() {
            return 0;
        }
        if sid_ctx_len as usize > SSL_MAX_SID_CTX_LENGTH {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG, 1052) };
            return 0;
        }
        // SAFETY: `ssl` is live; `sid_ctx` holds `sid_ctx_len` bytes per the caller.
        unsafe {
            (*ssl).sid_ctx_length = sid_ctx_len;
            ptr::copy_nonoverlapping(sid_ctx, (*ssl).sid_ctx.as_mut_ptr(), sid_ctx_len as usize);
        }
        1
    })
}

/// `int SSL_CTX_set_generate_session_id(SSL_CTX *ctx, GEN_SESSION_CB cb)` — `ssl/ssl_lib.c:1061-1068`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_generate_session_id(
    ctx: *mut SslCtx,
    cb: Option<GenerateSessionIdCb>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).generate_session_id = cb };
        1
    })
}

/// `int SSL_set_generate_session_id(SSL *ssl, GEN_SESSION_CB cb)` — `ssl/ssl_lib.c:1070-1079`.
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_generate_session_id(
    ssl: *mut Ssl,
    cb: Option<GenerateSessionIdCb>,
) -> c_int {
    guard_ffi(0, || {
        if ssl.is_null() {
            return 0;
        }
        // SAFETY: `ssl` is live.
        unsafe { (*ssl).generate_session_id = cb };
        1
    })
}

/// `int SSL_CTX_set_num_tickets(SSL_CTX *ctx, size_t num_tickets)` — `ssl/ssl_lib.c:6081-6086`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_num_tickets(ctx: *mut SslCtx, num_tickets: usize) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).num_tickets = num_tickets };
        1
    })
}

/// `size_t SSL_CTX_get_num_tickets(const SSL_CTX *ctx)` — `ssl/ssl_lib.c:6088-6091`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_num_tickets(ctx: *const SslCtx) -> usize {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi(0, || unsafe { (*ctx).num_tickets })
}

/// `int SSL_set_num_tickets(SSL *s, size_t num_tickets)` — `ssl/ssl_lib.c:6059-6069`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_num_tickets(s: *mut Ssl, num_tickets: usize) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).num_tickets = num_tickets };
        1
    })
}

/// `size_t SSL_get_num_tickets(const SSL *s)` — `ssl/ssl_lib.c:6071-6079`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_num_tickets(s: *const Ssl) -> usize {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).num_tickets }
    })
}

/// `int SSL_CTX_set_max_early_data(SSL_CTX *ctx, uint32_t max_early_data)` —
/// `ssl/ssl_lib.c:4236-4250` region.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_max_early_data(
    ctx: *mut SslCtx,
    max_early_data: u32,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).max_early_data = max_early_data };
        1
    })
}

/// `uint32_t SSL_CTX_get_max_early_data(const SSL_CTX *ctx)` — `ssl/ssl_lib.c:7264-7267`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_max_early_data(ctx: *const SslCtx) -> u32 {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi(0, || unsafe { (*ctx).max_early_data })
}

/// `int SSL_set_max_early_data(SSL *s, uint32_t max_early_data)` — `ssl/ssl_lib.c:7269-7279`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_max_early_data(s: *mut Ssl, max_early_data: u32) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).max_early_data = max_early_data };
        1
    })
}

/// `uint32_t SSL_get_max_early_data(const SSL *s)` — `ssl/ssl_lib.c:7281-7289`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_max_early_data(s: *const Ssl) -> u32 {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).max_early_data }
    })
}

/// `int SSL_CTX_set_recv_max_early_data(SSL_CTX *ctx, uint32_t recv_max_early_data)` —
/// `ssl/ssl_lib.c:7291-7296`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_recv_max_early_data(
    ctx: *mut SslCtx,
    recv_max_early_data: u32,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).recv_max_early_data = recv_max_early_data };
        1
    })
}

/// `uint32_t SSL_CTX_get_recv_max_early_data(const SSL_CTX *ctx)` — `ssl/ssl_lib.c:7298-7301`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_recv_max_early_data(ctx: *const SslCtx) -> u32 {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi(0, || unsafe { (*ctx).recv_max_early_data })
}

/// `int SSL_set_recv_max_early_data(SSL *s, uint32_t recv_max_early_data)` —
/// `ssl/ssl_lib.c:7303-7313`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_recv_max_early_data(
    s: *mut Ssl,
    recv_max_early_data: u32,
) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).recv_max_early_data = recv_max_early_data };
        1
    })
}

/// `uint32_t SSL_get_recv_max_early_data(const SSL *s)` — `ssl/ssl_lib.c:7315-7331` region.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_recv_max_early_data(s: *const Ssl) -> u32 {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).recv_max_early_data }
    })
}

// -------------------------------------------------------------------------------------------
// Version and state readers
// -------------------------------------------------------------------------------------------

/// `const char *ssl_protocol_to_string(int version)` — `ssl/ssl_lib.c:5038-5068`.
fn protocol_to_string(version: c_int) -> *const c_char {
    match version {
        0x0304 => c"TLSv1.3".as_ptr(),
        0x0303 => c"TLSv1.2".as_ptr(),
        0x0302 => c"TLSv1.1".as_ptr(),
        0x0301 => c"TLSv1".as_ptr(),
        0x0300 => c"SSLv3".as_ptr(),
        // `DTLS1_BAD_VER` = 0x0100, `DTLS1_VERSION` = 0xFEFF, `DTLS1_2_VERSION` = 0xFEFD.
        0x0100 => c"DTLSv0.9".as_ptr(),
        0xFEFF => c"DTLSv1".as_ptr(),
        0xFEFD => c"DTLSv1.2".as_ptr(),
        _ => c"unknown".as_ptr(),
    }
}

/// `int SSL_version(const SSL *s)` — `ssl/ssl_lib.c:5457-5470`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_version(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if unsafe { is_quic(s) } {
            return 0x0001_0001; // OSSL_QUIC1_VERSION
        }
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).version }
    })
}

/// `int SSL_client_version(const SSL *s)` — `ssl/ssl_lib.c:5472-5485`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_client_version(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if unsafe { is_quic(s) } {
            return 0x0001_0001;
        }
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).client_version }
    })
}

/// `const char *SSL_get_version(const SSL *s)` — `ssl/ssl_lib.c:5070-5084`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_version(s: *const Ssl) -> *const c_char {
    guard_ffi(ptr::null(), || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if unsafe { is_quic(s) } {
            return c"QUICv1".as_ptr();
        }
        if s.is_null() {
            return ptr::null();
        }
        // SAFETY: `s` is live.
        protocol_to_string(unsafe { (*s).version })
    })
}

/// `int SSL_session_reused(const SSL *s)` — `ssl/ssl_lib.c:6128-6136`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_session_reused(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).hit }
    })
}

/// `int SSL_is_server(const SSL *s)` — `ssl/ssl_lib.c:6138-6146`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_is_server(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).server }
    })
}

/// `int SSL_want(const SSL *s)` — `ssl/ssl_lib.c:5773-5785`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_want(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).rwstate }
    })
}

/// `int SSL_get_error(const SSL *s, int i)` — `ssl/ssl_lib.c:4826-4829`, via
/// `ossl_ssl_get_error` (`:4831-4933`).
///
/// The BIO-flag arms (`BIO_should_read`/`_write`/`_io_special`) belong to the record layer and the
/// BIO pair (14.4/14.6) and are not reproduced; with no record layer installed they answer the
/// authority's final `SSL_ERROR_SYSCALL` anyway.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_error(s: *const Ssl, i: c_int) -> c_int {
    guard_ffi(0, || {
        if i > 0 {
            return SSL_ERROR_NONE;
        }
        if s.is_null() {
            return SSL_ERROR_SSL;
        }
        // SAFETY: reads the thread-local error queue.
        if ERR_peek_error() != 0 {
            return SSL_ERROR_SSL;
        }
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        let want = unsafe { (*s).rwstate };
        if want != SSL_READING && want != SSL_WRITING {
            return SSL_ERROR_SYSCALL;
        }
        SSL_ERROR_SYSCALL
    })
}

/// `int SSL_pending(const SSL *s)` — `ssl/ssl_lib.c:1926-1941`.
///
/// The authority's body is `s->method->ssl_pending(s)` (`ssl3_pending`), which reports the bytes
/// buffered in the record layer; this slice has no record layer, and `ssl3_pending` reports 0 for
/// an empty one.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_pending(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        0
    })
}

/// `int SSL_has_pending(const SSL *s)` — `ssl/ssl_lib.c:1943-1977`.
///
/// As [`SSL_pending`], the record layer is 14.4's and an empty one reports 0.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_has_pending(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        0
    })
}

/// `size_t SSL_get_finished(const SSL *s, void *buf, size_t count)` — `ssl/ssl_lib.c:1799-1812`.
///
/// The finished-message digest is the handshake's (14.5); before one runs `finish_md_len` is 0 and
/// the authority copies nothing.
///
/// # Safety
/// `s` must be NULL or a live connection; `buf` must hold `count` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_finished(
    s: *const Ssl,
    _buf: *mut c_void,
    _count: usize,
) -> usize {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        0
    })
}

/// `size_t SSL_get_peer_finished(const SSL *s, void *buf, size_t count)` — `ssl/ssl_lib.c:1815-1828`.
///
/// # Safety
/// `s` must be NULL or a live connection; `buf` must hold `count` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_peer_finished(
    s: *const Ssl,
    _buf: *mut c_void,
    _count: usize,
) -> usize {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        0
    })
}

// -------------------------------------------------------------------------------------------
// The callback setters and their getters
// -------------------------------------------------------------------------------------------

/// `void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb)` — `ssl/ssl_lib.c:4470-4473`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_default_passwd_cb(
    ctx: *mut SslCtx,
    cb: Option<PemPasswordCb>,
) {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi((), || unsafe { (*ctx).default_passwd_callback = cb })
}

/// `void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u)` — `ssl/ssl_lib.c:4475-4478`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_default_passwd_cb_userdata(ctx: *mut SslCtx, u: *mut c_void) {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi((), || unsafe {
        (*ctx).default_passwd_callback_userdata = u
    })
}

/// `pem_password_cb *SSL_CTX_get_default_passwd_cb(SSL_CTX *ctx)` — `ssl/ssl_lib.c:4480-4483`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_default_passwd_cb(ctx: *mut SslCtx) -> Option<PemPasswordCb> {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi(None, || unsafe { (*ctx).default_passwd_callback })
}

/// `void *SSL_CTX_get_default_passwd_cb_userdata(SSL_CTX *ctx)` — `ssl/ssl_lib.c:4485-4488`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_default_passwd_cb_userdata(ctx: *mut SslCtx) -> *mut c_void {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi(ptr::null_mut(), || unsafe {
        (*ctx).default_passwd_callback_userdata
    })
}

/// `void SSL_set_default_passwd_cb(SSL *s, pem_password_cb *cb)` — `ssl/ssl_lib.c:4490-4498`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_default_passwd_cb(s: *mut Ssl, cb: Option<PemPasswordCb>) {
    guard_ffi((), || {
        if s.is_null() {
            return;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).default_passwd_callback = cb };
    })
}

/// `void SSL_set_default_passwd_cb_userdata(SSL *s, void *u)` — `ssl/ssl_lib.c:4500-4508`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_default_passwd_cb_userdata(s: *mut Ssl, u: *mut c_void) {
    guard_ffi((), || {
        if s.is_null() {
            return;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).default_passwd_callback_userdata = u };
    })
}

/// `pem_password_cb *SSL_get_default_passwd_cb(SSL *s)` — `ssl/ssl_lib.c:4510-4518`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_default_passwd_cb(s: *mut Ssl) -> Option<PemPasswordCb> {
    guard_ffi(None, || {
        if s.is_null() {
            return None;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).default_passwd_callback }
    })
}

/// `void *SSL_get_default_passwd_cb_userdata(SSL *s)` — `ssl/ssl_lib.c:4520-4528`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_default_passwd_cb_userdata(s: *mut Ssl) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        if s.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `s` is live.
        unsafe { (*s).default_passwd_callback_userdata }
    })
}

/// `void SSL_set_info_callback(SSL *ssl, void (*cb)(const SSL *, int, int))` — `ssl/ssl_lib.c:5635-5644`.
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_info_callback(ssl: *mut Ssl, cb: Option<InfoCb>) {
    guard_ffi((), || {
        if ssl.is_null() {
            return;
        }
        // SAFETY: `ssl` is live.
        unsafe { (*ssl).info_callback = cb };
    })
}

/// `void (*SSL_get_info_callback(const SSL *ssl))(const SSL *, int, int)` — `ssl/ssl_lib.c:5650-5660`.
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_info_callback(ssl: *const Ssl) -> Option<InfoCb> {
    guard_ffi(None, || {
        if ssl.is_null() {
            return None;
        }
        // SAFETY: `ssl` is live.
        unsafe { (*ssl).info_callback }
    })
}

/// `void SSL_CTX_set_msg_callback(SSL_CTX *ctx, void (*cb)(...))` — `ssl/ssl_lib.c:5909-5915`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_msg_callback(ctx: *mut SslCtx, cb: Option<MsgCb>) {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi((), || unsafe { (*ctx).msg_callback = cb })
}

/// `void SSL_set_msg_callback(SSL *ssl, void (*cb)(...))` — `ssl/ssl_lib.c:5917-5923`.
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_msg_callback(ssl: *mut Ssl, cb: Option<MsgCb>) {
    guard_ffi((), || {
        if ssl.is_null() {
            return;
        }
        // SAFETY: `ssl` is live.
        unsafe { (*ssl).msg_callback = cb };
    })
}

/// `void SSL_CTX_set_cert_cb(SSL_CTX *c, int (*cb)(SSL *, void *), void *arg)` —
/// `ssl/ssl_lib.c:4550-4553`.
///
/// # Safety
/// `c` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_cert_cb(c: *mut SslCtx, cb: Option<CertCb>, arg: *mut c_void) {
    guard_ffi((), || {
        // SAFETY: `c` and its `cert` are live.
        unsafe {
            (*(*c).cert).cert_cb = cb;
            (*(*c).cert).cert_cb_arg = arg;
        }
    })
}

/// `void SSL_set_cert_cb(SSL *s, int (*cb)(SSL *, void *), void *arg)` — `ssl/ssl_lib.c:4555-...`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_cert_cb(s: *mut Ssl, cb: Option<CertCb>, arg: *mut c_void) {
    guard_ffi((), || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() || unsafe { (*s).cert }.is_null() {
            return;
        }
        // SAFETY: `s` and its `cert` are live.
        unsafe {
            (*(*s).cert).cert_cb = cb;
            (*(*s).cert).cert_cb_arg = arg;
        }
    })
}

/// `void SSL_CTX_set_client_hello_cb(SSL_CTX *c, SSL_client_hello_cb_fn cb, void *arg)` —
/// `ssl/ssl_lib.c:6763-...`.
///
/// # Safety
/// `c` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_client_hello_cb(
    c: *mut SslCtx,
    cb: Option<ClientHelloCb>,
    arg: *mut c_void,
) {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi((), || unsafe {
        (*c).client_hello_cb = cb;
        (*c).client_hello_cb_arg = arg;
    })
}

/// `void SSL_CTX_set_keylog_callback(SSL_CTX *ctx, SSL_CTX_keylog_cb_func cb)` — `ssl/ssl_lib.c:6992-...`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_keylog_callback(ctx: *mut SslCtx, cb: Option<KeylogCb>) {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi((), || unsafe { (*ctx).keylog_callback = cb })
}

/// `SSL_CTX_keylog_cb_func SSL_CTX_get_keylog_callback(const SSL_CTX *ctx)` — `ssl/ssl_lib.c:6997-...`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_keylog_callback(ctx: *const SslCtx) -> Option<KeylogCb> {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi(None, || unsafe { (*ctx).keylog_callback })
}

/// `void SSL_CTX_set_psk_client_callback(SSL_CTX *ctx, SSL_psk_client_cb_func cb)` —
/// `ssl/ssl_lib.c:5856-5859`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_psk_client_callback(
    ctx: *mut SslCtx,
    cb: Option<PskClientCb>,
) {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi((), || unsafe { (*ctx).psk_client_callback = cb })
}

/// `void SSL_set_psk_client_callback(SSL *s, SSL_psk_client_cb_func cb)` — `ssl/ssl_lib.c:5846-5854`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_psk_client_callback(s: *mut Ssl, cb: Option<PskClientCb>) {
    guard_ffi((), || {
        if s.is_null() {
            return;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).psk_client_callback = cb };
    })
}

/// `void SSL_CTX_set_psk_server_callback(SSL_CTX *ctx, SSL_psk_server_cb_func cb)` —
/// `ssl/ssl_lib.c:5871-5874`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_psk_server_callback(
    ctx: *mut SslCtx,
    cb: Option<PskServerCb>,
) {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi((), || unsafe { (*ctx).psk_server_callback = cb })
}

/// `void SSL_set_psk_server_callback(SSL *s, SSL_psk_server_cb_func cb)` — `ssl/ssl_lib.c:5861-5869`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_psk_server_callback(s: *mut Ssl, cb: Option<PskServerCb>) {
    guard_ffi((), || {
        if s.is_null() {
            return;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).psk_server_callback = cb };
    })
}

/// `void SSL_CTX_set_psk_find_session_callback(SSL_CTX *ctx, SSL_psk_find_session_cb_func cb)` —
/// `ssl/ssl_lib.c:5887-5891`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_psk_find_session_callback(
    ctx: *mut SslCtx,
    cb: Option<PskFindSessionCb>,
) {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi((), || unsafe { (*ctx).psk_find_session_cb = cb })
}

/// `void SSL_set_psk_find_session_callback(SSL *s, SSL_psk_find_session_cb_func cb)` —
/// `ssl/ssl_lib.c:5877-5885`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_psk_find_session_callback(
    s: *mut Ssl,
    cb: Option<PskFindSessionCb>,
) {
    guard_ffi((), || {
        if s.is_null() {
            return;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).psk_find_session_cb = cb };
    })
}

/// `void SSL_CTX_set_psk_use_session_callback(SSL_CTX *ctx, SSL_psk_use_session_cb_func cb)` —
/// `ssl/ssl_lib.c:5903-5907`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_psk_use_session_callback(
    ctx: *mut SslCtx,
    cb: Option<PskUseSessionCb>,
) {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi((), || unsafe { (*ctx).psk_use_session_cb = cb })
}

/// `void SSL_set_psk_use_session_callback(SSL *s, SSL_psk_use_session_cb_func cb)` —
/// `ssl/ssl_lib.c:5893-5901`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_psk_use_session_callback(
    s: *mut Ssl,
    cb: Option<PskUseSessionCb>,
) {
    guard_ffi((), || {
        if s.is_null() {
            return;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).psk_use_session_cb = cb };
    })
}

/// `int SSL_CTX_set_async_callback(SSL_CTX *ctx, SSL_async_callback_fn callback)` —
/// `ssl/ssl_lib.c:2140-2144`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_async_callback(
    ctx: *mut SslCtx,
    callback: Option<AsyncCb>,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).async_cb = callback };
        1
    })
}

/// `int SSL_CTX_set_async_callback_arg(SSL_CTX *ctx, void *arg)` — `ssl/ssl_lib.c:2146-2150`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_async_callback_arg(
    ctx: *mut SslCtx,
    arg: *mut c_void,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live.
        unsafe { (*ctx).async_cb_arg = arg };
        1
    })
}

/// `int SSL_set_async_callback(SSL *s, SSL_async_callback_fn callback)` — `ssl/ssl_lib.c:2152-2161`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_async_callback(s: *mut Ssl, callback: Option<AsyncCb>) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).async_cb = callback };
        1
    })
}

/// `int SSL_set_async_callback_arg(SSL *s, void *arg)` — `ssl/ssl_lib.c:2163-2172`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_async_callback_arg(s: *mut Ssl, arg: *mut c_void) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live.
        unsafe { (*s).async_cb_arg = arg };
        1
    })
}

/// `void SSL_CTX_set_not_resumable_session_callback(SSL_CTX *ctx, int (*cb)(SSL *, int))` —
/// `ssl/ssl_lib.c:5925-5932`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_not_resumable_session_callback(
    ctx: *mut SslCtx,
    cb: Option<NotResumableCb>,
) {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi((), || unsafe { (*ctx).not_resumable_session_cb = cb })
}

/// `void SSL_set_not_resumable_session_callback(SSL *ssl, int (*cb)(SSL *, int))` —
/// `ssl/ssl_lib.c:5934-5940`.
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_not_resumable_session_callback(
    ssl: *mut Ssl,
    cb: Option<NotResumableCb>,
) {
    guard_ffi((), || {
        if ssl.is_null() {
            return;
        }
        // SAFETY: `ssl` is live.
        unsafe { (*ssl).not_resumable_session_cb = cb };
    })
}

/// `void SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx, SSL_CTX_alpn_select_cb_func cb, void *arg)` —
/// `ssl/ssl_lib.c:3784-3790`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_alpn_select_cb(
    ctx: *mut SslCtx,
    cb: Option<AlpnSelectCb>,
    arg: *mut c_void,
) {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi((), || unsafe {
        (*ctx).alpn_select_cb = cb;
        (*ctx).alpn_select_cb_arg = arg;
    })
}

/// `void SSL_CTX_set_session_ticket_cb(SSL_CTX *ctx, SSL_session_ticket_key_cb cb, void *arg)` —
/// `ssl/ssl_lib.c:7451-...`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_session_ticket_cb(
    ctx: *mut SslCtx,
    cb: Option<SessionTicketCb>,
    arg: *mut c_void,
) {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi((), || unsafe {
        (*ctx).session_ticket_cb = cb;
        (*ctx).session_ticket_cb_arg = arg;
    })
}

/// `void SSL_CTX_set_allow_early_data_cb(SSL_CTX *ctx, SSL_allow_early_data_cb_fn cb, void *arg)` —
/// `ssl/ssl_lib.c:7462-...`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_allow_early_data_cb(
    ctx: *mut SslCtx,
    cb: Option<AllowEarlyDataCb>,
    arg: *mut c_void,
) {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi((), || unsafe {
        (*ctx).allow_early_data_cb = cb;
        (*ctx).allow_early_data_cb_data = arg;
    })
}

/// `void SSL_set_allow_early_data_cb(SSL *s, SSL_allow_early_data_cb_fn cb, void *arg)` —
/// `ssl/ssl_lib.c:7470-...`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_allow_early_data_cb(
    s: *mut Ssl,
    cb: Option<AllowEarlyDataCb>,
    arg: *mut c_void,
) {
    guard_ffi((), || {
        if s.is_null() {
            return;
        }
        // SAFETY: `s` is live.
        unsafe {
            (*s).allow_early_data_cb = cb;
            (*s).allow_early_data_cb_data = arg;
        }
    })
}

/// `void SSL_CTX_set_new_pending_conn_cb(SSL_CTX *ctx, SSL_new_pending_conn_cb cb, void *arg)` —
/// `ssl/ssl_lib.c:6770-...`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_new_pending_conn_cb(
    ctx: *mut SslCtx,
    cb: Option<NewPendingConnCb>,
    arg: *mut c_void,
) {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi((), || unsafe {
        (*ctx).new_pending_conn_cb = cb;
        (*ctx).new_pending_conn_cb_arg = arg;
    })
}

/// `void SSL_CTX_set_record_padding_callback(SSL_CTX *ctx, size_t (*cb)(SSL *, int, size_t, void *))`
/// — `ssl/ssl_lib.c:5942-5947`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_record_padding_callback(
    ctx: *mut SslCtx,
    cb: Option<RecordPaddingCb>,
) {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi((), || unsafe { (*ctx).record_padding_cb = cb })
}

/// `void SSL_CTX_set_record_padding_callback_arg(SSL_CTX *ctx, void *arg)` — `ssl/ssl_lib.c:5949-5952`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_record_padding_callback_arg(
    ctx: *mut SslCtx,
    arg: *mut c_void,
) {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi((), || unsafe { (*ctx).record_padding_arg = arg })
}

/// `void *SSL_CTX_get_record_padding_callback_arg(const SSL_CTX *ctx)` — `ssl/ssl_lib.c:5954-5957`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_record_padding_callback_arg(
    ctx: *const SslCtx,
) -> *mut c_void {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi(ptr::null_mut(), || unsafe { (*ctx).record_padding_arg })
}

/// `int SSL_set_record_padding_callback(SSL *ssl, size_t (*cb)(SSL *, int, size_t, void *))` —
/// `ssl/ssl_lib.c:5988-6004`.
///
/// The authority refuses the setter only when kTLS is active on the write BIO; that is 14.6's.
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_record_padding_callback(
    ssl: *mut Ssl,
    cb: Option<RecordPaddingCb>,
) -> c_int {
    guard_ffi(0, || {
        if ssl.is_null() {
            return 0;
        }
        // SAFETY: `ssl` is live.
        unsafe { (*ssl).record_padding_cb = cb };
        1
    })
}

/// `void SSL_set_record_padding_callback_arg(SSL *ssl, void *arg)` — `ssl/ssl_lib.c:6006-6014`.
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_record_padding_callback_arg(ssl: *mut Ssl, arg: *mut c_void) {
    guard_ffi((), || {
        if ssl.is_null() {
            return;
        }
        // SAFETY: `ssl` is live.
        unsafe { (*ssl).record_padding_arg = arg };
    })
}

/// `void *SSL_get_record_padding_callback_arg(const SSL *ssl)` — `ssl/ssl_lib.c:6016-6024`.
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_record_padding_callback_arg(ssl: *const Ssl) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        if ssl.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `ssl` is live.
        unsafe { (*ssl).record_padding_arg }
    })
}

// -------------------------------------------------------------------------------------------
// The BIO plumbing
// -------------------------------------------------------------------------------------------

/// `void SSL_set0_rbio(SSL *s, BIO *rbio)` — `ssl/ssl_lib.c:1549-1566`.
///
/// # Safety
/// `s` must be NULL or a live connection; `rbio` must be NULL or a live BIO whose reference is
/// transferred.
#[no_mangle]
pub unsafe extern "C" fn SSL_set0_rbio(s: *mut Ssl, rbio: *mut Bio) {
    guard_ffi((), || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() || unsafe { is_quic(s) } {
            return;
        }
        // SAFETY: `s` is live; `rbio` is per the caller's contract.
        unsafe {
            BIO_free_all((*s).rbio);
            (*s).rbio = rbio;
        }
    })
}

/// `void SSL_set0_wbio(SSL *s, BIO *wbio)` — `ssl/ssl_lib.c:1568-1596`.
///
/// The record-layer `set1_bio` call at `:1595` is 14.4's and is not modelled.
///
/// # Safety
/// `s` must be NULL or a live connection; `wbio` must be NULL or a live BIO whose reference is
/// transferred.
#[no_mangle]
pub unsafe extern "C" fn SSL_set0_wbio(s: *mut Ssl, wbio: *mut Bio) {
    guard_ffi((), || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() || unsafe { is_quic(s) } {
            return;
        }
        // SAFETY: `s`, `wbio` and the buffering filter are per the caller's contract.
        unsafe {
            if !(*s).bbio.is_null() {
                (*s).wbio = BIO_pop((*s).wbio);
            }
            BIO_free_all((*s).wbio);
            (*s).wbio = wbio;
            if !(*s).bbio.is_null() {
                (*s).wbio = BIO_push((*s).bbio, (*s).wbio);
            }
        }
    })
}

/// `void SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio)` — `ssl/ssl_lib.c:1598-1638`.
///
/// # Safety
/// `s` must be NULL or a live connection; `rbio`/`wbio` must be NULL or live BIOs whose references
/// are handled by the function's ownership rules.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_bio(s: *mut Ssl, rbio: *mut Bio, wbio: *mut Bio) {
    guard_ffi((), || {
        if s.is_null() {
            return;
        }
        // SAFETY: `s` is live; the getters read its own BIO slots.
        unsafe {
            if rbio == SSL_get_rbio(s) && wbio == SSL_get_wbio(s) {
                return;
            }
            if !rbio.is_null() && rbio == wbio && BIO_up_ref(rbio) == 0 {
                return;
            }
            if rbio == SSL_get_rbio(s) {
                SSL_set0_wbio(s, wbio);
                return;
            }
            if wbio == SSL_get_wbio(s) && SSL_get_rbio(s) != SSL_get_wbio(s) {
                SSL_set0_rbio(s, rbio);
                return;
            }
            SSL_set0_rbio(s, rbio);
            SSL_set0_wbio(s, wbio);
        }
    })
}

/// `BIO *SSL_get_rbio(const SSL *s)` — `ssl/ssl_lib.c:1640-1653`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_rbio(s: *const Ssl) -> *mut Bio {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() || unsafe { is_quic(s) } {
            return ptr::null_mut();
        }
        // SAFETY: `s` is live.
        unsafe { (*s).rbio }
    })
}

/// `BIO *SSL_get_wbio(const SSL *s)` — `ssl/ssl_lib.c:1655-1675`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_wbio(s: *const Ssl) -> *mut Bio {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() || unsafe { is_quic(s) } {
            return ptr::null_mut();
        }
        // SAFETY: `s` is live.
        unsafe {
            if !(*s).bbio.is_null() {
                return BIO_next((*s).bbio);
            }
            (*s).wbio
        }
    })
}

/// `int SSL_get_fd(const SSL *s)` — `ssl/ssl_lib.c:1677-1680`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_fd(s: *const Ssl) -> c_int {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi(-1, || unsafe { SSL_get_rfd(s) })
}

/// `int SSL_get_rfd(const SSL *s)` — `ssl/ssl_lib.c:1682-1692`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_rfd(s: *const Ssl) -> c_int {
    guard_ffi(-1, || {
        let mut ret: c_int = -1;
        // SAFETY: `s` is NULL or live; the getter reads its own slot.
        let b = unsafe { SSL_get_rbio(s) };
        // SAFETY: `b` is NULL or a live BIO.
        let r = unsafe { BIO_find_type(b, BIO_TYPE_DESCRIPTOR) };
        if !r.is_null() {
            // SAFETY: `r` is live; `ret` is a writable slot and `BIO_C_GET_FD` writes it.
            unsafe { BIO_ctrl(r, BIO_C_GET_FD, 0, (&mut ret as *mut c_int).cast()) };
        }
        ret
    })
}

/// `int SSL_get_wfd(const SSL *s)` — `ssl/ssl_lib.c:1694-1704`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_wfd(s: *const Ssl) -> c_int {
    guard_ffi(-1, || {
        let mut ret: c_int = -1;
        // SAFETY: `s` is NULL or live; the getter reads its own slot.
        let b = unsafe { SSL_get_wbio(s) };
        // SAFETY: `b` is NULL or a live BIO.
        let r = unsafe { BIO_find_type(b, BIO_TYPE_DESCRIPTOR) };
        if !r.is_null() {
            // SAFETY: `r` is live; `ret` is a writable slot and `BIO_C_GET_FD` writes it.
            unsafe { BIO_ctrl(r, BIO_C_GET_FD, 0, (&mut ret as *mut c_int).cast()) };
        }
        ret
    })
}

/// `int SSL_set_fd(SSL *s, int fd)` — `ssl/ssl_lib.c:1717-1738`.
///
/// # Safety
/// `s` must be NULL or a live connection; `fd` is adopted with `BIO_NOCLOSE`.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_fd(s: *mut Ssl, fd: c_int) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: the socket method is a live static table.
        let bio = unsafe { BIO_new(BIO_s_socket()) };
        if bio.is_null() {
            return 0;
        }
        // SAFETY: `bio` is live; `fd` is adopted without close-on-free.
        unsafe {
            BIO_int_ctrl(bio, BIO_C_SET_FD, BIO_NOCLOSE as c_long, fd);
            SSL_set_bio(s, bio, bio);
        }
        1
    })
}

/// `int SSL_set_wfd(SSL *s, int fd)` — `ssl/ssl_lib.c:1740-1766`.
///
/// # Safety
/// `s` must be NULL or a live connection; `fd` is adopted with `BIO_NOCLOSE`.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_wfd(s: *mut Ssl, fd: c_int) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live; the getters read their own slots.
        let rbio = unsafe { SSL_get_rbio(s) };
        // SAFETY: `rbio` is NULL or live.
        let same = !rbio.is_null()
            && unsafe { BIO_method_type(rbio) } == crate::runtime::bio::BIO_TYPE_SOCKET
            && {
                let mut got: c_int = -1;
                // SAFETY: `rbio` is live and `got` writable.
                unsafe { BIO_ctrl(rbio, BIO_C_GET_FD, 0, (&mut got as *mut c_int).cast()) };
                got == fd
            };
        if same {
            // SAFETY: `rbio` is live.
            if unsafe { BIO_up_ref(rbio) } == 0 {
                return 0;
            }
            // SAFETY: `s` is live.
            unsafe { SSL_set0_wbio(s, rbio) };
        } else {
            // SAFETY: the socket method is a live static table.
            let bio = unsafe { BIO_new(BIO_s_socket()) };
            if bio.is_null() {
                return 0;
            }
            // SAFETY: `bio` is live; `s` is live.
            unsafe {
                BIO_int_ctrl(bio, BIO_C_SET_FD, BIO_NOCLOSE as c_long, fd);
                SSL_set0_wbio(s, bio);
            }
        }
        1
    })
}

/// `int SSL_set_rfd(SSL *s, int fd)` — `ssl/ssl_lib.c:1768-1795`.
///
/// # Safety
/// `s` must be NULL or a live connection; `fd` is adopted with `BIO_NOCLOSE`.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_rfd(s: *mut Ssl, fd: c_int) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live; the getters read their own slots.
        let wbio = unsafe { SSL_get_wbio(s) };
        // SAFETY: `wbio` is NULL or live.
        let same = !wbio.is_null()
            && unsafe { BIO_method_type(wbio) } == crate::runtime::bio::BIO_TYPE_SOCKET
            && {
                let mut got: c_int = -1;
                // SAFETY: `wbio` is live and `got` writable.
                unsafe { BIO_ctrl(wbio, BIO_C_GET_FD, 0, (&mut got as *mut c_int).cast()) };
                got == fd
            };
        if same {
            // SAFETY: `wbio` is live.
            if unsafe { BIO_up_ref(wbio) } == 0 {
                return 0;
            }
            // SAFETY: `s` is live.
            unsafe { SSL_set0_rbio(s, wbio) };
        } else {
            // SAFETY: the socket method is a live static table.
            let bio = unsafe { BIO_new(BIO_s_socket()) };
            if bio.is_null() {
                return 0;
            }
            // SAFETY: `bio` is live; `s` is live.
            unsafe {
                BIO_int_ctrl(bio, BIO_C_SET_FD, BIO_NOCLOSE as c_long, fd);
                SSL_set0_rbio(s, bio);
            }
        }
        1
    })
}

// -------------------------------------------------------------------------------------------
// The error/read/write/handshake entry guards
// -------------------------------------------------------------------------------------------

/// `ssl_read_internal` — `ssl/ssl_lib.c:2312-2362`, reduced to the uninitialised guard.
///
/// # Safety
/// `s` must be NULL or a live connection; `buf` must hold `num` writable bytes and `readbytes` be
/// writable.
unsafe fn ssl_read_internal(
    s: *mut Ssl,
    _buf: *mut c_void,
    _num: usize,
    _readbytes: *mut usize,
) -> c_int {
    if s.is_null() {
        return -1;
    }
    // SAFETY: `s` is live.
    if unsafe { (*s).handshake_func }.is_none() {
        // SAFETY: a constant site.
        unsafe { raise_ssl(SSL_R_UNINITIALIZED, 2325) };
        return -1;
    }
    -1
}

/// `ssl_peek_internal` — `ssl/ssl_lib.c:2461-2497`, reduced to the uninitialised guard.
///
/// # Safety
/// As [`ssl_read_internal`].
unsafe fn ssl_peek_internal(
    s: *mut Ssl,
    _buf: *mut c_void,
    _num: usize,
    _readbytes: *mut usize,
) -> c_int {
    if s.is_null() {
        return -1;
    }
    // SAFETY: `s` is live.
    if unsafe { (*s).handshake_func }.is_none() {
        // SAFETY: a constant site.
        unsafe { raise_ssl(SSL_R_UNINITIALIZED, 2474) };
        return -1;
    }
    -1
}

/// `ssl_write_internal` — `ssl/ssl_lib.c:2530-2585`, reduced to the uninitialised guard.
///
/// # Safety
/// `s` must be NULL or a live connection; `buf` must hold `num` readable bytes and `written` be
/// writable.
unsafe fn ssl_write_internal(
    s: *mut Ssl,
    _buf: *const c_void,
    _num: usize,
    _flags: u64,
    _written: *mut usize,
) -> c_int {
    if s.is_null() {
        return 0;
    }
    // SAFETY: `s` is live.
    if unsafe { (*s).handshake_func }.is_none() {
        // SAFETY: a constant site.
        unsafe { raise_ssl(SSL_R_UNINITIALIZED, 2544) };
        return -1;
    }
    -1
}

/// `int SSL_read(SSL *s, void *buf, int num)` — `ssl/ssl_lib.c:2364-2384`.
///
/// # Safety
/// `s` must be NULL or a live connection; `buf` must hold `num` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_read(s: *mut Ssl, buf: *mut c_void, num: c_int) -> c_int {
    guard_ffi(-1, || {
        if num < 0 {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_BAD_LENGTH, 2370) };
            return -1;
        }
        let mut readbytes: usize = 0;
        // SAFETY: `s`/`buf` per the caller; `readbytes` is a live local.
        let mut ret = unsafe { ssl_read_internal(s, buf, num as usize, &mut readbytes) };
        if ret > 0 {
            ret = readbytes as c_int;
        }
        ret
    })
}

/// `int SSL_read_ex(SSL *s, void *buf, size_t num, size_t *readbytes)` — `ssl/ssl_lib.c:2386-2393`.
///
/// # Safety
/// `s` must be NULL or a live connection; `buf` must hold `num` writable bytes and `readbytes` be
/// writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_read_ex(
    s: *mut Ssl,
    buf: *mut c_void,
    num: usize,
    readbytes: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: per the caller's contract.
        let mut ret = unsafe { ssl_read_internal(s, buf, num, readbytes) };
        if ret < 0 {
            ret = 0;
        }
        ret
    })
}

/// `int SSL_peek(SSL *s, void *buf, int num)` — `ssl/ssl_lib.c:2499-2519`.
///
/// # Safety
/// `s` must be NULL or a live connection; `buf` must hold `num` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_peek(s: *mut Ssl, buf: *mut c_void, num: c_int) -> c_int {
    guard_ffi(-1, || {
        if num < 0 {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_BAD_LENGTH, 2505) };
            return -1;
        }
        let mut readbytes: usize = 0;
        // SAFETY: `s`/`buf` per the caller; `readbytes` is a live local.
        let mut ret = unsafe { ssl_peek_internal(s, buf, num as usize, &mut readbytes) };
        if ret > 0 {
            ret = readbytes as c_int;
        }
        ret
    })
}

/// `int SSL_peek_ex(SSL *s, void *buf, size_t num, size_t *readbytes)` — `ssl/ssl_lib.c:2521-2528`.
///
/// # Safety
/// `s` must be NULL or a live connection; `buf` must hold `num` writable bytes and `readbytes` be
/// writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_peek_ex(
    s: *mut Ssl,
    buf: *mut c_void,
    num: usize,
    readbytes: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: per the caller's contract.
        let mut ret = unsafe { ssl_peek_internal(s, buf, num, readbytes) };
        if ret < 0 {
            ret = 0;
        }
        ret
    })
}

/// `int SSL_write(SSL *s, const void *buf, int num)` — `ssl/ssl_lib.c:2654-2674`.
///
/// # Safety
/// `s` must be NULL or a live connection; `buf` must hold `num` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_write(s: *mut Ssl, buf: *const c_void, num: c_int) -> c_int {
    guard_ffi(-1, || {
        if num < 0 {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_BAD_LENGTH, 2660) };
            return -1;
        }
        let mut written: usize = 0;
        // SAFETY: `s`/`buf` per the caller; `written` is a live local.
        let mut ret = unsafe { ssl_write_internal(s, buf, num as usize, 0, &mut written) };
        if ret > 0 {
            ret = written as c_int;
        }
        ret
    })
}

/// `int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written)` — `ssl/ssl_lib.c:2676-2679`.
///
/// # Safety
/// `s` must be NULL or a live connection; `buf` must hold `num` readable bytes and `written` be
/// writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_write_ex(
    s: *mut Ssl,
    buf: *const c_void,
    num: usize,
    written: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: per the caller's contract.
        unsafe { SSL_write_ex2(s, buf, num, 0, written) }
    })
}

/// `int SSL_write_ex2(SSL *s, const void *buf, size_t num, uint64_t flags, size_t *written)` —
/// `ssl/ssl_lib.c:2681-2689`.
///
/// # Safety
/// `s` must be NULL or a live connection; `buf` must hold `num` readable bytes and `written` be
/// writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_write_ex2(
    s: *mut Ssl,
    buf: *const c_void,
    num: usize,
    flags: u64,
    written: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: per the caller's contract.
        let mut ret = unsafe { ssl_write_internal(s, buf, num, flags, written) };
        if ret < 0 {
            ret = 0;
        }
        ret
    })
}

/// `int SSL_do_handshake(SSL *s)` — `ssl/ssl_lib.c:4947-4984`, reduced to the type guard.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_do_handshake(s: *mut Ssl) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() || unsafe { is_quic(s) } {
            return -1;
        }
        // SAFETY: `s` is live.
        if unsafe { (*s).handshake_func }.is_none() {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_CONNECTION_TYPE_NOT_SET, 4961) };
            return -1;
        }
        1
    })
}

/// `int SSL_shutdown(SSL *s)` — `ssl/ssl_lib.c:2767-2807`, reduced to the uninitialised guard.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_shutdown(s: *mut Ssl) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() || unsafe { is_quic(s) } {
            return -1;
        }
        // SAFETY: `s` is live.
        if unsafe { (*s).handshake_func }.is_none() {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_UNINITIALIZED, 2786) };
            return -1;
        }
        -1
    })
}

// -------------------------------------------------------------------------------------------
// Certificate and store accessors
// -------------------------------------------------------------------------------------------

/// `X509 *SSL_get_certificate(const SSL *s)` — `ssl/ssl_lib.c:5268-5279`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_certificate(s: *const Ssl) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() || unsafe { (*s).cert }.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `s` and its `cert` are live.
        unsafe { (*(*s).cert).key.x509 }
    })
}

/// `EVP_PKEY *SSL_get_privatekey(const SSL *s)` — `ssl/ssl_lib.c:5281-5292`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_privatekey(s: *const Ssl) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() || unsafe { (*s).cert }.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `s` and its `cert` are live.
        unsafe { (*(*s).cert).key.privatekey }
    })
}

/// `X509 *SSL_CTX_get0_certificate(const SSL_CTX *ctx)` — `ssl/ssl_lib.c:5294-5300`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get0_certificate(ctx: *const SslCtx) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if unsafe { (*ctx).cert }.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `ctx` and its `cert` are live.
        unsafe { (*(*ctx).cert).key.x509 }
    })
}

/// `EVP_PKEY *SSL_CTX_get0_privatekey(const SSL_CTX *ctx)` — `ssl/ssl_lib.c:5302-5308`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get0_privatekey(ctx: *const SslCtx) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if unsafe { (*ctx).cert }.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `ctx` and its `cert` are live.
        unsafe { (*(*ctx).cert).key.privatekey }
    })
}

/// `STACK_OF(X509) *SSL_get0_verified_chain(const SSL *s)` — `ssl/ssl_lib.c:6344-6352`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_verified_chain(s: *const Ssl) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        if s.is_null() {
            return ptr::null_mut();
        }
        // The chain is built by the verify path (14.7) and is empty before one runs.
        ptr::null_mut()
    })
}

/// `X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *ctx)` — `ssl/ssl_lib.c:5754-5757`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_cert_store(ctx: *const SslCtx) -> *mut X509Store {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi(ptr::null_mut(), || unsafe { (*ctx).cert_store })
}

/// `void SSL_CTX_set_cert_store(SSL_CTX *ctx, X509_STORE *store)` — `ssl/ssl_lib.c:5759-5763`.
///
/// # Safety
/// `ctx` must point to a live context; `store` must be NULL or a live store whose reference is
/// transferred.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_cert_store(ctx: *mut SslCtx, store: *mut X509Store) {
    // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
    guard_ffi((), || unsafe {
        X509_STORE_free((*ctx).cert_store);
        (*ctx).cert_store = store;
    })
}

/// `void SSL_CTX_set1_cert_store(SSL_CTX *ctx, X509_STORE *store)` — `ssl/ssl_lib.c:5765-5771`.
///
/// # Safety
/// `ctx` must point to a live context; `store` must be NULL or a live store.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set1_cert_store(ctx: *mut SslCtx, store: *mut X509Store) {
    guard_ffi((), || {
        if !store.is_null() {
            // SAFETY: `store` is live and this takes a reference.
            if unsafe { X509_STORE_up_ref(store) } == 0 {
                return;
            }
        }
        // SAFETY: `ctx` is live; `store` is per the caller's contract.
        unsafe { SSL_CTX_set_cert_store(ctx, store) };
    })
}
