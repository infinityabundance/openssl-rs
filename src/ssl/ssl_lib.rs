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

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::asn1::string::ASN1_STRING_free;
use crate::bn::bignum::BigNum;
use crate::crypto_async::async_wait::{
    ASYNC_WAIT_CTX_get_all_fds, ASYNC_WAIT_CTX_get_changed_fds, ASYNC_WAIT_CTX_get_status,
    AsyncWaitCtx, OsslAsyncFd,
};
use crate::ct::ct_log::{
    CTLOG_STORE_free, CTLOG_STORE_load_default_file, CTLOG_STORE_load_file, CTLOG_STORE_new_ex,
    CtlogStore,
};
use crate::engine::eng_lib::Engine;
use crate::evp::digest::{EVP_MD_get_size, EvpMd};
use crate::evp::legacy_evp::EVP_get_digestbyname;
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_get_security_bits, EVP_PKEY_up_ref, EvpPkey};
use crate::ffi::guard_ffi;
use crate::packet::Packet;
use crate::runtime::bio::bss_sock::BIO_s_socket;
use crate::runtime::bio::iolib::{BIO_get_rpoll_descriptor, BIO_get_wpoll_descriptor};
use crate::runtime::bio::sys::memcmp;
use crate::runtime::bio::{
    BIO_ctrl, BIO_find_type, BIO_free_all, BIO_int_ctrl, BIO_method_type, BIO_new, BIO_next,
    BIO_pop, BIO_push, BIO_up_ref, Bio, BioPollDescriptor, BIO_C_GET_FD, BIO_C_SET_FD, BIO_NOCLOSE,
    BIO_TYPE_DESCRIPTOR,
};
use crate::runtime::err::err_reasons::{
    SSL_R_CONTEXT_NOT_DANE_ENABLED, SSL_R_DANE_ALREADY_ENABLED,
    SSL_R_DANE_CANNOT_OVERRIDE_MTYPE_FULL, SSL_R_DANE_NOT_ENABLED, SSL_R_DANE_TLSA_BAD_CERTIFICATE,
    SSL_R_DANE_TLSA_BAD_CERTIFICATE_USAGE, SSL_R_DANE_TLSA_BAD_DATA_LENGTH,
    SSL_R_DANE_TLSA_BAD_DIGEST_LENGTH, SSL_R_DANE_TLSA_BAD_MATCHING_TYPE,
    SSL_R_DANE_TLSA_BAD_PUBLIC_KEY, SSL_R_DANE_TLSA_BAD_SELECTOR, SSL_R_DANE_TLSA_NULL_DATA,
    SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST, SSL_R_ERROR_SETTING_TLSA_BASE_DOMAIN,
    SSL_R_NO_CIPHERS_SPECIFIED,
};
use crate::runtime::err::{raise_with, ERR_peek_error, ERR_pop_to_mark, ERR_set_mark};
use crate::runtime::ex_data::{
    CRYPTO_dup_ex_data, CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data,
    CRYPTO_set_ex_data, CryptoExData, CRYPTO_EX_INDEX_SSL, CRYPTO_EX_INDEX_SSL_CTX,
};
use crate::runtime::mem::{
    CRYPTO_calloc, CRYPTO_free, CRYPTO_malloc, CRYPTO_memdup, CRYPTO_realloc_array, CRYPTO_strdup,
    CRYPTO_zalloc,
};
use crate::runtime::obj::{NID_sha256, NID_sha512, NID_undef, OBJ_nid2sn};
use crate::runtime::stack::{
    OPENSSL_sk_dup, OPENSSL_sk_find, OPENSSL_sk_free, OPENSSL_sk_insert, OPENSSL_sk_new_null,
    OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
    OpenSslStack,
};
use crate::runtime::thread::{CRYPTO_THREAD_lock_free, CRYPTO_THREAD_lock_new, CryptoRwlock};
use crate::ssl::d1_lib::{dtls1_free, dtls1_new_state, Dtls1State};
use crate::ssl::quic::quic_tls_api::QuicTlsCallbacks;
use crate::ssl::s3_lib::ssl3_ctrl_set_tlsext_host_name;
use crate::ssl::ssl_cert::{ssl_ctx_security, ssl_security};
use crate::ssl::ssl_ciph::ssl3_get_cipher_by_char;
use crate::ssl::ssl_ciph_table::SslCipher;
use crate::ssl::ssl_conf::ssl_set_version_bound;
use crate::ssl::ssl_sess::{
    ssl_ctx_session_cache_free, SSL_SESSION_free, SSL_get_session, SSL_set_session,
};
use crate::ssl::statem::extensions_cust::{
    custom_exts_copy, custom_exts_copy_conn, custom_exts_copy_flags, CustomExtMethod,
};
use crate::ssl::statem::statem::{
    ossl_statem_accept, ossl_statem_check_finish_init, ossl_statem_clear, ossl_statem_connect,
    ossl_statem_in_error, ossl_statem_set_in_init, SSL_in_before, SSL_in_init,
    SSL_is_init_finished,
};
use crate::ssl::t1_lib::{ssl_cipher_disabled, ssl_set_client_disabled};
use crate::x509::by_dir::X509_LOOKUP_hash_dir;
use crate::x509::by_file::X509_LOOKUP_file;
use crate::x509::by_store::X509_LOOKUP_store;
use crate::x509::dane::{
    danetls_enabled, danetls_usage_bit, DaneCtx, DanetlsRecord, SslDane, DANETLS_MATCHING_2256,
    DANETLS_MATCHING_2512, DANETLS_MATCHING_FULL, DANETLS_MATCHING_LAST, DANETLS_SELECTOR_CERT,
    DANETLS_SELECTOR_LAST, DANETLS_SELECTOR_SPKI, DANETLS_TA_MASK, DANETLS_USAGE_DANE_EE,
    DANETLS_USAGE_DANE_TA, DANETLS_USAGE_LAST,
};
use crate::x509::t_x509::OSSL_STACK_OF_X509_free;
use crate::x509::v3_utl::a2i_IPADDRESS;
use crate::x509::x509_cmp::{X509_chain_up_ref, X509_check_private_key, X509_get0_pubkey};
use crate::x509::x509_d2::{
    X509_STORE_load_file_ex, X509_STORE_load_path, X509_STORE_load_store_ex,
    X509_STORE_set_default_paths_ex,
};
use crate::x509::x509_lu::{
    X509Store, X509_LOOKUP_ctrl, X509_LOOKUP_ctrl_ex, X509_STORE_add_lookup, X509_STORE_free,
    X509_STORE_new, X509_STORE_up_ref,
};
use crate::x509::x509_set::X509_up_ref;
use crate::x509::x509_vpm::{
    X509VerifyParam, X509_VERIFY_PARAM_add1_host, X509_VERIFY_PARAM_free,
    X509_VERIFY_PARAM_get0_peername, X509_VERIFY_PARAM_get1_ip_asc, X509_VERIFY_PARAM_get_depth,
    X509_VERIFY_PARAM_inherit, X509_VERIFY_PARAM_new, X509_VERIFY_PARAM_set1,
    X509_VERIFY_PARAM_set1_host, X509_VERIFY_PARAM_set1_ip, X509_VERIFY_PARAM_set1_ip_asc,
    X509_VERIFY_PARAM_set_depth, X509_VERIFY_PARAM_set_hostflags, X509_VERIFY_PARAM_set_purpose,
    X509_VERIFY_PARAM_set_trust,
};
use crate::x509::x_name::{X509Name, X509_NAME_dup, X509_NAME_free};
use crate::x509::x_pubkey::{d2i_PUBKEY, i2d_PUBKEY};
use crate::x509::x_x509::{d2i_X509, X509_free, X509};

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
/// `SSL_R_NO_METHOD_SPECIFIED` — `sslerr.h:188`.
const SSL_R_NO_METHOD_SPECIFIED: c_int = 188;
/// `SSL_R_NO_CERTIFICATE_ASSIGNED` — `sslerr.h:177`.
const SSL_R_NO_CERTIFICATE_ASSIGNED: c_int = 177;
/// `SSL_R_NO_PRIVATE_KEY_ASSIGNED` — `sslerr.h:190`.
const SSL_R_NO_PRIVATE_KEY_ASSIGNED: c_int = 190;
/// `SSL_R_DATA_LENGTH_TOO_LONG` — `sslerr.h:146`.
const SSL_R_DATA_LENGTH_TOO_LONG: c_int = 146;
/// `SSL_R_INVALID_CT_VALIDATION_TYPE` — `sslerr.h:212`.
const SSL_R_INVALID_CT_VALIDATION_TYPE: c_int = 212;
/// `SSL_R_NO_VALID_SCTS` — `sslerr.h:216`.
const SSL_R_NO_VALID_SCTS: c_int = 216;
/// `SSL_R_UNSUPPORTED_PROTOCOL` — `sslerr.h:258`.
const SSL_R_UNSUPPORTED_PROTOCOL: c_int = 258;
/// `SSL_R_WRONG_SSL_VERSION` — `sslerr.h:266`.
const SSL_R_WRONG_SSL_VERSION: c_int = 266;
/// `SSL_R_INVALID_KEY_UPDATE_TYPE` — `sslerr.h:120`.
const SSL_R_INVALID_KEY_UPDATE_TYPE: c_int = 120;
/// `SSL_R_STILL_IN_INIT` — `sslerr.h:121`.
const SSL_R_STILL_IN_INIT: c_int = 121;
/// `SSL_R_BAD_WRITE_RETRY` — `sslerr.h:127`.
const SSL_R_BAD_WRITE_RETRY: c_int = 127;
/// `SSL_R_NO_RENEGOTIATION` — `sslerr.h:339`.
const SSL_R_NO_RENEGOTIATION: c_int = 339;
/// `SSL_R_NOT_SERVER` — `sslerr.h:284`.
const SSL_R_NOT_SERVER: c_int = 284;
/// `SSL_R_EXTENSION_NOT_RECEIVED` — `sslerr.h:279`.
const SSL_R_EXTENSION_NOT_RECEIVED: c_int = 279;
/// `SSL_R_REQUEST_PENDING` — `sslerr.h:285`.
const SSL_R_REQUEST_PENDING: c_int = 285;
/// `SSL_R_REQUEST_SENT` — `sslerr.h:286`.
const SSL_R_REQUEST_SENT: c_int = 286;
/// `SSL_R_PROTOCOL_IS_SHUTDOWN` — `sslerr.h:207`.
const SSL_R_PROTOCOL_IS_SHUTDOWN: c_int = 207;
/// `SSL_R_UNSUPPORTED_WRITE_FLAG` — `sslerr.h:412`.
const SSL_R_UNSUPPORTED_WRITE_FLAG: c_int = 412;
/// `SSL_R_INVALID_CONFIG` — `sslerr.h:283`.
const SSL_R_INVALID_CONFIG: c_int = 283;
/// `SSL_KEY_UPDATE_NOT_REQUESTED` — `ssl.h:1003`.
const SSL_KEY_UPDATE_NOT_REQUESTED: c_int = 0;
/// `SSL_KEY_UPDATE_REQUESTED` — `ssl.h:1004`.
const SSL_KEY_UPDATE_REQUESTED: c_int = 1;
/// `SSL_OP_NO_RENEGOTIATION` — `ssl.h:413` (`SSL_OP_BIT(30)`).
const SSL_OP_NO_RENEGOTIATION: u64 = 1 << 30;
/// `TLS1_VERSION` — `tls1.h:199`.
const TLS1_VERSION: c_int = 0x0301;
/// `DTLS1_BAD_VER` — `ssl3.h:231`.
const DTLS1_BAD_VER: c_int = 0x0100;
/// `SSL_SENT_SHUTDOWN` — `ssl.h:216`.
const SSL_SENT_SHUTDOWN: c_int = 1;
/// `SSL_RECEIVED_SHUTDOWN` — `ssl.h:217`.
const SSL_RECEIVED_SHUTDOWN: c_int = 2;
/// `SSL_AD_CLOSE_NOTIFY` — `ssl3.h:240`.
const SSL_AD_CLOSE_NOTIFY: c_int = 0;
/// `SSL_AD_INTERNAL_ERROR` — `ssl3.h` (80).
const SSL_AD_INTERNAL_ERROR: c_int = 80;
/// `SSL3_AL_WARNING` — `ssl3.h:252`.
const SSL3_AL_WARNING: c_int = 1;
/// `SSL_R_SHUTDOWN_WHILE_IN_INIT` — `sslerr.h:262`.
const SSL_R_SHUTDOWN_WHILE_IN_INIT: c_int = 407;
/// `SSL_EARLY_DATA_CONNECT_RETRY` — `ssl_local.h:592`.
const SSL_EARLY_DATA_CONNECT_RETRY: c_int = 1;
/// `SSL_EARLY_DATA_ACCEPT_RETRY` — `ssl_local.h:599`.
const SSL_EARLY_DATA_ACCEPT_RETRY: c_int = 8;
/// `SSL_EARLY_DATA_WRITE_RETRY` — `ssl_local.h:594`.
const SSL_EARLY_DATA_WRITE_RETRY: c_int = 3;
/// `SSL_EARLY_DATA_FINISHED_READING` — `ssl_local.h:603`.
const SSL_EARLY_DATA_FINISHED_READING: c_int = 12;
/// `SSL_EARLY_DATA_READ_RETRY` — `ssl_local.h:601`.
const SSL_EARLY_DATA_READ_RETRY: c_int = 10;
/// `SSL_EARLY_DATA_NONE` — `ssl_local.h:591`.
const SSL_EARLY_DATA_NONE: c_int = 0;
/// `SSL_EARLY_DATA_CONNECTING` — `ssl_local.h:593`.
const SSL_EARLY_DATA_CONNECTING: c_int = 2;
/// `SSL_EARLY_DATA_ACCEPTING` — `ssl_local.h:600`.
const SSL_EARLY_DATA_ACCEPTING: c_int = 9;
/// `SSL_EARLY_DATA_READING` — `ssl_local.h:602`.
const SSL_EARLY_DATA_READING: c_int = 11;
/// `SSL_EARLY_DATA_ACCEPTED` — `ssl.h:1990`.
const SSL_EARLY_DATA_ACCEPTED: c_int = 2;
/// `SSL_READ_EARLY_DATA_ERROR` — `ssl.h:1963`.
const SSL_READ_EARLY_DATA_ERROR: c_int = 0;
/// `SSL_READ_EARLY_DATA_FINISH` — `ssl.h:1965`.
const SSL_READ_EARLY_DATA_FINISH: c_int = 2;
/// `SSL_PHA_NONE` — `ssl_local.h:371`.
const SSL_PHA_NONE: c_int = 0;
/// `SSL_PHA_EXT_SENT` — `ssl_local.h:372`.
const SSL_PHA_EXT_SENT: c_int = 1;
/// `SSL_PHA_EXT_RECEIVED` — `ssl_local.h:373`.
const SSL_PHA_EXT_RECEIVED: c_int = 2;
/// `SSL_PHA_REQUEST_PENDING` — `ssl_local.h:374`.
const SSL_PHA_REQUEST_PENDING: c_int = 3;
/// `SSL_PHA_REQUESTED` — `ssl_local.h:375`.
const SSL_PHA_REQUESTED: c_int = 4;
/// `TLS1_FLAGS_STATELESS` — `tls1.h:263`.
const TLS1_FLAGS_STATELESS: u64 = 0x0002_0000;
/// `SSL_HRR_PENDING` — `ssl_local.h:1535`.
const SSL_HRR_PENDING: c_int = 1;
/// `ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED` — `err.h.in:355` (`257 | ERR_R_FATAL`, `ERR_R_FATAL = 3 << 18`).
const ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED: c_int = 257 | (3 << 18);
/// `ERR_R_UNSUPPORTED` — `err.h.in:366` (`268 | ERR_RFLAG_COMMON`, `ERR_RFLAG_COMMON = 2 << 18`).
const ERR_R_UNSUPPORTED: c_int = 268 | (2 << 18);
/// `ERR_R_CRYPTO_LIB` — `err.h` (`15 | ERR_RFLAG_COMMON`).
const ERR_R_CRYPTO_LIB: c_int = 15 | (2 << 18);
/// `ERR_R_PASSED_INVALID_ARGUMENT` — `err.h.in:360` (`262 | ERR_RFLAG_COMMON`).
const ERR_R_PASSED_INVALID_ARGUMENT: c_int = 262 | (2 << 18);

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
/// `TLS_MAX_VERSION_INTERNAL` — `ssl_local.h:50`: `tls1_clear` installs it for an any-version method.
const TLS_MAX_VERSION_INTERNAL: c_int = TLS1_3_VERSION;
/// `DTLS1_VERSION_MAJOR` — `include/openssl/dtls1.h`; the `ssl_check_allowed_versions`
/// family test (`ssl/ssl_lib.c:452`) shifts a version by 8 and compares to it.
const DTLS1_VERSION_MAJOR: c_int = 0xFE;
/// `DTLS1_2_VERSION` — `include/openssl/prov_ssl.h:29`; the max a DTLS method negotiates.
const DTLS1_2_VERSION: c_int = 0xFEFD;
/// `DTLS_ANY_VERSION` — `include/openssl/dtls1.h:35`; the version `DTLS_method` carries.
pub const DTLS_ANY_VERSION: c_int = 0x1_FFFF;
/// `DTLS_MAX_VERSION_INTERNAL` — `ssl_local.h:51`: `dtls1_clear` installs it for an
/// any-version method (`d1_lib.c:217`).
const DTLS_MAX_VERSION_INTERNAL: c_int = DTLS1_2_VERSION;

/// `SSL_MAX_SID_CTX_LENGTH` — `ssl.h:64`.
pub const SSL_MAX_SID_CTX_LENGTH: usize = 32;
/// `SSL_PKEY_NUM` — `ssl_local.h:328`.
pub const SSL_PKEY_NUM: usize = 9;
/// `SSL_PKEY_RSA` — `ssl_local.h:319`.
pub const SSL_PKEY_RSA: usize = 0;
/// `TLSEXT_comp_cert_limit` — `tls1.h:216`.
pub const TLSEXT_COMP_CERT_LIMIT: usize = 4;
/// `SSL_MAX_SSL_SESSION_ID_LENGTH` — `ssl.h:64`.
pub const SSL_MAX_SSL_SESSION_ID_LENGTH: usize = 32;
/// `SSL3_MAX_SSL_SESSION_ID_LENGTH` — `ssl3.h:134`.
pub const SSL3_MAX_SSL_SESSION_ID_LENGTH: usize = 32;
/// `TLS13_MAX_RESUMPTION_PSK_LENGTH` — `ssl_local.h:448`.
pub const TLS13_MAX_RESUMPTION_PSK_LENGTH: usize = 512;
/// `EVP_MAX_MD_SIZE` — `evp.h`.
pub const EVP_MAX_MD_SIZE: usize = 64;
/// The reduced transcript buffer's capacity — the authority's `s3.handshake_buffer` (`BUF_MEM`)
/// holds the handshake bytes seen before the cipher (and so the hash) is known
/// (`ssl/statem/statem.c`). A fixed 16 KiB covers the reduced flight (`ClientHello` through
/// `Finished`), so the reduced schedule buffers instead of allocating a `BUF_MEM` (17.2c).
pub(crate) const TLS13_HS_BUF_LEN: usize = 16384;
/// `SSL_MAX_MASTER_KEY_LENGTH` — `ssl.h`: the TLS1.2 master-key ceiling.
pub const SSL_MAX_MASTER_KEY_LENGTH: usize = 48;
/// `SSL_SESS_FLAG_EXTMS` — `ssl_local.h:567`.
pub const SSL_SESS_FLAG_EXTMS: u32 = 0x1;
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
/// `SSL_CTRL_SET_TLSEXT_SERVERNAME_CB` — `ssl.h:1266` (the `SSL_CTX_set_tlsext_servername_callback`
/// macro's control code).
const SSL_CTRL_SET_TLSEXT_SERVERNAME_CB: c_int = 53;
/// `SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG` — `ssl.h:1267` (the `SSL_CTX_set_tlsext_servername_arg`
/// macro's control code). It is dispatched by `ssl3_ctx_ctrl` (`s3_lib.c:4463-4465`), the
/// `SSL_CTX_ctrl` fall-through, not by `SSL_CTX_callback_ctrl`.
const SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG: c_int = 54;
/// `SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB` — `ssl.h:1286` (the deprecated
/// `SSL_CTX_set_tlsext_ticket_key_cb` macro's control code).
const SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB: c_int = 72;
/// `SSL_CTRL_CERT_FLAGS` — `ssl.h:1357`.
const SSL_CTRL_CERT_FLAGS: c_int = 99;
/// `SSL_CTRL_CLEAR_CERT_FLAGS` — `ssl.h:1358`.
const SSL_CTRL_CLEAR_CERT_FLAGS: c_int = 100;
/// `SSL_CTRL_SET_SPLIT_SEND_FRAGMENT` — `ssl.h:1379`.
const SSL_CTRL_SET_SPLIT_SEND_FRAGMENT: c_int = 125;
/// `SSL_CTRL_SET_MAX_PIPELINES` — `ssl.h:1380`.
const SSL_CTRL_SET_MAX_PIPELINES: c_int = 126;
/// `SSL_CTRL_SET_MIN_PROTO_VERSION` — `ssl.h:1377`; setters are `ssl_set_version_bound`
/// (`ssl/ssl_lib.c:3199-3202`).
const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
/// `SSL_CTRL_GET_MIN_PROTO_VERSION` — `ssl.h:1384`.
const SSL_CTRL_GET_MIN_PROTO_VERSION: c_int = 130;
/// `SSL_CTRL_SET_MAX_PROTO_VERSION` — `ssl.h:1378` (as the min setter).
const SSL_CTRL_SET_MAX_PROTO_VERSION: c_int = 124;
/// `SSL_CTRL_GET_MAX_PROTO_VERSION` — `ssl.h:1385`.
const SSL_CTRL_GET_MAX_PROTO_VERSION: c_int = 131;
/// `SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS` — `sslerr.h:288`.
const SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS: c_int = 230;
/// `SSL_R_DH_KEY_TOO_SMALL` — `sslerr.h:106`.
const SSL_R_DH_KEY_TOO_SMALL: c_int = 394;
/// `SSL_SECOP_TMP_DH` — `ssl.h:2775` (`7 | SSL_SECOP_OTHER_PKEY`).
const SSL_SECOP_TMP_DH: c_int = 7 | (4 << 16);
/// `X509_L_FILE_LOAD` — `x509_vfy.h:283`.
const X509_L_FILE_LOAD: c_int = 1;
/// `X509_L_ADD_DIR` — `x509_vfy.h:284`.
const X509_L_ADD_DIR: c_int = 2;
/// `X509_L_ADD_STORE` — `x509_vfy.h:285`.
const X509_L_ADD_STORE: c_int = 3;
/// `X509_FILETYPE_DEFAULT` — `x509.h:170`.
const X509_FILETYPE_DEFAULT: c_long = 3;
/// `SSL_CTRL_SET_TMP_DH_CB` — `ssl.h:1276`; the deprecated temporary-DH callback command.
pub(crate) const SSL_CTRL_SET_TMP_DH_CB: c_int = 6;
/// `SSL_CTRL_SET_TMP_DH` — `ssl.h:1274` (`SSL_CTX_set_tmp_dh`).
const SSL_CTRL_SET_TMP_DH: c_int = 3;
/// `SSL_CTRL_SET_TMP_ECDH` — `ssl.h:1275` (`SSL_CTX_set_tmp_ecdh`).
const SSL_CTRL_SET_TMP_ECDH: c_int = 4;
/// `SSL_CTRL_SET_GROUPS` — `ssl.h:1352` (`SSL_CTX_set1_groups`).
const SSL_CTRL_SET_GROUPS: c_int = 91;
/// `SSL_CTRL_CHAIN` — `ssl.h:1349` (`SSL_CTX_set0_chain`/`SSL_CTX_set1_chain`).
const SSL_CTRL_CHAIN: c_int = 88;
/// `SSL_CTRL_CHAIN_CERT` — `ssl.h:1350` (`SSL_CTX_add0_chain_cert`/`add1`).
const SSL_CTRL_CHAIN_CERT: c_int = 89;
/// `SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB` — `ssl.h:1335` (the callback ctrl).
pub(crate) const SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB: c_int = 75;
/// `SSL_CTRL_SET_SRP_VERIFY_PARAM_CB` — `ssl.h:1336` (the callback ctrl).
pub(crate) const SSL_CTRL_SET_SRP_VERIFY_PARAM_CB: c_int = 76;
/// `SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB` — `ssl.h:1337` (the callback ctrl).
pub(crate) const SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB: c_int = 77;
/// `SSL_CTRL_SET_SRP_ARG` — `ssl.h:1338`.
pub(crate) const SSL_CTRL_SET_SRP_ARG: c_int = 78;
/// `SSL_CTRL_SET_TLS_EXT_SRP_USERNAME` — `ssl.h:1339`.
pub(crate) const SSL_CTRL_SET_TLS_EXT_SRP_USERNAME: c_int = 79;
/// `SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH` — `ssl.h:1340`.
pub(crate) const SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH: c_int = 80;
/// `SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD` — `ssl.h:1341`.
pub(crate) const SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD: c_int = 81;
/// `SSL_R_INVALID_SRP_USERNAME` — `sslerr.h:159`.
const SSL_R_INVALID_SRP_USERNAME: c_int = 357;
/// `SSL_kSRP` — `ssl_local.h:91`; the SRP key-exchange bit the SRP setters OR into `srp_Mask`.
pub(crate) const SSL_KSRP: c_ulong = 0x20;
/// `ERR_R_INTERNAL_ERROR` — `err.h:356` (`259 | ERR_R_FATAL`).
const ERR_R_INTERNAL_ERROR: c_int = 259 | (3 << 18);
/// `OPENSSL_INIT_LOAD_SSL_STRINGS` — `ssl.h:2827` (`ssl_lib.c:4005`).
pub(crate) const OPENSSL_INIT_LOAD_SSL_STRINGS: u64 = 0x0020_0000;
/// `ERR_R_PASSED_NULL_PARAMETER` — `err.h` (`258 | ERR_R_FATAL`).
const ERR_R_PASSED_NULL_PARAMETER: c_int = 258 | (3 << 18);
/// `ERR_R_DH_LIB` — `err.h` (`ERR_LIB_DH | ERR_RFLAG_COMMON`).
const ERR_R_DH_LIB: c_int = 5 | (2 << 18);
/// `SSL_R_MISSING_PARAMETERS` — `sslerr.h:173`.
const SSL_R_MISSING_PARAMETERS: c_int = 290;

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
/// `SSL_ERROR_WANT_READ` — `ssl.h:1260`.
const SSL_ERROR_WANT_READ: c_int = 2;
/// `SSL_ERROR_WANT_WRITE` — `ssl.h:1261`.
const SSL_ERROR_WANT_WRITE: c_int = 3;
/// `SSL_ERROR_ZERO_RETURN` — `ssl.h:1262`.
const SSL_ERROR_ZERO_RETURN: c_int = 6;
/// `SSL_ERROR_SYSCALL` — `ssl.h:1263`.
const SSL_ERROR_SYSCALL: c_int = 5;

/// `TLS_CIPHER_LEN` — `ssl_local.h`: the two-byte cipher-suite coordinate.
const TLS_CIPHER_LEN: c_int = 2;
/// `SSLV2_CIPHER_LEN` — `ssl_local.h`: the three-byte SSLv2-compatible coordinate.
const SSLV2_CIPHER_LEN: c_int = 3;
/// `SSL_SECOP_CIPHER_SUPPORTED` — `ssl.h:2716` (`1 | SSL_SECOP_OTHER_CIPHER`).
const SSL_SECOP_CIPHER_SUPPORTED: c_int = 1 | (1 << 16);

/// `SSL_TYPE_SSL_CONNECTION` — the ordinary connection type.
const SSL_TYPE_SSL_CONNECTION: c_int = 0;
/// `SSL_TYPE_QUIC_CONNECTION` — a QUIC connection, never produced by this slice.
const SSL_TYPE_QUIC_CONNECTION: c_int = 1;
/// `SSL_TYPE_QUIC_XSO` — a QUIC stream object, never produced by this slice.
const SSL_TYPE_QUIC_XSO: c_int = 2;

/// `X509_V_OK` — `include/openssl/x509_vfy.h`.
const X509_V_OK: c_long = 0;

/// `OPENSSL_NPN_NEGOTIATED` — `ssl.h:814`.
const OPENSSL_NPN_NEGOTIATED: c_int = 1;
/// `OPENSSL_NPN_NO_OVERLAP` — `ssl.h:815`.
const OPENSSL_NPN_NO_OVERLAP: c_int = 2;
/// `SSL_STREAM_TYPE_BIDI` — `ssl.h:2351`.
const SSL_STREAM_TYPE_BIDI: c_int = 3;
/// `SSL_STREAM_STATE_NONE` — `ssl.h:2409`.
const SSL_STREAM_STATE_NONE: c_int = 0;
/// `SSL_CT_VALIDATION_PERMISSIVE` — `ssl.h`.
const SSL_CT_VALIDATION_PERMISSIVE: c_int = 0;
/// `SSL_CT_VALIDATION_STRICT` — `ssl.h`.
const SSL_CT_VALIDATION_STRICT: c_int = 1;
/// `TLSEXT_NAMETYPE_host_name` — `tls1.h:171`.
const TLSEXT_NAMETYPE_HOST_NAME: c_int = 0;
/// `SSL_CTRL_SET_TLSEXT_HOSTNAME` — `ssl.h:1268`.
const SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;
/// `TLSEXT_STATUSTYPE_nothing` — `tls1.h` (the "no OCSP status request" sentinel).
const TLSEXT_STATUSTYPE_NOTHING: c_int = -1;
/// `TLSEXT_cert_type_x509` — `tls1.h:240`.
const TLSEXT_CERT_TYPE_X509: u8 = 0;
/// `TLSEXT_cert_type_rpk` — `tls1.h:242`.
const TLSEXT_CERT_TYPE_RPK: u8 = 2;
/// `PSK_MAX_IDENTITY_LEN` — `ssl.h:838`.
const PSK_MAX_IDENTITY_LEN: usize = 256;
/// `SSL3_RANDOM_SIZE` — `ssl3.h:137`.
const SSL3_RANDOM_SIZE: usize = 32;
/// `SSL_KEY_UPDATE_NONE` — `ssl.h:1001`.
const SSL_KEY_UPDATE_NONE: c_int = -1;
/// `SSL_ERROR_WANT_READ` — `ssl.h` (`SSL_want_read` is `SSL_want(s) == SSL_READING`).
const SSL_WANT_READING: c_int = SSL_READING;
/// `SSL_WANT_WRITING`.
const SSL_WANT_WRITING: c_int = SSL_WRITING;
/// `TLS_ST_BEFORE` — `ssl.h:1066`, the first `OSSL_HANDSHAKE_STATE`; the state a fresh
/// connection reports (`ossl_statem_clear`, `statem.c:133`).
const TLS_ST_BEFORE: c_int = 0;
/// `MSG_FLOW_UNINITED` — `internal/statem.h:52`, the first `MSG_FLOW_STATE`; the message-flow
/// state a fresh connection reports (`ossl_statem_clear`, `statem.c:132`).
const MSG_FLOW_UNINITED: c_int = 0;
/// `SSL_ST_READ_HEADER` — `ssl.h:1113`; the record read state a fresh connection installs.
const SSL_ST_READ_HEADER: c_int = 0xF0;

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
    /// `ssl3_enc->enc_flags` — the `SSL_ENC_FLAG_*` bits the cipher parser reads (14.3).
    pub enc_flags: c_uint,
    /// `method->ssl_accept != ssl_undefined_function` — the default role `SSL_new` installs
    /// (`ssl_lib.c:917`).
    pub default_server: bool,
    /// `method->ssl_connect != ssl_undefined_function` — whether the method can drive a client
    /// handshake (`ssl_mcnf.c:70-73`). A server-only method is `default_server && !default_client`.
    pub default_client: bool,
}

// -------------------------------------------------------------------------------------------
// CERT — the per-context/per-connection certificate container (a reduced `ssl_cert_st`)
// -------------------------------------------------------------------------------------------

/// `struct cert_pkey` — `ssl_local.h:2008-2026`, reduced to the fields this stratum reads.
#[repr(C)]
pub struct CertKey {
    /// `X509 *x509` — the leaf certificate, NULL until a loader runs (14.7).
    pub x509: *mut X509,
    /// `EVP_PKEY *privatekey` — the leaf key, NULL until a loader runs (14.7).
    pub privatekey: *mut c_void,
    /// `STACK_OF(X509) *chain` — the extra chain certificates (`ssl_set_cert_and_key`).
    pub chain: *mut OpenSslStack,
    /// `unsigned char *serverinfo` — the serverinfo block (`SSL_CTX_use_serverinfo_ex`).
    pub serverinfo: *mut u8,
    /// `size_t serverinfo_length`.
    pub serverinfo_length: usize,
    /// `OSSL_COMP_CERT *comp_cert[TLSEXT_comp_cert_limit]` — the pre-compressed forms
    /// (`ssl_cert_comp.c`).
    pub comp_cert: [*mut crate::ssl::ssl_cert_comp::OsslCompCert; TLSEXT_COMP_CERT_LIMIT],
    /// `int cert_comp_used` — set by the compression pass.
    pub cert_comp_used: c_int,
}

/// `struct ssl_cert_st` — `ssl_local.h:2008-2145`, reduced to the fields this stratum reads.
#[repr(C)]
pub struct Cert {
    /// `CERT_PKEY *pkeys` — the per-key-type certificate slots (`SSL_PKEY_NUM` of them).
    pub pkeys: [CertKey; SSL_PKEY_NUM],
    /// `ssl_pkey_num` — the slot count (always `SSL_PKEY_NUM` here).
    pub ssl_pkey_num: usize,
    /// `CERT_PKEY *key` — the active slot, stored as an index into `pkeys`.
    pub key_index: usize,
    /// `CRYPTO_REF_COUNT references` — `ssl_cert_dup`/`ssl_cert_free`.
    pub references: AtomicI32,
    /// `int cert_comp_prefs[TLSEXT_comp_cert_limit]` — `SSL_CTX_set1_cert_comp_preference`.
    pub cert_comp_prefs: [c_int; TLSEXT_COMP_CERT_LIMIT],
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
    /// `char *psk_identity_hint` — the PSK identity hint (`SSL_[CTX_]use_psk_identity_hint`).
    pub psk_identity_hint: *mut c_char,
    /// `EVP_PKEY *dh_tmp` — the explicit temporary DH key (`SSL_[CTX_]set0_tmp_dh_pkey`).
    #[allow(dead_code)] // stored for the tmp-DH setter; read by the DH key-exchange path
    pub dh_tmp: *mut c_void,
    /// `DH *(*dh_tmp_cb)(SSL *, int, int)` — the deprecated temporary-DH callback
    /// `SSL_CTRL_SET_TMP_DH_CB` installs (`s3_lib.c:4665-4667`).
    #[allow(dead_code)] // stored for the setter's contract; read by the DH path
    pub dh_tmp_cb: *mut c_void,
    /// `custom_ext_methods custext` — the registered custom extensions. The authority stores a
    /// heap array of `custom_ext_method`; this crate stores the same records in a `Vec`, because
    /// the table is this crate's own and never crosses the FFI boundary as a struct. The
    /// callbacks are never invoked in this slice (no handshake), so their arguments are kept
    /// verbatim rather than wrapped.
    pub custext: Vec<CustomExtMethod>,
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
            (*c).ssl_pkey_num = SSL_PKEY_NUM;
            (*c).key_index = SSL_PKEY_RSA;
            (*c).references = AtomicI32::new(1);
        }
    }
    c
}

/// The active `CERT_PKEY` a certificate container holds (`c->key`, stored here as an index).
///
/// # Safety
/// `c` must be a live `Cert`.
pub(crate) unsafe fn cert_active_key(c: *mut Cert) -> *mut CertKey {
    // SAFETY: `c` is live per the caller's contract; `key_index` is in range because it is only
    // ever written with a slot index.
    unsafe { ptr::addr_of_mut!((*c).pkeys[(*c).key_index]) }
}

/// Free one certificate slot's heap contents (the authority's `ssl_cert_clear_certs` body for one
/// `CERT_PKEY`).
///
/// # Safety
/// `cpk` must be a live `CertKey`.
unsafe fn cert_pkey_clear(cpk: *mut CertKey) {
    // SAFETY: `cpk` is live per the caller's contract; each field is NULL or an owned object.
    unsafe {
        X509_free((*cpk).x509);
        (*cpk).x509 = ptr::null_mut();
        EVP_PKEY_free((*cpk).privatekey.cast());
        (*cpk).privatekey = ptr::null_mut();
        OSSL_STACK_OF_X509_free((*cpk).chain);
        (*cpk).chain = ptr::null_mut();
        CRYPTO_free((*cpk).serverinfo.cast(), FILE, 0);
        (*cpk).serverinfo = ptr::null_mut();
        (*cpk).serverinfo_length = 0;
        for j in 0..TLSEXT_COMP_CERT_LIMIT {
            crate::ssl::ssl_cert_comp::OSSL_COMP_CERT_free((*cpk).comp_cert[j]);
            (*cpk).comp_cert[j] = ptr::null_mut();
        }
        (*cpk).cert_comp_used = 0;
    }
}

/// Release a certificate container.
///
/// # Safety
/// `c` must be NULL or a live `Cert` previously returned by [`cert_new`].
unsafe fn cert_free(c: *mut Cert) {
    if !c.is_null() {
        // SAFETY: `c` is a live `Cert` per the caller's contract; a NULL `psk_identity_hint` is
        // `CRYPTO_free`'s own no-op.
        unsafe {
            for i in 0..SSL_PKEY_NUM {
                cert_pkey_clear(ptr::addr_of_mut!((*c).pkeys[i]));
            }
            // SAFETY: `c` is live; `custext` is the `Vec` `cert_new` zero-initialised and
            // `SSL_CTX_add_*_custom_ext` may have grown. Dropping it in place releases the
            // record buffer (the records hold only borrowed callback pointers and raw args the
            // caller owns, exactly as the authority's `custom_exts_free` releases only the
            // array when the old-style wrapper is absent).
            ptr::drop_in_place(ptr::addr_of_mut!((*c).custext));
            CRYPTO_free((*c).psk_identity_hint.cast(), FILE, 0);
            // SAFETY: `dh_tmp` is NULL or the key the tmp-DH setter installed.
            EVP_PKEY_free((*c).dh_tmp.cast());
            CRYPTO_free(c.cast(), FILE, 0);
        }
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
    t.key_index = f.key_index;
    // The active leaf pair is **up-reffed** into the copy, so the copy owns its own references
    // and `cert_free` can release them (the authority's `ssl_cert_dup` reference-counts every
    // slot; this reduced copy handles the active one).
    let fslot = &f.pkeys[f.key_index];
    let tslot = &mut t.pkeys[f.key_index];
    if !fslot.x509.is_null() {
        // SAFETY: `fslot.x509` is a live certificate.
        unsafe { X509_up_ref(fslot.x509) };
        tslot.x509 = fslot.x509;
    }
    if !fslot.privatekey.is_null() {
        // SAFETY: `fslot.privatekey` is a live key.
        unsafe { crate::evp::pkey::EVP_PKEY_up_ref(fslot.privatekey.cast()) };
        tslot.privatekey = fslot.privatekey;
    }
}

/// `CERT *ssl_cert_dup(CERT *cert)` — `ssl/ssl_cert.c:95-236`.
///
/// The authority's per-slot duplication in full: every `pkeys[]` entry up-refs its
/// certificate, private key, chain, serverinfo block and compressed forms, and the container's
/// `dh_tmp`, flag word, certificate callback, security attributes, custom-extension table and PSK
/// identity hint are copied. The fields this crate's `Cert` does not model — the authority's
/// `conf_sigalgs`/`client_sigalgs`/`ctype`, `verify_store`/`chain_store` and `dh_tmp_auto` — are
/// not copied; `src/ssl/mod.rs` records the reduction. `OPENSSL_NO_COMP_ALG` is defined in the
/// admitted build, so the `comp_cert[]` loop is the authority's guard-off body.
///
/// # Safety
/// `cert` must be NULL or a live certificate container.
unsafe fn ssl_cert_dup(cert: *const Cert) -> *mut Cert {
    if cert.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `cert_new` returns a live zeroed container or NULL.
    let ret = unsafe { cert_new() };
    if ret.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `cert` and `ret` are live; every write is to the fresh container `ret`.
    unsafe {
        (*ret).ssl_pkey_num = (*cert).ssl_pkey_num;
        (*ret).key_index = (*cert).key_index;

        if !(*cert).dh_tmp.is_null() {
            if EVP_PKEY_up_ref((*cert).dh_tmp.cast()) == 0 {
                cert_free(ret);
                return ptr::null_mut();
            }
            (*ret).dh_tmp = (*cert).dh_tmp;
        }
        (*ret).dh_tmp_cb = (*cert).dh_tmp_cb;

        for i in 0..(*ret).ssl_pkey_num {
            let cpk = &(*cert).pkeys[i];
            let rpk = &mut (*ret).pkeys[i];
            if !cpk.x509.is_null() {
                X509_up_ref(cpk.x509);
                rpk.x509 = cpk.x509;
            }
            if !cpk.privatekey.is_null() {
                EVP_PKEY_up_ref(cpk.privatekey.cast());
                rpk.privatekey = cpk.privatekey;
            }
            if !cpk.chain.is_null() {
                rpk.chain = X509_chain_up_ref(cpk.chain);
                if rpk.chain.is_null() {
                    cert_free(ret);
                    return ptr::null_mut();
                }
            }
            if !cpk.serverinfo.is_null() {
                rpk.serverinfo =
                    CRYPTO_memdup(cpk.serverinfo.cast(), cpk.serverinfo_length, FILE, 154)
                        .cast::<u8>();
                if rpk.serverinfo.is_null() {
                    cert_free(ret);
                    return ptr::null_mut();
                }
                rpk.serverinfo_length = cpk.serverinfo_length;
            }
            for j in 0..TLSEXT_COMP_CERT_LIMIT {
                if !cpk.comp_cert[j].is_null() {
                    crate::ssl::ssl_cert_comp::OSSL_COMP_CERT_up_ref(cpk.comp_cert[j]);
                    rpk.comp_cert[j] = cpk.comp_cert[j];
                }
            }
        }

        (*ret).cert_flags = (*cert).cert_flags;
        (*ret).cert_cb = (*cert).cert_cb;
        (*ret).cert_cb_arg = (*cert).cert_cb_arg;
        (*ret).sec_cb = (*cert).sec_cb;
        (*ret).sec_level = (*cert).sec_level;
        (*ret).sec_ex = (*cert).sec_ex;

        if custom_exts_copy(&mut (*ret).custext, &(*cert).custext) == 0 {
            cert_free(ret);
            return ptr::null_mut();
        }
        if !(*cert).psk_identity_hint.is_null() {
            (*ret).psk_identity_hint = CRYPTO_strdup((*cert).psk_identity_hint, FILE, 225);
            if (*ret).psk_identity_hint.is_null() {
                cert_free(ret);
                return ptr::null_mut();
            }
        }
    }
    ret
}

/// `static int dup_ca_names(STACK_OF(X509_NAME) **dst, STACK_OF(X509_NAME) *src)` —
/// `ssl/ssl_lib.c:5101-5129`.
///
/// # Safety
/// `dst` must be a writable slot; `src` must be NULL or a live name stack.
unsafe fn dup_ca_names(dst: *mut *mut OpenSslStack, src: *mut OpenSslStack) -> c_int {
    if src.is_null() {
        // SAFETY: `dst` is writable per the caller's contract.
        unsafe { *dst = ptr::null_mut() };
        return 1;
    }
    // SAFETY: no preconditions.
    let sk = OPENSSL_sk_new_null();
    if sk.is_null() {
        return 0;
    }
    // SAFETY: `src` is a live stack per the caller's contract.
    let num = unsafe { OPENSSL_sk_num(src) };
    let mut i = 0;
    while i < num {
        // SAFETY: `i` is in range of `src`.
        let xn = unsafe { OPENSSL_sk_value(src, i) }.cast::<X509Name>();
        // SAFETY: `xn` is a live name.
        let dup = unsafe { X509_NAME_dup(xn) };
        if dup.is_null() {
            // SAFETY: `sk` is a live stack of owned names.
            unsafe { OPENSSL_sk_pop_free(sk, Some(x509_name_free_void)) };
            return 0;
        }
        // SAFETY: `sk` is live; `dup` is an owned name whose ownership moves on insert.
        if unsafe { OPENSSL_sk_insert(sk, dup.cast(), i) } == 0 {
            // SAFETY: `dup` is an owned name; `sk` a live stack of owned names.
            unsafe {
                X509_NAME_free(dup);
                OPENSSL_sk_pop_free(sk, Some(x509_name_free_void));
            }
            return 0;
        }
        i += 1;
    }
    // SAFETY: `dst` is writable.
    unsafe { *dst = sk };
    1
}

// -------------------------------------------------------------------------------------------
// SSL_CTX and SSL
// -------------------------------------------------------------------------------------------

/// `int (*TLS_ext_srp_username_callback)(SSL *, int *, void *)` — `ssl_local.h:575`.
pub type SrpUsernameCb = unsafe extern "C" fn(*mut Ssl, *mut c_int, *mut c_void) -> c_int;
/// `int (*SRP_verify_param_callback)(SSL *, void *)` — `ssl_local.h:577`.
pub type SrpVerifyParamCb = unsafe extern "C" fn(*mut Ssl, *mut c_void) -> c_int;
/// `char *(*SRP_give_srp_client_pwd_callback)(SSL *, void *)` — `ssl_local.h:579`.
pub type SrpClientPwdCb = unsafe extern "C" fn(*mut Ssl, *mut c_void) -> *mut c_char;

/// `struct srp_ctx_st` — `ssl_local.h:571-586`, the SRP credential block on a context or a
/// connection (`tls_srp.c`).
#[repr(C)]
pub struct SrpCtx {
    /// `void *SRP_cb_arg` — the argument for all the callbacks.
    pub srp_cb_arg: *mut c_void,
    /// `int (*TLS_ext_srp_username_callback)(SSL *, int *, void *)`.
    pub username_callback: Option<SrpUsernameCb>,
    /// `int (*SRP_verify_param_callback)(SSL *, void *)`.
    pub verify_param_callback: Option<SrpVerifyParamCb>,
    /// `char *(*SRP_give_srp_client_pwd_callback)(SSL *, void *)`.
    pub give_client_pwd_callback: Option<SrpClientPwdCb>,
    /// `char *login` — the client login name.
    pub login: *mut c_char,
    /// `BIGNUM *N` — the group prime.
    pub n: *mut BigNum,
    /// `BIGNUM *g` — the group generator.
    pub g: *mut BigNum,
    /// `BIGNUM *s` — the salt.
    pub s: *mut BigNum,
    /// `BIGNUM *B` — the server public value.
    pub b_pub: *mut BigNum,
    /// `BIGNUM *A` — the client public value.
    pub a_pub: *mut BigNum,
    /// `BIGNUM *a` — the client private value.
    pub a: *mut BigNum,
    /// `BIGNUM *b` — the server private value.
    pub b: *mut BigNum,
    /// `BIGNUM *v` — the verifier.
    pub v: *mut BigNum,
    /// `char *info` — the password the `SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD` handler stores.
    pub info: *mut c_char,
    /// `int strength` — the minimum group bit length (`SRP_MINIMAL_N` unless set).
    pub strength: c_int,
    /// `unsigned long srp_Mask` — `SSL_kSRP` once any SRP setter runs.
    pub srp_mask: c_ulong,
}

/// `struct ssl_cert_st` — `ssl_local.h:2008-2145`.
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
    /// `SSL_client_hello_cb_fn client_hello_cb` — read by `tls_process_client_hello` when it
    /// publishes the message and invokes the callback (`statem_srvr.c:1881`).
    pub client_hello_cb: Option<ClientHelloCb>,
    /// `void *client_hello_cb_arg`.
    pub client_hello_cb_arg: *mut c_void,
    /// `SSL_CTX_keylog_cb_func keylog_callback`.
    pub keylog_callback: Option<KeylogCb>,
    /// `int (*ext.ticket_key_evp_cb)(...)` — the callback `SSL_CTX_set_tlsext_ticket_key_evp_cb`
    /// installs (`s3_lib.c:4711`).
    pub ticket_key_evp_cb: Option<TicketKeyEvpCb>,
    /// `int (*ext.ticket_key_cb)(...)` — the deprecated callback
    /// `SSL_CTX_set_tlsext_ticket_key_cb` installs through `SSL_CTX_callback_ctrl`
    /// (`s3_lib.c:4678-4683`).
    pub ticket_key_cb: Option<TicketKeyCb>,
    /// `int (*ext.servername_cb)(SSL *, int *, void *)` — the SNI callback
    /// `SSL_CTX_set_tlsext_servername_callback` installs (`s3_lib.c:4669-4671`).
    pub servername_cb: Option<ServernameCb>,
    /// `void *ext.servername_arg` — the callback's argument (NULL for nginx, which uses the
    /// two-argument macro).
    pub servername_arg: *mut c_void,
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
    /// `struct dane_ctx_st dane` — the context's shared DANE digest table (`ssl_local.h:1093`);
    /// `SSL_CTX_dane_*` writes it and `dane_ctx_enable` fills it (`x509::dane`).
    #[allow(dead_code)] // read by the DANE setters/getters landed in 14.7b
    pub(crate) dane: DaneCtx,
    /// `ENGINE *client_cert_engine` — the engine `SSL_CTX_set_client_cert_engine` installs
    /// (`ssl_local.h:1065`).
    #[allow(dead_code)] // stored for the setter's contract; read by the client-cert path
    pub client_cert_engine: *mut Engine,
    /// `SRP_CTX srp_ctx` — the SRP credential block (`ssl_local.h:1089`).
    pub srp_ctx: SrpCtx,
    /// `ssl_ct_validation_cb ct_validation_callback`.
    pub ct_validation_callback: Option<CtValidationCb>,
    /// `void *ct_validation_callback_arg`.
    pub ct_validation_callback_arg: *mut c_void,
    /// `CTLOG_STORE *ctlog_store` — allocated by `SSL_CTX_new_ex` (`ssl_lib.c:4067`).
    pub ctlog_store: *mut CtlogStore,
    /// `unsigned char *client_cert_type` (the `SSL_set1_client_cert_type` list).
    pub client_cert_type: *mut u8,
    /// `size_t client_cert_type_len`.
    pub client_cert_type_len: usize,
    /// `unsigned char *server_cert_type`.
    pub server_cert_type: *mut u8,
    /// `size_t server_cert_type_len`.
    pub server_cert_type_len: usize,
    /// `size_t block_padding` (`SSL_CTX_set_block_padding_ex`).
    pub block_padding: usize,
    /// `size_t hs_padding`.
    pub hs_padding: usize,
    /// `unsigned char *ext.alpn` — the client ALPN offer list, owned.
    pub ext_alpn: *mut u8,
    /// `unsigned int ext.alpn_len`.
    pub ext_alpn_len: c_uint,
    /// `uint16_t *ext.supportedgroups` — the context's supported group list, owned.
    pub supportedgroups: *mut u16,
    /// `size_t ext.supportedgroups_len`.
    pub supportedgroups_len: usize,
    /// `uint8_t ext.max_fragment_len_mode` — the context-wide MFL (`SSL_CTX_set_tlsext_max_fragment_length`).
    pub ext_max_fragment_len_mode: u8,
    /// `int ext.status_type` — the OCSP status request type (`ssl_lib.c:4222`'s `TLSEXT_STATUSTYPE_nothing`).
    pub ext_status_type: c_int,
    /// `SSL_CTX_npn_select_cb_func ext.npn_select_cb`.
    pub npn_select_cb: Option<NpnSelectCb>,
    /// `void *ext.npn_select_cb_arg`.
    pub npn_select_cb_arg: *mut c_void,
    /// `SSL_CTX_npn_advertised_cb_func ext.npn_advertised_cb`.
    pub npn_advertised_cb: Option<NpnAdvertisedCb>,
    /// `void *ext.npn_advertised_cb_arg`.
    pub npn_advertised_cb_arg: *mut c_void,
    /// `uint64_t domain_flags`.
    pub domain_flags: u64,
    /// `int pha_enabled` (`SSL_CTX_set_post_handshake_auth`).
    pub pha_enabled: c_int,
    /// `STACK_OF(SSL_CIPHER) *cipher_list` — the preference-ordered list (14.3).
    pub cipher_list: *mut OpenSslStack,
    /// `STACK_OF(SSL_CIPHER) *cipher_list_by_id` — the id-ordered duplicate (14.3).
    pub cipher_list_by_id: *mut OpenSslStack,
    /// `STACK_OF(SSL_CIPHER) *tls13_ciphersuites` — the TLSv1.3 suite list (14.3).
    pub tls13_ciphersuites: *mut OpenSslStack,
    /// `uint32_t disabled_mkey_mask` — `ssl_load_ciphers`'s key-exchange word (14.3).
    pub disabled_mkey_mask: u32,
    /// `uint32_t disabled_auth_mask`.
    pub disabled_auth_mask: u32,
    /// `uint32_t disabled_enc_mask`.
    pub disabled_enc_mask: u32,
    /// `uint32_t disabled_mac_mask`.
    pub disabled_mac_mask: u32,
    /// `STACK_OF(SRTP_PROTECTION_PROFILE) *srtp_profiles` — the DTLS-SRTP offer list
    /// (`SSL_CTX_set_tlsext_use_srtp`); NULL until the setter runs. `src/ssl/d1_srtp.rs` owns it.
    pub srtp_profiles: *mut OpenSslStack,
    /// `STACK_OF(X509_NAME) *ca_names` — the CA-name list (`SSL_CTX_[set0|get0]_CA_list`).
    pub ca_names: *mut OpenSslStack,
    /// `STACK_OF(X509_NAME) *client_ca_names` — the client-CA list.
    pub client_ca_names: *mut OpenSslStack,
    /// `int cert_comp_prefs[TLSEXT_comp_cert_limit]` — `SSL_CTX_set1_cert_comp_preference`.
    pub cert_comp_prefs: [c_int; TLSEXT_COMP_CERT_LIMIT],
    /// `LHASH_OF(SSL_SESSION) *sessions` — the internal session cache (`ssl_sess.c`). The
    /// authority uses an `LHASH` keyed on the session id; this crate stores the sessions in an
    /// `OpenSslStack` and searches it linearly, which is observational-equivalent for the cache
    /// controls the court drives.
    pub sessions: *mut OpenSslStack,
    /// `int (*new_session_cb)(SSL *, SSL_SESSION *)` — `SSL_CTX_sess_set_new_cb`.
    pub new_session_cb: Option<NewSessionCb>,
    /// `void (*remove_session_cb)(SSL_CTX *, SSL_SESSION *)` — `SSL_CTX_sess_set_remove_cb`.
    pub remove_session_cb: Option<RemoveSessionCb>,
    /// `SSL_SESSION *(*get_session_cb)(SSL *, const unsigned char *, int, int *)`.
    pub get_session_cb: Option<GetSessionCb>,
    /// `int (*client_cert_cb)(SSL *, X509 **, EVP_PKEY **)` — `SSL_CTX_set_client_cert_cb`.
    pub client_cert_cb: Option<ClientCertCb>,
    /// `int (*app_gen_cookie_cb)(SSL *, unsigned char *, unsigned int *)`.
    pub app_gen_cookie_cb: Option<GenCookieCb>,
    /// `int (*app_verify_cookie_cb)(SSL *, const unsigned char *, unsigned int)`.
    pub app_verify_cookie_cb: Option<VerifyCookieCb>,
    /// `int (*gen_stateless_cookie_cb)(SSL *, unsigned char *, size_t *)`.
    pub gen_stateless_cookie_cb: Option<GenStatelessCookieCb>,
    /// `int (*verify_stateless_cookie_cb)(SSL *, const unsigned char *, size_t)`.
    pub verify_stateless_cookie_cb: Option<VerifyStatelessCookieCb>,
    /// `void (*info_callback)(const SSL *, int, int)` — `SSL_CTX_set_info_callback`.
    pub info_callback: Option<InfoCb>,
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
    /// `STACK_OF(SSL_CIPHER) *cipher_list` — the connection's own list, if it overrode one (14.3).
    pub cipher_list: *mut OpenSslStack,
    /// `STACK_OF(SSL_CIPHER) *cipher_list_by_id` (14.3).
    pub cipher_list_by_id: *mut OpenSslStack,
    /// `STACK_OF(SSL_CIPHER) *tls13_ciphersuites` (14.3).
    pub tls13_ciphersuites: *mut OpenSslStack,
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
    /// `int s3.fatal_alert` — the description of a fatal alert received from the peer
    /// (`ssl3_read_bytes`, `rec_layer_s3.c:917`).
    pub fatal_alert: c_int,
    /// `int s3.warn_alert` — the description of the last warning alert received; `close_notify`
    /// leaves it set (`ssl3_read_bytes`, `rec_layer_s3.c:893`).
    pub warn_alert: c_int,
    /// `int rlayer.alert_count` — the consecutive warning-alert counter
    /// (`ssl3_read_bytes`, `rec_layer_s3.c:897`).
    pub alert_count: c_int,
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
    /// `size_t rlayer.default_read_buf_len` — the connection's MFL read buffer
    /// (`SSL_set_default_read_buffer_len`). Distinct from the context field only by identity,
    /// as in the authority; the record layer that would consume it is not modelled.
    pub rlayer_default_read_buf_len: usize,
    /// `int rlayer.rstate` — the record read state (`SSL_ST_READ_HEADER`/`SSL_ST_READ_BODY`).
    /// `RECORD_LAYER_reset` installs a fresh read method, whose init sets it to `SSL_ST_READ_HEADER`
    /// (`tls_common.c:1335`), so `SSL_rstate_string` answers `"RH"` for a fresh connection.
    pub rstate: c_int,
    /// `uint8_t ext.max_fragment_len_mode` — the connection-wide MFL
    /// (`SSL_set_tlsext_max_fragment_length`).
    pub max_fragment_len_mode: u8,
    /// `int ext.status_type` — the OCSP status request type, copied from the context by `SSL_new`
    /// (`ssl_lib.c:820`).
    pub ext_status_type: c_int,
    /// `OSSL_HANDSHAKE_STATE statem.hand_state` — the state `SSL_get_state` reports.
    pub hand_state: c_int,
    /// `enum MSG_FLOW_* statem.state` — the message-flow state `SSL_in_before` reads.
    pub statem_state: c_int,
    /// `int statem.in_init` — the flag `SSL_in_init`/`SSL_is_init_finished` read.
    pub in_init: c_int,
    /// `OSSL_HANDSHAKE_STATE statem.request_state` — set by `ossl_statem_set_renegotiate` (14.5b).
    pub statem_request_state: c_int,
    /// `int statem.no_cert_verify` — cleared by `ossl_statem_clear` (14.5b).
    pub statem_no_cert_verify: c_int,
    /// `int statem.in_handshake` — the re-entry counter the state machine bumps (14.5b).
    pub statem_in_handshake: c_int,
    /// `uint32_t s3.flags` — the record/`TLS1_FLAGS_*` word (`SSL_stateless` sets `TLS1_FLAGS_STATELESS`).
    pub s3_flags: u64,
    /// `int s3.in_read_app_data` — the record layer's application-data re-entry flag (14.5b).
    pub s3_in_read_app_data: c_int,
    /// `uint32_t s3.previous_server_finished_len` — 0 before a handshake (`ossl_statem_export_allowed`).
    pub s3_previous_server_finished_len: c_int,
    /// `int s3.renegotiate` — the renegotiation request `ssl3_renegotiate[_check]` drive (14.5b).
    pub s3_renegotiate: c_int,
    /// `int s3.total_renegotiations` (`ossl_statem_app_data_allowed`).
    pub s3_total_renegotiations: c_int,
    /// `int s3.num_renegotiations` (`ssl3_renegotiate_check`).
    pub s3_num_renegotiations: c_int,
    /// `uint32_t s3.tmp.finish_md_len` — 0 before a handshake (`SSL_IS_FIRST_HANDSHAKE`, 14.5b).
    pub s3_tmp_finish_md_len: c_int,
    /// `uint32_t s3.tmp.peer_finish_md_len` — 0 before a handshake (`SSL_IS_FIRST_HANDSHAKE`, 14.5b).
    pub s3_tmp_peer_finish_md_len: c_int,
    /// `uint32_t s3.tmp.mask_a` — the disabled auth-algorithm mask `ssl_set_client_disabled` builds
    /// and `ssl_cipher_disabled` reads (`t1_lib.c:2850`). Lands with 14.7b's `SSL_get1_supported_ciphers`.
    pub mask_a: u32,
    /// `uint32_t s3.tmp.mask_k` — the disabled key-exchange mask (`t1_lib.c:2851`).
    pub mask_k: u32,
    /// `int s3.tmp.min_ver` — the connection's minimum supported version (`ssl_get_min_max_version`).
    pub min_ver: c_int,
    /// `int s3.tmp.max_ver` — the connection's maximum supported version; 0 disables every cipher.
    pub max_ver: c_int,
    /// `int s3.tmp.cert_req` — the client's pending CertificateRequest flag (`statem_clnt.c`, 16.5).
    pub s3_tmp_cert_req: c_int,
    /// `int s3.tmp.cert_request` — the server's CertificateRequest-sent flag (`statem_srvr.c`, 16.5).
    pub s3_tmp_cert_request: c_int,
    /// `int s3.npn_seen` — the NPN extension seen flag (`statem_clnt.c`/`statem_srvr.c`, 16.5).
    pub s3_npn_seen: c_int,
    /// `int ext.ticket_expected` — the session-ticket extension flag (`statem_*.c`, 16.5).
    pub ext_ticket_expected: c_int,
    /// `int ext.status_expected` — the OCSP status-request extension flag (`statem_*.c`, 16.5).
    pub ext_status_expected: c_int,
    /// `int ext.compress_certificate_sent` — the certificate-compression flag (`statem_*.c`, 16.5).
    pub ext_compress_certificate_sent: c_int,
    /// `uint8_t ext.compress_certificate_from_peer[0]` — the peer's first compression
    /// algorithm byte (`statem_clnt.c`/`statem_srvr.c`, 16.5).
    pub ext_compress_certificate_from_peer_0: u8,
    /// `int certreqs_sent` — CertificateRequests sent, for `send_certificate_request` (16.5).
    pub certreqs_sent: c_int,
    /// `uint32_t sent_tickets` — session tickets sent (`statem_srvr.c`, 16.5).
    pub sent_tickets: usize,
    /// `size_t rlayer.wpend_tot` — the pending-write counter (`RECORD_LAYER_write_pending`, 14.5b).
    pub wpend_tot: usize,
    /// `int ext.extra_tickets_expected` — `SSL_new_session_ticket`'s counter (14.5b).
    pub extra_tickets_expected: c_int,
    /// `int hello_retry_request` — `SSL_HRR_NONE`/`_PENDING`/`_COMPLETE` (14.5b).
    pub hello_retry_request: c_int,
    /// `int ext.cookieok` — the stateless cookie result (`SSL_stateless`, 14.5b).
    pub cookieok: c_int,
    /// `int post_handshake_auth` — the connection's `SSL_PHA_*` state (14.5b).
    pub post_handshake_auth: c_int,
    /// `unsigned char *pha_context` — the request context echoed from a TLS1.3 CertificateRequest
    /// (`tls_construct_certificate_request`, `statem_srvr.c:3028-3048`). Owned; freed by `SSL_free`.
    pub pha_context: *mut u8,
    /// `size_t pha_context_len`.
    pub pha_context_len: usize,
    /// `EVP_MD_CTX *pha_dgst` — the handshake digest through the client Finished, saved for PHA
    /// (`tls13_save_handshake_digest_for_pha`, `statem_lib.c:2846-2867`). Owned; freed by `SSL_free`.
    pub pha_dgst: *mut c_void,
    /// `uint16_t *s3.tmp.peer_sigalgs` — the peer's signature-algorithm list (always NULL here).
    pub peer_sigalgs: *mut u16,
    /// `size_t s3.tmp.peer_sigalgslen`.
    pub peer_sigalgslen: usize,
    /// `SIGALG_LOOKUP **shared_sigalgs` — the negotiated list (always NULL here).
    pub shared_sigalgs: *mut c_void,
    /// `size_t shared_sigalgslen`.
    pub shared_sigalgslen: usize,
    /// `const SIGALG_LOOKUP *s3.tmp.sigalg` — this side's chosen sigalg (always NULL here).
    pub sigalg: *const c_void,
    /// `const SIGALG_LOOKUP *s3.tmp.peer_sigalg` — the peer's chosen sigalg (always NULL here).
    pub peer_sigalg: *const c_void,
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
    /// `SSL_SESSION *session` — 14.7's; NULL throughout this slice.
    pub session: *mut SslSession,
    /// `SSL_CTX *session_ctx` — the session-cache context (14.7).
    pub session_ctx: *mut SslCtx,
    /// `STACK_OF(SSL_CIPHER) *peer_ciphers` — the ClientHello's offered ciphers
    /// (`SSL_get_client_ciphers`). The authority builds it from the ClientHello; no handshake
    /// reaches it here, so it stays NULL.
    pub peer_ciphers: *mut OpenSslStack,
    /// `const SSL_CIPHER *s3.tmp.new_cipher` — the pending cipher (`SSL_get_pending_cipher`). Set
    /// by the handshake; NULL before one.
    pub pending_cipher: *const crate::ssl::ssl_ciph_table::SslCipher,
    /// `unsigned char tmp_session_id[SSL_MAX_SSL_SESSION_ID_LENGTH]` — the TLSv1.3 session id the
    /// server echoes from the ClientHello (`statem_srvr.c`, 17.2b).
    pub tmp_session_id: [u8; SSL_MAX_SSL_SESSION_ID_LENGTH],
    /// `size_t tmp_session_id_len`.
    pub tmp_session_id_len: usize,
    /// `uint16_t s3.group_id` — the key-exchange group the server selected
    /// (`tls_parse_ctos_key_share`/`tls1_setup_key_share`, `statem_srvr.c`, 17.2b).
    pub group_id: u16,
    /// `SSL_DANE dane` — the DANE per-connection state (`ssl_local.h:1493`).
    #[allow(dead_code)] // read by the DANE setters/getters landed in 14.7b
    pub(crate) dane: SslDane,
    /// `SRP_CTX srp_ctx` — the SRP credential block a connection copies from its context
    /// (`ssl_local.h:1794`).
    pub srp_ctx: SrpCtx,
    /// `STACK_OF(X509) *verified_chain` — built by the verify path (14.7); this slice copies the
    /// presented chain into it so [`SSL_get0_verified_chain`] is non-empty after a handshake.
    pub verified_chain: *mut c_void,
    /// `ASYNC_WAIT_CTX *waitctx` — allocated by the async path (14.5).
    pub waitctx: *mut AsyncWaitCtx,
    /// `ASYNC_JOB *job` — NULL unless an async job is paused (14.5).
    pub job: *mut c_void,
    /// `size_t asyncrw` — the async job's transferred byte count.
    pub asyncrw: usize,
    /// `int early_data_state` — `SSL_EARLY_DATA_*`.
    pub early_data_state: c_int,
    /// `int ext.early_data` — `SSL_EARLY_DATA_NONE` before a handshake.
    pub ext_early_data: c_int,
    /// `int key_update` — `SSL_KEY_UPDATE_*`.
    pub key_update: c_int,
    /// `int renegotiate`.
    pub renegotiate: c_int,
    /// `int new_session`.
    pub new_session: c_int,
    /// `OSSL_TIME ts_msg_write` — nanoseconds; 0 means "not available".
    pub ts_msg_write: u64,
    /// `OSSL_TIME ts_msg_read` — nanoseconds; 0 means "not available".
    pub ts_msg_read: u64,
    /// `unsigned char *ext.alpn` — this connection's ALPN offer, owned.
    pub ext_alpn: *mut u8,
    /// `unsigned int ext.alpn_len`.
    pub ext_alpn_len: c_uint,
    /// `unsigned char *ext.npn` — the negotiated NPN protocol, owned.
    pub ext_npn: *mut u8,
    /// `size_t ext.npn_len`.
    pub ext_npn_len: usize,
    /// `char *ext.hostname` — the SNI name, owned (set by 14.5's `SSL_set_tlsext_host_name`).
    pub ext_hostname: *mut c_char,
    /// `unsigned char *s3.alpn_selected` — the negotiated ALPN protocol, owned (14.5).
    pub s3_alpn_selected: *mut u8,
    /// `size_t s3.alpn_selected_len`.
    pub s3_alpn_selected_len: usize,
    /// `unsigned char *s3.alpn_proposed` — the client's offered protocol list, owned (server side).
    pub s3_alpn_proposed: *mut u8,
    /// `size_t s3.alpn_proposed_len`.
    pub s3_alpn_proposed_len: usize,
    /// `uint16_t *ext.supportedgroups` — the connection's supported group list, owned.
    pub supportedgroups: *mut u16,
    /// `size_t ext.supportedgroups_len`.
    pub supportedgroups_len: usize,
    /// `unsigned char *client_cert_type`.
    pub client_cert_type: *mut u8,
    /// `size_t client_cert_type_len`.
    pub client_cert_type_len: usize,
    /// `unsigned char *server_cert_type`.
    pub server_cert_type: *mut u8,
    /// `size_t server_cert_type_len`.
    pub server_cert_type_len: usize,
    /// `uint8_t ext.client_cert_type` — the negotiated client cert type (14.5).
    pub ext_client_cert_type: u8,
    /// `uint8_t ext.server_cert_type` — the negotiated server cert type (14.5).
    pub ext_server_cert_type: u8,
    /// `ssl_ct_validation_cb ct_validation_callback`.
    pub ct_validation_callback: Option<CtValidationCb>,
    /// `void *ct_validation_callback_arg`.
    pub ct_validation_callback_arg: *mut c_void,
    /// `size_t rlayer.block_padding`.
    pub block_padding: usize,
    /// `size_t rlayer.hs_padding`.
    pub hs_padding: usize,
    /// `STACK_OF(SCT) *scts` — parsed SCTs (14.9's).
    pub scts: *mut c_void,
    /// `int scts_parsed`.
    pub scts_parsed: c_int,
    /// `CLIENTHELLO_MSG *clienthello` — set only while a ClientHello callback runs (14.5).
    pub clienthello: *mut c_void,
    /// `int pha_enabled`.
    pub pha_enabled: c_int,
    /// `STACK_OF(SRTP_PROTECTION_PROFILE) *srtp_profiles` — the connection's own offer list
    /// (`SSL_set_tlsext_use_srtp`); NULL until the setter runs. `src/ssl/d1_srtp.rs` owns it.
    pub srtp_profiles: *mut OpenSslStack,
    /// `SRTP_PROTECTION_PROFILE *srtp_profile` — the negotiated profile, NULL before a handshake.
    pub srtp_profile: *mut c_void,
    /// `DTLS1_STATE *d1` — the DTLS state block (`dtls1_new`, `d1_lib.c:65`). `SSL_new` allocates it
    /// for a DTLS method and leaves it NULL for a TLS one, as the authority does; `src/ssl/d1_lib.rs`
    /// owns its fields.
    pub d1: *mut Dtls1State,
    /// `QUIC_TLS *qtls` — the QUIC TLS object `SSL_set_quic_tls_cbs` would build. NULL for every
    /// connection this crate builds, because the QUIC bridge is reduced to its refusal arms
    /// (14.10; `src/ssl/quic/quic_tls_api.rs`).
    pub qtls: *mut c_void,
    /// `OSSL_QUIC_TLS_CALLBACKS qtcb` — the callback table `SSL_set_quic_tls_cbs` fills from a
    /// dispatch array.
    pub qtcb: QuicTlsCallbacks,
    /// `void *qtarg` — the callback argument `SSL_set_quic_tls_cbs` stores.
    pub qtarg: *mut c_void,
    /// `STACK_OF(X509_NAME) *ca_names` — the connection's own CA-name list.
    pub ca_names: *mut OpenSslStack,
    /// `STACK_OF(X509_NAME) *client_ca_names` — the connection's own client-CA list.
    pub client_ca_names: *mut OpenSslStack,
    /// `STACK_OF(X509_NAME) *s3.tmp.peer_ca_names` — the CA names the peer sent
    /// (`SSL_get0_peer_CA_list`).
    pub peer_ca_names: *mut OpenSslStack,
    /// `int cert_comp_prefs[TLSEXT_comp_cert_limit]` — `SSL_set1_cert_comp_preference`.
    pub cert_comp_prefs: [c_int; TLSEXT_COMP_CERT_LIMIT],
    /// `tls_session_secret_cb_fn ext.session_secret_cb` — `SSL_set_session_secret_cb`.
    pub session_secret_cb: Option<SessionSecretCb>,
    /// `void *ext.session_secret_cb_arg`.
    pub session_secret_cb_arg: *mut c_void,
    /// `tls_session_ticket_ext_cb_fn ext.session_ticket_cb` — `SSL_set_session_ticket_ext_cb`.
    pub session_ticket_cb: Option<SessionTicketExtCb>,
    /// `void *ext.session_ticket_cb_arg`.
    pub session_ticket_cb_arg: *mut c_void,
    /// `TLS_SESSION_TICKET_EXT *ext.session_ticket` — `SSL_set_session_ticket_ext`.
    pub session_ticket: *mut TlsSessionTicketExt,

    // --- Phase 17.2c: the reduced TLS 1.3 key schedule and record protection ------------------
    /// `EVP_MD_CTX *s3.handshake_dgst` — the running transcript hash (`ssl_handshake_hash`,
    /// `ssl/ssl_lib.c:6094`). NULL until the cipher (and so the hash) is known.
    pub hs_md_ctx: *mut c_void,
    /// `s3.handshake_buffer` — the handshake bytes seen before `hs_md_ctx` could be initialised.
    pub hs_buf: [u8; TLS13_HS_BUF_LEN],
    /// `size_t hs_buf_len` — the buffered transcript length.
    pub hs_buf_len: usize,
    /// `EVP_PKEY *s3.tmp.pkey` — this side's ephemeral key share (`ssl_derive`, `s3_lib.c:5474`).
    pub pkey: *mut c_void,
    /// `EVP_PKEY *s3.peer_tmp` — the peer's ephemeral key share.
    pub peer_tmp: *mut c_void,
    /// `unsigned char early_secret[EVP_MAX_MD_SIZE]` (`tls13_generate_secret`, `tls13_enc.c:5461`).
    pub early_secret: [u8; EVP_MAX_MD_SIZE],
    /// `unsigned char handshake_secret[EVP_MAX_MD_SIZE]` (`tls13_enc.c:236`).
    pub handshake_secret: [u8; EVP_MAX_MD_SIZE],
    /// `unsigned char master_secret[EVP_MAX_MD_SIZE]` (`tls13_enc.c:260`).
    pub master_secret: [u8; EVP_MAX_MD_SIZE],
    /// `client_handshake_traffic_secret` (`tls13_enc.c:610`).
    pub client_hs_traffic: [u8; EVP_MAX_MD_SIZE],
    /// `server_handshake_traffic_secret` (`tls13_enc.c:645`).
    pub server_hs_traffic: [u8; EVP_MAX_MD_SIZE],
    /// `client_application_traffic_secret_0` (`tls13_enc.c:631`).
    pub client_app_traffic: [u8; EVP_MAX_MD_SIZE],
    /// `server_application_traffic_secret_0` (`tls13_enc.c:657`).
    pub server_app_traffic: [u8; EVP_MAX_MD_SIZE],
    /// `unsigned char handshake_traffic_hash[EVP_MAX_MD_SIZE]` (`tls13_enc.c:462`).
    pub handshake_traffic_hash: [u8; EVP_MAX_MD_SIZE],
    /// `unsigned char server_finished_hash[EVP_MAX_MD_SIZE]` (`tls13_enc.c:468`).
    pub server_finished_hash: [u8; EVP_MAX_MD_SIZE],
    /// `EVP_MD_get_size(ssl_handshake_md(s))` — the negotiated transcript hash length.
    pub hs_md_len: usize,
    /// The reduced digest selector: 0 is SHA256, 1 is SHA384 (`ssl_cipher_get_evp`, `t1_enc.c`).
    pub hs_md_kind: c_int,
    /// The fetched AEAD cipher (`ssl_cipher_get_evp_cipher`, `tls13_enc.c:558`).
    pub tls13_cipher: *mut c_void,
    /// The record-protection contexts (`ssl_set_new_record_layer`, `tls13_enc.c:747`). Unused by
    /// the reduced per-record AEAD (a fresh context is built per record), retained for the join.
    pub enc_ctx: *mut c_void,
    /// The read-protection context companion to [`Self::enc_ctx`].
    pub dec_ctx: *mut c_void,
    /// `set_plain_alerts`/protection-level flag — 1 once the handshake write key is installed
    /// (`tls13_change_cipher_state`, `tls13_enc.c:734`).
    pub enc_active: c_int,
    /// The read-protection-level flag companion to [`Self::enc_active`].
    pub dec_active: c_int,
    /// `write_key`/`write_iv` and the read pair.
    pub enc_key: [u8; 32],
    /// The write IV (`write_iv`).
    pub enc_iv: [u8; 16],
    /// The read key (`read_key`).
    pub dec_key: [u8; 32],
    /// The read IV (`read_iv`).
    pub dec_iv: [u8; 16],

    // --- Phase 17: the reduced TLS 1.2 key schedule and record protection ---------------------
    /// `unsigned char master_secret[SSL_MAX_MASTER_KEY_LENGTH]` — the TLS1.2 master secret
    /// (`tls1_generate_master_secret`, `t1_enc.c:267-275`). A connection is either TLS1.2 or
    /// TLS1.3, so this never coexists with the TLS1.3 schedule's [`Self::master_secret`].
    pub tls12_master_secret: [u8; SSL_MAX_MASTER_KEY_LENGTH],
    /// The TLS1.2 key block (`tls1_setup_key_block`, `t1_enc.c:315-370`):
    /// `client_write_key || server_write_key || client_write_IV || server_write_IV` for the reduced
    /// AEAD suites (no MAC keys).
    pub tls12_key_block: [u8; 128],
    /// The number of valid bytes in [`Self::tls12_key_block`].
    pub tls12_key_block_len: usize,
    /// The TLS1.2 PRF hash selector: 0 is SHA256, 1 is SHA384 (`ssl_cipher_get_evp`, `t1_enc.c`).
    pub tls12_md_kind: c_int,
    /// `uint64_t write_sequence`.
    pub enc_seq: u64,
    /// `uint64_t read_sequence`.
    pub dec_seq: u64,
    /// `EVP_CIPHER_get_key_length(new_sym_enc)`.
    pub cipher_key_len: usize,
    /// `EVP_CIPHER_get_iv_length(new_sym_enc)`.
    pub cipher_iv_len: usize,
    /// The AEAD tag length (16 for the reduced suites).
    pub cipher_tag_len: usize,
    /// `unsigned char peer_finish_md[EVP_MAX_MD_SIZE]` (`ssl3_take_mac`, `statem_lib.c:762`).
    pub peer_finish_md: [u8; EVP_MAX_MD_SIZE],
    /// `size_t peer_finish_md_len`.
    pub peer_finish_md_len: usize,
    /// `unsigned char finish_md[EVP_MAX_MD_SIZE]` (`tls_construct_finished`, `statem_lib.c:658`).
    pub finish_md: [u8; EVP_MAX_MD_SIZE],
    /// `size_t finish_md_len`.
    pub finish_md_len: usize,
    /// Phase 17.2: the content of the last record read by the reduced TLS 1.3 message reader
    /// (`tls_get_message_body`), with the byte offset of the next handshake message in it. The
    /// authority coalesces its flight (EncryptedExtensions/Certificate/CertificateVerify/Finished)
    /// into one record (`statem_flush`, `statem.c:945`), so the reduced read path buffers the
    /// record and delivers one handshake message per call.
    pub rd_msg_buf: [u8; TLS13_HS_BUF_LEN],
    /// The number of valid bytes in [`Self::rd_msg_buf`].
    pub rd_msg_len: usize,
    /// The offset of the next unread handshake message in [`Self::rd_msg_buf`].
    pub rd_msg_off: usize,
    /// Phase 17.2: the peer's leaf certificate, parsed from the server's `Certificate` message
    /// (`tls_process_server_certificate`, `statem_clnt.c:1995`) so `tls_process_cert_verify` can
    /// verify the `CertificateVerify` signature against its public key. Owned and freed by
    /// `SSL_free`.
    pub peer_cert: *mut c_void,
    /// Phase 17: the presented certificate chain, in wire order (leaf first), the reduction of
    /// `s->session->peer_chain` (`tls_process_server_certificate`, `statem_clnt.c:2013-2077`). The
    /// authority stores it on the handshake-created session and fills `session->peer` from its head
    /// (`tls_post_process_server_certificate`, `statem_clnt.c:2137,2165-2172`); the reduced path has
    /// no such session, so the chain lives on the connection and [`SSL_get_peer_cert_chain`] reads
    /// it when `s->session` is NULL. Owned; freed by `SSL_free`.
    pub peer_chain: *mut OpenSslStack,
    /// Phase 17: the unread tail of a decrypted application record, the reduction of the
    /// authority's record-layer record buffers (`s->rlayer.tlsrecs[i].data`/`off`,
    /// `ssl3_read_bytes`, `rec_layer_s3.c:778-820`): a read smaller than the record leaves the
    /// remainder here for the next `SSL_read_ex`. Inline; no separate allocation.
    pub rx_buf: [u8; TLS13_HS_BUF_LEN],
    /// The number of valid plaintext bytes in [`Self::rx_buf`].
    pub rx_len: usize,
    /// The offset of the next unread plaintext byte in [`Self::rx_buf`].
    pub rx_off: usize,
    /// Phase 17 — the record-layer read accumulator: the partially-read five-byte record header.
    /// The authority's `RECORD_LAYER` keeps the record it is assembling in `rlayer.rrec` between
    /// `ssl3_read_bytes` calls (`rec_layer_s3.c:161-...`), so a `BIO_read` that returns fewer than
    /// five header bytes is resumed rather than lost; `rec_hdr_len` bytes are valid.
    pub rec_hdr: [u8; 5],
    /// The number of valid bytes in [`Self::rec_hdr`].
    pub rec_hdr_len: usize,
    /// The body of the record being accumulated: ciphertext for a TLS 1.3 protected record,
    /// plaintext otherwise. `rec_body_len` bytes are valid; the record is processed only once the
    /// body length encoded in the header has arrived.
    pub rec_body: [u8; 17000],
    /// The number of valid bytes in [`Self::rec_body`].
    pub rec_body_len: usize,
}

// -------------------------------------------------------------------------------------------
// Callback type aliases (their arities are the authority's; Slice 1 stores and returns them)
// -------------------------------------------------------------------------------------------

/// `pem_password_cb` — `evp.h`. Re-exported from `src/evp/pem_bridge.rs`, the one definition:
/// a second `type PemPasswordCb` here would duplicate the alias and defeat the prototype
/// court's unique-alias resolution (`forensics/tools/prototype_court.py`).
pub use crate::evp::pem_bridge::PemPasswordCb;
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
/// `int (*)(SSL *, unsigned char *, unsigned char *, EVP_CIPHER_CTX *, EVP_MAC_CTX *, int)` — the
/// session-ticket key callback `SSL_CTX_set_tlsext_ticket_key_evp_cb` installs (`tls1.h:372`).
/// The two EVP context parameters are opaque here (14.7's crypto path is the only caller).
pub type TicketKeyEvpCb =
    unsafe extern "C" fn(*mut Ssl, *mut u8, *mut u8, *mut c_void, *mut c_void, c_int) -> c_int;
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
/// `int (*)(SSL *, int *, void *)` — the server-name callback
/// `SSL_CTX_set_tlsext_servername_callback` installs (`ssl_local.h:994`).
pub type ServernameCb = unsafe extern "C" fn(*mut Ssl, *mut c_int, *mut c_void) -> c_int;
/// `int (*)(SSL *, unsigned char *, unsigned char *, EVP_CIPHER_CTX *, HMAC_CTX *, int)` — the
/// deprecated ticket-key callback `SSL_CTX_set_tlsext_ticket_key_cb` installs (`ssl_local.h:1001`).
/// The cipher and MAC contexts are opaque here, as they are for [`TicketKeyEvpCb`].
pub type TicketKeyCb =
    unsafe extern "C" fn(*mut Ssl, *mut u8, *mut u8, *mut c_void, *mut c_void, c_int) -> c_int;
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
/// `ssl_ct_validation_cb` — `ssl.h` (`int (*)(const CT_POLICY_EVAL_CTX *, const STACK_OF(SCT) *,
/// void *)`). Both `CT_POLICY_EVAL_CTX` and `STACK_OF(SCT)` are opaque here (14.9's).
pub type CtValidationCb = unsafe extern "C" fn(*const c_void, *const c_void, *mut c_void) -> c_int;
/// `SSL_CTX_npn_select_cb_func` — `ssl.h`.
pub type NpnSelectCb =
    unsafe extern "C" fn(*mut Ssl, *mut *mut u8, *mut u8, *const u8, c_uint, *mut c_void) -> c_int;
/// `SSL_CTX_npn_advertised_cb_func` — `ssl.h`.
pub type NpnAdvertisedCb =
    unsafe extern "C" fn(*mut Ssl, *mut *const u8, *mut c_uint, *mut c_void) -> c_int;
/// `int (*new_session_cb)(SSL *, SSL_SESSION *)` — `ssl.h`.
pub type NewSessionCb = unsafe extern "C" fn(*mut Ssl, *mut SslSession) -> c_int;
/// `void (*remove_session_cb)(SSL_CTX *, SSL_SESSION *)` — `ssl.h`.
pub type RemoveSessionCb = unsafe extern "C" fn(*mut SslCtx, *mut SslSession);
/// `SSL_SESSION *(*get_session_cb)(SSL *, const unsigned char *, int, int *)` — `ssl.h`.
pub type GetSessionCb =
    unsafe extern "C" fn(*mut Ssl, *const u8, c_int, *mut c_int) -> *mut SslSession;
/// `int (*client_cert_cb)(SSL *, X509 **, EVP_PKEY **)` — `ssl.h`.
pub type ClientCertCb = unsafe extern "C" fn(*mut Ssl, *mut *mut X509, *mut *mut c_void) -> c_int;
/// `int (*app_gen_cookie_cb)(SSL *, unsigned char *, unsigned int *)` — `ssl.h`.
pub type GenCookieCb = unsafe extern "C" fn(*mut Ssl, *mut u8, *mut c_uint) -> c_int;
/// `int (*app_verify_cookie_cb)(SSL *, const unsigned char *, unsigned int)` — `ssl.h`.
pub type VerifyCookieCb = unsafe extern "C" fn(*mut Ssl, *const u8, c_uint) -> c_int;
/// `int (*gen_stateless_cookie_cb)(SSL *, unsigned char *, size_t *)` — `ssl.h`.
pub type GenStatelessCookieCb = unsafe extern "C" fn(*mut Ssl, *mut u8, *mut usize) -> c_int;
/// `int (*verify_stateless_cookie_cb)(SSL *, const unsigned char *, size_t)` — `ssl.h`.
pub type VerifyStatelessCookieCb = unsafe extern "C" fn(*mut Ssl, *const u8, usize) -> c_int;
/// `tls_session_secret_cb_fn` — `ssl.h:934`.
pub type SessionSecretCb = unsafe extern "C" fn(
    *mut Ssl,
    *mut c_void,
    *mut c_int,
    *mut OpenSslStack,
    *mut *const crate::ssl::ssl_ciph_table::SslCipher,
    *mut c_void,
) -> c_int;
/// `tls_session_ticket_ext_cb_fn` — `ssl.h`.
pub type SessionTicketExtCb =
    unsafe extern "C" fn(*mut Ssl, *const u8, c_int, *mut c_void) -> c_int;

/// `struct tls_session_ticket_ext_st` — `ssl_local.h`, the record `SSL_set_session_ticket_ext`
/// allocates: a length and a flexible data array that follows it (`data = self + 1`).
#[repr(C)]
pub struct TlsSessionTicketExt {
    /// `unsigned short length`.
    pub length: u16,
    /// `void *data` — the bytes immediately after this record in the authority; stored as a
    /// pointer into the same allocation here.
    pub data: *mut c_void,
}

/// `struct SSL_SESSION` — `ssl_local.h:476-564`, the whole record.
///
/// The structure is opaque to a consumer, so its field order here is this crate's own; the
/// fields and their types are the authority's. `time`/`timeout`/`calc_timeout` store **seconds**
/// rather than the authority's `OSSL_TIME` nanoseconds (`ssl_session_calculate_timeout`,
/// `ssl_sess.c:48`), because every reader in this stratum converts back to `time_t` and no
/// nanosecond-resolution arm is observable.
#[repr(C)]
pub struct SslSession {
    /// `int ssl_version`.
    pub ssl_version: c_int,
    /// `size_t master_key_length`.
    pub master_key_length: usize,
    /// `unsigned char early_secret[EVP_MAX_MD_SIZE]`.
    pub early_secret: [u8; EVP_MAX_MD_SIZE],
    /// `unsigned char master_key[TLS13_MAX_RESUMPTION_PSK_LENGTH]`.
    pub master_key: [u8; TLS13_MAX_RESUMPTION_PSK_LENGTH],
    /// `size_t session_id_length`.
    pub session_id_length: usize,
    /// `unsigned char session_id[SSL_MAX_SSL_SESSION_ID_LENGTH]`.
    pub session_id: [u8; SSL_MAX_SSL_SESSION_ID_LENGTH],
    /// `size_t sid_ctx_length`.
    pub sid_ctx_length: usize,
    /// `unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH]`.
    pub sid_ctx: [u8; SSL_MAX_SID_CTX_LENGTH],
    /// `char *psk_identity_hint`.
    pub psk_identity_hint: *mut c_char,
    /// `char *psk_identity`.
    pub psk_identity: *mut c_char,
    /// `int not_resumable`.
    pub not_resumable: c_int,
    /// `EVP_PKEY *peer_rpk`.
    pub peer_rpk: *mut c_void,
    /// `X509 *peer`.
    pub peer: *mut X509,
    /// `STACK_OF(X509) *peer_chain`.
    pub peer_chain: *mut OpenSslStack,
    /// `long verify_result`.
    pub verify_result: c_long,
    /// `OSSL_TIME time`, in seconds (see the type note).
    pub time: u64,
    /// `OSSL_TIME timeout`, in seconds.
    pub timeout: u64,
    /// `OSSL_TIME calc_timeout`, in seconds.
    pub calc_timeout: u64,
    /// `unsigned int compress_meth`.
    pub compress_meth: c_uint,
    /// `const SSL_CIPHER *cipher`.
    pub cipher: *const crate::ssl::ssl_ciph_table::SslCipher,
    /// `unsigned long cipher_id`.
    pub cipher_id: c_ulong,
    /// `unsigned int kex_group`.
    pub kex_group: c_uint,
    /// `CRYPTO_EX_DATA ex_data`.
    pub ex_data: CryptoExData,
    /// `char *ext.hostname`.
    pub ext_hostname: *mut c_char,
    /// `unsigned char *ext.tick`.
    pub ext_tick: *mut u8,
    /// `size_t ext.ticklen`.
    pub ext_ticklen: usize,
    /// `unsigned long ext.tick_lifetime_hint`.
    pub ext_tick_lifetime_hint: c_ulong,
    /// `uint32_t ext.tick_age_add`.
    pub ext_tick_age_add: u32,
    /// `uint32_t ext.max_early_data`.
    pub ext_max_early_data: u32,
    /// `unsigned char *ext.alpn_selected`.
    pub ext_alpn_selected: *mut u8,
    /// `size_t ext.alpn_selected_len`.
    pub ext_alpn_selected_len: usize,
    /// `uint8_t ext.max_fragment_len_mode` — `SSL_SESSION_get_max_fragment_length` reads it.
    pub max_fragment_len_mode: u8,
    /// `char *srp_username`.
    pub srp_username: *mut c_char,
    /// `unsigned char *ticket_appdata`.
    pub ticket_appdata: *mut u8,
    /// `size_t ticket_appdata_len`.
    pub ticket_appdata_len: usize,
    /// `uint32_t flags`.
    pub flags: u32,
    /// `SSL_CTX *owner` — the cache context the session is linked into.
    pub owner: *mut SslCtx,
    /// `struct ssl_session_st *prev`.
    pub prev: *mut SslSession,
    /// `struct ssl_session_st *next`.
    pub next: *mut SslSession,
    /// `CRYPTO_REF_COUNT references`.
    pub references: AtomicI32,
}

/// `struct timeval` — the two-`long` layout `SSL_get_event_timeout` writes on this platform.
#[repr(C)]
pub struct Timeval {
    /// `time_t tv_sec`.
    pub tv_sec: c_long,
    /// `suseconds_t tv_usec`.
    pub tv_usec: c_long,
}

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

/// The state machine's `ERR_raise(ERR_LIB_SSL, reason)` at a `statem*.c` coordinate.
///
/// The authority's `ossl_statem_fatal`/`ossl_statem_send_fatal` live in `ssl/statem/statem.c` and
/// raise through the same `ERR_LIB_SSL` queue; this crate keeps one raise helper so every libssl
/// coordinate lands in one place.
///
/// # Safety
/// Nothing beyond the FFI contract: the error state is thread-local.
pub(crate) unsafe fn raise_statem(reason: c_int, file: *const core::ffi::c_char, line: c_int) {
    // SAFETY: `file` is a static NUL-terminated string supplied by the caller and `reason` is a
    // `statem*.c` reason constant; `raise_with` writes the thread-local error queue only.
    unsafe { raise_with(ERR_LIB_SSL, reason, file, line) };
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
        // `ssl_lib.c:4005`: `OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL)` loads the SSL
        // reason strings, which `ERR_reason_error_string` then answers for every lib-20 code. The
        // string table `ERR_reason_error_string` reads belongs to libcrypto, so the load is routed
        // through libcrypto's exported `OPENSSL_init_crypto` (`runtime::dso_shared`).
        // SAFETY: the setting pointer is NULL, which the initialisers accept.
        if unsafe {
            crate::ssl::ssl_init::OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, ptr::null())
        } == 0
        {
            return ptr::null_mut();
        }
        let _ = crate::runtime::dso_shared::openssl_init_crypto(OPENSSL_INIT_LOAD_SSL_STRINGS);

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
            // `ssl_lib.c:4174`: the authority initialises the SRP credential block at construction
            // (`ssl_ctx_srp_ctx_init_intern`), which zeroes it and sets `strength = SRP_MINIMAL_N`.
            crate::ssl::tls_srp::ssl_ctx_srp_ctx_init_intern(ret);
            // `ssl_lib.c:4056`: allocate the internal session cache at construction.
            (*ret).sessions = OPENSSL_sk_new_null();
            if (*ret).sessions.is_null() {
                SSL_CTX_free(ret);
                return ptr::null_mut();
            }
            // `ssl_lib.c:4067` allocates the CT log store for every context.
            (*ret).ctlog_store = CTLOG_STORE_new_ex(libctx, propq);
            if (*ret).ctlog_store.is_null() {
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
            // `ssl_lib.c:4222`: no OCSP status request type is configured by default.
            (*ret).ext_status_type = TLSEXT_STATUSTYPE_NOTHING;

            // `ssl_lib.c:4075-4111`: load the cipher tables, install the default TLSv1.3
            // ciphersuites and build the default TLSv1.2-and-earlier preference list.
            crate::ssl::ssl_ciph::ssl_load_ciphers(ret);
            if crate::ssl::ssl_ciph::SSL_CTX_set_ciphersuites(
                ret,
                crate::ssl::ssl_ciph::OSSL_default_ciphersuites(),
            ) == 0
            {
                SSL_CTX_free(ret);
                return ptr::null_mut();
            }
            let sk = crate::ssl::ssl_ciph::ssl_create_cipher_list(
                ret,
                (*ret).tls13_ciphersuites,
                &mut (*ret).cipher_list,
                &mut (*ret).cipher_list_by_id,
                crate::ssl::ssl_ciph::OSSL_default_cipher_list(),
                (*ret).cert,
            );
            if sk.is_null() || crate::runtime::stack::OPENSSL_sk_num(sk) <= 0 {
                SSL_CTX_free(ret);
                return ptr::null_mut();
            }
            // `ssl_lib.c:4280`: apply the configuration's `system_default` command set.
            if crate::ssl::ssl_mcnf::ssl_ctx_system_config(ret) == 0 {
                SSL_CTX_free(ret);
                return ptr::null_mut();
            }
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

/// `sk_X509_NAME_pop_free`'s destructor thunk: `X509_NAME_free` over a `void *` slot.
///
/// # Safety
/// `p` must be NULL or a live `X509_NAME`.
unsafe extern "C" fn x509_name_free_void(p: *mut c_void) {
    // SAFETY: `p` is NULL or a live name per the caller's contract.
    unsafe { X509_NAME_free(p.cast::<X509Name>()) };
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
            OPENSSL_sk_free((*ctx).cipher_list);
            OPENSSL_sk_free((*ctx).cipher_list_by_id);
            OPENSSL_sk_free((*ctx).tls13_ciphersuites);
            OPENSSL_sk_free((*ctx).srtp_profiles);
            ssl_ctx_session_cache_free(ctx);
            crate::ssl::tls_srp::ssl_ctx_srp_ctx_free_intern(ctx);
            OPENSSL_sk_pop_free((*ctx).ca_names, Some(x509_name_free_void));
            OPENSSL_sk_pop_free((*ctx).client_ca_names, Some(x509_name_free_void));
            X509_VERIFY_PARAM_free((*ctx).param);
            CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ctx.cast(), &mut (*ctx).ex_data);
            X509_STORE_free((*ctx).cert_store);
            cert_free((*ctx).cert);
            dane_ctx_final(&mut (*ctx).dane);
            CTLOG_STORE_free((*ctx).ctlog_store);
            CRYPTO_free((*ctx).client_cert_type.cast(), FILE, 0);
            CRYPTO_free((*ctx).server_cert_type.cast(), FILE, 0);
            CRYPTO_free((*ctx).ext_alpn.cast(), FILE, 0);
            CRYPTO_free((*ctx).supportedgroups.cast(), FILE, 0);
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
            // `tls1_clear` (`t1_lib.c:136-139`) installs `TLS_MAX_VERSION_INTERNAL` for a TLS
            // any-version method and `dtls1_clear` (`d1_lib.c:217-218`) installs
            // `DTLS_MAX_VERSION_INTERNAL` for a DTLS one; `ossl_ssl_connection_reset`
            // (`ssl_lib.c:607-608`) sets the client version to the method's own version. The fresh
            // connection therefore reports the max of the method's family while `SSL_client_version`
            // reports the method's raw version (`TLS_ANY_VERSION`, `DTLS_ANY_VERSION` or a pinned one).
            (*s).version = match (*method).version {
                TLS_ANY_VERSION => TLS_MAX_VERSION_INTERNAL,
                DTLS_ANY_VERSION => DTLS_MAX_VERSION_INTERNAL,
                v => v,
            };
            (*s).client_version = (*method).version;
            (*s).server = c_int::from((*method).default_server);
            (*s).rwstate = SSL_NOTHING;
            // `ossl_ssl_connection_reset` (`ssl_lib.c:605`) calls `ossl_statem_clear`, which
            // resets the message-flow state to `MSG_FLOW_UNINITED`, the handshake state to
            // `TLS_ST_BEFORE` and `in_init` to 1 (`statem.c:130-136`). This slice does not run
            // the method's `ssl_init`/`ssl_reset`, so the same observable state is installed here.
            (*s).hand_state = TLS_ST_BEFORE;
            (*s).statem_state = MSG_FLOW_UNINITED;
            (*s).in_init = 1;
            // `ossl_ssl_connection_new_int` (`ssl_lib.c:810`) copies the context MFL when the
            // object is not QUIC; every object here is a TLS connection.
            (*s).max_fragment_len_mode = (*ctx).ext_max_fragment_len_mode;
            (*s).ext_status_type = (*ctx).ext_status_type;
            (*s).rlayer_default_read_buf_len = (*ctx).default_read_buf_len;
            // `RECORD_LAYER_reset` (`rec_layer_s3.c:72-98`) installs a fresh record-read method on
            // the connection; its init sets `rl->rstate = SSL_ST_READ_HEADER` (`tls_common.c:1335`).
            (*s).rstate = SSL_ST_READ_HEADER;
            // `ossl_ssl_connection_new_int` (`ssl_lib.c:907`) seeds the key-update state.
            (*s).key_update = SSL_KEY_UPDATE_NONE;
            // `SSL_new` runs the method's `ssl_new`, which for a DTLS method is `dtls1_new`
            // (`d1_lib.c:65-108`): allocate the DTLS state block, with the server cookie length
            // pre-set. A TLS method leaves `d1` NULL, exactly as the authority does.
            if (*method).dtls {
                (*s).d1 = dtls1_new_state((*s).server != 0);
                if (*s).d1.is_null() {
                    SSL_free(s);
                    return ptr::null_mut();
                }
            }

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

            (*s).cert = ssl_cert_dup((*ctx).cert);
            if (*s).cert.is_null() {
                SSL_free(s);
                return ptr::null_mut();
            }

            // `ssl3_new` (`s3_lib.c:3808-3824`) runs `ssl_srp_ctx_init_intern`, copying the
            // context's SRP credentials and callbacks onto the connection. The crate's `SSL_new`
            // does not run the method's `ssl_init`, so the copy is made here for the one field that
            // an observable reader (`SSL_SRP_CTX_init`, the `SSL_get_srp_*` accessors) reaches.
            if crate::ssl::tls_srp::ssl_srp_ctx_init_intern(s) == 0 {
                SSL_free(s);
                return ptr::null_mut();
            }

            // `ssl_lib.c:763-956` copies the remaining connection configuration from the context.
            (*s).session_ctx = ctx;
            (*s).pha_enabled = (*ctx).pha_enabled;
            (*s).ct_validation_callback = (*ctx).ct_validation_callback;
            (*s).ct_validation_callback_arg = (*ctx).ct_validation_callback_arg;
            (*s).block_padding = (*ctx).block_padding;
            (*s).hs_padding = (*ctx).hs_padding;
            if !(*ctx).client_cert_type.is_null() {
                (*s).client_cert_type = CRYPTO_memdup(
                    (*ctx).client_cert_type.cast(),
                    (*ctx).client_cert_type_len,
                    FILE,
                    938,
                )
                .cast::<u8>();
                if (*s).client_cert_type.is_null() {
                    SSL_free(s);
                    return ptr::null_mut();
                }
                (*s).client_cert_type_len = (*ctx).client_cert_type_len;
            }
            if !(*ctx).server_cert_type.is_null() {
                (*s).server_cert_type = CRYPTO_memdup(
                    (*ctx).server_cert_type.cast(),
                    (*ctx).server_cert_type_len,
                    FILE,
                    945,
                )
                .cast::<u8>();
                if (*s).server_cert_type.is_null() {
                    SSL_free(s);
                    return ptr::null_mut();
                }
                (*s).server_cert_type_len = (*ctx).server_cert_type_len;
            }
            if !(*ctx).ext_alpn.is_null() {
                (*s).ext_alpn = CRYPTO_memdup(
                    (*ctx).ext_alpn.cast(),
                    (*ctx).ext_alpn_len as usize,
                    FILE,
                    892,
                )
                .cast::<u8>();
                if (*s).ext_alpn.is_null() {
                    SSL_free(s);
                    return ptr::null_mut();
                }
                (*s).ext_alpn_len = (*ctx).ext_alpn_len;
            }
            if !(*ctx).supportedgroups.is_null() {
                (*s).supportedgroups = CRYPTO_memdup(
                    (*ctx).supportedgroups.cast(),
                    (*ctx).supportedgroups_len * core::mem::size_of::<u16>(),
                    FILE,
                    893,
                )
                .cast::<u16>();
                if (*s).supportedgroups.is_null() {
                    SSL_free(s);
                    return ptr::null_mut();
                }
                (*s).supportedgroups_len = (*ctx).supportedgroups_len;
            }
        }
        s
    })
}

/// `ssl_set_accept_state` — the non-QUIC body of `void SSL_set_accept_state(SSL *s)`
/// (`ssl/ssl_lib.c:4986-5004`).
///
/// The public entry point is `ssl_lib.c`'s row and stays in the Phase 2 ABI scaffold, so this is
/// the internal equivalent 14.6 and 14.8 call: it installs the server role, clears the shutdown
/// word, resets the message-flow state (`ossl_statem_clear`) and the record read state
/// (`RECORD_LAYER_reset`), and sets the handshake entry. The authority's `handshake_func` is
/// `method->ssl_accept`; this crate's method table carries no such pointer (14.2 stores scalars), so
/// the engine's own `ossl_statem_accept` stands in (14.5b).
///
/// # Safety
/// `s` must be NULL or a live connection.
pub(crate) unsafe fn ssl_set_accept_state(s: *mut Ssl) {
    if s.is_null() {
        return;
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    unsafe {
        (*s).server = 1;
        (*s).shutdown = 0;
        ossl_statem_clear(s);
        (*s).handshake_func = Some(ossl_statem_accept);
        (*s).rstate = SSL_ST_READ_HEADER;
    }
}

/// `ssl_set_connect_state` — the non-QUIC body of `void SSL_set_connect_state(SSL *s)`
/// (`ssl/ssl_lib.c:5006-5024`). As [`ssl_set_accept_state`], with the client role.
///
/// # Safety
/// `s` must be NULL or a live connection.
pub(crate) unsafe fn ssl_set_connect_state(s: *mut Ssl) {
    if s.is_null() {
        return;
    }
    // SAFETY: `s` is non-NULL and live per the caller's contract.
    unsafe {
        (*s).server = 0;
        (*s).shutdown = 0;
        ossl_statem_clear(s);
        (*s).handshake_func = Some(ossl_statem_connect);
        (*s).rstate = SSL_ST_READ_HEADER;
    }
}

/// `SSL_copy_session_id` — the reduced body of `int SSL_copy_session_id(SSL *t, const SSL *f)`
/// (`ssl/ssl_lib.c:2029-2062`), for `bio_ssl.c`'s `BIO_ssl_copy_session_id`.
///
/// The authority first re-points `t`'s session at `f`'s (`SSL_set_session`, 14.7's) and shares
/// `f`'s certificate container under a new reference (`ssl_cert_free`/`CRYPTO_UP_REF`). This crate
/// models neither the session object nor the certificate reference count in 14.1, and both are
/// 14.7's; the reachable arm here is a pair of fresh connections, where `SSL_set_session(t, NULL)`
/// succeeds, the methods are equal, and the shared container's observable (`SSL_get_certificate`)
/// is NULL on both sides. This reduced body copies the security attributes into `t`'s own
/// container (never sharing the pointer, so `SSL_free` cannot double-free) and copies the
/// session-id context, and reports the authority's answer for that case. The deeper arms are
/// recorded as reduced in `src/ssl/bio_ssl.rs`.
///
/// # Safety
/// `t` and `f` must point to live connections.
pub(crate) unsafe fn ssl_copy_session_id(t: *mut Ssl, f: *const Ssl) -> c_int {
    if t.is_null() || f.is_null() {
        return 0;
    }
    // SAFETY: both pointers are live per the caller's contract.
    unsafe {
        cert_copy_security((*t).cert, (*f).cert);
        let len = (*f).sid_ctx_length;
        if SSL_set_session_id_context(t, (*f).sid_ctx.as_ptr(), len) == 0 {
            return 0;
        }
    }
    1
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
            OPENSSL_sk_free((*s).cipher_list);
            OPENSSL_sk_free((*s).cipher_list_by_id);
            OPENSSL_sk_free((*s).tls13_ciphersuites);
            OPENSSL_sk_free((*s).peer_ciphers);
            OPENSSL_sk_free((*s).srtp_profiles);
            OPENSSL_sk_pop_free((*s).ca_names, Some(x509_name_free_void));
            OPENSSL_sk_pop_free((*s).client_ca_names, Some(x509_name_free_void));
            OPENSSL_sk_pop_free((*s).peer_ca_names, Some(x509_name_free_void));
            SSL_SESSION_free((*s).session);
            crate::ssl::tls_srp::ssl_srp_ctx_free_intern(s);
            CRYPTO_free((*s).session_ticket.cast(), FILE, 0);
            dtls1_free(s);
            BIO_free_all((*s).wbio);
            BIO_free_all((*s).rbio);
            // Phase 17.2c — release the reduced key-schedule and record-protection state.
            crate::evp::digest::EVP_MD_CTX_free((*s).hs_md_ctx.cast());
            crate::evp::cipher_ctx::EVP_CIPHER_CTX_free((*s).enc_ctx.cast());
            crate::evp::cipher_ctx::EVP_CIPHER_CTX_free((*s).dec_ctx.cast());
            crate::evp::cipher::EVP_CIPHER_free((*s).tls13_cipher.cast());
            crate::evp::pkey::EVP_PKEY_free((*s).pkey.cast());
            crate::evp::pkey::EVP_PKEY_free((*s).peer_tmp.cast());
            X509_free((*s).peer_cert.cast());
            // The presented chain and its verified copy own their own references: the authority
            // pushes one cert per `CertificateEntry` (`statem_clnt.c:2072`) and frees
            // `verified_chain` with `OSSL_STACK_OF_X509_free` (`ssl_lib.c:1521`).
            crate::x509::t_x509::OSSL_STACK_OF_X509_free((*s).peer_chain);
            crate::x509::t_x509::OSSL_STACK_OF_X509_free((*s).verified_chain.cast());
            X509_VERIFY_PARAM_free((*s).param);
            cert_free((*s).cert);
            CRYPTO_free((*s).client_cert_type.cast(), FILE, 0);
            CRYPTO_free((*s).server_cert_type.cast(), FILE, 0);
            CRYPTO_free((*s).ext_alpn.cast(), FILE, 0);
            CRYPTO_free((*s).ext_npn.cast(), FILE, 0);
            CRYPTO_free((*s).ext_hostname.cast(), FILE, 0);
            CRYPTO_free((*s).s3_alpn_selected.cast(), FILE, 0);
            CRYPTO_free((*s).s3_alpn_proposed.cast(), FILE, 0);
            CRYPTO_free((*s).supportedgroups.cast(), FILE, 0);
            CRYPTO_free((*s).pha_context.cast(), FILE, 0);
            crate::evp::digest::EVP_MD_CTX_free((*s).pha_dgst.cast());
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
/// The authority's body is `SSL_CONNECTION_FROM_CONST_SSL(s) == NULL ? 0 :
/// !SSL_CONNECTION_IS_DTLS(sc)`, so a NULL connection is not TLS; the crate's shared `is_dtls`
/// helper answers `false` for NULL, which is why the NULL test is explicit here.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_is_tls(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() || unsafe { is_quic(s) } {
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

/// `ssl_check_allowed_versions` — `ssl/ssl_lib.c:449-554`.
///
/// The authority ORs an `OPENSSL_NO_*` disjunct into each family guard and applies a version
/// "massaging" step (`0` -> the family's min/max) ahead of it. This build enables every protocol
/// (`src/ssl/statem/statem_lib.rs`'s `TLS_VERSION_TABLE`/`DTLS_VERSION_TABLE` carry `present: true`
/// on every row, and no `OPENSSL_NO_TLS*`/`OPENSSL_NO_SSL3`/`OPENSSL_NO_DTLS1*` is defined), so
/// every `#ifdef` disjunct is preprocessed out, the guards reduce to the source's literal
/// `if (0 ...)`, and only the DTLS/TLS family-mixing rejection can return 0. The observable result
/// is therefore the mixing test below followed by success.
fn ssl_check_allowed_versions(min_version: c_int, max_version: c_int) -> bool {
    // Figure out if we're doing DTLS versions or TLS versions (`ssl/ssl_lib.c:451-456`).
    let minisdtls = min_version == DTLS1_BAD_VER || min_version >> 8 == DTLS1_VERSION_MAJOR;
    let maxisdtls = max_version == DTLS1_BAD_VER || max_version >> 8 == DTLS1_VERSION_MAJOR;
    // A wildcard version of 0 could be DTLS or TLS (`ssl/ssl_lib.c:458-462`); mixing the two
    // families "will lead to sadness", so deny it.
    if (minisdtls && !maxisdtls && max_version != 0)
        || (maxisdtls && !minisdtls && min_version != 0)
    {
        return false;
    }
    // Both families' `if (0 ...)` guards have every disjunct compiled out (all protocols enabled),
    // so neither rejects; the authority returns 1 (`ssl/ssl_lib.c:554`).
    true
}

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
            // `ssl3_ctrl`'s `SSL_CTRL_SET_TLSEXT_HOSTNAME` arm (`s3_lib.c:4024-4054`), reached
            // because the authority's `SSL_ctrl` falls through to the method's control dispatcher.
            // This crate has no `ssl3_ctrl` pointer, so the one arm DANE needs is landed here.
            SSL_CTRL_SET_TLSEXT_HOSTNAME => {
                // SAFETY: `sc` is live; `parg` is NULL or a NUL-terminated name per the contract.
                unsafe { ssl3_ctrl_set_tlsext_host_name(s, larg, parg) }
            }
            // `ssl/ssl_lib.c:3056-3067` (`ossl_ctrl_internal`). The bound is checked against the
            // other bound first, then committed through `ssl_set_version_bound` for the method's
            // family; `&&` preserves the authority's short-circuit, so a rejected check does not
            // write the field.
            SSL_CTRL_SET_MIN_PROTO_VERSION => {
                // SAFETY: `sc` is live; `defltmeth` is the connection's method pointer.
                let method_version = unsafe { (*sc.defltmeth).version };
                let ok = ssl_check_allowed_versions(larg as c_int, sc.max_proto_version)
                    && ssl_set_version_bound(
                        method_version,
                        larg as c_int,
                        &mut sc.min_proto_version,
                    );
                c_long::from(ok)
            }
            SSL_CTRL_GET_MIN_PROTO_VERSION => sc.min_proto_version as c_long,
            SSL_CTRL_SET_MAX_PROTO_VERSION => {
                // SAFETY: `sc` is live; `defltmeth` is the connection's method pointer.
                let method_version = unsafe { (*sc.defltmeth).version };
                let ok = ssl_check_allowed_versions(sc.min_proto_version, larg as c_int)
                    && ssl_set_version_bound(
                        method_version,
                        larg as c_int,
                        &mut sc.max_proto_version,
                    );
                c_long::from(ok)
            }
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
            SSL_CTRL_SET_TMP_DH_CB => {
                // SAFETY: `s` is live; only the pointer bits are stored (`s3_lib.c:4394-4396`).
                unsafe {
                    (*(*s).cert).dh_tmp_cb =
                        fp.map(|f| f as *mut c_void).unwrap_or(ptr::null_mut());
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
            // `ssl/ssl_lib.c:3199-3209`. As in `SSL_ctrl`, the cross-bound check runs before
            // `ssl_set_version_bound` commits, and the `&&` short-circuit matches the authority's.
            SSL_CTRL_SET_MIN_PROTO_VERSION => {
                // SAFETY: `c` is live; `method` is the context's method pointer.
                let method_version = unsafe { (*c.method).version };
                let ok = ssl_check_allowed_versions(larg as c_int, c.max_proto_version)
                    && ssl_set_version_bound(
                        method_version,
                        larg as c_int,
                        &mut c.min_proto_version,
                    );
                c_long::from(ok)
            }
            SSL_CTRL_GET_MIN_PROTO_VERSION => c.min_proto_version as c_long,
            SSL_CTRL_SET_MAX_PROTO_VERSION => {
                // SAFETY: `c` is live; `method` is the context's method pointer.
                let method_version = unsafe { (*c.method).version };
                let ok = ssl_check_allowed_versions(c.min_proto_version, larg as c_int)
                    && ssl_set_version_bound(
                        method_version,
                        larg as c_int,
                        &mut c.max_proto_version,
                    );
                c_long::from(ok)
            }
            SSL_CTRL_GET_MAX_PROTO_VERSION => c.max_proto_version as c_long,
            // The authority's fall-through is `ctx->method->ssl_ctx_ctrl` (`ssl3_ctx_ctrl`); the
            // crate's reduced method carries the SRP credential arms there.
            // SAFETY: `ctx` is live per the caller's contract; `cmd`/`larg`/`parg` are the
            // caller's control arguments.
            _ => unsafe { ssl3_ctx_ctrl(ctx, cmd, larg, parg) },
        }
    })
}

/// `long ssl3_ctx_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)` — `ssl/s3_lib.c:4207`,
/// reduced to the SRP credential arms (`s3_lib.c:4517-4550`).
///
/// The authority's `SSL_CTX_set_srp_*` setters call this through `tls1_ctx_ctrl`; the crate keeps
/// it separate from `SSL_CTX_ctrl` because `SSL_CTRL_SET_SRP_ARG` (78) collides with
/// `SSL_CTRL_CLEAR_MODE` (78), so a command-78 call on `SSL_CTX_ctrl` is the mode clear and only a
/// direct `ssl3_ctx_ctrl` call is the SRP argument set — exactly as the authority splits them.
///
/// # Safety
/// `ctx` must point to a live context; `parg` must be valid for `cmd`.
pub(crate) unsafe fn ssl3_ctx_ctrl(
    ctx: *mut SslCtx,
    cmd: c_int,
    larg: c_long,
    parg: *mut c_void,
) -> c_long {
    // SAFETY: `ctx` is live per the caller's contract.
    let c = unsafe { &mut *ctx };
    match cmd {
        SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG => {
            // `s3_lib.c:4463-4465`: store the servername callback argument, then `break` to the
            // function's trailing `return 1`. HAProxy's `ssl_sock_switchctx_err_cbk` is invoked
            // through `final_server_name` with this pointer as its `priv`.
            c.servername_arg = parg;
            1
        }
        SSL_CTRL_SET_GROUPS => {
            // `s3_lib.c:4552-4560`: install the supported-groups list.
            // SAFETY: `parg` holds `larg` ints per the command's contract; `c`'s fields are
            // writable.
            c_long::from(unsafe {
                crate::ssl::t1_lib::tls1_set_groups(
                    &mut c.supportedgroups,
                    &mut c.supportedgroups_len,
                    parg.cast::<c_int>(),
                    larg as usize,
                )
            })
        }
        SSL_CTRL_SET_TMP_ECDH => {
            // `s3_lib.c:4449-4462` -> `ssl_set_tmp_ecdh_groups` (`tls_depr.c:167-190`).
            if parg.is_null() {
                // SAFETY: a constant site.
                unsafe { raise_ssl(ERR_R_PASSED_NULL_PARAMETER, 4451) };
                return 0;
            }
            // SAFETY: `parg` is a live `EC_KEY` for this command.
            let group =
                unsafe { crate::ec::key::EC_KEY_get0_group(parg.cast::<crate::ec::EcKey>()) };
            if group.is_null() {
                // SAFETY: a constant site.
                unsafe { raise_ssl(SSL_R_MISSING_PARAMETERS, 4457) };
                return 0;
            }
            // SAFETY: `group` is live.
            let nid = unsafe { crate::ec::lib::EC_GROUP_get_curve_name(group) };
            if nid == NID_undef {
                return 0;
            }
            // SAFETY: `nid` is this frame's int; `c`'s fields are writable.
            c_long::from(unsafe {
                crate::ssl::t1_lib::tls1_set_groups(
                    &mut c.supportedgroups,
                    &mut c.supportedgroups_len,
                    &nid,
                    1,
                )
            })
        }
        SSL_CTRL_SET_TMP_DH => {
            // `s3_lib.c:4423-4439`.
            if parg.is_null() {
                // SAFETY: a constant site.
                unsafe { raise_ssl(ERR_R_PASSED_NULL_PARAMETER, 4425) };
                return 0;
            }
            // SAFETY: `parg` is a live `DH` for this command.
            let pkdh = unsafe { ssl_dh_to_pkey(parg) };
            if pkdh.is_null() {
                // SAFETY: a constant site.
                unsafe { raise_ssl(ERR_R_DH_LIB, 4433) };
                return 0;
            }
            // SAFETY: `ctx` is live; on failure the caller frees `pkdh` (`s3_lib.c:4435-4438`).
            if unsafe { SSL_CTX_set0_tmp_dh_pkey(ctx, pkdh.cast()) } == 0 {
                // SAFETY: `pkdh` is this frame's key.
                unsafe { crate::evp::pkey::EVP_PKEY_free(pkdh) };
                return 0;
            }
            1
        }
        SSL_CTRL_SET_TLS_EXT_SRP_USERNAME => {
            c.srp_ctx.srp_mask |= SSL_KSRP;
            // SAFETY: `c` is live; `login` is NULL or an owned string.
            unsafe { CRYPTO_free(c.srp_ctx.login.cast(), FILE, 0) };
            c.srp_ctx.login = ptr::null_mut();
            if parg.is_null() {
                return 1;
            }
            // SAFETY: `parg` is a NUL-terminated string for this command.
            let len = unsafe { core::ffi::CStr::from_ptr(parg.cast::<c_char>()) }
                .to_bytes()
                .len();
            if !(1..=255).contains(&len) {
                // SAFETY: a constant site.
                unsafe { raise_ssl(SSL_R_INVALID_SRP_USERNAME, 4525) };
                return 0;
            }
            // SAFETY: `parg` is NUL-terminated; `CRYPTO_strdup` copies it.
            let dup = unsafe { CRYPTO_strdup(parg.cast::<c_char>(), FILE, 4528) };
            if dup.is_null() {
                // SAFETY: a constant site.
                unsafe { raise_ssl(ERR_R_INTERNAL_ERROR, 4529) };
                return 0;
            }
            c.srp_ctx.login = dup;
            1
        }
        SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD => {
            c.srp_ctx.give_client_pwd_callback =
                Some(crate::ssl::tls_srp::srp_password_from_info_cb);
            // SAFETY: `c` is live; `info` is NULL or an owned string.
            unsafe { CRYPTO_free(c.srp_ctx.info.cast(), FILE, 0) };
            // SAFETY: `parg` is a NUL-terminated string for this command.
            let dup = unsafe { CRYPTO_strdup(parg.cast::<c_char>(), FILE, 4537) };
            if dup.is_null() {
                // SAFETY: a constant site.
                unsafe { raise_ssl(ERR_R_INTERNAL_ERROR, 4538) };
                return 0;
            }
            c.srp_ctx.info = dup;
            1
        }
        SSL_CTRL_SET_SRP_ARG => {
            c.srp_ctx.srp_mask |= SSL_KSRP;
            c.srp_ctx.srp_cb_arg = parg;
            1
        }
        SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH => {
            c.srp_ctx.strength = larg as c_int;
            1
        }
        // `ssl_cert_set0_chain`/`ssl_cert_set1_chain` and `ssl_cert_add[01]_chain_cert`
        // (`s3_lib.c:4633-4645`).
        SSL_CTRL_CHAIN => {
            if larg == 0 {
                // SAFETY: `ctx` is live; `parg` is the chain to take ownership of.
                unsafe {
                    crate::ssl::ssl_cert::ssl_cert_set0_chain(
                        ptr::null_mut(),
                        ctx,
                        parg.cast::<OpenSslStack>(),
                    ) as c_long
                }
            } else {
                // SAFETY: `parg` is a live chain; `X509_chain_up_ref` copies it.
                let dchain = unsafe { crate::x509::x509_cmp::X509_chain_up_ref(parg.cast()) };
                if dchain.is_null() {
                    return 0;
                }
                // SAFETY: `dchain` is a fresh owned chain; the helper takes it.
                let r = unsafe {
                    crate::ssl::ssl_cert::ssl_cert_set0_chain(ptr::null_mut(), ctx, dchain)
                };
                if r == 0 {
                    // SAFETY: `dchain` is live and this call owns it.
                    unsafe { OSSL_STACK_OF_X509_free(dchain) };
                }
                r as c_long
            }
        }
        SSL_CTRL_CHAIN_CERT => {
            let x = parg.cast::<X509>();
            // SAFETY: `ctx` is live; `x` is the certificate for this command.
            unsafe {
                (if larg == 0 {
                    crate::ssl::ssl_cert::ssl_cert_add0_chain_cert(ptr::null_mut(), ctx, x)
                } else {
                    crate::ssl::ssl_cert::ssl_cert_add1_chain_cert(ptr::null_mut(), ctx, x)
                }) as c_long
            }
        }
        _ => 0,
    }
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
        SSL_CTRL_SET_NOT_RESUMABLE_SESS_CB => {
            // SAFETY: `ctx` is live; a `void (*)(void)` is pointer-sized (`s3_lib.c:4700-4702`).
            unsafe {
                (*ctx).not_resumable_session_cb =
                    fp.map(|f| core::mem::transmute::<_, NotResumableCb>(f));
            }
            1
        }
        SSL_CTRL_SET_TMP_DH_CB => {
            // SAFETY: `ctx` is live; only the pointer bits are stored (`s3_lib.c:4665-4667`).
            unsafe {
                (*(*ctx).cert).dh_tmp_cb = fp.map(|f| f as *mut c_void).unwrap_or(ptr::null_mut());
            }
            1
        }
        SSL_CTRL_SET_SRP_VERIFY_PARAM_CB => {
            // SAFETY: `ctx` is live; the pointer is stored as the SRP verify callback.
            unsafe {
                (*ctx).srp_ctx.srp_mask |= SSL_KSRP;
                (*ctx).srp_ctx.verify_param_callback =
                    fp.map(|f| core::mem::transmute::<_, SrpVerifyParamCb>(f));
            }
            1
        }
        SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB => {
            // SAFETY: `ctx` is live; the pointer is stored as the SRP username callback.
            unsafe {
                (*ctx).srp_ctx.srp_mask |= SSL_KSRP;
                (*ctx).srp_ctx.username_callback =
                    fp.map(|f| core::mem::transmute::<_, SrpUsernameCb>(f));
            }
            1
        }
        SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB => {
            // SAFETY: `ctx` is live; the pointer is stored as the SRP client-password callback.
            unsafe {
                (*ctx).srp_ctx.srp_mask |= SSL_KSRP;
                (*ctx).srp_ctx.give_client_pwd_callback =
                    fp.map(|f| core::mem::transmute::<_, SrpClientPwdCb>(f));
            }
            1
        }
        SSL_CTRL_SET_TLSEXT_SERVERNAME_CB => {
            // `ssl3_ctx_callback_ctrl`, `s3_lib.c:4669-4671`: the SNI callback. `fp` is the
            // `int (*)(SSL *, int *, void *)` argument nginx's `ngx_http_ssl_servername` has.
            // SAFETY: `ctx` is live; the pointer bits are stored as the callback.
            unsafe {
                (*ctx).servername_cb = fp.map(|f| core::mem::transmute::<_, ServernameCb>(f));
            }
            1
        }
        SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB => {
            // `ssl3_ctx_callback_ctrl`, `s3_lib.c:4678-4683`: the deprecated ticket-key callback.
            // SAFETY: `ctx` is live; the pointer bits are stored as the callback.
            unsafe {
                (*ctx).ticket_key_cb = fp.map(|f| core::mem::transmute::<_, TicketKeyCb>(f));
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
/// The order is the authority's: `i > 0` answers `SSL_ERROR_NONE`, then a non-empty error queue
/// answers `SSL_ERROR_SSL`/`SSL_ERROR_SYSCALL`, then the `rwstate` want words answer the
/// `WANT_READ`/`WANT_WRITE` arms. The BIO-flag refinements (`BIO_should_read`/`_write`/`_io_special`)
/// belong to the record layer and the BIO pair and are not reproduced; the crate's state machine
/// sets `rwstate` and leaves the want code the authority's retry flags would also produce, so the
/// want arms answer the authority's values (recorded in `src/ssl/mod.rs`).
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
        let (rwstate, shutdown, warn_alert) =
            unsafe { ((*s).rwstate, (*s).shutdown, (*s).warn_alert) };
        match rwstate {
            SSL_READING => SSL_ERROR_WANT_READ,
            SSL_WRITING => SSL_ERROR_WANT_WRITE,
            // `(sc->shutdown & SSL_RECEIVED_SHUTDOWN) && sc->s3.warn_alert == SSL_AD_CLOSE_NOTIFY`
            // (`ssl_lib.c:4929-4930`). `ssl3_read_bytes`' `close_notify` arm sets both
            // (`rec_layer_s3.c:913-914`); a fatal alert sets `shutdown` too but never sets
            // `warn_alert`, so it does not answer `SSL_ERROR_ZERO_RETURN` here.
            _ if shutdown & SSL_RECEIVED_SHUTDOWN != 0 && warn_alert == SSL_AD_CLOSE_NOTIFY => {
                SSL_ERROR_ZERO_RETURN
            }
            _ => SSL_ERROR_SYSCALL,
        }
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
pub unsafe extern "C" fn SSL_get_finished(s: *const Ssl, buf: *mut c_void, count: usize) -> usize {
    guard_ffi(0, || {
        if s.is_null() || buf.is_null() {
            return 0;
        }
        // `ssl3_take_mac`/`tls_construct_finished` store this side's `verify_data` in
        // `s3.tmp.finish_md` (`ssl/ssl_lib.c:1804-1809`).
        // SAFETY: `s` is live; `buf` holds `count` writable bytes.
        unsafe {
            let n = (*s).finish_md_len.min(count);
            if n != 0 {
                ptr::copy_nonoverlapping((*s).finish_md.as_ptr(), buf.cast::<u8>(), n);
            }
            n
        }
    })
}

/// `size_t SSL_get_peer_finished(const SSL *s, void *buf, size_t count)` — `ssl/ssl_lib.c:1815-1828`.
///
/// # Safety
/// `s` must be NULL or a live connection; `buf` must hold `count` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_peer_finished(
    s: *const Ssl,
    buf: *mut c_void,
    count: usize,
) -> usize {
    guard_ffi(0, || {
        if s.is_null() || buf.is_null() {
            return 0;
        }
        // The peer's `verify_data` is stored on receipt (`ssl3_take_mac`,
        // `ssl/ssl_lib.c:1820-1825`).
        // SAFETY: `s` is live; `buf` holds `count` writable bytes.
        unsafe {
            let n = (*s).peer_finish_md_len.min(count);
            if n != 0 {
                ptr::copy_nonoverlapping((*s).peer_finish_md.as_ptr(), buf.cast::<u8>(), n);
            }
            n
        }
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

/// `BIO_should_read(BIO *)` (`bio.h`) over the connection's read BIO. `SSL_get_error` consults it
/// to answer `SSL_ERROR_WANT_READ` (`ssl_lib.c:4867-4870`); `BIO_set_retry_read` sets the flag on
/// a retryable read.
///
/// # Safety
/// `s` must be a live connection.
unsafe fn read_bio_should_read(s: *const Ssl) -> bool {
    // SAFETY: `s` is live per the caller's contract.
    let b = unsafe { (*s).rbio };
    if b.is_null() {
        return false;
    }
    // SAFETY: `b` is the live read BIO.
    let flags = unsafe { (*b).flags };
    flags & crate::runtime::bio::BIO_FLAGS_READ != 0
}

/// `ssl_read_internal` — `ssl/ssl_lib.c:2312-2362`, reduced at the record layer's read.
///
/// The uninitialised, received-shutdown, early-data-retry and `ossl_statem_check_finish_init`
/// guards are the authority's (14.5b lands the state machine those last two consult). The tail
/// runs the authority's `ssl3_read` -> `ssl3_read_bytes(SSL3_RT_APPLICATION_DATA, ...)`
/// (`s3_lib.c:5151-5154`, `s3_lib.c:5118-5149`) over the reduced record layer, returning only
/// application plaintext and dropping post-handshake records the reduced state machine cannot yet
/// process.
///
/// # Safety
/// `s` must be NULL or a live connection; `buf` must hold `num` writable bytes and `readbytes` be
/// writable.
pub(crate) unsafe fn ssl_read_internal(
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
    // SAFETY: `s` is live.
    unsafe {
        if (*s).shutdown & SSL_RECEIVED_SHUTDOWN != 0 {
            (*s).rwstate = SSL_NOTHING;
            return 0;
        }
        if (*s).early_data_state == SSL_EARLY_DATA_CONNECT_RETRY
            || (*s).early_data_state == SSL_EARLY_DATA_ACCEPT_RETRY
        {
            raise_ssl(ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, 2336);
            return 0;
        }
        if ossl_statem_check_finish_init(s, 0) == 0 {
            return -1;
        }
        // Phase 17: once the handshake has finished, read through the reduced record layer the way
        // the authority reaches `ssl3_read_bytes` from `ssl3_read` with `SSL3_RT_APPLICATION_DATA`
        // (`s3_lib.c:5151-5154`, `s3_lib.c:5118-5149` -> `rec_layer_s3.c:622`). A post-handshake
        // record that is not application data (a TLS 1.3 `NewSessionTicket` is a handshake record,
        // `rec_layer_s3.c:992-1066`) is consumed by the authority's state machine and the read
        // loops (`goto start`, `rec_layer_s3.c:1065`). This slice has no post-handshake state
        // machine, so it drops such records and reads again; only application plaintext is returned.
        if (*s).in_init != 0 {
            return -1;
        }
        // Phase 17: first satisfy the caller from the unread tail of the previous record, which
        // `ssl3_read_bytes` left in `rx_buf` (`ssl3_read_internal`, `s3_lib.c`; the authority's
        // `ssl_release_record` advances `rr->off` and keeps the rest, `rec_layer_s3.c:778-820`).
        if (*s).rx_off < (*s).rx_len {
            let avail = (*s).rx_len - (*s).rx_off;
            let n = if _num < avail { _num } else { avail };
            if !_buf.is_null() && n != 0 {
                ptr::copy_nonoverlapping(
                    (*s).rx_buf.as_ptr().add((*s).rx_off),
                    _buf.cast::<u8>(),
                    n,
                );
            }
            (*s).rx_off += n;
            if (*s).rx_off >= (*s).rx_len {
                (*s).rx_off = 0;
                (*s).rx_len = 0;
            }
            if !_readbytes.is_null() {
                *_readbytes = n;
            }
            (*s).rwstate = SSL_NOTHING;
            return 1;
        }
        loop {
            let mut rt = 0u8;
            // SAFETY: `s` is live; `rx_buf` is the full record-sized scratch the record layer
            // decrypts into, so no record is lost when the caller's buffer is smaller.
            let n = crate::ssl::record::rec_layer_s3::ssl3_read_bytes(
                s,
                &mut rt,
                (*s).rx_buf.as_mut_ptr(),
                (*s).rx_buf.len(),
            );
            if n <= 0 {
                // `ssl3_read_bytes` now returns the authority's `ssl3_read_internal` value: `0`
                // for the terminal cases (`close_notify`, a fatal alert, an unexpected EOF) whose
                // connection state and error queue it has already set (`rec_layer_s3.c:864-944`,
                // `:501-524`), and `-1` for a retry, for which it left `rwstate = SSL_READING`
                // (`rec_layer_s3.c:497`). Propagate it as the authority's `ssl_read_internal`
                // propagates `ssl_read`'s return.
                if n < 0 && read_bio_should_read(s) {
                    (*s).rwstate = SSL_READING;
                }
                return n;
            }
            match rt {
                // `SSL3_RT_APPLICATION_DATA` (`ssl3.h`, 23): hand the caller `min(len, available)`
                // and keep the rest buffered (`ssl3_read_bytes`, `rec_layer_s3.c:786-823`).
                23 => {
                    let avail = n as usize;
                    let want = if _num < avail { _num } else { avail };
                    if !_buf.is_null() && want != 0 {
                        ptr::copy_nonoverlapping((*s).rx_buf.as_ptr(), _buf.cast::<u8>(), want);
                    }
                    (*s).rx_off = want;
                    (*s).rx_len = avail;
                    if (*s).rx_off >= (*s).rx_len {
                        (*s).rx_off = 0;
                        (*s).rx_len = 0;
                    }
                    if !_readbytes.is_null() {
                        *_readbytes = want;
                    }
                    (*s).rwstate = SSL_NOTHING;
                    return 1;
                }
                // `SSL3_RT_HANDSHAKE` (22): a post-handshake message. `NewSessionTicket` and
                // `KeyUpdate` are dropped and read on; a TLS1.3 post-handshake-authentication
                // exchange is driven here (`ssl3_read_bytes`'s `handshake_fragment` dispatch,
                // `rec_layer_s3.c:1026-1066`, and `ossl_statem_*_read_transition`'s `TLS_ST_OK`
                // arms).
                22 => {
                    // Copy the message out before dispatching: the handlers may write the
                    // connection (they send the client's response), so `rx_buf` must not be
                    // aliased by `msg`.
                    let mlen = n as usize;
                    let mut scratch = [0u8; 16384];
                    if mlen > scratch.len() {
                        return -1;
                    }
                    ptr::copy_nonoverlapping((*s).rx_buf.as_ptr(), scratch.as_mut_ptr(), mlen);
                    let msg = &scratch[..mlen];
                    let handled = if (*s).server == 0 {
                        // The client: a post-handshake `CertificateRequest` (`SSL_PHA_EXT_SENT`).
                        if (*s).post_handshake_auth == SSL_PHA_EXT_SENT {
                            if crate::ssl::statem::statem_clnt::tls13_client_process_post_handshake(
                                s, msg,
                            ) == 0
                            {
                                if crate::ssl::statem::statem::ossl_statem_in_error(s) == 0 {
                                    crate::ssl::statem::statem::ossl_statem_fatal(
                                        s,
                                        SSL_AD_INTERNAL_ERROR,
                                        ERR_R_INTERNAL_ERROR,
                                    );
                                }
                                return -1;
                            }
                            true
                        } else {
                            false
                        }
                    } else {
                        // The server: the response to its own `verify_client_post_handshake`.
                        if (*s).post_handshake_auth == SSL_PHA_REQUESTED {
                            if crate::ssl::statem::statem_srvr::tls13_server_process_post_handshake(
                                s, msg,
                            ) == 0
                            {
                                if crate::ssl::statem::statem::ossl_statem_in_error(s) == 0 {
                                    crate::ssl::statem::statem::ossl_statem_fatal(
                                        s,
                                        SSL_AD_INTERNAL_ERROR,
                                        ERR_R_INTERNAL_ERROR,
                                    );
                                }
                                return -1;
                            }
                            true
                        } else {
                            false
                        }
                    };
                    let _ = handled;
                    continue;
                }
                // `SSL3_RT_ALERT` (21): the record layer now decodes every alert itself
                // (`ssl3_read_bytes`, `rec_layer_s3.c:864-944`), so a returned alert record would
                // be one this reduced matcher already consumed; drop and read on.
                21 => continue,
                // Any other record type is not application data; drop it and read again.
                _ => continue,
            }
        }
    }
}
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

/// `ssl_write_internal` — `ssl/ssl_lib.c:2530-2585`, reduced at the record layer's write.
///
/// The uninitialised, sent-shutdown, write-flag, early-data-retry and
/// `ossl_statem_check_finish_init` guards are the authority's (14.5b lands the state machine the
/// last consults); the record-layer write the tail would call (`ssl3_write`) is unlanded, so it
/// answers -1 there.
///
/// # Safety
/// `s` must be NULL or a live connection; `buf` must hold `num` readable bytes and `written` be
/// writable.
pub(crate) unsafe fn ssl_write_internal(
    s: *mut Ssl,
    _buf: *const c_void,
    _num: usize,
    flags: u64,
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
    // SAFETY: `s` is live; every read below is from it.
    unsafe {
        if (*s).shutdown & SSL_SENT_SHUTDOWN != 0 {
            (*s).rwstate = SSL_NOTHING;
            raise_ssl(SSL_R_PROTOCOL_IS_SHUTDOWN, 2550);
            return -1;
        }
        if flags != 0 {
            raise_ssl(SSL_R_UNSUPPORTED_WRITE_FLAG, 2555);
            return -1;
        }
        if (*s).early_data_state == SSL_EARLY_DATA_CONNECT_RETRY
            || (*s).early_data_state == SSL_EARLY_DATA_ACCEPT_RETRY
            || (*s).early_data_state == SSL_EARLY_DATA_READ_RETRY
        {
            raise_ssl(ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, 2562);
            return 0;
        }
        if ossl_statem_check_finish_init(s, 1) == 0 {
            return -1;
        }
        // `ssl3_write_bytes`'s in-init dispatch (`rec_layer_s3.c:313-335`): while a handshake is in
        // progress (a TLS1.3 post-handshake `CertificateRequest` queued by
        // `SSL_verify_client_post_handshake`) the connection's `handshake_func` runs before the
        // application record. `-1` surfaces the authority's `i == 0`/-1 arms.
        if (*s).in_init != 0 {
            // SAFETY: `s` is live; `handshake_func` is non-NULL (checked above).
            let func = (*s).handshake_func;
            if let Some(f) = func {
                let r = f(s);
                if r <= 0 {
                    return -1;
                }
            }
        }
        // `SSL3_RT_APPLICATION_DATA` — `ssl3.h` (23).
        // SAFETY: `s` is live; `_buf` holds `_num` readable bytes per the contract.
        if crate::ssl::record::rec_layer_s3::ssl3_write_bytes(s, 23, _buf.cast(), _num) <= 0 {
            return -1;
        }
        // A completed write leaves the authority's record layer at `rwstate = SSL_NOTHING`
        // (`ossl_tls_handle_rlayer_return`, `rec_layer_s3.c:499`).
        (*s).rwstate = SSL_NOTHING;
        if !_written.is_null() {
            // SAFETY: `_written` is writable per the contract.
            *_written = _num;
        }
        1
    }
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

/// `int SSL_do_handshake(SSL *s)` — `ssl/ssl_lib.c:4947-4984`.
///
/// The authority's body drives `ossl_statem_check_finish_init`, the method's
/// `ssl_renegotiate_check` (transcribed in `src/ssl/s3_lib.rs`) and the connection's
/// `handshake_func` — the state machine 14.5b installs. The message layer the state machine would
/// reach is unlanded, so a fresh connection returns the state machine's `-1`; the guards and the
/// state it leaves are the authority's (see `src/ssl/statem/statem.rs`).
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
        // SAFETY: `s` is live; `check_finish_init` and the renegotiation check read/write its
        // state words, and `handshake_func` is the engine entry this crate installed.
        unsafe {
            if ossl_statem_check_finish_init(s, -1) == 0 {
                return -1;
            }
            crate::ssl::s3_lib::ssl3_renegotiate_check(s, 0);
            let mut ret = 1;
            if SSL_in_init(s) != 0 || SSL_in_before(s) != 0 {
                if let Some(func) = (*s).handshake_func {
                    ret = func(s);
                }
            }
            ret
        }
    })
}

/// `int SSL_accept(SSL *s)` — `ssl/ssl_lib.c:2188-2206`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_accept(s: *mut Ssl) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live; the setter installs the server role and the engine entry.
        unsafe {
            if (*s).handshake_func.is_none() {
                ssl_set_accept_state(s);
            }
        }
        // SAFETY: per the caller's contract.
        unsafe { SSL_do_handshake(s) }
    })
}

/// `int SSL_connect(SSL *s)` — `ssl/ssl_lib.c:2208-2226`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_connect(s: *mut Ssl) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live; the setter installs the client role and the engine entry.
        unsafe {
            if (*s).handshake_func.is_none() {
                ssl_set_connect_state(s);
            }
        }
        // SAFETY: per the caller's contract.
        unsafe { SSL_do_handshake(s) }
    })
}

/// `int SSL_read_early_data(SSL *s, void *buf, size_t num, size_t *readbytes)` —
/// `ssl/ssl_lib.c:2395-2448`.
///
/// The client refusal (`sc == NULL || !sc->server`) is the authority's; the server arm enters the
/// engine, whose driver returns the authority's `-1` for an empty peer BIO, so the retry/`ERROR`
/// answer is the authority's too (see `src/ssl/statem/statem.rs`). The `SSL_read_ex` tail of the
/// accepted-early-data arm is unreachable without the message layer.
///
/// # Safety
/// `s` must be NULL or a live connection; `buf` must hold `num` writable bytes and `readbytes` be
/// writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_read_early_data(
    s: *mut Ssl,
    buf: *mut c_void,
    num: usize,
    readbytes: *mut usize,
) -> c_int {
    guard_ffi(SSL_READ_EARLY_DATA_ERROR, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() || unsafe { (*s).server } == 0 {
            // SAFETY: a constant site.
            unsafe { raise_ssl(ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, 2402) };
            return SSL_READ_EARLY_DATA_ERROR;
        }
        // SAFETY: `s` is live; every read/write below is to it.
        unsafe {
            match (*s).early_data_state {
                SSL_EARLY_DATA_NONE => {
                    if SSL_in_before(s) == 0 {
                        raise_ssl(ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, 2409);
                        return SSL_READ_EARLY_DATA_ERROR;
                    }
                    (*s).early_data_state = SSL_EARLY_DATA_ACCEPTING;
                    let ret = SSL_accept(s);
                    if ret <= 0 {
                        (*s).early_data_state = SSL_EARLY_DATA_ACCEPT_RETRY;
                        return SSL_READ_EARLY_DATA_ERROR;
                    }
                }
                SSL_EARLY_DATA_ACCEPT_RETRY => {
                    (*s).early_data_state = SSL_EARLY_DATA_ACCEPTING;
                    let ret = SSL_accept(s);
                    if ret <= 0 {
                        (*s).early_data_state = SSL_EARLY_DATA_ACCEPT_RETRY;
                        return SSL_READ_EARLY_DATA_ERROR;
                    }
                }
                _ => {}
            }
            // `SSL_EARLY_DATA_READ_RETRY`: the accepted-early-data `SSL_read_ex` tail needs the
            // message layer, so the not-accepted arm answers the authority's `FINISH`.
            if (*s).early_data_state == SSL_EARLY_DATA_READ_RETRY
                && (*s).ext_early_data == SSL_EARLY_DATA_ACCEPTED
            {
                let _ = (buf, num, readbytes);
                (*s).early_data_state = SSL_EARLY_DATA_READING;
                return SSL_READ_EARLY_DATA_ERROR;
            }
            if !readbytes.is_null() {
                *readbytes = 0;
            }
            (*s).early_data_state = SSL_EARLY_DATA_FINISHED_READING;
            SSL_READ_EARLY_DATA_FINISH
        }
    })
}

/// `int SSL_write_early_data(SSL *s, const void *buf, size_t num, size_t *written)` —
/// `ssl/ssl_lib.c:2691-2765`.
///
/// The `sc == NULL`, server-role, not-`SSL_in_before` and no-early-data-session refusals are the
/// authority's; the `SSL_connect`/`SSL_write_ex` arms need the message layer and are unreachable
/// for a fresh connection.
///
/// # Safety
/// `s` must be NULL or a live connection; `buf` must hold `num` readable bytes and `written` be
/// writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_write_early_data(
    s: *mut Ssl,
    buf: *const c_void,
    num: usize,
    written: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live; every read/write below is to it.
        unsafe {
            match (*s).early_data_state {
                SSL_EARLY_DATA_NONE => {
                    if (*s).server != 0
                        || SSL_in_before(s) == 0
                        || (((*s).session.is_null() || (*(*s).session).ext_max_early_data == 0)
                            && (*s).psk_use_session_cb.is_none())
                    {
                        raise_ssl(ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, 2708);
                        return 0;
                    }
                    (*s).early_data_state = SSL_EARLY_DATA_CONNECTING;
                    let ret = SSL_connect(s);
                    if ret <= 0 {
                        (*s).early_data_state = SSL_EARLY_DATA_CONNECT_RETRY;
                        return 0;
                    }
                }
                SSL_EARLY_DATA_CONNECT_RETRY => {
                    (*s).early_data_state = SSL_EARLY_DATA_CONNECTING;
                    let ret = SSL_connect(s);
                    if ret <= 0 {
                        (*s).early_data_state = SSL_EARLY_DATA_CONNECT_RETRY;
                        return 0;
                    }
                }
                _ => {}
            }
            // `SSL_EARLY_DATA_WRITE_RETRY`/`_WRITE_FLUSH`: the `SSL_write_ex` and `statem_flush`
            // tail needs a running handshake, so the fresh connection never reaches it here.
            if (*s).early_data_state == SSL_EARLY_DATA_WRITE_RETRY {
                let _ = (buf, num, written);
                return 0;
            }
            0
        }
    })
}

/// `SSL3_RT_ALERT` — `ssl3.h` (21).
const SSL3_RT_ALERT: u8 = 21;

/// `int ssl3_send_alert(SSL_CONNECTION *s, int level, int desc)` — `ssl/s3_msg.c:45-77`, reduced to
/// the synchronous dispatch arm.
///
/// The authority queues the two alert bytes and calls `ssl_dispatch_alert` when no write is pending;
/// this crate's record writer ([`crate::ssl::record::rec_layer_s3::ssl3_write_bytes`]) writes one
/// record synchronously, so the dispatch is performed inline and the queued-dispatch return arm is
/// unreachable. `tls13_alert_code` (`statem_lib.c`) is the identity for `close_notify`.
///
/// # Safety
/// `s` must be a live connection whose write BIO is the caller's to write.
unsafe fn ssl3_send_alert(s: *mut Ssl, level: c_int, desc: c_int) -> c_int {
    // `s3_msg.c:59-60`: a second alert other than `close_notify` is refused once shutdown is sent.
    // SAFETY: `s` is live per the caller's contract.
    if unsafe { (*s).shutdown } & SSL_SENT_SHUTDOWN != 0 && desc != SSL_AD_CLOSE_NOTIFY {
        return -1;
    }
    let body = [level as u8, desc as u8];
    // SAFETY: `s` is live; `body` is two readable bytes.
    if unsafe {
        crate::ssl::record::rec_layer_s3::ssl3_write_bytes(s, SSL3_RT_ALERT, body.as_ptr(), 2)
    } <= 0
    {
        return -1;
    }
    1
}

/// `int ssl3_shutdown(SSL *s)` — `ssl/s3_lib.c:5048-5101`.
///
/// The authority's two-call protocol: the first call sends `close_notify` and (unless the peer has
/// already been marked shut down) waits for the peer's `close_notify`; the second call reaps it. A
/// `quiet_shutdown` connection, or one still before the handshake, is shut down silently. This
/// reduced form dispatches the alert synchronously, so `s3.alert_dispatch` never stays pending.
///
/// # Safety
/// `s` must be a live connection whose write BIO is the caller's to write.
unsafe fn ssl3_shutdown(s: *mut Ssl) -> c_int {
    // SAFETY: `s` is live per the caller's contract.
    let (quiet, before, mut shutdown) =
        unsafe { ((*s).quiet_shutdown, SSL_in_before(s), (*s).shutdown) };
    if quiet != 0 || before != 0 {
        // SAFETY: `s` is live.
        unsafe { (*s).shutdown = SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN };
        return 1;
    }

    if shutdown & SSL_SENT_SHUTDOWN == 0 {
        shutdown |= SSL_SENT_SHUTDOWN;
        // SAFETY: `s` is live.
        unsafe {
            (*s).shutdown = shutdown;
            ssl3_send_alert(s, SSL3_AL_WARNING, SSL_AD_CLOSE_NOTIFY);
        }
    } else if shutdown & SSL_RECEIVED_SHUTDOWN == 0 {
        // `ssl3_lib.c:5085-5093`: wait for the peer's `close_notify`, discarding whatever record
        // arrives. A retry leaves `rwstate = SSL_READING` and this call answers -1 (WANT_READ).
        let mut rt = 0u8;
        let mut buf = [0u8; 2048];
        // SAFETY: `s` is live; the buffers are this frame's.
        let _ = unsafe {
            crate::ssl::record::rec_layer_s3::ssl3_read_bytes(
                s,
                &mut rt,
                buf.as_mut_ptr(),
                buf.len(),
            )
        };
        // SAFETY: `s` is live; the read may have set `SSL_RECEIVED_SHUTDOWN`.
        shutdown = unsafe { (*s).shutdown };
        if shutdown & SSL_RECEIVED_SHUTDOWN == 0 {
            return -1;
        }
    }

    if shutdown == (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN) {
        1
    } else {
        0
    }
}

/// `int SSL_shutdown(SSL *s)` — `ssl/ssl_lib.c:2767-2807`.
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
        // SAFETY: `s` is live.
        if unsafe { SSL_in_init(s) } == 0 {
            // SAFETY: `s` is live; this is the authority's `method->ssl_shutdown`.
            unsafe { ssl3_shutdown(s) }
        } else {
            // `ssl_lib.c:2799-2801`.
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_SHUTDOWN_WHILE_IN_INIT, 2800) };
            -1
        }
    })
}

// -------------------------------------------------------------------------------------------
// The handshake entry points (14.5b)
// -------------------------------------------------------------------------------------------

/// `SSL_CONNECTION_IS_TLS13(s)` — `ssl_local.h:265-267`.
///
/// A method whose version is `TLS_ANY_VERSION` is *not* TLS 1.3 here even though its connection's
/// `version` is the max; the authority negotiates that at runtime. Every method this crate builds
/// is any-version, so this is false unless a pinned TLS 1.3 method is added.
///
/// # Safety
/// `s` must point to a live connection.
unsafe fn connection_is_tls13(s: *const Ssl) -> bool {
    // SAFETY: `s` is live per the caller's contract.
    unsafe {
        if is_dtls(s) || (*s).method.is_null() {
            return false;
        }
        let v = (*(*s).method).version;
        v >= TLS1_3_VERSION && v != TLS_ANY_VERSION
    }
}

/// `SSL_IS_FIRST_HANDSHAKE(s)` — `ssl_local.h:277-278`.
///
/// # Safety
/// `s` must point to a live connection.
unsafe fn ssl_is_first_handshake(s: *const Ssl) -> bool {
    // SAFETY: `s` is live per the caller's contract.
    unsafe { (*s).s3_tmp_finish_md_len == 0 || (*s).s3_tmp_peer_finish_md_len == 0 }
}

/// `int SSL_key_update(SSL *s, int updatetype)` — `ssl/ssl_lib.c:2809-2845`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_key_update(s: *mut Ssl, updatetype: c_int) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is non-NULL and live; `connection_is_tls13` reads its method's version.
        let is_tls13 = unsafe { connection_is_tls13(s) };
        if !is_tls13 {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_WRONG_SSL_VERSION, 2822) };
            return 0;
        }
        if updatetype != SSL_KEY_UPDATE_NOT_REQUESTED && updatetype != SSL_KEY_UPDATE_REQUESTED {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_INVALID_KEY_UPDATE_TYPE, 2828) };
            return 0;
        }
        // SAFETY: `s` is live; every read/write below is to it.
        unsafe {
            if SSL_is_init_finished(s) == 0 {
                raise_ssl(SSL_R_STILL_IN_INIT, 2833);
                return 0;
            }
            if crate::ssl::record::rec_layer_s3::record_layer_write_pending(s) != 0 {
                raise_ssl(SSL_R_BAD_WRITE_RETRY, 2837);
                return 0;
            }
            ossl_statem_set_in_init(s, 1);
            (*s).key_update = updatetype;
        }
        1
    })
}

/// `can_renegotiate(const SSL_CONNECTION *sc)` — `ssl/ssl_lib.c:2866-2879`.
///
/// # Safety
/// `s` must point to a live connection.
unsafe fn can_renegotiate(s: *const Ssl) -> bool {
    // SAFETY: `s` is live per the caller's contract; `connection_is_tls13` reads its method
    // version.
    if unsafe { connection_is_tls13(s) } {
        // SAFETY: a constant site.
        unsafe { raise_ssl(SSL_R_WRONG_SSL_VERSION, 2869) };
        return false;
    }
    // SAFETY: `s` is live per the caller's contract.
    if unsafe { (*s).options } & SSL_OP_NO_RENEGOTIATION != 0 {
        // SAFETY: a constant site.
        unsafe { raise_ssl(SSL_R_NO_RENEGOTIATION, 2874) };
        return false;
    }
    true
}

/// `int SSL_renegotiate(SSL *s)` — `ssl/ssl_lib.c:2881-2894`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_renegotiate(s: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is non-NULL and live; `can_renegotiate` reads its method version and options.
        let ok = unsafe { can_renegotiate(s) };
        if !ok {
            return 0;
        }
        // SAFETY: `s` is live; the flags and the method's `ssl_renegotiate` are the authority's.
        unsafe {
            (*s).renegotiate = 1;
            (*s).new_session = 1;
            crate::ssl::s3_lib::ssl3_renegotiate(s)
        }
    })
}

/// `int SSL_renegotiate_abbreviated(SSL *s)` — `ssl/ssl_lib.c:2896-2909`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_renegotiate_abbreviated(s: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is non-NULL and live; `can_renegotiate` reads its method version and options.
        let ok = unsafe { can_renegotiate(s) };
        if !ok {
            return 0;
        }
        // SAFETY: `s` is live; the flags and the method's `ssl_renegotiate` are the authority's.
        unsafe {
            (*s).renegotiate = 1;
            (*s).new_session = 0;
            crate::ssl::s3_lib::ssl3_renegotiate(s)
        }
    })
}

/// `int SSL_new_session_ticket(SSL *s)` — `ssl/ssl_lib.c:2925-2941`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_new_session_ticket(s: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live; every read/write below is to it.
        unsafe {
            if (SSL_in_init(s) != 0 && (*s).extra_tickets_expected == 0)
                || ssl_is_first_handshake(s)
                || (*s).server == 0
                || !connection_is_tls13(s)
            {
                return 0;
            }
            (*s).extra_tickets_expected += 1;
            if crate::ssl::record::rec_layer_s3::record_layer_write_pending(s) == 0
                && SSL_in_init(s) == 0
            {
                ossl_statem_set_in_init(s, 1);
            }
        }
        1
    })
}

/// `int SSL_export_keying_material(SSL *s, ...)` — `ssl/ssl_lib.c:3817-3835`, reduced at the
/// encryption method's own exporter.
///
/// The NULL-connection and no-session/bad-version guards are the authority's; the tail delegates
/// to `sc->ssl.method->ssl3_enc->export_keying_material`, and the `ssl3_enc` method table and its
/// TLS exporter (`tls1_export_keying_material`/`tls13_export_keying_material`) are unlanded, so the
/// reachable no-session arm returns -1 and the deeper arm is recorded rather than approximated.
///
/// # Safety
/// `s` must be NULL or a live connection; `out` must hold `olen` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_export_keying_material(
    s: *mut Ssl,
    out: *mut u8,
    olen: usize,
    label: *const c_char,
    llen: usize,
    context: *const u8,
    contextlen: usize,
    use_context: c_int,
) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() {
            return -1;
        }
        // SAFETY: `s` is live; every read below is from it.
        unsafe {
            if (*s).session.is_null()
                || ((*s).version < TLS1_VERSION && (*s).version != DTLS1_BAD_VER)
            {
                return -1;
            }
        }
        // The `ssl3_enc->export_keying_material` tail is unlanded (recorded in src/ssl/mod.rs).
        let _ = (out, olen, label, llen, context, contextlen, use_context);
        -1
    })
}

/// `int SSL_export_keying_material_early(SSL *s, ...)` — `ssl/ssl_lib.c:3837-3852`, reduced to the
/// early-exporter predicate.
///
/// The version guard is the authority's; `tls13_export_keying_material_early`'s own first check is
/// `ossl_statem_export_early_allowed`, which is 0 for every pre-handshake state, so the answer is
/// the authority's 0. The key-schedule tail beyond that check is unlanded and recorded.
///
/// # Safety
/// `s` must be NULL or a live connection; `out` must hold `olen` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_export_keying_material_early(
    s: *mut Ssl,
    out: *mut u8,
    olen: usize,
    label: *const c_char,
    llen: usize,
    context: *const u8,
    contextlen: usize,
) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() {
            return -1;
        }
        // SAFETY: `s` is live; every read below is from it.
        unsafe {
            if (*s).version != TLS1_3_VERSION {
                return 0;
            }
            if crate::ssl::statem::statem::ossl_statem_export_early_allowed(s) == 0 {
                return 0;
            }
        }
        // The key-schedule tail is unlanded (recorded in src/ssl/mod.rs).
        let _ = (out, olen, label, llen, context, contextlen);
        -1
    })
}

/// `ossl_ssize_t SSL_sendfile(SSL *s, int fd, off_t offset, size_t size, int flags)` —
/// `ssl/ssl_lib.c:2587-2652`, reduced to the guards.
///
/// The NULL-connection, uninitialised and sent-shutdown guards are the authority's; the KTLS-send
/// check is 0 for every BIO this crate builds (no record method reports it), so the authority's
/// next guard answers -1 as well. The KTLS arm is unlanded and recorded.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_sendfile(
    s: *mut Ssl,
    fd: c_int,
    offset: i64,
    size: usize,
    flags: c_int,
) -> isize {
    guard_ffi(0, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live; every read below is from it.
        unsafe {
            if (*s).handshake_func.is_none() {
                raise_ssl(SSL_R_UNINITIALIZED, 2596);
                return -1;
            }
            if (*s).shutdown & SSL_SENT_SHUTDOWN != 0 {
                (*s).rwstate = SSL_NOTHING;
                raise_ssl(SSL_R_PROTOCOL_IS_SHUTDOWN, 2602);
                return -1;
            }
            // `BIO_get_ktls_send(wbio)` is 0 here: no BIO this crate builds reports KTLS send, so
            // the authority's next guard answers -1.
            raise_ssl(SSL_R_UNINITIALIZED, 2607);
        }
        let _ = (fd, offset, size, flags);
        -1
    })
}

/// `int SSL_stateless(SSL *s)` — `ssl/ssl_lib.c:7350-7375`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_stateless(s: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live; every read/write below is to it.
        unsafe {
            if SSL_clear(s) == 0 {
                return 0;
            }
            crate::runtime::err::ERR_clear_error();
            (*s).s3_flags |= TLS1_FLAGS_STATELESS;
            let ret = SSL_accept(s);
            (*s).s3_flags &= !TLS1_FLAGS_STATELESS;
            if ret > 0 && (*s).cookieok != 0 {
                return 1;
            }
            if (*s).hello_retry_request == SSL_HRR_PENDING && ossl_statem_in_error(s) == 0 {
                return 0;
            }
        }
        -1
    })
}

/// `int SSL_verify_client_post_handshake(SSL *ssl)` — `ssl/ssl_lib.c:7392-7449`, reduced to the
/// refusal ladder.
///
/// The NULL-connection, non-TLS-1.3, non-server and not-init-finished refusals plus the
/// `post_handshake_auth` switch's refusal arms are the authority's; the `send_certificate_request`
/// success arm needs the message layer and is unreachable for the states this crate reaches.
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_verify_client_post_handshake(ssl: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if ssl.is_null() {
            return 0;
        }
        // SAFETY: `ssl` is non-NULL and live; `connection_is_tls13` reads its method version.
        let is_tls13 = unsafe { connection_is_tls13(ssl) };
        if !is_tls13 {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_WRONG_SSL_VERSION, 7407) };
            return 0;
        }
        // SAFETY: `ssl` is live; every read below is from it.
        unsafe {
            if (*ssl).server == 0 {
                raise_ssl(SSL_R_NOT_SERVER, 7411);
                return 0;
            }
            if SSL_is_init_finished(ssl) == 0 {
                raise_ssl(SSL_R_STILL_IN_INIT, 7416);
                return 0;
            }
            match (*ssl).post_handshake_auth {
                SSL_PHA_NONE => {
                    raise_ssl(SSL_R_EXTENSION_NOT_RECEIVED, 7422);
                    return 0;
                }
                SSL_PHA_REQUEST_PENDING => {
                    raise_ssl(SSL_R_REQUEST_PENDING, 7431);
                    return 0;
                }
                SSL_PHA_REQUESTED => {
                    raise_ssl(SSL_R_REQUEST_SENT, 7434);
                    return 0;
                }
                SSL_PHA_EXT_RECEIVED => {}
                _ => {
                    raise_ssl(SSL_R_INVALID_CONFIG, 7443);
                    return 0;
                }
            }
            // `ssl_lib.c:7438-7447`: mark the request pending, refuse an unusable configuration,
            // then re-enter the state machine so the next read/write emits the CertificateRequest.
            (*ssl).post_handshake_auth = SSL_PHA_REQUEST_PENDING;
            if !crate::ssl::statem::statem_srvr::send_certificate_request(ssl) {
                (*ssl).post_handshake_auth = SSL_PHA_EXT_RECEIVED;
                raise_ssl(SSL_R_INVALID_CONFIG, 7443);
                return 0;
            }
            ossl_statem_set_in_init(ssl, 1);
        }
        1
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
        unsafe { (*cert_active_key((*s).cert)).x509.cast::<c_void>() }
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
        unsafe { (*cert_active_key((*s).cert)).privatekey }
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
        unsafe { (*cert_active_key((*ctx).cert)).x509.cast::<c_void>() }
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
        unsafe { (*cert_active_key((*ctx).cert)).privatekey }
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
        // The authority returns `sc->verified_chain` (`ssl_lib.c:6344-6352`), which
        // `ssl_verify_cert_chain` fills after validation. This slice copies the presented chain
        // there in `tls_process_server_certificate` (14.7's real verify path is unlanded), so the
        // accessor returns that chain.
        // SAFETY: `s` is non-NULL per the check above; `verified_chain` is NULL or the chain owned
        // by this connection.
        unsafe { (*s).verified_chain }
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

// -------------------------------------------------------------------------------------------
// Slice 2 — the verify-parameter, host, DANE/CT, cipher-type and connection-accessor surface
// -------------------------------------------------------------------------------------------

/// `int SSL_CTX_set_purpose(SSL_CTX *s, int purpose)` — `ssl/ssl_lib.c:1108-1111`.
///
/// # Safety
/// `s` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_purpose(s: *mut SslCtx, purpose: c_int) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `s` is live.
        unsafe { X509_VERIFY_PARAM_set_purpose((*s).param, purpose) }
    })
}

/// `int SSL_set_purpose(SSL *s, int purpose)` — `ssl/ssl_lib.c:1113-1121`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_purpose(s: *mut Ssl, purpose: c_int) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `s` is live.
        unsafe { X509_VERIFY_PARAM_set_purpose((*s).param, purpose) }
    })
}

/// `int SSL_CTX_set_trust(SSL_CTX *s, int trust)` — `ssl/ssl_lib.c:1123-1126`.
///
/// # Safety
/// `s` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_trust(s: *mut SslCtx, trust: c_int) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `s` is live.
        unsafe { X509_VERIFY_PARAM_set_trust((*s).param, trust) }
    })
}

/// `int SSL_set_trust(SSL *s, int trust)` — `ssl/ssl_lib.c:1128-1136`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_trust(s: *mut Ssl, trust: c_int) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `s` is live.
        unsafe { X509_VERIFY_PARAM_set_trust((*s).param, trust) }
    })
}

/// `int SSL_set1_host(SSL *s, const char *host)` — `ssl/ssl_lib.c:1138-1154`.
///
/// # Safety
/// `s` must point to a live connection; `host` must be NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_set1_host(s: *mut Ssl, host: *const c_char) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        let param = unsafe { (*s).param };
        // Clear hostname(s) and any IP in every case, exactly as the authority does.
        // SAFETY: `param` is live; the NULL arguments are the authority's clear
        // (`X509_VERIFY_PARAM_set1_host(param, NULL, 0)`).
        unsafe {
            X509_VERIFY_PARAM_set1_host(param, ptr::null(), 0);
            X509_VERIFY_PARAM_set1_ip(param, ptr::null(), 0);
        }
        if host.is_null() {
            return 1;
        }
        // SAFETY: `param` and `host` are per the caller's contract.
        unsafe {
            let as_ip = X509_VERIFY_PARAM_set1_ip_asc(param, host);
            let as_host = X509_VERIFY_PARAM_set1_host(param, host, 0);
            c_int::from(as_ip != 0 || as_host != 0)
        }
    })
}

/// `int SSL_add1_host(SSL *s, const char *host)` — `ssl/ssl_lib.c:1156-1187`.
///
/// # Safety
/// `s` must point to a live connection; `host` must be NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_add1_host(s: *mut Ssl, host: *const c_char) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        let param = unsafe { (*s).param };
        if !host.is_null() {
            // SAFETY: `host` is NUL-terminated per the caller's contract.
            let ip = unsafe { a2i_IPADDRESS(host) };
            if !ip.is_null() {
                // We did not want the address; it was only an IP test.
                // SAFETY: `ip` is the live `ASN1_OCTET_STRING` just returned.
                unsafe { ASN1_STRING_free(ip) };
                // SAFETY: `param` is live.
                let old_ip = unsafe { X509_VERIFY_PARAM_get1_ip_asc(param) };
                if !old_ip.is_null() {
                    // SAFETY: `old_ip` is the allocation `get1_ip_asc` returned.
                    unsafe { CRYPTO_free(old_ip.cast(), FILE, 1175) };
                    // SAFETY: a constant site.
                    unsafe { raise_ssl(ERR_R_PASSED_INVALID_ARGUMENT, 1177) };
                    return 0;
                }
                // SAFETY: `param` and `host` are per the caller's contract.
                return unsafe { X509_VERIFY_PARAM_set1_ip_asc(param, host) };
            }
        }
        // SAFETY: `param` is live; `host` is per the caller's contract.
        unsafe { X509_VERIFY_PARAM_add1_host(param, host, 0) }
    })
}

/// `void SSL_set_hostflags(SSL *s, unsigned int flags)` — `ssl/ssl_lib.c:1189-1197`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_hostflags(s: *mut Ssl, flags: c_uint) {
    guard_ffi((), || {
        // SAFETY: the caller guarantees `s` is live.
        unsafe { X509_VERIFY_PARAM_set_hostflags((*s).param, flags) };
    })
}

/// `const char *SSL_get0_peername(SSL *s)` — `ssl/ssl_lib.c:1199-1207`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_peername(s: *mut Ssl) -> *const c_char {
    guard_ffi(ptr::null(), || {
        // SAFETY: the caller guarantees `s` is live.
        unsafe { X509_VERIFY_PARAM_get0_peername((*s).param) }
    })
}

/// `int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath)` —
/// `ssl/ssl_lib.c:5623-5633`.
///
/// # Safety
/// `ctx` must point to a live context; `CAfile`/`CApath` must be NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_load_verify_locations(
    ctx: *mut SslCtx,
    cafile: *const c_char,
    capath: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        if cafile.is_null() && capath.is_null() {
            return 0;
        }
        // SAFETY: `ctx` is live per the caller's contract.
        if !cafile.is_null() && unsafe { SSL_CTX_load_verify_file(ctx, cafile) } == 0 {
            return 0;
        }
        // SAFETY: `ctx` is live per the caller's contract.
        if !capath.is_null() && unsafe { SSL_CTX_load_verify_dir(ctx, capath) } == 0 {
            return 0;
        }
        1
    })
}

/// `int SSL_CTX_load_verify_file(SSL_CTX *ctx, const char *CAfile)` — `ssl/ssl_lib.c:5606-5610`.
///
/// # Safety
/// `ctx` must point to a live context; `CAfile` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_load_verify_file(
    ctx: *mut SslCtx,
    cafile: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the caller's contract; its store, libctx and propq are its own.
        unsafe { X509_STORE_load_file_ex((*ctx).cert_store, cafile, (*ctx).libctx, (*ctx).propq) }
    })
}

/// `int SSL_CTX_load_verify_dir(SSL_CTX *ctx, const char *CApath)` — `ssl/ssl_lib.c:5612-5615`.
///
/// # Safety
/// `ctx` must point to a live context; `CApath` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_load_verify_dir(ctx: *mut SslCtx, capath: *const c_char) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { X509_STORE_load_path((*ctx).cert_store, capath) }
    })
}

/// `int SSL_CTX_load_verify_store(SSL_CTX *ctx, const char *CAstore)` — `ssl/ssl_lib.c:5617-5621`.
///
/// # Safety
/// `ctx` must point to a live context; `CAstore` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_load_verify_store(
    ctx: *mut SslCtx,
    castore: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the caller's contract; its store, libctx and propq are its own.
        unsafe { X509_STORE_load_store_ex((*ctx).cert_store, castore, (*ctx).libctx, (*ctx).propq) }
    })
}

/// `int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx)` — `ssl/ssl_lib.c:5545-5549`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_default_verify_paths(ctx: *mut SslCtx) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the caller's contract; its store, libctx and propq are its own.
        unsafe { X509_STORE_set_default_paths_ex((*ctx).cert_store, (*ctx).libctx, (*ctx).propq) }
    })
}

/// `int SSL_CTX_check_private_key(const SSL_CTX *ctx)` — `ssl/ssl_lib.c:2065-2076`.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_check_private_key(ctx: *const SslCtx) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if ctx.is_null() {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_NO_CERTIFICATE_ASSIGNED, 2068) };
            return 0;
        }
        // SAFETY: `ctx` is non-NULL and live.
        let cpk = unsafe { cert_active_key((*ctx).cert) };
        // SAFETY: `cpk` points into the live container.
        if unsafe { (*cpk).x509 }.is_null() {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_NO_CERTIFICATE_ASSIGNED, 2068) };
            return 0;
        }
        // SAFETY: `cpk` points into the live container.
        if unsafe { (*cpk).privatekey }.is_null() {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_NO_PRIVATE_KEY_ASSIGNED, 2072) };
            return 0;
        }
        // SAFETY: both pointers are the live leaf pair per the checks above.
        unsafe {
            X509_check_private_key(
                (*cpk).x509,
                (*cpk).privatekey.cast::<crate::evp::pkey::EvpPkey>(),
            )
        }
    })
}

/// `int SSL_check_private_key(const SSL *ssl)` — `ssl/ssl_lib.c:2079-2097`.
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_check_private_key(ssl: *const Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the function's # Safety contract makes every pointer this block uses valid.
        if ssl.is_null() {
            // SAFETY: a constant site.
            unsafe { raise_ssl(ERR_R_PASSED_INVALID_ARGUMENT, 2084) };
            return 0;
        }
        // SAFETY: `ssl` is non-NULL and live.
        let cpk = unsafe { cert_active_key((*ssl).cert) };
        // SAFETY: `cpk` points into the live container.
        if unsafe { (*cpk).x509 }.is_null() {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_NO_CERTIFICATE_ASSIGNED, 2088) };
            return 0;
        }
        // SAFETY: `cpk` points into the live container.
        if unsafe { (*cpk).privatekey }.is_null() {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_NO_PRIVATE_KEY_ASSIGNED, 2092) };
            return 0;
        }
        // SAFETY: both pointers are the live leaf pair per the checks above.
        unsafe {
            X509_check_private_key(
                (*cpk).x509,
                (*cpk).privatekey.cast::<crate::evp::pkey::EvpPkey>(),
            )
        }
    })
}

/// `void SSL_certs_clear(SSL *s)` — `ssl/ssl_lib.c:1412-1420`.
///
/// The authority calls `ssl_cert_clear_certs`, which walks every `cert_pkey` and frees the extra
/// certificate chain and custom extensions. Only the single active leaf pair exists in this slice
/// (14.7's chains and the `custext` list are unlanded), so this clears the leaf pointers; the
/// divergence is recorded in `src/ssl/mod.rs`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_certs_clear(s: *mut Ssl) {
    guard_ffi((), || {
        // SAFETY: `s` is live per the caller's contract.
        let c = unsafe { (*s).cert };
        if !c.is_null() {
            // SAFETY: `c` is the live certificate container; clearing every slot is the
            // authority's `ssl_cert_clear_certs` body.
            unsafe {
                for i in 0..SSL_PKEY_NUM {
                    cert_pkey_clear(ptr::addr_of_mut!((*c).pkeys[i]));
                }
            }
        }
    })
}

/// `X509 *SSL_get0_peer_certificate(const SSL *s)` — `ssl/ssl_lib.c:1991-2002`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_peer_certificate(s: *const Ssl) -> *mut X509 {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the caller guarantees `s` is live.
        // The authority reads `sc->session->peer` (`ssl_lib.c:1991-2002`). The reduced path has no
        // handshake-created session (`ssl_get_new_session` is unlanded), so it falls back to the
        // leaf `tls_process_server_certificate` stored on the connection.
        let session = unsafe { (*s).session };
        // SAFETY: `session` is NULL or the live session; a non-NULL session's `peer` is read.
        let session_peer = unsafe {
            if session.is_null() {
                ptr::null_mut()
            } else {
                (*session).peer
            }
        };
        if !session_peer.is_null() {
            session_peer
        } else {
            // SAFETY: `peer_cert` is NULL or the live leaf owned by this connection.
            unsafe { (*s).peer_cert.cast::<X509>() }
        }
    })
}

/// `X509 *SSL_get1_peer_certificate(const SSL *s)` — `ssl/ssl_lib.c:1981-1989`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get1_peer_certificate(s: *const Ssl) -> *mut X509 {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: `s` is live per the caller's contract.
        let r = unsafe { SSL_get0_peer_certificate(s) };
        if !r.is_null() {
            // SAFETY: `r` is the live certificate just returned.
            if unsafe { X509_up_ref(r.cast()) } == 0 {
                return ptr::null_mut();
            }
        }
        r
    })
}

/// `STACK_OF(X509) *SSL_get_peer_cert_chain(const SSL *s)` — `ssl/ssl_lib.c:2004-2023`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_peer_cert_chain(s: *const Ssl) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: the caller guarantees `s` is live.
        // The authority reads `sc->session->peer_chain` (`ssl_lib.c:2004-2023`, which includes the
        // peer's own certificate for a client). The reduced path falls back to the chain
        // `tls_process_server_certificate` stored on the connection, including when a reduced
        // handshake-created session carries no chain of its own.
        let session = unsafe { (*s).session };
        // SAFETY: `session` is NULL or the live session; a non-NULL session's `peer_chain` is read.
        if !session.is_null() && unsafe { !(*session).peer_chain.is_null() } {
            // SAFETY: `session` is the live session per the check above.
            unsafe { (*session).peer_chain.cast::<c_void>() }
        } else {
            // SAFETY: `peer_chain` is NULL or the live presented chain owned by this connection.
            unsafe { (*s).peer_chain.cast::<c_void>() }
        }
    })
}

// -------------------------------------------------------------------------------------------
// The certificate-transparency surface (the store and the validation callback)
// -------------------------------------------------------------------------------------------

/// `int SSL_CTX_set_ct_validation_callback(SSL_CTX *ctx, ssl_ct_validation_cb callback, void
/// *arg)` — `ssl/ssl_lib.c:6583-6598`.
///
/// The authority first refuses when a custom extension handler for the SCT extension is already
/// registered; that check (`SSL_CTX_has_client_custom_ext`, 14.9) is unreachable here because this
/// slice installs no custom extensions, so it is omitted and recorded in `src/ssl/mod.rs`.
///
/// # Safety
/// `ctx` must point to a live context; `callback` is stored verbatim and `arg` is its argument.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_ct_validation_callback(
    ctx: *mut SslCtx,
    callback: Option<CtValidationCb>,
    arg: *mut c_void,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe {
            (*ctx).ct_validation_callback = callback;
            (*ctx).ct_validation_callback_arg = arg;
        }
        1
    })
}

/// `int SSL_set_ct_validation_callback(SSL *s, ssl_ct_validation_cb callback, void *arg)` —
/// `ssl/ssl_lib.c:6552-6581`.
///
/// As the `SSL_CTX` form, the authority's custom-extension refusal and its OCSP status-set
/// (`SSL_set_tlsext_status_type`, 14.9) are omitted here; both are recorded in `src/ssl/mod.rs`.
///
/// # Safety
/// `s` must point to a live connection; `callback` is stored verbatim and `arg` its argument.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_ct_validation_callback(
    s: *mut Ssl,
    callback: Option<CtValidationCb>,
    arg: *mut c_void,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            (*s).ct_validation_callback = callback;
            (*s).ct_validation_callback_arg = arg;
        }
        1
    })
}

/// `ct_permissive` — `ssl/ssl_lib.c:6529-6533`: the information-gathering callback, always 1.
unsafe extern "C" fn ct_permissive(
    _ctx: *const c_void,
    _scts: *const c_void,
    _arg: *mut c_void,
) -> c_int {
    1
}

/// `ct_strict` — `ssl/ssl_lib.c:6535-6550`: 1 only when an SCT validates. Parsed SCT stacks are
/// 14.9's, so no SCT list ever reaches this slice and the authority's `SSL_R_NO_VALID_SCTS` refusal
/// is the answer.
unsafe extern "C" fn ct_strict(
    _ctx: *const c_void,
    scts: *const c_void,
    _arg: *mut c_void,
) -> c_int {
    // An empty (or absent) SCT list drops straight to the authority's refusal path.
    let _ = scts;
    // SAFETY: a constant site.
    unsafe { raise_ssl(SSL_R_NO_VALID_SCTS, 6548) };
    0
}

/// `int SSL_CTX_enable_ct(SSL_CTX *ctx, int validation_mode)` — `ssl/ssl_lib.c:6714-6725`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_enable_ct(ctx: *mut SslCtx, validation_mode: c_int) -> c_int {
    guard_ffi(0, || match validation_mode {
        SSL_CT_VALIDATION_PERMISSIVE => {
            // SAFETY: `ctx` is live per the caller's contract.
            unsafe { SSL_CTX_set_ct_validation_callback(ctx, Some(ct_permissive), ptr::null_mut()) }
        }
        SSL_CT_VALIDATION_STRICT => {
            // SAFETY: `ctx` is live per the caller's contract.
            unsafe { SSL_CTX_set_ct_validation_callback(ctx, Some(ct_strict), ptr::null_mut()) }
        }
        _ => {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_INVALID_CT_VALIDATION_TYPE, 6718) };
            0
        }
    })
}

/// `int SSL_enable_ct(SSL *s, int validation_mode)` — `ssl/ssl_lib.c:6727-6738`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_enable_ct(s: *mut Ssl, validation_mode: c_int) -> c_int {
    guard_ffi(0, || match validation_mode {
        SSL_CT_VALIDATION_PERMISSIVE => {
            // SAFETY: `s` is live per the caller's contract.
            unsafe { SSL_set_ct_validation_callback(s, Some(ct_permissive), ptr::null_mut()) }
        }
        SSL_CT_VALIDATION_STRICT => {
            // SAFETY: `s` is live per the caller's contract.
            unsafe { SSL_set_ct_validation_callback(s, Some(ct_strict), ptr::null_mut()) }
        }
        _ => {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_INVALID_CT_VALIDATION_TYPE, 6731) };
            0
        }
    })
}

/// `int SSL_ct_is_enabled(const SSL *s)` — `ssl/ssl_lib.c:6600-6608`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_ct_is_enabled(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `s` is live.
        c_int::from(unsafe { (*s).ct_validation_callback }.is_some())
    })
}

/// `int SSL_CTX_ct_is_enabled(const SSL_CTX *ctx)` — `ssl/ssl_lib.c:6610-6613`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_ct_is_enabled(ctx: *const SslCtx) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `ctx` is live.
        c_int::from(unsafe { (*ctx).ct_validation_callback }.is_some())
    })
}

/// `int SSL_CTX_set_ctlog_list_file(SSL_CTX *ctx, const char *path)` — `ssl/ssl_lib.c:6745-6748`.
///
/// # Safety
/// `ctx` must point to a live context; `path` must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_ctlog_list_file(
    ctx: *mut SslCtx,
    path: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live; its `ctlog_store` was allocated by `SSL_CTX_new_ex`.
        unsafe { CTLOG_STORE_load_file((*ctx).ctlog_store, path) }
    })
}

/// `int SSL_CTX_set_default_ctlog_list_file(SSL_CTX *ctx)` — `ssl/ssl_lib.c:6740-6743`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_default_ctlog_list_file(ctx: *mut SslCtx) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live; its `ctlog_store` was allocated by `SSL_CTX_new_ex`.
        unsafe { CTLOG_STORE_load_default_file((*ctx).ctlog_store) }
    })
}

/// `void SSL_CTX_set0_ctlog_store(SSL_CTX *ctx, CTLOG_STORE *logs)` — `ssl/ssl_lib.c:6750-6754`.
///
/// # Safety
/// `ctx` must point to a live context; `logs` must be NULL or a live store whose reference is
/// transferred.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set0_ctlog_store(ctx: *mut SslCtx, logs: *mut CtlogStore) {
    guard_ffi((), || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe {
            CTLOG_STORE_free((*ctx).ctlog_store);
            (*ctx).ctlog_store = logs;
        }
    })
}

/// `const CTLOG_STORE *SSL_CTX_get0_ctlog_store(const SSL_CTX *ctx)` — `ssl/ssl_lib.c:6756-6759`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get0_ctlog_store(ctx: *const SslCtx) -> *const CtlogStore {
    guard_ffi(ptr::null(), || {
        // SAFETY: the caller guarantees `ctx` is live.
        unsafe { (*ctx).ctlog_store }
    })
}

/// `const STACK_OF(SCT) *SSL_get0_peer_scts(SSL *s)` — `ssl/ssl_lib.c:6511-6527`.
///
/// The authority extracts SCTs from the TLS extension, the OCSP response and the certificate's
/// `X509v3` extensions; those sources are the handshake (14.5) and the certificate path (14.7), so
/// this slice reports the parsed list it has (NULL) and marks it parsed, matching the authority for
/// a connection with no peer. Recorded in `src/ssl/mod.rs`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_peer_scts(s: *mut Ssl) -> *const c_void {
    guard_ffi(ptr::null(), || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).scts_parsed = 1 };
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).scts }
    })
}

// -------------------------------------------------------------------------------------------
// ALPN, NPN and the SNI reader
// -------------------------------------------------------------------------------------------

/// `alpn_value_ok` — `ssl/ssl_lib.c:3702-3714`: the wire-format validity test for an ALPN list.
///
/// # Safety
/// `protos` must be NULL or readable for `protos_len` bytes.
unsafe fn alpn_value_ok(protos: *const u8, protos_len: c_uint) -> bool {
    if protos_len < 2 || protos.is_null() {
        return false;
    }
    let mut idx: c_uint = 0;
    while idx < protos_len {
        // SAFETY: `idx < protos_len` and `protos` is readable for `protos_len` bytes.
        let step = unsafe { *protos.add(idx as usize) } as c_uint;
        if step == 0 {
            return false;
        }
        idx += step + 1;
    }
    idx == protos_len
}

/// `int SSL_CTX_set_alpn_protos(SSL_CTX *ctx, const unsigned char *protos, unsigned int
/// protos_len)` — `ssl/ssl_lib.c:3720-3743`.
///
/// # Safety
/// `ctx` must point to a live context; `protos` must be NULL or readable for `protos_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_alpn_protos(
    ctx: *mut SslCtx,
    protos: *const u8,
    protos_len: c_uint,
) -> c_int {
    guard_ffi(1, || {
        if protos_len == 0 || protos.is_null() {
            // SAFETY: `ctx` is live; a NULL `ext_alpn` is `CRYPTO_free`'s own no-op.
            unsafe {
                CRYPTO_free((*ctx).ext_alpn.cast(), FILE, 3726);
                (*ctx).ext_alpn = ptr::null_mut();
                (*ctx).ext_alpn_len = 0;
            }
            return 0;
        }
        // SAFETY: `protos` is readable for `protos_len` bytes per the contract.
        if !unsafe { alpn_value_ok(protos, protos_len) } {
            return 1;
        }
        // SAFETY: `protos` is readable for `protos_len` bytes per the contract.
        let alpn =
            unsafe { CRYPTO_memdup(protos.cast(), protos_len as usize, FILE, 3735).cast::<u8>() };
        if alpn.is_null() {
            return 1;
        }
        // SAFETY: `ctx` is live.
        unsafe {
            CRYPTO_free((*ctx).ext_alpn.cast(), FILE, 3738);
            (*ctx).ext_alpn = alpn;
            (*ctx).ext_alpn_len = protos_len;
        }
        0
    })
}

/// `int SSL_set_alpn_protos(SSL *ssl, const unsigned char *protos, unsigned int protos_len)` —
/// `ssl/ssl_lib.c:3750-3777`.
///
/// # Safety
/// `ssl` must point to a live connection; `protos` must be NULL or readable for `protos_len`
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_alpn_protos(
    ssl: *mut Ssl,
    protos: *const u8,
    protos_len: c_uint,
) -> c_int {
    guard_ffi(1, || {
        if protos_len == 0 || protos.is_null() {
            // SAFETY: `ssl` is live; a NULL `ext_alpn` is `CRYPTO_free`'s own no-op.
            unsafe {
                CRYPTO_free((*ssl).ext_alpn.cast(), FILE, 3760);
                (*ssl).ext_alpn = ptr::null_mut();
                (*ssl).ext_alpn_len = 0;
            }
            return 0;
        }
        // SAFETY: `protos` is readable for `protos_len` bytes per the contract.
        if !unsafe { alpn_value_ok(protos, protos_len) } {
            return 1;
        }
        // SAFETY: `protos` is readable for `protos_len` bytes per the contract.
        let alpn =
            unsafe { CRYPTO_memdup(protos.cast(), protos_len as usize, FILE, 3769).cast::<u8>() };
        if alpn.is_null() {
            return 1;
        }
        // SAFETY: `ssl` is live.
        unsafe {
            CRYPTO_free((*ssl).ext_alpn.cast(), FILE, 3772);
            (*ssl).ext_alpn = alpn;
            (*ssl).ext_alpn_len = protos_len;
        }
        0
    })
}

/// `void SSL_get0_alpn_selected(const SSL *ssl, const unsigned char **data, unsigned int *len)` —
/// `ssl/ssl_lib.c:3798-3815`.
///
/// # Safety
/// `ssl` must point to a live connection; `data` and `len` must be writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_alpn_selected(
    ssl: *const Ssl,
    data: *mut *const u8,
    len: *mut c_uint,
) {
    guard_ffi((), || {
        // SAFETY: `ssl`, `data` and `len` are per the caller's contract.
        let (selected, selected_len) =
            unsafe { ((*ssl).s3_alpn_selected, (*ssl).s3_alpn_selected_len) };
        // SAFETY: `data` is writable per the contract.
        unsafe { *data = selected };
        // SAFETY: `len` is writable per the contract.
        unsafe {
            *len = if selected.is_null() {
                0
            } else {
                selected_len as c_uint
            }
        };
    })
}

/// `void SSL_CTX_set_next_proto_select_cb(SSL_CTX *s, SSL_CTX_npn_select_cb_func cb, void *arg)` —
/// `ssl/ssl_lib.c:3689-3699` (the authority spells it `SSL_CTX_set_npn_select_cb`).
///
/// # Safety
/// `s` must point to a live context; `cb` is stored verbatim and `arg` its argument.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_next_proto_select_cb(
    s: *mut SslCtx,
    cb: Option<NpnSelectCb>,
    arg: *mut c_void,
) {
    guard_ffi((), || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            (*s).npn_select_cb = cb;
            (*s).npn_select_cb_arg = arg;
        }
    })
}

/// `void SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *s, SSL_CTX_npn_advertised_cb_func cb, void
/// *arg)` — `ssl/ssl_lib.c:3667-3677` (the authority spells it
/// `SSL_CTX_set_npn_advertised_cb`).
///
/// # Safety
/// `s` must point to a live context; `cb` is stored verbatim and `arg` its argument.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_next_protos_advertised_cb(
    s: *mut SslCtx,
    cb: Option<NpnAdvertisedCb>,
    arg: *mut c_void,
) {
    guard_ffi((), || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            (*s).npn_advertised_cb = cb;
            (*s).npn_advertised_cb_arg = arg;
        }
    })
}

/// `void SSL_get0_next_proto_negotiated(const SSL *s, const unsigned char **data, unsigned *len)` —
/// `ssl/ssl_lib.c:3637-3655`.
///
/// # Safety
/// `s` must point to a live connection; `data` and `len` must be writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_next_proto_negotiated(
    s: *const Ssl,
    data: *mut *const u8,
    len: *mut c_uint,
) {
    guard_ffi((), || {
        // SAFETY: `s` is live per the caller's contract.
        let (npn, npn_len) = unsafe { ((*s).ext_npn, (*s).ext_npn_len) };
        // SAFETY: `data` is writable per the contract.
        unsafe { *data = npn };
        // SAFETY: `len` is writable per the contract.
        unsafe {
            *len = if npn.is_null() { 0 } else { npn_len as c_uint };
        };
    })
}

/// `int SSL_select_next_proto(unsigned char **out, unsigned char *outlen, const unsigned char
/// *server, unsigned int server_len, const unsigned char *client, unsigned int client_len)` —
/// `ssl/ssl_lib.c:3573-3626`.
///
/// # Safety
/// `out`/`outlen` must be writable; `server`/`client` must be readable for their lengths.
#[no_mangle]
pub unsafe extern "C" fn SSL_select_next_proto(
    out: *mut *mut u8,
    outlen: *mut u8,
    server: *const u8,
    server_len: c_uint,
    client: *const u8,
    client_len: c_uint,
) -> c_int {
    guard_ffi(OPENSSL_NPN_NO_OVERLAP, || {
        // Read the first length-prefixed entry of the client list; if there is none, there is no
        // overlap. The pointer arithmetic mirrors `PACKET_get_length_prefixed_1`.
        let c_first = if client.is_null() || client_len < 1 {
            None
        } else {
            // SAFETY: `client_len >= 1` and `client` is readable for `client_len` bytes.
            let n = unsafe { *client } as c_uint;
            if n == 0 || n + 1 > client_len {
                None
            } else {
                // SAFETY: `super::SSL_select_next_proto`'s caller makes `client` readable for
                // `client_len > n` bytes.
                Some(unsafe { client.add(1) })
            }
        };
        let Some(c_first_ptr) = c_first else {
            // SAFETY: `out`/`outlen` are writable per the contract.
            unsafe {
                *out = ptr::null_mut();
                *outlen = 0;
            }
            return OPENSSL_NPN_NO_OVERLAP;
        };
        // SAFETY: `client_len >= 1`; the entry length byte is `*client`.
        let c_first_len = unsafe { *client };
        // Set the default opportunistic protocol; overwritten if a match is found.
        // SAFETY: `out`/`outlen` are writable per the contract.
        unsafe {
            *out = c_first_ptr.cast_mut();
            *outlen = c_first_len;
        }

        // Walk the server preference list, looking for any client entry equal to a server entry.
        let mut soff: c_uint = 0;
        while !server.is_null() && soff < server_len {
            // SAFETY: `soff < server_len` and `server` is readable for `server_len` bytes.
            let slen = unsafe { *server.add(soff as usize) } as c_uint;
            soff += 1;
            if slen == 0 || soff + slen > server_len {
                break;
            }
            // SAFETY: `soff + slen <= server_len` and `server` is readable for `server_len`
            // bytes, so the entry start is in bounds.
            let s_ent = unsafe { server.add(soff as usize) };
            let mut coff: c_uint = 0;
            while coff < client_len {
                // SAFETY: `coff < client_len` and `client` is readable for `client_len` bytes.
                let clen = unsafe { *client.add(coff as usize) } as c_uint;
                coff += 1;
                if clen == 0 || coff + clen > client_len {
                    break;
                }
                // SAFETY: `s_ent`/`server.add(coff...)` are within their buffers per the bounds
                // checks above.
                let equal = unsafe {
                    let c_ent = client.add(coff as usize);
                    slen == clen
                        && core::slice::from_raw_parts(s_ent, slen as usize)
                            == core::slice::from_raw_parts(c_ent, clen as usize)
                };
                if equal {
                    // SAFETY: `out`/`outlen` are writable per the contract.
                    unsafe {
                        *out = s_ent.cast_mut();
                        *outlen = slen as u8;
                    }
                    return OPENSSL_NPN_NEGOTIATED;
                }
                coff += clen;
            }
            soff += slen;
        }
        OPENSSL_NPN_NO_OVERLAP
    })
}

/// `const char *SSL_get_servername(const SSL *s, const int type)` — `ssl/ssl_lib.c:3472-3544`,
/// reduced to the state this slice can hold.
///
/// `handshake_func` is never installed here (14.5 does that), so the authority's `server` test is
/// always the client path and `SSL_in_before` is always true; the server and resumption branches
/// are therefore unreachable and are recorded in `src/ssl/mod.rs`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_servername(s: *const Ssl, type_: c_int) -> *const c_char {
    guard_ffi(ptr::null(), || {
        // SAFETY: `s` is live per the caller's contract.
        let sc = unsafe { &*s };
        if type_ != TLSEXT_NAMETYPE_HOST_NAME {
            return ptr::null();
        }
        // Client side, before the handshake: a set SNI name wins; otherwise a TLSv1.2 session's
        // hostname would win, but no session exists in this slice.
        if sc.ext_hostname.is_null() && !sc.session.is_null() {
            // SAFETY: `session` is live per the non-NULL check; its version is readable.
            let session = unsafe { &*sc.session };
            if session.ssl_version != TLS1_3_VERSION {
                return session.ext_hostname;
            }
        }
        sc.ext_hostname
    })
}

/// `int SSL_get_servername_type(const SSL *s)` — `ssl/ssl_lib.c:3546-3551`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_servername_type(s: *const Ssl) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: `s` is live per the caller's contract.
        if unsafe { SSL_get_servername(s, TLSEXT_NAMETYPE_HOST_NAME) }.is_null() {
            -1
        } else {
            TLSEXT_NAMETYPE_HOST_NAME
        }
    })
}

/// `int SSL_set0_tmp_dh_pkey` and `SSL_CTX_set0_tmp_dh_pkey` are withheld from this slice: both
/// run `ssl_security(..., SSL_SECOP_TMP_DH, ...)` first (`ssl_lib.c:7595`, `:7607`), and the
/// security check lives in `ssl_cert.c` (14.7). Recorded in `src/ssl/mod.rs`.
///
/// `int SSL_CTX_set_block_padding_ex(SSL_CTX *ctx, size_t app_block_size, size_t hs_block_size)` —
/// `ssl/ssl_lib.c:5959-5981`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_block_padding_ex(
    ctx: *mut SslCtx,
    app_block_size: usize,
    hs_block_size: usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe {
            if app_block_size == 1 {
                (*ctx).block_padding = 0;
            } else if app_block_size <= SSL3_RT_MAX_PLAIN_LENGTH as usize {
                (*ctx).block_padding = app_block_size;
            } else {
                return 0;
            }
            if hs_block_size == 1 {
                (*ctx).hs_padding = 0;
            } else if hs_block_size <= SSL3_RT_MAX_PLAIN_LENGTH as usize {
                (*ctx).hs_padding = hs_block_size;
            } else {
                return 0;
            }
        }
        1
    })
}

/// `int SSL_CTX_set_block_padding(SSL_CTX *ctx, size_t block_size)` — `ssl/ssl_lib.c:5983-5986`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_block_padding(ctx: *mut SslCtx, block_size: usize) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { SSL_CTX_set_block_padding_ex(ctx, block_size, block_size) }
    })
}

/// `int SSL_set_block_padding_ex(SSL *ssl, size_t app_block_size, size_t hs_block_size)` —
/// `ssl/ssl_lib.c:6026-6052`.
///
/// # Safety
/// `ssl` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_block_padding_ex(
    ssl: *mut Ssl,
    app_block_size: usize,
    hs_block_size: usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ssl` is live per the caller's contract.
        unsafe {
            if app_block_size == 1 {
                (*ssl).block_padding = 0;
            } else if app_block_size <= SSL3_RT_MAX_PLAIN_LENGTH as usize {
                (*ssl).block_padding = app_block_size;
            } else {
                return 0;
            }
            if hs_block_size == 1 {
                (*ssl).hs_padding = 0;
            } else if hs_block_size <= SSL3_RT_MAX_PLAIN_LENGTH as usize {
                (*ssl).hs_padding = hs_block_size;
            } else {
                return 0;
            }
        }
        1
    })
}

/// `int SSL_set_block_padding(SSL *ssl, size_t block_size)` — `ssl/ssl_lib.c:6054-6057`.
///
/// # Safety
/// `ssl` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_block_padding(ssl: *mut Ssl, block_size: usize) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ssl` is live per the caller's contract.
        unsafe { SSL_set_block_padding_ex(ssl, block_size, block_size) }
    })
}

/// `void SSL_CTX_set_post_handshake_auth(SSL_CTX *ctx, int val)` — `ssl/ssl_lib.c:7377-7380`.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_post_handshake_auth(ctx: *mut SslCtx, val: c_int) {
    guard_ffi((), || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).pha_enabled = val };
    })
}

/// `void SSL_set_post_handshake_auth(SSL *ssl, int val)` — `ssl/ssl_lib.c:7382-7390`.
///
/// # Safety
/// `ssl` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_post_handshake_auth(ssl: *mut Ssl, val: c_int) {
    guard_ffi((), || {
        // SAFETY: `ssl` is live per the caller's contract.
        unsafe { (*ssl).pha_enabled = val };
    })
}

// -------------------------------------------------------------------------------------------
// The negotiated/expected certificate-type list and the domain flags
// -------------------------------------------------------------------------------------------

/// `validate_cert_type` — `ssl/ssl_lib.c:8239-8270`: only a list of distinct `x509`/`rpk` bytes is
/// accepted; every ``pgp``/`1609dot2` byte and every repeat is refused.
///
/// # Safety
/// `val` must be NULL or readable for `len` bytes.
unsafe fn validate_cert_type(val: *const u8, len: usize) -> bool {
    if val.is_null() && len == 0 {
        return true;
    }
    if val.is_null() || len == 0 {
        return false;
    }
    let mut saw_rpk = false;
    let mut saw_x509 = false;
    for i in 0..len {
        // SAFETY: `i < len` and `val` is readable for `len` bytes.
        match unsafe { *val.add(i) } {
            TLSEXT_CERT_TYPE_RPK => {
                if saw_rpk {
                    return false;
                }
                saw_rpk = true;
            }
            TLSEXT_CERT_TYPE_X509 => {
                if saw_x509 {
                    return false;
                }
                saw_x509 = true;
            }
            _ => return false,
        }
    }
    true
}

/// `set_cert_type` — `ssl/ssl_lib.c:8272-8289`: validate, replace, and take a copy.
///
/// # Safety
/// `cert_type`/`cert_type_len` must be the live fields of one object; `val` NULL or readable for
/// `len` bytes.
unsafe fn set_cert_type(
    cert_type: *mut *mut u8,
    cert_type_len: *mut usize,
    val: *const u8,
    len: usize,
) -> c_int {
    // SAFETY: per the caller's contract.
    if !unsafe { validate_cert_type(val, len) } {
        return 0;
    }
    let mut tmp: *mut u8 = ptr::null_mut();
    if !val.is_null() {
        // SAFETY: `val` is readable for `len` bytes.
        tmp = unsafe { CRYPTO_memdup(val.cast(), len, FILE, 8282).cast::<u8>() };
        if tmp.is_null() {
            return 0;
        }
    }
    // SAFETY: `cert_type`/`cert_type_len` are live per the caller's contract.
    unsafe {
        CRYPTO_free((*cert_type).cast(), FILE, 8285);
        *cert_type = tmp;
        *cert_type_len = len;
    }
    1
}

/// `int SSL_set1_client_cert_type(SSL *s, const unsigned char *val, size_t len)` —
/// `ssl/ssl_lib.c:8291-8300`.
///
/// # Safety
/// `s` must point to a live connection; `val` NULL or readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_set1_client_cert_type(
    s: *mut Ssl,
    val: *const u8,
    len: usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            set_cert_type(
                ptr::addr_of_mut!((*s).client_cert_type),
                ptr::addr_of_mut!((*s).client_cert_type_len),
                val,
                len,
            )
        }
    })
}

/// `int SSL_set1_server_cert_type(SSL *s, const unsigned char *val, size_t len)` —
/// `ssl/ssl_lib.c:8302-8311`.
///
/// # Safety
/// `s` must point to a live connection; `val` NULL or readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_set1_server_cert_type(
    s: *mut Ssl,
    val: *const u8,
    len: usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            set_cert_type(
                ptr::addr_of_mut!((*s).server_cert_type),
                ptr::addr_of_mut!((*s).server_cert_type_len),
                val,
                len,
            )
        }
    })
}

/// `int SSL_CTX_set1_client_cert_type(SSL_CTX *ctx, const unsigned char *val, size_t len)` —
/// `ssl/ssl_lib.c:8313-8317`.
///
/// # Safety
/// `ctx` must point to a live context; `val` NULL or readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set1_client_cert_type(
    ctx: *mut SslCtx,
    val: *const u8,
    len: usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe {
            set_cert_type(
                ptr::addr_of_mut!((*ctx).client_cert_type),
                ptr::addr_of_mut!((*ctx).client_cert_type_len),
                val,
                len,
            )
        }
    })
}

/// `int SSL_CTX_set1_server_cert_type(SSL_CTX *ctx, const unsigned char *val, size_t len)` —
/// `ssl/ssl_lib.c:8319-8323`.
///
/// # Safety
/// `ctx` must point to a live context; `val` NULL or readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set1_server_cert_type(
    ctx: *mut SslCtx,
    val: *const u8,
    len: usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe {
            set_cert_type(
                ptr::addr_of_mut!((*ctx).server_cert_type),
                ptr::addr_of_mut!((*ctx).server_cert_type_len),
                val,
                len,
            )
        }
    })
}

/// `int SSL_get0_client_cert_type(const SSL *s, unsigned char **t, size_t *len)` —
/// `ssl/ssl_lib.c:8325-8335`.
///
/// # Safety
/// `s` must point to a live connection; `t`/`len` must be writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_client_cert_type(
    s: *const Ssl,
    t: *mut *mut u8,
    len: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        if t.is_null() || len.is_null() {
            return 0;
        }
        // SAFETY: `s`, `t` and `len` are per the caller's contract.
        unsafe {
            *t = (*s).client_cert_type;
            *len = (*s).client_cert_type_len;
        }
        1
    })
}

/// `int SSL_get0_server_cert_type(const SSL *s, unsigned char **t, size_t *len)` —
/// `ssl/ssl_lib.c:8337-8347`.
///
/// # Safety
/// `s` must point to a live connection; `t`/`len` must be writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_server_cert_type(
    s: *const Ssl,
    t: *mut *mut u8,
    len: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        if t.is_null() || len.is_null() {
            return 0;
        }
        // SAFETY: `s`, `t` and `len` are per the caller's contract.
        unsafe {
            *t = (*s).server_cert_type;
            *len = (*s).server_cert_type_len;
        }
        1
    })
}

/// `int SSL_CTX_get0_client_cert_type(const SSL_CTX *ctx, unsigned char **t, size_t *len)` —
/// `ssl/ssl_lib.c:8349-8357`.
///
/// # Safety
/// `ctx` must point to a live context; `t`/`len` must be writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get0_client_cert_type(
    ctx: *const SslCtx,
    t: *mut *mut u8,
    len: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        if t.is_null() || len.is_null() {
            return 0;
        }
        // SAFETY: `ctx`, `t` and `len` are per the caller's contract.
        unsafe {
            *t = (*ctx).client_cert_type;
            *len = (*ctx).client_cert_type_len;
        }
        1
    })
}

/// `int SSL_CTX_get0_server_cert_type(const SSL_CTX *ctx, unsigned char **t, size_t *len)` —
/// `ssl/ssl_lib.c:8359-8367`.
///
/// # Safety
/// `ctx` must point to a live context; `t`/`len` must be writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get0_server_cert_type(
    ctx: *const SslCtx,
    t: *mut *mut u8,
    len: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        if t.is_null() || len.is_null() {
            return 0;
        }
        // SAFETY: `ctx`, `t` and `len` are per the caller's contract.
        unsafe {
            *t = (*ctx).server_cert_type;
            *len = (*ctx).server_cert_type_len;
        }
        1
    })
}

/// `int SSL_get_negotiated_client_cert_type(const SSL *s)` — `ssl/ssl_lib.c:8219-8227`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_negotiated_client_cert_type(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).ext_client_cert_type as c_int }
    })
}

/// `int SSL_get_negotiated_server_cert_type(const SSL *s)` — `ssl/ssl_lib.c:8229-8237`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_negotiated_server_cert_type(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).ext_server_cert_type as c_int }
    })
}

/// `int SSL_CTX_set_domain_flags(SSL_CTX *ctx, uint64_t domain_flags)` — `ssl/ssl_lib.c:8147-8162`.
///
/// The flags are a QUIC-only (`IS_QUIC_CTX`) property; for the TLS contexts this crate builds the
/// authority raises `ERR_R_UNSUPPORTED` and answers 0, which this slice reproduces. Recorded in
/// `src/ssl/mod.rs` (QUIC is 14.10's).
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_domain_flags(ctx: *mut SslCtx, domain_flags: u64) -> c_int {
    guard_ffi(0, || {
        let _ = (ctx, domain_flags);
        // SAFETY: a constant site.
        unsafe { raise_ssl(ERR_R_UNSUPPORTED, 8159) };
        0
    })
}

/// `int SSL_CTX_get_domain_flags(const SSL_CTX *ctx, uint64_t *domain_flags)` —
/// `ssl/ssl_lib.c:8164-8178`. As [`SSL_CTX_set_domain_flags`], a non-QUIC context is unsupported.
///
/// # Safety
/// `ctx` must point to a live context; `domain_flags` must be writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_domain_flags(
    ctx: *const SslCtx,
    domain_flags: *mut u64,
) -> c_int {
    guard_ffi(0, || {
        let _ = (ctx, domain_flags);
        // SAFETY: a constant site.
        unsafe { raise_ssl(ERR_R_UNSUPPORTED, 8175) };
        0
    })
}

/// `int SSL_get_domain_flags(const SSL *ssl, uint64_t *domain_flags)` — `ssl/ssl_lib.c:8180-8188`.
///
/// # Safety
/// `ssl` must point to a live connection; `domain_flags` must be writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_domain_flags(ssl: *const Ssl, domain_flags: *mut u64) -> c_int {
    guard_ffi(0, || {
        let _ = (ssl, domain_flags);
        // `IS_QUIC(ssl)` is false for every object this crate builds, so the authority's
        // falling-through 0 is its answer (no `ERR` is raised on this path).
        0
    })
}

// -------------------------------------------------------------------------------------------
// The async wait-context accessors (the job itself is 14.5's)
// -------------------------------------------------------------------------------------------

/// `int SSL_waiting_for_async(SSL *s)` — `ssl/ssl_lib.c:2099-2110`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_waiting_for_async(s: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract; its `job` is NULL in this slice.
        c_int::from(!unsafe { (*s).job }.is_null())
    })
}

/// `int SSL_get_async_status(SSL *s, int *status)` — `ssl/ssl_lib.c:2174-2186`.
///
/// # Safety
/// `s` must point to a live connection; `status` must be writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_async_status(s: *mut Ssl, status: *mut c_int) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract; `waitctx` is NULL in this slice.
        let ctx = unsafe { (*s).waitctx };
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `ctx` is a live `ASYNC_WAIT_CTX` and `status` is writable per the contract.
        unsafe { *status = ASYNC_WAIT_CTX_get_status(ctx) };
        1
    })
}

/// `int SSL_get_all_async_fds(SSL *s, OSSL_ASYNC_FD *fds, size_t *numfds)` —
/// `ssl/ssl_lib.c:2112-2123`.
///
/// # Safety
/// `s` must point to a live connection; `numfds` writable; `fds` NULL or a sufficient buffer.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_all_async_fds(
    s: *mut Ssl,
    fds: *mut OsslAsyncFd,
    numfds: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        let ctx = unsafe { (*s).waitctx };
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `ctx` is live; `fds`/`numfds` are per the contract.
        unsafe { ASYNC_WAIT_CTX_get_all_fds(ctx, fds, numfds) }
    })
}

/// `int SSL_get_changed_async_fds(SSL *s, OSSL_ASYNC_FD *addfd, size_t *numaddfds, OSSL_ASYNC_FD
/// *delfd, size_t *numdelfds)` — `ssl/ssl_lib.c:2125-2138`.
///
/// # Safety
/// `s` must point to a live connection; the counts writable; the fd buffers NULL or sufficient.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_changed_async_fds(
    s: *mut Ssl,
    addfd: *mut OsslAsyncFd,
    numaddfds: *mut usize,
    delfd: *mut OsslAsyncFd,
    numdelfds: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        let ctx = unsafe { (*s).waitctx };
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `ctx` is live; the buffers and counts are per the contract.
        unsafe { ASYNC_WAIT_CTX_get_changed_fds(ctx, addfd, numaddfds, delfd, numdelfds) }
    })
}

// -------------------------------------------------------------------------------------------
// The remaining state readers, buffer hooks and the QUIC-dispatch non-QUIC arms
// -------------------------------------------------------------------------------------------

/// `int SSL_get_key_update_type(const SSL *s)` — `ssl/ssl_lib.c:2847-2860`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_key_update_type(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).key_update }
    })
}

/// `int SSL_renegotiate_pending(const SSL *s)` — `ssl/ssl_lib.c:2911-2923`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_renegotiate_pending(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        c_int::from(unsafe { (*s).renegotiate } != 0)
    })
}

/// `int SSL_get_early_data_status(const SSL *s)` — `ssl/ssl_lib.c:2450-2459`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_early_data_status(s: *const Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).ext_early_data }
    })
}

/// `int SSL_get_handshake_rtt(const SSL *s, uint64_t *rtt)` — `ssl/ssl_lib.c:5086-5099`.
///
/// # Safety
/// `s` must point to a live connection; `rtt` must be writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_handshake_rtt(s: *const Ssl, rtt: *mut u64) -> c_int {
    guard_ffi(-1, || {
        // SAFETY: `s` is live per the caller's contract.
        let (write, read) = unsafe { ((*s).ts_msg_write, (*s).ts_msg_read) };
        if write == 0 || read == 0 {
            return 0; // data not (yet) available
        }
        if read < write {
            return -1;
        }
        // SAFETY: `rtt` is writable per the contract; `ossl_time2us` divides nanoseconds by 1000.
        unsafe { *rtt = (read - write) / 1000 };
        1
    })
}

/// `size_t SSL_get_client_random(const SSL *ssl, unsigned char *out, size_t outlen)` —
/// `ssl/ssl_lib.c:5682-5695`.
///
/// # Safety
/// `ssl` must point to a live connection; `out` must hold `outlen` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_client_random(
    ssl: *const Ssl,
    out: *mut u8,
    outlen: usize,
) -> usize {
    guard_ffi(0, || {
        // SAFETY: `ssl` is live per the caller's contract.
        let rand = unsafe { (*ssl).client_random };
        if outlen == 0 {
            return SSL3_RANDOM_SIZE;
        }
        let n = if outlen > SSL3_RANDOM_SIZE {
            SSL3_RANDOM_SIZE
        } else {
            outlen
        };
        // SAFETY: `out` holds `outlen >= n` writable bytes per the contract.
        unsafe { ptr::copy_nonoverlapping(rand.as_ptr(), out, n) };
        n
    })
}

/// `size_t SSL_get_server_random(const SSL *ssl, unsigned char *out, size_t outlen)` —
/// `ssl/ssl_lib.c:5697-5710`.
///
/// # Safety
/// `ssl` must point to a live connection; `out` must hold `outlen` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_server_random(
    ssl: *const Ssl,
    out: *mut u8,
    outlen: usize,
) -> usize {
    guard_ffi(0, || {
        // SAFETY: `ssl` is live per the caller's contract.
        let rand = unsafe { (*ssl).server_random };
        if outlen == 0 {
            return SSL3_RANDOM_SIZE;
        }
        let n = if outlen > SSL3_RANDOM_SIZE {
            SSL3_RANDOM_SIZE
        } else {
            outlen
        };
        // SAFETY: `out` holds `outlen >= n` writable bytes per the contract.
        unsafe { ptr::copy_nonoverlapping(rand.as_ptr(), out, n) };
        n
    })
}

/// `int SSL_alloc_buffers(SSL *ssl)` — `ssl/ssl_lib.c:6974-6990`.
///
/// The authority calls the record layer's `alloc_buffers` method. The record layer is 14.4's;
/// a fresh connection holds no buffers and the authority's TLS methods allocate none eagerly, so
/// this slice answers 1 and the divergence is recorded in `src/ssl/mod.rs`.
///
/// # Safety
/// `ssl` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_alloc_buffers(ssl: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        let _ = ssl;
        1
    })
}

/// `int SSL_free_buffers(SSL *ssl)` — `ssl/ssl_lib.c:6960-6972`.
///
/// As [`SSL_alloc_buffers`], the record layer is 14.4's; the authority's methods free nothing for a
/// fresh connection and answer 1, which this slice reproduces (recorded in `src/ssl/mod.rs`).
///
/// # Safety
/// `ssl` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_free_buffers(ssl: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        let _ = ssl;
        1
    })
}

/// `int SSL_get_value_uint(SSL *s, uint32_t class_, uint32_t id, uint64_t *value)` —
/// `ssl/ssl_lib.c:8002-8012`.
///
/// # Safety
/// `s` must point to a live connection; `value` must be writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_value_uint(
    s: *mut Ssl,
    class_: u32,
    id: u32,
    value: *mut u64,
) -> c_int {
    guard_ffi(0, || {
        let _ = (s, class_, id, value);
        // SAFETY: a constant site.
        unsafe { raise_ssl(SSL_R_UNSUPPORTED_PROTOCOL, 8010) };
        0
    })
}

/// `int SSL_set_value_uint(SSL *s, uint32_t class_, uint32_t id, uint64_t value)` —
/// `ssl/ssl_lib.c:8014-8024`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_value_uint(
    s: *mut Ssl,
    class_: u32,
    id: u32,
    value: u64,
) -> c_int {
    guard_ffi(0, || {
        let _ = (s, class_, id, value);
        // SAFETY: a constant site.
        unsafe { raise_ssl(SSL_R_UNSUPPORTED_PROTOCOL, 8022) };
        0
    })
}

/// `void SSL_set_debug(SSL *s, int debug)` — `ssl/ssl_lib.c:6149-6154`: the authority's body is
/// empty ("Old function was do-nothing anyway").
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_debug(s: *mut Ssl, debug: c_int) {
    guard_ffi((), || {
        let _ = (s, debug);
    })
}

/// `int SSL_get_blocking_mode(SSL *s)` — `ssl/ssl_lib.c:7730-7740`: `-1` for a non-QUIC object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_blocking_mode(s: *mut Ssl) -> c_int {
    guard_ffi(-1, || {
        let _ = s;
        -1
    })
}

/// `int SSL_set_blocking_mode(SSL *s, int blocking)` — `ssl/ssl_lib.c:7718-7728`: `0` for a
/// non-QUIC object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_blocking_mode(s: *mut Ssl, blocking: c_int) -> c_int {
    guard_ffi(0, || {
        let _ = (s, blocking);
        0
    })
}

/// `int SSL_handle_events(SSL *s)` — `ssl/ssl_lib.c:7618-7640`.
///
/// The authority's DTLS arm (`DTLSv1_handle_timeout`) is 14.8's; the transport here is TLS, for
/// which the authority answers 1. Recorded in `src/ssl/mod.rs`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_handle_events(s: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        // `is_dtls(s)` is false for every method this slice builds.
        let _ = s;
        1
    })
}

/// `int SSL_get_event_timeout(SSL *s, struct timeval *tv, int *is_infinite)` —
/// `ssl/ssl_lib.c:7642-7662`.
///
/// # Safety
/// `s` must point to a live connection; `tv` and `is_infinite` must be writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_event_timeout(
    s: *mut Ssl,
    tv: *mut Timeval,
    is_infinite: *mut c_int,
) -> c_int {
    guard_ffi(0, || {
        // `is_dtls(s)` is false for every method this slice builds, so the authority's infinite
        // default is its answer (its DTLS `DTLSv1_get_timeout` arm is 14.8's).
        let _ = s;
        // SAFETY: `tv` and `is_infinite` are writable per the contract.
        unsafe {
            (*tv).tv_sec = 1000000;
            (*tv).tv_usec = 0;
            *is_infinite = 1;
        }
        1
    })
}

/// `int SSL_get_rpoll_descriptor(SSL *s, BIO_POLL_DESCRIPTOR *desc)` — `ssl/ssl_lib.c:7664-7677`.
///
/// # Safety
/// `s` must point to a live connection; `desc` must be writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_rpoll_descriptor(
    s: *mut Ssl,
    desc: *mut BioPollDescriptor,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        let rbio = unsafe { (*s).rbio };
        if rbio.is_null() {
            return 0;
        }
        // SAFETY: `rbio` is live and `desc` is writable per the contract.
        unsafe { BIO_get_rpoll_descriptor(rbio, desc) }
    })
}

/// `int SSL_get_wpoll_descriptor(SSL *s, BIO_POLL_DESCRIPTOR *desc)` — `ssl/ssl_lib.c:7679-7692`.
///
/// # Safety
/// `s` must point to a live connection; `desc` must be writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_wpoll_descriptor(
    s: *mut Ssl,
    desc: *mut BioPollDescriptor,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        let wbio = unsafe { (*s).wbio };
        if wbio.is_null() {
            return 0;
        }
        // SAFETY: `wbio` is live and `desc` is writable per the contract.
        unsafe { BIO_get_wpoll_descriptor(wbio, desc) }
    })
}

/// `int SSL_net_read_desired(SSL *s)` — `ssl/ssl_lib.c:7694-7704`: `SSL_want_read(s)` for a
/// non-QUIC object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_net_read_desired(s: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        c_int::from(unsafe { (*s).rwstate } == SSL_WANT_READING)
    })
}

/// `int SSL_net_write_desired(SSL *s)` — `ssl/ssl_lib.c:7706-7716`: `SSL_want_write(s)` for a
/// non-QUIC object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_net_write_desired(s: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        c_int::from(unsafe { (*s).rwstate } == SSL_WANT_WRITING)
    })
}

/// `int SSL_shutdown_ex(SSL *ssl, uint64_t flags, const SSL_SHUTDOWN_EX_ARGS *args, size_t
/// args_len)` — `ssl/ssl_lib.c:7754-7766`: a non-QUIC object delegates to [`SSL_shutdown`].
///
/// # Safety
/// `ssl` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_shutdown_ex(
    ssl: *mut Ssl,
    flags: u64,
    args: *const c_void,
    args_len: usize,
) -> c_int {
    guard_ffi(-1, || {
        let _ = (flags, args, args_len);
        // SAFETY: `ssl` is live per the caller's contract.
        unsafe { SSL_shutdown(ssl) }
    })
}

/// `int SSL_set1_initial_peer_addr(SSL *s, const BIO_ADDR *peer_addr)` — `ssl/ssl_lib.c:7742-7752`:
/// `0` for a non-QUIC object.
///
/// # Safety
/// `s` must point to a live connection; `peer_addr` is not read on this path.
#[no_mangle]
pub unsafe extern "C" fn SSL_set1_initial_peer_addr(
    s: *mut Ssl,
    peer_addr: *const c_void,
) -> c_int {
    guard_ffi(0, || {
        let _ = (s, peer_addr);
        0
    })
}

/// `SSL *SSL_new_stream(SSL *s, uint64_t flags)` — `ssl/ssl_lib.c:7780-7790`: NULL for a non-QUIC
/// object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_new_stream(s: *mut Ssl, flags: u64) -> *mut Ssl {
    guard_ffi(ptr::null_mut(), || {
        let _ = (s, flags);
        ptr::null_mut()
    })
}

/// `SSL *SSL_accept_stream(SSL *s, uint64_t flags)` — `ssl/ssl_lib.c:7903-7913`: NULL for a
/// non-QUIC object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_accept_stream(s: *mut Ssl, flags: u64) -> *mut Ssl {
    guard_ffi(ptr::null_mut(), || {
        let _ = (s, flags);
        ptr::null_mut()
    })
}

/// `size_t SSL_get_accept_stream_queue_len(SSL *s)` — `ssl/ssl_lib.c:7915-7925`: 0 for a non-QUIC
/// object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_accept_stream_queue_len(s: *mut Ssl) -> usize {
    guard_ffi(0, || {
        let _ = s;
        0
    })
}

/// `int SSL_stream_conclude(SSL *ssl, uint64_t flags)` — `ssl/ssl_lib.c:7768-7778`: 0 for a
/// non-QUIC object.
///
/// # Safety
/// `ssl` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_stream_conclude(ssl: *mut Ssl, flags: u64) -> c_int {
    guard_ffi(0, || {
        let _ = (ssl, flags);
        0
    })
}

/// `int SSL_stream_reset(SSL *s, const SSL_STREAM_RESET_ARGS *args, size_t args_len)` —
/// `ssl/ssl_lib.c:7927-7939`: 0 for a non-QUIC object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_stream_reset(
    s: *mut Ssl,
    args: *const c_void,
    args_len: usize,
) -> c_int {
    guard_ffi(0, || {
        let _ = (s, args, args_len);
        0
    })
}

/// `int SSL_get_stream_type(SSL *s)` — `ssl/ssl_lib.c:7843-7853`: `SSL_STREAM_TYPE_BIDI` for a
/// non-QUIC object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_stream_type(s: *mut Ssl) -> c_int {
    guard_ffi(SSL_STREAM_TYPE_BIDI, || {
        let _ = s;
        SSL_STREAM_TYPE_BIDI
    })
}

/// `uint64_t SSL_get_stream_id(SSL *s)` — `ssl/ssl_lib.c:7855-7865`: `UINT64_MAX` for a non-QUIC
/// object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_stream_id(s: *mut Ssl) -> u64 {
    guard_ffi(u64::MAX, || {
        let _ = s;
        u64::MAX
    })
}

/// `int SSL_is_stream_local(SSL *s)` — `ssl/ssl_lib.c:7867-7877`: `-1` for a non-QUIC object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_is_stream_local(s: *mut Ssl) -> c_int {
    guard_ffi(-1, || {
        let _ = s;
        -1
    })
}

/// `int SSL_get_stream_read_state(SSL *s)` — `ssl/ssl_lib.c:7941-7951`:
/// `SSL_STREAM_STATE_NONE` for a non-QUIC object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_stream_read_state(s: *mut Ssl) -> c_int {
    guard_ffi(SSL_STREAM_STATE_NONE, || {
        let _ = s;
        SSL_STREAM_STATE_NONE
    })
}

/// `int SSL_get_stream_write_state(SSL *s)` — `ssl/ssl_lib.c:7953-7963`:
/// `SSL_STREAM_STATE_NONE` for a non-QUIC object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_stream_write_state(s: *mut Ssl) -> c_int {
    guard_ffi(SSL_STREAM_STATE_NONE, || {
        let _ = s;
        SSL_STREAM_STATE_NONE
    })
}

/// `int SSL_get_stream_read_error_code(SSL *s, uint64_t *app_error_code)` —
/// `ssl/ssl_lib.c:7965-7975`: `-1` for a non-QUIC object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_stream_read_error_code(
    s: *mut Ssl,
    app_error_code: *mut u64,
) -> c_int {
    guard_ffi(-1, || {
        let _ = (s, app_error_code);
        -1
    })
}

/// `int SSL_get_stream_write_error_code(SSL *s, uint64_t *app_error_code)` —
/// `ssl/ssl_lib.c:7977-7987`: `-1` for a non-QUIC object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_stream_write_error_code(
    s: *mut Ssl,
    app_error_code: *mut u64,
) -> c_int {
    guard_ffi(-1, || {
        let _ = (s, app_error_code);
        -1
    })
}

/// `int SSL_set_default_stream_mode(SSL *s, uint32_t mode)` — `ssl/ssl_lib.c:7879-7889`: 0 for a
/// non-QUIC object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_default_stream_mode(s: *mut Ssl, mode: u32) -> c_int {
    guard_ffi(0, || {
        let _ = (s, mode);
        0
    })
}

/// `int SSL_set_incoming_stream_policy(SSL *s, int policy, uint64_t aec)` —
/// `ssl/ssl_lib.c:7891-7901`: 0 for a non-QUIC object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_incoming_stream_policy(
    s: *mut Ssl,
    policy: c_int,
    aec: u64,
) -> c_int {
    guard_ffi(0, || {
        let _ = (s, policy, aec);
        0
    })
}

/// `SSL *SSL_get0_connection(SSL *s)` — `ssl/ssl_lib.c:7792-7802`: `s` for a non-QUIC object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_connection(s: *mut Ssl) -> *mut Ssl {
    guard_ffi(ptr::null_mut(), || s)
}

/// `SSL *SSL_get0_listener(SSL *s)` — `ssl/ssl_lib.c:7809-7819`: NULL for a non-QUIC object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_listener(s: *mut Ssl) -> *mut Ssl {
    guard_ffi(ptr::null_mut(), || {
        let _ = s;
        ptr::null_mut()
    })
}

/// `SSL *SSL_get0_domain(SSL *s)` — `ssl/ssl_lib.c:7821-7831`: NULL for a non-QUIC object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_domain(s: *mut Ssl) -> *mut Ssl {
    guard_ffi(ptr::null_mut(), || {
        let _ = s;
        ptr::null_mut()
    })
}

/// `int SSL_is_connection(SSL *s)` — `ssl/ssl_lib.c:7804-7807`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_is_connection(s: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        c_int::from(unsafe { SSL_get0_connection(s) } == s)
    })
}

/// `int SSL_is_listener(SSL *s)` — `ssl/ssl_lib.c:7833-7836`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_is_listener(s: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        c_int::from(unsafe { SSL_get0_listener(s) } == s)
    })
}

/// `int SSL_is_domain(SSL *s)` — `ssl/ssl_lib.c:7838-7841`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_is_domain(s: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `s` is live per the caller's contract.
        c_int::from(unsafe { SSL_get0_domain(s) } == s)
    })
}

/// `SSL *SSL_new_listener(SSL_CTX *ctx, uint64_t flags)` — `ssl/ssl_lib.c:8026-8036`: NULL for a
/// non-QUIC context.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_new_listener(ctx: *mut SslCtx, flags: u64) -> *mut Ssl {
    guard_ffi(ptr::null_mut(), || {
        let _ = (ctx, flags);
        ptr::null_mut()
    })
}

/// `SSL *SSL_new_listener_from(SSL *ssl, uint64_t flags)` — `ssl/ssl_lib.c:8038-8048`: NULL for a
/// non-QUIC object.
///
/// # Safety
/// `ssl` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_new_listener_from(ssl: *mut Ssl, flags: u64) -> *mut Ssl {
    guard_ffi(ptr::null_mut(), || {
        let _ = (ssl, flags);
        ptr::null_mut()
    })
}

/// `SSL *SSL_new_from_listener(SSL *ssl, uint64_t flags)` — `ssl/ssl_lib.c:8050-8060`: NULL for a
/// non-QUIC object.
///
/// # Safety
/// `ssl` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_new_from_listener(ssl: *mut Ssl, flags: u64) -> *mut Ssl {
    guard_ffi(ptr::null_mut(), || {
        let _ = (ssl, flags);
        ptr::null_mut()
    })
}

/// `SSL *SSL_accept_connection(SSL *ssl, uint64_t flags)` — `ssl/ssl_lib.c:8062-8072`: NULL for a
/// non-QUIC object.
///
/// # Safety
/// `ssl` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_accept_connection(ssl: *mut Ssl, flags: u64) -> *mut Ssl {
    guard_ffi(ptr::null_mut(), || {
        let _ = (ssl, flags);
        ptr::null_mut()
    })
}

/// `size_t SSL_get_accept_connection_queue_len(SSL *ssl)` — `ssl/ssl_lib.c:8074-8084`: 0 for a
/// non-QUIC object.
///
/// # Safety
/// `ssl` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_accept_connection_queue_len(ssl: *mut Ssl) -> usize {
    guard_ffi(0, || {
        let _ = ssl;
        0
    })
}

/// `int SSL_listen(SSL *ssl)` — `ssl/ssl_lib.c:8086-8096`: 0 for a non-QUIC object.
///
/// # Safety
/// `ssl` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_listen(ssl: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        let _ = ssl;
        0
    })
}

/// `SSL *SSL_new_domain(SSL_CTX *ctx, uint64_t flags)` — `ssl/ssl_lib.c:8098-8108`: NULL for a
/// non-QUIC context.
///
/// # Safety
/// `ctx` must point to a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_new_domain(ctx: *mut SslCtx, flags: u64) -> *mut Ssl {
    guard_ffi(ptr::null_mut(), || {
        let _ = (ctx, flags);
        ptr::null_mut()
    })
}

/// `int SSL_get_conn_close_info(SSL *s, SSL_CONN_CLOSE_INFO *info, size_t info_len)` —
/// `ssl/ssl_lib.c:7989-8000`: `-1` for a non-QUIC object.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_conn_close_info(
    s: *mut Ssl,
    info: *mut c_void,
    info_len: usize,
) -> c_int {
    guard_ffi(-1, || {
        let _ = (s, info, info_len);
        -1
    })
}

// -------------------------------------------------------------------------------------------
// PSK identity, the session master key and the ClientHello readers
// -------------------------------------------------------------------------------------------

/// `strlen` over a NUL-terminated C string.
///
/// # Safety
/// `p` must be NUL-terminated.
unsafe fn c_strlen(p: *const c_char) -> usize {
    let mut n: usize = 0;
    // SAFETY: `p` is NUL-terminated per the caller's contract.
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    n
}

/// `int SSL_CTX_use_psk_identity_hint(SSL_CTX *ctx, const char *identity_hint)` —
/// `ssl/ssl_lib.c:5789-5803`.
///
/// # Safety
/// `ctx` must point to a live context; `identity_hint` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_use_psk_identity_hint(
    ctx: *mut SslCtx,
    identity_hint: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        if !identity_hint.is_null() {
            // SAFETY: `identity_hint` is NUL-terminated per the contract.
            if unsafe { c_strlen(identity_hint) } > PSK_MAX_IDENTITY_LEN {
                // SAFETY: a constant site.
                unsafe { raise_ssl(SSL_R_DATA_LENGTH_TOO_LONG, 5792) };
                return 0;
            }
        }
        // SAFETY: `ctx` and its `cert` are live.
        unsafe {
            let cert = (*ctx).cert;
            CRYPTO_free((*cert).psk_identity_hint.cast(), FILE, 5795);
            if identity_hint.is_null() {
                (*cert).psk_identity_hint = ptr::null_mut();
            } else {
                (*cert).psk_identity_hint = CRYPTO_strdup(identity_hint, FILE, 5797);
                if (*cert).psk_identity_hint.is_null() {
                    return 0;
                }
            }
        }
        1
    })
}

/// `int SSL_use_psk_identity_hint(SSL *s, const char *identity_hint)` — `ssl/ssl_lib.c:5805-5824`.
///
/// # Safety
/// `s` must point to a live connection; `identity_hint` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_use_psk_identity_hint(
    s: *mut Ssl,
    identity_hint: *const c_char,
) -> c_int {
    guard_ffi(0, || {
        if !identity_hint.is_null() {
            // SAFETY: `identity_hint` is NUL-terminated per the contract.
            if unsafe { c_strlen(identity_hint) } > PSK_MAX_IDENTITY_LEN {
                // SAFETY: a constant site.
                unsafe { raise_ssl(SSL_R_DATA_LENGTH_TOO_LONG, 5813) };
                return 0;
            }
        }
        // SAFETY: `s` and its `cert` are live.
        unsafe {
            let cert = (*s).cert;
            CRYPTO_free((*cert).psk_identity_hint.cast(), FILE, 5816);
            if identity_hint.is_null() {
                (*cert).psk_identity_hint = ptr::null_mut();
            } else {
                (*cert).psk_identity_hint = CRYPTO_strdup(identity_hint, FILE, 5818);
                if (*cert).psk_identity_hint.is_null() {
                    return 0;
                }
            }
        }
        1
    })
}

/// `const char *SSL_get_psk_identity_hint(const SSL *s)` — `ssl/ssl_lib.c:5826-5834`. The hint is
/// read from the session, which is 14.7's and NULL throughout this slice.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_psk_identity_hint(s: *const Ssl) -> *const c_char {
    guard_ffi(ptr::null(), || {
        // SAFETY: `s` is live per the caller's contract; its session is NULL in this slice.
        let session = unsafe { (*s).session };
        if session.is_null() {
            ptr::null()
        } else {
            // SAFETY: `session` is live per the check above.
            unsafe { (*session).psk_identity_hint }
        }
    })
}

/// `const char *SSL_get_psk_identity(const SSL *s)` — `ssl/ssl_lib.c:5836-5844`. As
/// [`SSL_get_psk_identity_hint`], the session is 14.7's and NULL here.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_psk_identity(s: *const Ssl) -> *const c_char {
    guard_ffi(ptr::null(), || {
        // SAFETY: `s` is live per the caller's contract; its session is NULL in this slice.
        let session = unsafe { (*s).session };
        if session.is_null() {
            ptr::null()
        } else {
            // SAFETY: `session` is live per the check above.
            unsafe { (*session).psk_identity }
        }
    })
}

/// `size_t SSL_SESSION_get_master_key(const SSL_SESSION *session, unsigned char *out, size_t
/// outlen)` — `ssl/ssl_lib.c:5712-5721`.
///
/// # Safety
/// `session` must point to a live session; `out` must hold `outlen` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_get_master_key(
    session: *const SslSession,
    out: *mut u8,
    outlen: usize,
) -> usize {
    guard_ffi(0, || {
        // SAFETY: `session` is live per the caller's contract.
        let len = unsafe { (*session).master_key_length };
        if outlen == 0 {
            return len;
        }
        let n = if outlen > len { len } else { outlen };
        // SAFETY: `out` holds `outlen >= n` writable bytes per the contract; the master key is
        // `len >= n` readable bytes.
        unsafe { ptr::copy_nonoverlapping((*session).master_key.as_ptr(), out, n) };
        n
    })
}

/// `int SSL_SESSION_set1_master_key(SSL_SESSION *sess, const unsigned char *in, size_t len)` —
/// `ssl/ssl_lib.c:5723-5732`.
///
/// # Safety
/// `sess` must point to a live session; `in` must be readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_SESSION_set1_master_key(
    sess: *mut SslSession,
    input: *const u8,
    len: usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: `sess` is live per the caller's contract.
        if len > unsafe { (*sess).master_key.len() } {
            return 0;
        }
        // SAFETY: `in` is readable for `len` bytes; the destination is `len` writable bytes.
        unsafe {
            ptr::copy_nonoverlapping(input, (*sess).master_key.as_mut_ptr(), len);
            (*sess).master_key_length = len;
        }
        1
    })
}

/// The candidate's reduction of the authority's `CLIENTHELLO_MSG` (`ssl/ssl_local.h:642-655`),
/// published on `SSL.clienthello` only while a `SSL_CTX_set_client_hello_cb` callback runs. The
/// authority parses the extension block into an ordered `RAW_EXTENSION` array; the reduced readers
/// walk the raw block in place, which is the same received order.
#[repr(C)]
pub(crate) struct ClientHelloMsg {
    /// `unsigned int isv2`.
    pub isv2: c_uint,
    /// `unsigned int legacy_version`.
    pub legacy_version: c_uint,
    /// `unsigned char random[SSL3_RANDOM_SIZE]`.
    pub random: [u8; SSL3_RANDOM_SIZE],
    /// `size_t session_id_len`.
    pub session_id_len: usize,
    /// `unsigned char session_id[SSL_MAX_SSL_SESSION_ID_LENGTH]`.
    pub session_id: [u8; SSL_MAX_SSL_SESSION_ID_LENGTH],
    /// `PACKET ciphersuites` — borrowed from the received handshake message.
    pub ciphersuites: *const u8,
    /// `PACKET_remaining(&ciphersuites)`.
    pub ciphersuites_len: usize,
    /// `size_t compressions_len`.
    pub compressions_len: usize,
    /// `unsigned char compressions[MAX_COMPRESSIONS_SIZE]` — borrowed.
    pub compressions: *const u8,
    /// `PACKET extensions` — the raw `Extension extensions<2..>` block, borrowed.
    pub extensions: *const u8,
    /// `PACKET_remaining(&extensions)`.
    pub extensions_len: usize,
}

/// The connection's `SSL.clienthello` as the reduced [`ClientHelloMsg`], or NULL outside a
/// ClientHello callback.
///
/// # Safety
/// `s` must be NULL or a live connection.
unsafe fn client_hello_msg(s: *mut Ssl) -> *const ClientHelloMsg {
    if s.is_null() {
        return ptr::null();
    }
    // SAFETY: `s` is live per the caller's contract; `clienthello` is NULL or the message the
    // ClientHello path published for the duration of the callback.
    unsafe { (*s).clienthello as *const ClientHelloMsg }
}

/// Count the well-formed entries of a raw `Extension extensions<2..>` block. The authority counts
/// the `present` rows of its parsed `pre_proc_exts`; walking the raw block yields the same number
/// and the same received order.
fn count_raw_extensions(exts: &[u8]) -> usize {
    let mut num = 0usize;
    let mut off = 0usize;
    while off + 4 <= exts.len() {
        let el = ((exts[off + 2] as usize) << 8) | exts[off + 3] as usize;
        off += 4;
        if off + el > exts.len() {
            break;
        }
        num += 1;
        off += el;
    }
    num
}

/// `int SSL_client_hello_isv2(SSL *s)` — `ssl/ssl_lib.c:6777-6787`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_client_hello_isv2(s: *mut Ssl) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `s` is live, so the connection is dereferenceable.
        let ch = unsafe { client_hello_msg(s) };
        if ch.is_null() {
            0
        } else {
            // SAFETY: `ch` is the live message read above.
            unsafe { (*ch).isv2 as c_int }
        }
    })
}

/// `unsigned int SSL_client_hello_get0_legacy_version(SSL *s)` — `ssl/ssl_lib.c:6789-6799`.
///
/// # Safety
/// `s` must point to a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_client_hello_get0_legacy_version(s: *mut Ssl) -> c_uint {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `s` is live, so the connection is dereferenceable.
        let ch = unsafe { client_hello_msg(s) };
        if ch.is_null() {
            0
        } else {
            // SAFETY: `ch` is the live message read above.
            unsafe { (*ch).legacy_version }
        }
    })
}

/// `size_t SSL_client_hello_get0_random(SSL *s, const unsigned char **out)` —
/// `ssl/ssl_lib.c:6801-6813`.
///
/// # Safety
/// `s` must point to a live connection; `out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_client_hello_get0_random(s: *mut Ssl, out: *mut *const u8) -> usize {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `s` is live, so the connection is dereferenceable.
        let ch = unsafe { client_hello_msg(s) };
        if ch.is_null() {
            return 0;
        }
        if !out.is_null() {
            // SAFETY: `ch` is the live message; `random` is a 32-byte array.
            unsafe { *out = (*ch).random.as_ptr() };
        }
        SSL3_RANDOM_SIZE
    })
}

/// `size_t SSL_client_hello_get0_session_id(SSL *s, const unsigned char **out)` —
/// `ssl/ssl_lib.c:6815-6827`.
///
/// # Safety
/// `s` must point to a live connection; `out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_client_hello_get0_session_id(
    s: *mut Ssl,
    out: *mut *const u8,
) -> usize {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `s` is live, so the connection is dereferenceable.
        let ch = unsafe { client_hello_msg(s) };
        if ch.is_null() {
            return 0;
        }
        if !out.is_null() {
            // SAFETY: `ch` is the live message; `session_id` is a 32-byte array.
            unsafe { *out = (*ch).session_id.as_ptr() };
        }
        // SAFETY: `ch` is the live message read above.
        unsafe { (*ch).session_id_len }
    })
}

/// `size_t SSL_client_hello_get0_ciphers(SSL *s, const unsigned char **out)` —
/// `ssl/ssl_lib.c:6829-6841`.
///
/// # Safety
/// `s` must point to a live connection; `out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_client_hello_get0_ciphers(s: *mut Ssl, out: *mut *const u8) -> usize {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `s` is live, so the connection is dereferenceable.
        let ch = unsafe { client_hello_msg(s) };
        if ch.is_null() {
            return 0;
        }
        if !out.is_null() {
            // SAFETY: `ch` is the live message; `ciphersuites` borrows the received handshake
            // message, which outlives the callback this accessor serves.
            unsafe { *out = (*ch).ciphersuites };
        }
        // SAFETY: `ch` is the live message read above.
        unsafe { (*ch).ciphersuites_len }
    })
}

/// `size_t SSL_client_hello_get0_compression_methods(SSL *s, const unsigned char **out)` —
/// `ssl/ssl_lib.c:6843-6855`.
///
/// # Safety
/// `s` must point to a live connection; `out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_client_hello_get0_compression_methods(
    s: *mut Ssl,
    out: *mut *const u8,
) -> usize {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `s` is live, so the connection is dereferenceable.
        let ch = unsafe { client_hello_msg(s) };
        if ch.is_null() {
            return 0;
        }
        if !out.is_null() {
            // SAFETY: `ch` is the live message; `compressions` borrows the received handshake
            // message, which outlives the callback this accessor serves.
            unsafe { *out = (*ch).compressions };
        }
        // SAFETY: `ch` is the live message read above.
        unsafe { (*ch).compressions_len }
    })
}

/// `int SSL_client_hello_get1_extensions_present(SSL *s, int **out, size_t *outlen)` —
/// `ssl/ssl_lib.c:6857-6895`.
///
/// # Safety
/// `s` must point to a live connection; `out`/`outlen` must be writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_client_hello_get1_extensions_present(
    s: *mut Ssl,
    out: *mut *mut c_int,
    outlen: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `s` is live, so the connection is dereferenceable.
        let ch = unsafe { client_hello_msg(s) };
        if ch.is_null() || out.is_null() || outlen.is_null() {
            return 0;
        }
        // SAFETY: `ch` is the live message; the raw extension block outlives the callback.
        let exts = unsafe { core::slice::from_raw_parts((*ch).extensions, (*ch).extensions_len) };
        let num = count_raw_extensions(exts);
        if num == 0 {
            // SAFETY: `out`/`outlen` are writable per the checks above.
            unsafe {
                *out = ptr::null_mut();
                *outlen = 0;
            }
            return 1;
        }
        // `OPENSSL_malloc_array(num, sizeof(*present))` (`ssl_lib.c:6874`), exercised through the
        // same allocator `OPENSSL_free` releases.
        let present = CRYPTO_calloc(num, core::mem::size_of::<c_int>(), FILE, 6874).cast::<c_int>();
        if present.is_null() {
            return 0;
        }
        let mut i = 0usize;
        let mut off = 0usize;
        while off + 4 <= exts.len() {
            let et = ((exts[off] as c_int) << 8) | exts[off + 1] as c_int;
            let el = ((exts[off + 2] as usize) << 8) | exts[off + 3] as usize;
            off += 4;
            if off + el > exts.len() {
                break;
            }
            // SAFETY: `i < num`, and `present` holds `num` `c_int`s.
            unsafe { *present.add(i) = et };
            i += 1;
            off += el;
        }
        // SAFETY: `out`/`outlen` are writable; `present` is owned by the caller now.
        unsafe {
            *out = present;
            *outlen = num;
        }
        1
    })
}

/// `int SSL_client_hello_get_extension_order(SSL *s, uint16_t *exts, size_t *num_exts)` —
/// `ssl/ssl_lib.c:6897-6933`.
///
/// # Safety
/// `s` must point to a live connection; `exts`/`num_exts` per the caller's contract.
#[no_mangle]
pub unsafe extern "C" fn SSL_client_hello_get_extension_order(
    s: *mut Ssl,
    exts: *mut u16,
    num_exts: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `s` is live, so the connection is dereferenceable.
        let ch = unsafe { client_hello_msg(s) };
        if ch.is_null() || num_exts.is_null() {
            return 0;
        }
        // SAFETY: `ch` is the live message; the raw extension block outlives the callback.
        let raw = unsafe { core::slice::from_raw_parts((*ch).extensions, (*ch).extensions_len) };
        let num = count_raw_extensions(raw);
        if num == 0 {
            // SAFETY: `num_exts` is writable per the check above.
            unsafe { *num_exts = 0 };
            return 1;
        }
        if exts.is_null() {
            // SAFETY: `num_exts` is writable.
            unsafe { *num_exts = num };
            return 1;
        }
        // SAFETY: `num_exts` is writable.
        if unsafe { *num_exts } < num {
            return 0;
        }
        let mut i = 0usize;
        let mut off = 0usize;
        while off + 4 <= raw.len() {
            let et = ((raw[off] as u16) << 8) | raw[off + 1] as u16;
            let el = ((raw[off + 2] as usize) << 8) | raw[off + 3] as usize;
            off += 4;
            if off + el > raw.len() {
                break;
            }
            // SAFETY: `i < num <= *num_exts`, and `exts` holds at least `*num_exts` `u16`s.
            unsafe { *exts.add(i) = et };
            i += 1;
            off += el;
        }
        // SAFETY: `num_exts` is writable.
        unsafe { *num_exts = num };
        1
    })
}

/// `int SSL_client_hello_get0_ext(SSL *s, unsigned int type, const unsigned char **out, size_t
/// *outlen)` — `ssl/ssl_lib.c:6935-6958`.
///
/// # Safety
/// `s` must point to a live connection; `out`/`outlen` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn SSL_client_hello_get0_ext(
    s: *mut Ssl,
    type_: c_uint,
    out: *mut *const u8,
    outlen: *mut usize,
) -> c_int {
    guard_ffi(0, || {
        // SAFETY: the caller guarantees `s` is live, so the connection is dereferenceable.
        let ch = unsafe { client_hello_msg(s) };
        if ch.is_null() {
            return 0;
        }
        // SAFETY: `ch` is the live message; `extensions`/`extensions_len` describe the received
        // `Extension extensions<2..>` block, which outlives the callback this accessor serves.
        let exts = unsafe { core::slice::from_raw_parts((*ch).extensions, (*ch).extensions_len) };
        let mut off = 0usize;
        while off + 4 <= exts.len() {
            let et = ((exts[off] as c_uint) << 8) | exts[off + 1] as c_uint;
            let el = ((exts[off + 2] as usize) << 8) | exts[off + 3] as usize;
            off += 4;
            if off + el > exts.len() {
                return 0;
            }
            if et == type_ {
                if !out.is_null() {
                    // SAFETY: `off` indexes a body of `el` readable bytes inside `exts`.
                    unsafe { *out = exts.as_ptr().add(off) };
                }
                if !outlen.is_null() {
                    // SAFETY: `outlen` is writable per the caller's contract.
                    unsafe { *outlen = el };
                }
                return 1;
            }
            off += el;
        }
        0
    })
}
// ---------------------------------------------------------------------------------------------
// The cipher-list accessors (Phase 14.3; `ssl/ssl_lib.c:3253-3412`)
//
// `docs/PHASE-14-SUBPHASES.md` names these "the cipher tables and parser, 14.3 (`ssl_ciph.c`)"
// even though `ssl_lib.c` defines them, and the ledger's module label is that defining unit; the
// parser and tables they drive are `src/ssl/ssl_ciph.rs`.
// ---------------------------------------------------------------------------------------------

/// `STACK_OF(SSL_CIPHER) *SSL_get_ciphers(const SSL *s)` — `ssl/ssl_lib.c:3253-3265`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_ciphers(s: *const Ssl) -> *mut OpenSslStack {
    guard_ffi(ptr::null_mut(), || {
        if s.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            if !(*s).cipher_list.is_null() {
                return (*s).cipher_list;
            }
            if !(*s).ctx.is_null() && !(*(*s).ctx).cipher_list.is_null() {
                return (*(*s).ctx).cipher_list;
            }
        }
        ptr::null_mut()
    })
}

/** The old interface to get the same thing as `SSL_get_ciphers()`. */
/// `const char *SSL_get_cipher_list(const SSL *s, int n)` — `ssl/ssl_lib.c:3321-3335`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_cipher_list(s: *const Ssl, n: c_int) -> *const c_char {
    guard_ffi(ptr::null(), || {
        if s.is_null() {
            return ptr::null();
        }
        // SAFETY: `s` is live per the caller's contract.
        let sk = unsafe { SSL_get_ciphers(s) };
        // SAFETY: `sk` is NULL or a live stack from `SSL_get_ciphers`.
        let num = if sk.is_null() {
            0
        } else {
            // SAFETY: `sk` is non-NULL, so it is a live stack from `SSL_get_ciphers`.
            unsafe { crate::runtime::stack::OPENSSL_sk_num(sk) }
        };
        if num <= n {
            return ptr::null();
        }
        // SAFETY: `n` is in range for the stack.
        let c = unsafe {
            crate::runtime::stack::OPENSSL_sk_value(sk, n)
                as *const crate::ssl::ssl_ciph_table::SslCipher
        };
        if c.is_null() {
            return ptr::null();
        }
        // SAFETY: `c` is a process-lifetime table row.
        unsafe { (*c).name.as_ptr().cast::<c_char>() }
    })
}

/// `STACK_OF(SSL_CIPHER) *SSL_CTX_get_ciphers(const SSL_CTX *ctx)` — `ssl/ssl_lib.c:3339-3344`.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_get_ciphers(ctx: *const SslCtx) -> *mut OpenSslStack {
    guard_ffi(ptr::null_mut(), || {
        if ctx.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).cipher_list }
    })
}

/** specify the ciphers to be used by default by the SSL_CTX */
/// `int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str)` — `ssl/ssl_lib.c:3367-3388`.
///
/// # Safety
/// `ctx` must be NULL or live; `str` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_cipher_list(ctx: *mut SslCtx, str_: *const c_char) -> c_int {
    guard_ffi(0, || {
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `ctx` is live per the caller's contract.
        let (method, cert) = unsafe { ((*ctx).method, (*ctx).cert) };
        if method.is_null() {
            return 0;
        }
        // SAFETY: `ctx` and its method/cert are live; the stack slots belong to `ctx`.
        let sk = unsafe {
            crate::ssl::ssl_ciph::ssl_create_cipher_list(
                ctx,
                (*ctx).tls13_ciphersuites,
                &mut (*ctx).cipher_list,
                &mut (*ctx).cipher_list_by_id,
                str_,
                cert,
            )
        };
        if sk.is_null() {
            return 0;
        }
        // `ctx->method->num_ciphers()` is `ssl3_num_ciphers()` (167) for every method here.
        // SAFETY: `sk` is a live stack.
        if unsafe { crate::ssl::ssl_ciph::cipher_list_tls12_num(sk) } == 0 {
            // SSL_R_NO_CIPHER_MATCH
            return 0;
        }
        1
    })
}

/** specify the ciphers to be used by the SSL */
/// `int SSL_set_cipher_list(SSL *s, const char *str)` — `ssl/ssl_lib.c:3391-3412`.
///
/// # Safety
/// `s` must be NULL or live; `str` NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_cipher_list(s: *mut Ssl, str_: *const c_char) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live per the caller's contract.
        let (ctx, cert) = unsafe { ((*s).ctx, (*s).cert) };
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `ctx` and `cert` are live; the stack slots belong to `s`.
        let sk = unsafe {
            crate::ssl::ssl_ciph::ssl_create_cipher_list(
                ctx,
                (*s).tls13_ciphersuites,
                &mut (*s).cipher_list,
                &mut (*s).cipher_list_by_id,
                str_,
                cert,
            )
        };
        if sk.is_null() {
            return 0;
        }
        // SAFETY: `sk` is a live stack.
        if unsafe { crate::ssl::ssl_ciph::cipher_list_tls12_num(sk) } == 0 {
            return 0;
        }
        1
    })
}

// -------------------------------------------------------------------------------------------
// Phase 14.1 remainder — the rows its now-landed dependencies (14.3/14.4/14.5/14.7) unblock
// -------------------------------------------------------------------------------------------

/** Used to change an SSL_CTXs default SSL method type */
/// `int SSL_CTX_set_ssl_version(SSL_CTX *ctx, const SSL_METHOD *meth)` — `ssl/ssl_lib.c:662-687`.
///
/// # Safety
/// `ctx` must be a live context; `meth` a live method table.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_ssl_version(
    ctx: *mut SslCtx,
    meth: *const SslMethod,
) -> c_int {
    guard_ffi(0, || {
        if ctx.is_null() || meth.is_null() {
            return 0;
        }
        // `IS_QUIC_CTX(ctx)` is unreachable for the contexts this crate builds.
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).method = meth };
        // SAFETY: `ctx` is live; the ciphersuite setter takes the default list.
        if unsafe {
            crate::ssl::ssl_ciph::SSL_CTX_set_ciphersuites(
                ctx,
                crate::ssl::ssl_ciph::OSSL_default_ciphersuites(),
            )
        } == 0
        {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS, 675) };
            return 0;
        }
        // SAFETY: `ctx` and its cert are live.
        let sk = unsafe {
            crate::ssl::ssl_ciph::ssl_create_cipher_list(
                ctx,
                (*ctx).tls13_ciphersuites,
                &mut (*ctx).cipher_list,
                &mut (*ctx).cipher_list_by_id,
                crate::ssl::ssl_ciph::OSSL_default_cipher_list(),
                (*ctx).cert,
            )
        };
        // SAFETY: `sk` is the live stack `ssl_create_cipher_list` just built.
        if sk.is_null() || unsafe { OPENSSL_sk_num(sk) } <= 0 {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS, 683) };
            return 0;
        }
        1
    })
}

/// `LHASH_OF(SSL_SESSION) *SSL_CTX_sessions(SSL_CTX *ctx)` — `ssl/ssl_lib.c:3081-3084`.
///
/// The crate's internal cache is an `OpenSslStack` rather than an `LHASH`; the returned pointer is
/// the same cache the `SSL_CTX_sess_*` controls and `SSL_CTX_add_session` operate on.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_sessions(ctx: *mut SslCtx) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        if ctx.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `ctx` is live per the caller's contract.
        unsafe { (*ctx).sessions.cast() }
    })
}

/// `int SSL_has_matching_session_id(const SSL *ssl, const unsigned char *id, unsigned int id_len)`
/// — `ssl/ssl_lib.c:1081-1106`.
///
/// # Safety
/// `ssl` must be a live connection; `id` readable for `id_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_has_matching_session_id(
    ssl: *const Ssl,
    id: *const u8,
    id_len: c_uint,
) -> c_int {
    guard_ffi(0, || {
        if ssl.is_null() || id_len as usize > SSL_MAX_SSL_SESSION_ID_LENGTH {
            return 0;
        }
        // SAFETY: `ssl` is live per the caller's contract.
        let version = unsafe { (*ssl).version };
        // SAFETY: `ssl` is live; its session-cache context is live.
        let ctx = unsafe { (*ssl).session_ctx };
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `ctx` is live; its cache is an `OpenSslStack`.
        let st = unsafe { (*ctx).sessions };
        if st.is_null() {
            return 0;
        }
        // SAFETY: `st` is the non-NULL cache stack per the guard above.
        let n = unsafe { OPENSSL_sk_num(st) };
        for i in 0..n {
            // SAFETY: the index is in range.
            let p = unsafe { OPENSSL_sk_value(st, i).cast::<SslSession>() };
            if p.is_null() {
                continue;
            }
            // SAFETY: `p` is a live cached session.
            if unsafe { (*p).ssl_version } != version
                // SAFETY: `p` is a live cached session.
                || unsafe { (*p).session_id_length } != id_len as usize
            {
                continue;
            }
            if id_len == 0 {
                return 1;
            }
            let mut same = true;
            for j in 0..id_len as usize {
                // SAFETY: `id` is readable for `id_len`; the session's id for its length.
                if unsafe { *id.add(j) } != unsafe { (*p).session_id[j] } {
                    same = false;
                    break;
                }
            }
            if same {
                return 1;
            }
        }
        0
    })
}

/// `void SSL_set_accept_state(SSL *s)` — `ssl/ssl_lib.c:4986-5004`.
///
/// # Safety
/// `s` must be a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_accept_state(s: *mut Ssl) {
    guard_ffi((), || {
        // SAFETY: `s` is live per the caller's contract; the QUIC arm is unreachable here.
        unsafe { ssl_set_accept_state(s) };
    })
}

/// `void SSL_set_connect_state(SSL *s)` — `ssl/ssl_lib.c:5006-5024`.
///
/// # Safety
/// `s` must be a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_connect_state(s: *mut Ssl) {
    guard_ffi((), || {
        // SAFETY: `s` is live per the caller's contract; the QUIC arm is unreachable here.
        unsafe { ssl_set_connect_state(s) };
    })
}

/// `const SSL_CIPHER *SSL_get_current_cipher(const SSL *s)` — `ssl/ssl_lib.c:5310-5320`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_current_cipher(
    s: *const Ssl,
) -> *const crate::ssl::ssl_ciph_table::SslCipher {
    guard_ffi(ptr::null(), || {
        if s.is_null() {
            return ptr::null();
        }
        // SAFETY: `s` is live per the caller's contract.
        let session = unsafe { (*s).session };
        if !session.is_null() {
            // SAFETY: `session` is live.
            if !unsafe { (*session).cipher }.is_null() {
                // SAFETY: `session` is live.
                return unsafe { (*session).cipher };
            }
        }
        // The authority reads `sc->session->cipher` (`ssl_lib.c:5310-5320`). The reduced path has
        // no handshake-created session (`ssl_get_new_session` is unlanded), so the negotiated
        // cipher it stores in `s3.tmp.new_cipher` (`SSL_get_pending_cipher`) is the current one.
        // SAFETY: `s` is live.
        unsafe { (*s).pending_cipher }
    })
}

/// `const SSL_CIPHER *SSL_get_pending_cipher(const SSL *s)` — `ssl/ssl_lib.c:5322-5330`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_pending_cipher(
    s: *const Ssl,
) -> *const crate::ssl::ssl_ciph_table::SslCipher {
    guard_ffi(ptr::null(), || {
        if s.is_null() {
            return ptr::null();
        }
        // SAFETY: `s` is live per the caller's contract.
        unsafe { (*s).pending_cipher }
    })
}

/// `const COMP_METHOD *SSL_get_current_compression(const SSL *s)` — `ssl/ssl_lib.c:5332-5344`.
///
/// The authority asks the write record method; this crate models no record method, and the
/// authority's own default record method answers NULL for a connection that has negotiated no
/// compression, so NULL is its answer for the states this stratum reaches.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_current_compression(_s: *const Ssl) -> *const c_void {
    ptr::null()
}

/// `const COMP_METHOD *SSL_get_current_expansion(const SSL *s)` — `ssl/ssl_lib.c:5346-5358`.
///
/// As [`SSL_get_current_compression`], for the read record method.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_current_expansion(_s: *const Ssl) -> *const c_void {
    ptr::null()
}

/// `STACK_OF(SSL_CIPHER) *SSL_get_client_ciphers(const SSL *s)` — `ssl/ssl_lib.c:3267-3274`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_client_ciphers(s: *const Ssl) -> *mut OpenSslStack {
    guard_ffi(ptr::null_mut(), || {
        if s.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `s` is live per the caller's contract.
        if unsafe { (*s).server } == 0 {
            return ptr::null_mut();
        }
        // SAFETY: `s` is live.
        unsafe { (*s).peer_ciphers }
    })
}

/// `char *SSL_get_shared_ciphers(const SSL *s, char *buf, int size)` — `ssl/ssl_lib.c:3414-3460`.
///
/// # Safety
/// `s` NULL or live; `buf` writable for `size` bytes.
#[no_mangle]
pub unsafe extern "C" fn SSL_get_shared_ciphers(
    s: *const Ssl,
    buf: *mut c_char,
    size: c_int,
) -> *mut c_char {
    guard_ffi(ptr::null_mut(), || {
        if size < 2 || buf.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `buf` is writable for `size` bytes.
        unsafe { *buf = 0 };
        if s.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `s` is live per the caller's contract.
        if unsafe { (*s).server } == 0 {
            return ptr::null_mut();
        }
        // SAFETY: `s` is live.
        let clntsk = unsafe { (*s).peer_ciphers };
        // SAFETY: `s` is live.
        let srvrsk = unsafe { SSL_get_ciphers(s) };
        let cnum = if clntsk.is_null() {
            0
        } else {
            // SAFETY: `clntsk` is non-NULL, so it is a live stack.
            unsafe { OPENSSL_sk_num(clntsk) }
        };
        let snum = if srvrsk.is_null() {
            0
        } else {
            // SAFETY: `srvrsk` is non-NULL, so it is a live stack.
            unsafe { OPENSSL_sk_num(srvrsk) }
        };
        if cnum == 0 || snum == 0 {
            return buf;
        }
        let mut p = buf;
        let mut remaining = size;
        for i in 0..cnum {
            // SAFETY: the index is in range.
            let c = unsafe { OPENSSL_sk_value(clntsk, i) }
                .cast::<crate::ssl::ssl_ciph_table::SslCipher>();
            if c.is_null() {
                continue;
            }
            // SAFETY: `srvrsk` is a live stack; `c` is a live cipher.
            if unsafe { OPENSSL_sk_find(srvrsk, c.cast()) } < 0 {
                continue;
            }
            // SAFETY: `c` is a live cipher.
            let name = unsafe { (*c).name };
            let n = if name.len() >= remaining as usize {
                remaining as usize
            } else {
                name.len()
            };
            if n >= remaining as usize {
                break;
            }
            // SAFETY: `p` is writable for `remaining` bytes and `n < remaining`; `name` is readable.
            unsafe {
                ptr::copy_nonoverlapping(name.as_ptr(), p.cast::<u8>(), n);
                p = p.add(n);
                *p.cast::<u8>() = b':';
                p = p.add(1);
            }
            remaining -= (n + 1) as c_int;
        }
        if p != buf {
            // SAFETY: `p > buf`, so `p - 1` is inside the buffer.
            unsafe { *p.sub(1) = 0 };
        }
        buf
    })
}

/// `int SSL_set0_tmp_dh_pkey(SSL *s, EVP_PKEY *dhpkey)` — `ssl/ssl_lib.c:7588-7603`.
///
/// # Safety
/// `s` must be NULL or a live connection; `dhpkey` a live key.
#[no_mangle]
pub unsafe extern "C" fn SSL_set0_tmp_dh_pkey(s: *mut Ssl, dhpkey: *mut c_void) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live; `dhpkey` is a live key.
        if unsafe {
            ssl_security(
                s,
                SSL_SECOP_TMP_DH,
                EVP_PKEY_get_security_bits(dhpkey.cast()),
                0,
                dhpkey,
            )
        } == 0
        {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_DH_KEY_TOO_SMALL, 7597) };
            return 0;
        }
        // SAFETY: `s` and its cert are live; `dhpkey` is live.
        unsafe {
            let cert = (*s).cert;
            EVP_PKEY_free((*cert).dh_tmp.cast());
            (*cert).dh_tmp = dhpkey;
        }
        1
    })
}

/// `EVP_PKEY *ssl_dh_to_pkey(DH *dh)` — `ssl/tls_depr.c:154-170`.
///
/// # Safety
/// `dh` must be a live `DH *` or NULL.
unsafe fn ssl_dh_to_pkey(dh: *mut c_void) -> *mut EvpPkey {
    use crate::evp::pkey::{EVP_PKEY_new, EVP_PKEY_set1_DH};
    if dh.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `EVP_PKEY_new` allocates a fresh key and takes no caller state.
    let ret = unsafe { EVP_PKEY_new() };
    if ret.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ret` is this frame's fresh key; `dh` is the caller's live DH.
    if unsafe { EVP_PKEY_set1_DH(ret, dh.cast()) } <= 0 {
        // SAFETY: `ret` is this frame's.
        unsafe { EVP_PKEY_free(ret) };
        return ptr::null_mut();
    }
    ret
}

/// `int SSL_CTX_set0_tmp_dh_pkey(SSL_CTX *ctx, EVP_PKEY *dhpkey)` — `ssl/ssl_lib.c:7605-7615`.
///
/// # Safety
/// `ctx` must be a live context; `dhpkey` a live key.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set0_tmp_dh_pkey(ctx: *mut SslCtx, dhpkey: *mut c_void) -> c_int {
    guard_ffi(0, || {
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `ctx` is live; `dhpkey` is a live key.
        if unsafe {
            ssl_ctx_security(
                ctx,
                SSL_SECOP_TMP_DH,
                EVP_PKEY_get_security_bits(dhpkey.cast()),
                0,
                dhpkey,
            )
        } == 0
        {
            // SAFETY: a constant site.
            unsafe { raise_ssl(SSL_R_DH_KEY_TOO_SMALL, 7609) };
            return 0;
        }
        // SAFETY: `ctx` and its cert are live; `dhpkey` is live.
        unsafe {
            let cert = (*ctx).cert;
            EVP_PKEY_free((*cert).dh_tmp.cast());
            (*cert).dh_tmp = dhpkey;
        }
        1
    })
}

/// `int SSL_CTX_set_default_verify_dir(SSL_CTX *ctx)` — `ssl/ssl_lib.c:5551-5567`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_default_verify_dir(ctx: *mut SslCtx) -> c_int {
    guard_ffi(0, || {
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `ctx` and its store are live; the method is a process-lifetime static.
        let lookup = unsafe { X509_STORE_add_lookup((*ctx).cert_store, X509_LOOKUP_hash_dir()) };
        if lookup.is_null() {
            return 0;
        }
        // The authority ignores a missing directory.
        // SAFETY: thread-local error queue only.
        ERR_set_mark();
        // SAFETY: `lookup` is live; NULL name is the default-path arm.
        unsafe {
            X509_LOOKUP_ctrl(
                lookup,
                X509_L_ADD_DIR,
                ptr::null(),
                X509_FILETYPE_DEFAULT,
                ptr::null_mut(),
            )
        };
        // SAFETY: thread-local error queue only.
        ERR_pop_to_mark();
        1
    })
}

/// `int SSL_CTX_set_default_verify_file(SSL_CTX *ctx)` — `ssl/ssl_lib.c:5569-5586`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_default_verify_file(ctx: *mut SslCtx) -> c_int {
    guard_ffi(0, || {
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `ctx` and its store are live.
        let lookup = unsafe { X509_STORE_add_lookup((*ctx).cert_store, X509_LOOKUP_file()) };
        if lookup.is_null() {
            return 0;
        }
        // SAFETY: thread-local error queue only.
        ERR_set_mark();
        // SAFETY: `ctx` is live; `lookup` is live; NULL name is the default-path arm.
        unsafe {
            X509_LOOKUP_ctrl_ex(
                lookup,
                X509_L_FILE_LOAD,
                ptr::null(),
                X509_FILETYPE_DEFAULT as c_long,
                ptr::null_mut(),
                (*ctx).libctx,
                (*ctx).propq,
            )
        };
        // SAFETY: thread-local error queue only.
        ERR_pop_to_mark();
        1
    })
}

/// `int SSL_CTX_set_default_verify_store(SSL_CTX *ctx)` — `ssl/ssl_lib.c:5588-5604`.
///
/// # Safety
/// `ctx` must be a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_default_verify_store(ctx: *mut SslCtx) -> c_int {
    guard_ffi(0, || {
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `ctx` and its store are live.
        let lookup = unsafe { X509_STORE_add_lookup((*ctx).cert_store, X509_LOOKUP_store()) };
        if lookup.is_null() {
            return 0;
        }
        // SAFETY: thread-local error queue only.
        ERR_set_mark();
        // SAFETY: `ctx` is live; `lookup` is live; NULL name is the default-path arm.
        unsafe {
            X509_LOOKUP_ctrl_ex(
                lookup,
                X509_L_ADD_STORE,
                ptr::null(),
                0,
                ptr::null_mut(),
                (*ctx).libctx,
                (*ctx).propq,
            )
        };
        // SAFETY: thread-local error queue only.
        ERR_pop_to_mark();
        1
    })
}

/// `int SSL_copy_session_id(SSL *t, const SSL *f)` — `ssl/ssl_lib.c:2029-2062`.
///
/// The crate copies the session-id context and the certificate security attributes rather than
/// sharing the certificate pointer: `SSL_cert_free` in this reduced model releases the leaf, so a
/// shared pointer would be freed twice. The observable (`SSL_get_certificate`, the sid context) is
/// the authority's for the fresh-connection pair the court drives; the method-changed arm's
/// `ssl_deinit`/`ssl_init` is the record layer's and is recorded in `src/ssl/mod.rs`.
///
/// # Safety
/// `t` and `f` must be live connections.
#[no_mangle]
pub unsafe extern "C" fn SSL_copy_session_id(t: *mut Ssl, f: *const Ssl) -> c_int {
    guard_ffi(0, || {
        if t.is_null() || f.is_null() {
            return 0;
        }
        // SAFETY: both pointers are live per the caller's contract.
        if unsafe { SSL_set_session(t, SSL_get_session(f)) } == 0 {
            return 0;
        }
        // SAFETY: `t` and `f` are live.
        unsafe {
            if (*t).method != (*f).method {
                (*t).method = (*f).method;
            }
            cert_copy_security((*t).cert, (*f).cert);
            let len = (*f).sid_ctx_length;
            if SSL_set_session_id_context(t, (*f).sid_ctx.as_ptr(), len) == 0 {
                return 0;
            }
        }
        1
    })
}

/// `EVP_PKEY *SSL_get0_peer_rpk(const SSL *s)` — `ssl/ssl_lib.c:8210-8217`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_peer_rpk(s: *const Ssl) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        if s.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `s` is live per the caller's contract.
        let session = unsafe { (*s).session };
        if session.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `session` is live.
        unsafe { (*session).peer_rpk }
    })
}

// -------------------------------------------------------------------------------------------
// 14.7b — the DANE record surface and the RPK-expected setter (`ssl/ssl_lib.c`)
//
// The twelve DANE/RPK exports 14.1 withheld, and the internal helpers `ssl_lib.c`'s own body
// reaches: `dane_ctx_enable`/`dane_ctx_final`, the `dane_mds` table, `tlsa_free`/`dane_final`,
// `ssl_dane_dup`, `dane_mtype_set`, `tlsa_md_get` and `dane_tlsa_add`. The public `SSL_DANE`
// record itself is `crate::x509::dane`'s, modelled from `include/internal/dane.h`, because
// Phase 11's verification engine shares it; this section is the `ssl_lib.c` half that fills and
// reads it. `SSL_dane_enable` reaches the `SSL_CTRL_SET_TLSEXT_HOSTNAME` arm of `ssl3_ctrl`
// (`src/ssl/s3_lib.rs`) through `SSL_ctrl`.
// -------------------------------------------------------------------------------------------

/// `dane_mds[]` — `ssl/ssl_lib.c:102-110`, the `(mtype, ord, nid)` default digest table.
const DANE_MDS: [(u8, u8, c_int); 3] = [
    (DANETLS_MATCHING_FULL, 0, NID_undef),
    (DANETLS_MATCHING_2256, 1, NID_sha256),
    (DANETLS_MATCHING_2512, 2, NID_sha512),
];

/// `EVP_get_digestbynid(nid)` — the `evp.h` macro `EVP_get_digestbyname(OBJ_nid2sn(nid))`.
///
/// # Safety
/// `nid` is a digest NID; the resolved object is a process-lifetime static.
unsafe fn evp_get_digestbynid(nid: c_int) -> *const EvpMd {
    // SAFETY: both calls are the macro's own expansion; `OBJ_nid2sn` answers a static string or
    // NULL, and `EVP_get_digestbyname` tolerates the NULL name.
    unsafe { EVP_get_digestbyname(OBJ_nid2sn(nid)) }
}

/// `static int dane_ctx_enable(struct dane_ctx_st *dctx)` — `ssl/ssl_lib.c:112-147`.
///
/// # Safety
/// `dctx` must be a live `DaneCtx`.
unsafe fn dane_ctx_enable(dctx: *mut DaneCtx) -> c_int {
    // SAFETY: `dctx` is live per the caller's contract.
    if !unsafe { (*dctx).mdevp }.is_null() {
        return 1;
    }
    let mdmax = DANETLS_MATCHING_LAST;
    let n = mdmax as usize + 1;
    // SAFETY: two fresh `CRYPTO_calloc` blocks of `n` pointer-sized slots / `n` bytes.
    let mdevp =
        CRYPTO_calloc(n, core::mem::size_of::<*const EvpMd>(), FILE, 123).cast::<*const EvpMd>();
    let mdord = CRYPTO_calloc(n, 1, FILE, 124).cast::<u8>();
    if mdord.is_null() || mdevp.is_null() {
        // SAFETY: each pointer is NULL or an owned `CRYPTO_calloc` block.
        unsafe {
            CRYPTO_free(mdord.cast(), FILE, 127);
            CRYPTO_free(mdevp.cast(), FILE, 128);
        }
        return 0;
    }
    let mut i = 0usize;
    while i < DANE_MDS.len() {
        let (mtype, ord, nid) = DANE_MDS[i];
        if nid != NID_undef {
            // SAFETY: `nid` is a table NID.
            let md = unsafe { evp_get_digestbynid(nid) };
            if !md.is_null() {
                // SAFETY: `mdevp`/`mdord` have `n` slots and `mtype <= mdmax < n`.
                unsafe {
                    *mdevp.add(mtype as usize) = md;
                    *mdord.add(mtype as usize) = ord;
                }
            }
        }
        i += 1;
    }
    // SAFETY: `dctx` is live.
    unsafe {
        (*dctx).mdevp = mdevp;
        (*dctx).mdord = mdord;
        (*dctx).mdmax = mdmax;
    }
    1
}

/// `static void dane_ctx_final(struct dane_ctx_st *dctx)` — `ssl/ssl_lib.c:149-157`.
///
/// # Safety
/// `dctx` must be a live `DaneCtx`.
unsafe fn dane_ctx_final(dctx: *mut DaneCtx) {
    // SAFETY: `dctx` is live per the caller's contract; each pointer is NULL or owned.
    unsafe {
        CRYPTO_free((*dctx).mdevp.cast(), FILE, 151);
        (*dctx).mdevp = ptr::null_mut();
        CRYPTO_free((*dctx).mdord.cast(), FILE, 154);
        (*dctx).mdord = ptr::null_mut();
        (*dctx).mdmax = 0;
    }
}

/// `static void tlsa_free(danetls_record *t)` — `ssl/ssl_lib.c:159-166`.
///
/// # Safety
/// `t` must be NULL or an owned `danetls_record`.
unsafe extern "C" fn tlsa_free(t: *mut c_void) {
    let t = t.cast::<DanetlsRecord>();
    if t.is_null() {
        return;
    }
    // SAFETY: `t` is a live owned record per the caller's contract.
    unsafe {
        CRYPTO_free((*t).data.cast(), FILE, 163);
        EVP_PKEY_free((*t).spki);
        CRYPTO_free(t.cast(), FILE, 165);
    }
}

/// `static void dane_final(SSL_DANE *dane)` — `ssl/ssl_lib.c:168-181`.
///
/// # Safety
/// `dane` must be a live `SslDane`.
unsafe fn dane_final(dane: *mut SslDane) {
    // SAFETY: `dane` is live per the caller's contract; each field is NULL or owned.
    unsafe {
        OPENSSL_sk_pop_free((*dane).trecs, Some(tlsa_free));
        (*dane).trecs = ptr::null_mut();
        OSSL_STACK_OF_X509_free((*dane).certs);
        (*dane).certs = ptr::null_mut();
        X509_free((*dane).mcert);
        (*dane).mcert = ptr::null_mut();
        (*dane).mtlsa = ptr::null_mut();
        (*dane).mdpth = -1;
        (*dane).pdpth = -1;
    }
}

/// `static int ssl_dane_dup(SSL_CONNECTION *to, SSL_CONNECTION *from)` — `ssl/ssl_lib.c:186-214`.
///
/// # Safety
/// `to` and `from` must be live connections.
pub(crate) unsafe fn ssl_dane_dup(to: *mut Ssl, from: *const Ssl) -> c_int {
    // SAFETY: `from` is live per the caller's contract.
    if !unsafe { danetls_enabled(ptr::addr_of!((*from).dane) as *mut SslDane) } {
        return 1;
    }
    // SAFETY: both are live; `trecs` is a live stack because `DANETLS_ENABLED` held.
    let num = unsafe { OPENSSL_sk_num((*from).dane.trecs) };
    // SAFETY: `to` is live.
    unsafe { dane_final(ptr::addr_of_mut!((*to).dane)) };
    // SAFETY: `to` is live; its context is a live context.
    let ctx = unsafe { (*to).ctx };
    // SAFETY: `to` is live and its `dane` was just finalised.
    unsafe {
        (*to).dane.flags = (*from).dane.flags;
        (*to).dane.dctx = ptr::addr_of_mut!((*ctx).dane);
        (*to).dane.trecs = OPENSSL_sk_new_reserve(None, num);
    }
    // SAFETY: `trecs` was just assigned.
    if unsafe { (*to).dane.trecs }.is_null() {
        // SAFETY: thread-local error state.
        unsafe { raise_ssl(ERR_R_CRYPTO_LIB, 201) };
        return 0;
    }
    let mut i = 0;
    while i < num {
        // SAFETY: `i` is in range of `from`'s record stack.
        let t = unsafe { OPENSSL_sk_value((*from).dane.trecs, i) }.cast::<DanetlsRecord>();
        // SAFETY: `t` is a live record; `to`/`from` are live.
        let r = unsafe {
            dane_tlsa_add(
                ptr::addr_of_mut!((*to).dane),
                (*t).usage,
                (*t).selector,
                (*t).mtype,
                (*t).data,
                (*t).dlen,
            )
        };
        if r <= 0 {
            return 0;
        }
        i += 1;
    }
    1
}

/// `static int dane_mtype_set(struct dane_ctx_st *dctx, const EVP_MD *md, uint8_t mtype,
/// uint8_t ord)` — `ssl/ssl_lib.c:216-255`.
///
/// # Safety
/// `dctx` must be a live `DaneCtx`; `md` must be NULL or a live digest.
unsafe fn dane_mtype_set(dctx: *mut DaneCtx, md: *const EvpMd, mtype: u8, ord: u8) -> c_int {
    if mtype == DANETLS_MATCHING_FULL && !md.is_null() {
        // SAFETY: thread-local error state.
        unsafe { raise_ssl(SSL_R_DANE_CANNOT_OVERRIDE_MTYPE_FULL, 222) };
        return 0;
    }
    // SAFETY: `dctx` is live per the caller's contract.
    if mtype > unsafe { (*dctx).mdmax } {
        let n = mtype as usize + 1;
        // SAFETY: `dctx->mdevp` is NULL or an owned block being grown to `n` slots.
        let mdevp = unsafe {
            CRYPTO_realloc_array(
                (*dctx).mdevp.cast(),
                n,
                core::mem::size_of::<*const EvpMd>(),
                FILE,
                231,
            )
        }
        .cast::<*const EvpMd>();
        if mdevp.is_null() {
            return -1;
        }
        // SAFETY: `dctx` is live.
        unsafe { (*dctx).mdevp = mdevp };
        // SAFETY: `dctx->mdord` is NULL or an owned block being grown to `n` bytes.
        let mdord =
            unsafe { CRYPTO_realloc_array((*dctx).mdord.cast(), n, 1, FILE, 236) }.cast::<u8>();
        if mdord.is_null() {
            return -1;
        }
        // SAFETY: `dctx` is live.
        unsafe { (*dctx).mdord = mdord };
        // Zero-fill any gaps.
        // SAFETY: `dctx` is live per the caller's contract.
        let mut i = unsafe { (*dctx).mdmax } as usize + 1;
        while i < mtype as usize {
            // SAFETY: `mdevp`/`mdord` have `n` slots and `i < mtype < n`.
            unsafe {
                *mdevp.add(i) = ptr::null();
                *mdord.add(i) = 0;
            }
            i += 1;
        }
        // SAFETY: `dctx` is live.
        unsafe { (*dctx).mdmax = mtype };
    }
    // SAFETY: `dctx` is live and both tables have at least `mtype+1` slots after the growth above.
    unsafe {
        *(*dctx).mdevp.add(mtype as usize) = md;
        *(*dctx).mdord.add(mtype as usize) = if md.is_null() { 0 } else { ord };
    }
    1
}

/// `static const EVP_MD *tlsa_md_get(SSL_DANE *dane, uint8_t mtype)` — `ssl/ssl_lib.c:257-262`.
///
/// # Safety
/// `dane` and its `dctx` must be live.
unsafe fn tlsa_md_get(dane: *const SslDane, mtype: u8) -> *const EvpMd {
    // SAFETY: `dane` and its `dctx` are live per the caller's contract.
    unsafe {
        let dctx = (*dane).dctx;
        if mtype > (*dctx).mdmax {
            return ptr::null();
        }
        *(*dctx).mdevp.add(mtype as usize)
    }
}

/// `static int dane_tlsa_add(SSL_DANE *dane, uint8_t usage, uint8_t selector, uint8_t mtype,
/// const unsigned char *data, size_t dlen)` — `ssl/ssl_lib.c:264-443`.
///
/// # Safety
/// `dane` must be a live `SslDane`; `data` must be readable for `dlen` bytes or NULL.
unsafe fn dane_tlsa_add(
    dane: *mut SslDane,
    usage: u8,
    selector: u8,
    mtype: u8,
    data: *const u8,
    dlen: usize,
) -> c_int {
    // SAFETY: `dane` is live per the caller's contract.
    if unsafe { (*dane).trecs }.is_null() {
        // SAFETY: thread-local error state.
        unsafe { raise_ssl(SSL_R_DANE_NOT_ENABLED, 277) };
        return -1;
    }
    if dlen > c_int::MAX as usize {
        // SAFETY: thread-local error state.
        unsafe { raise_ssl(SSL_R_DANE_TLSA_BAD_DATA_LENGTH, 282) };
        return 0;
    }
    let ilen = dlen as c_int;
    if usage > DANETLS_USAGE_LAST {
        // SAFETY: thread-local error state.
        unsafe { raise_ssl(SSL_R_DANE_TLSA_BAD_CERTIFICATE_USAGE, 287) };
        return 0;
    }
    if selector > DANETLS_SELECTOR_LAST {
        // SAFETY: thread-local error state.
        unsafe { raise_ssl(SSL_R_DANE_TLSA_BAD_SELECTOR, 292) };
        return 0;
    }
    let mut md: *const EvpMd = ptr::null();
    if mtype != DANETLS_MATCHING_FULL {
        // SAFETY: `dane` is live.
        md = unsafe { tlsa_md_get(dane, mtype) };
        if md.is_null() {
            // SAFETY: thread-local error state.
            unsafe { raise_ssl(SSL_R_DANE_TLSA_BAD_MATCHING_TYPE, 299) };
            return 0;
        }
    }
    if !md.is_null() {
        // SAFETY: `md` is a live digest.
        let mdsize = unsafe { EVP_MD_get_size(md) };
        if mdsize <= 0 || dlen != mdsize as usize {
            // SAFETY: thread-local error state.
            unsafe { raise_ssl(SSL_R_DANE_TLSA_BAD_DIGEST_LENGTH, 307) };
            return 0;
        }
    }
    if data.is_null() {
        // SAFETY: thread-local error state.
        unsafe { raise_ssl(SSL_R_DANE_TLSA_NULL_DATA, 312) };
        return 0;
    }
    // SAFETY: a fresh zeroed `danetls_record`.
    let t = CRYPTO_zalloc(core::mem::size_of::<DanetlsRecord>(), FILE, 316).cast::<DanetlsRecord>();
    if t.is_null() {
        return -1;
    }
    // SAFETY: `t` is a fresh record; `data` is readable for `dlen` bytes.
    unsafe {
        (*t).usage = usage;
        (*t).selector = selector;
        (*t).mtype = mtype;
        (*t).data = CRYPTO_malloc(dlen, FILE, 322).cast::<u8>();
    }
    // SAFETY: `t->data` was just assigned.
    if unsafe { (*t).data }.is_null() {
        // SAFETY: `t` is an owned record.
        unsafe { tlsa_free(t.cast()) };
        return -1;
    }
    // SAFETY: `t->data` has `dlen` bytes; `data` is readable for `dlen`.
    unsafe {
        ptr::copy_nonoverlapping(data, (*t).data, dlen);
        (*t).dlen = dlen;
    }

    // Validate and cache a full certificate or public key.
    if mtype == DANETLS_MATCHING_FULL {
        let mut cert: *mut X509 = ptr::null_mut();
        let mut pkey: *mut EvpPkey = ptr::null_mut();
        let mut p = data;
        match selector {
            DANETLS_SELECTOR_CERT => {
                // SAFETY: `data` is readable for `ilen` bytes; `p` is the cursor `d2i_X509` advances.
                let decoded = unsafe { d2i_X509(&mut cert, &mut p, ilen as c_long) };
                if decoded.is_null() || p < data || dlen != p as usize - data as usize {
                    // SAFETY: `cert` is NULL or an owned certificate.
                    unsafe { X509_free(cert) };
                    // SAFETY: `t` is an owned record.
                    unsafe { tlsa_free(t.cast()) };
                    // SAFETY: thread-local error state.
                    unsafe { raise_ssl(SSL_R_DANE_TLSA_BAD_CERTIFICATE, 341) };
                    return 0;
                }
                // SAFETY: `cert` is a live certificate.
                if unsafe { X509_get0_pubkey(cert) }.is_null() {
                    // SAFETY: `cert` is an owned certificate; `t` an owned record.
                    unsafe {
                        X509_free(cert);
                        tlsa_free(t.cast());
                    }
                    // SAFETY: thread-local error state.
                    unsafe { raise_ssl(SSL_R_DANE_TLSA_BAD_CERTIFICATE, 347) };
                    return 0;
                }
                if (danetls_usage_bit(usage as u32) & DANETLS_TA_MASK) == 0 {
                    // SAFETY: `cert` is an owned certificate no longer needed.
                    unsafe { X509_free(cert) };
                } else {
                    // SAFETY: `dane` is live; `cert` is an owned certificate.
                    let pushed = unsafe {
                        if (*dane).certs.is_null() {
                            (*dane).certs = OPENSSL_sk_new_null();
                        }
                        !(*dane).certs.is_null() && OPENSSL_sk_push((*dane).certs, cert.cast()) != 0
                    };
                    if !pushed {
                        // SAFETY: thread-local error state.
                        unsafe { raise_ssl(ERR_R_CRYPTO_LIB, 376) };
                        // SAFETY: `cert` an owned certificate; `t` an owned record.
                        unsafe {
                            X509_free(cert);
                            tlsa_free(t.cast());
                        }
                        return -1;
                    }
                }
            }
            DANETLS_SELECTOR_SPKI => {
                // SAFETY: `data` is readable for `ilen` bytes; `p` is the cursor `d2i_PUBKEY` advances.
                let decoded = unsafe { d2i_PUBKEY(&mut pkey, &mut p, ilen as c_long) };
                if decoded.is_null() || p < data || dlen != p as usize - data as usize {
                    // SAFETY: `pkey` is NULL or an owned key.
                    unsafe { EVP_PKEY_free(pkey) };
                    // SAFETY: `t` is an owned record.
                    unsafe { tlsa_free(t.cast()) };
                    // SAFETY: thread-local error state.
                    unsafe { raise_ssl(SSL_R_DANE_TLSA_BAD_PUBLIC_KEY, 387) };
                    return 0;
                }
                if usage == DANETLS_USAGE_DANE_TA {
                    // SAFETY: `t` is a live record; `pkey` is an owned key now owned by it.
                    unsafe { (*t).spki = pkey };
                } else {
                    // SAFETY: `pkey` is an owned key no longer needed.
                    unsafe { EVP_PKEY_free(pkey) };
                }
            }
            _ => {}
        }
    }

    // Find the insertion point, sorted descending by usage, selector and digest ordinal.
    // SAFETY: `dane` is live; `trecs` is live.
    let num = unsafe { OPENSSL_sk_num((*dane).trecs) };
    let mut i = 0;
    while i < num {
        // SAFETY: `i` is in range.
        let rec = unsafe { OPENSSL_sk_value((*dane).trecs, i) }.cast::<DanetlsRecord>();
        // SAFETY: `rec` is a live record; `dane->dctx` is live.
        unsafe {
            if (*rec).usage > usage {
                i += 1;
                continue;
            }
            if (*rec).usage < usage {
                break;
            }
            if (*rec).selector > selector {
                i += 1;
                continue;
            }
            if (*rec).selector < selector {
                break;
            }
            let dctx = (*dane).dctx;
            if *(*dctx).mdord.add((*rec).mtype as usize) > *(*dctx).mdord.add(mtype as usize) {
                i += 1;
                continue;
            }
            break;
        }
    }
    // SAFETY: `dane->trecs` is live; `t` is an owned record whose ownership moves into the stack.
    if unsafe { OPENSSL_sk_insert((*dane).trecs, t.cast(), i) } == 0 {
        // SAFETY: `t` is an owned record.
        unsafe { tlsa_free(t.cast()) };
        // SAFETY: thread-local error state.
        unsafe { raise_ssl(ERR_R_CRYPTO_LIB, 437) };
        return -1;
    }
    // SAFETY: `dane` is live.
    unsafe { (*dane).umask |= danetls_usage_bit(usage as u32) };
    1
}

/// `int SSL_CTX_dane_enable(SSL_CTX *ctx)` — `ssl/ssl_lib.c:1209-1212`.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_dane_enable(ctx: *mut SslCtx) -> c_int {
    guard_ffi(0, || {
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `ctx` is non-NULL and live.
        unsafe { dane_ctx_enable(ptr::addr_of_mut!((*ctx).dane)) }
    })
}

/// `unsigned long SSL_CTX_dane_set_flags(SSL_CTX *ctx, unsigned long flags)` —
/// `ssl/ssl_lib.c:1214-1220`.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_dane_set_flags(ctx: *mut SslCtx, flags: c_ulong) -> c_ulong {
    guard_ffi(0, || {
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `ctx` is non-NULL and live.
        let d = unsafe { &mut (*ctx).dane };
        let orig = d.flags;
        d.flags |= flags;
        orig
    })
}

/// `unsigned long SSL_CTX_dane_clear_flags(SSL_CTX *ctx, unsigned long flags)` —
/// `ssl/ssl_lib.c:1222-1228`.
///
/// # Safety
/// `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_dane_clear_flags(ctx: *mut SslCtx, flags: c_ulong) -> c_ulong {
    guard_ffi(0, || {
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `ctx` is non-NULL and live.
        let d = unsafe { &mut (*ctx).dane };
        let orig = d.flags;
        d.flags &= !flags;
        orig
    })
}

/// `SSL_set_tlsext_host_name(s, name)` — the `ssl.h:1893` macro, whose body is
/// `SSL_ctrl(s, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, (char *)name)`.
///
/// # Safety
/// `s` must be a live connection; `name` must be NULL or NUL-terminated.
unsafe fn ssl_set_tlsext_host_name(s: *mut Ssl, name: *const c_char) -> c_long {
    // SAFETY: forwarded per the caller's contract.
    unsafe {
        SSL_ctrl(
            s,
            SSL_CTRL_SET_TLSEXT_HOSTNAME,
            TLSEXT_NAMETYPE_HOST_NAME as c_long,
            name.cast_mut().cast(),
        )
    }
}

/// `int SSL_dane_enable(SSL *s, const char *basedomain)` — `ssl/ssl_lib.c:1230-1276`.
///
/// # Safety
/// `s` must be NULL or a live connection; `basedomain` must be NULL or NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn SSL_dane_enable(s: *mut Ssl, basedomain: *const c_char) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live per the caller's contract; `basedomain` is NULL or NUL-terminated.
        unsafe {
            let ctx = (*s).ctx;
            if (*ctx).dane.mdmax == 0 {
                raise_ssl(SSL_R_CONTEXT_NOT_DANE_ENABLED, 1240);
                return 0;
            }
            if !(*s).dane.trecs.is_null() {
                raise_ssl(SSL_R_DANE_ALREADY_ENABLED, 1244);
                return 0;
            }
            if (*s).ext_hostname.is_null() && ssl_set_tlsext_host_name(s, basedomain) == 0 {
                raise_ssl(SSL_R_ERROR_SETTING_TLSA_BASE_DOMAIN, 1255);
                return -1;
            }
            if X509_VERIFY_PARAM_set1_host((*s).param, basedomain, 0) == 0 {
                raise_ssl(SSL_R_ERROR_SETTING_TLSA_BASE_DOMAIN, 1262);
                return -1;
            }
            (*s).dane.mdpth = -1;
            (*s).dane.pdpth = -1;
            (*s).dane.dctx = ptr::addr_of_mut!((*ctx).dane);
            (*s).dane.trecs = OPENSSL_sk_new_null();
            if (*s).dane.trecs.is_null() {
                raise_ssl(ERR_R_CRYPTO_LIB, 1272);
                return -1;
            }
        }
        1
    })
}

/// `unsigned long SSL_dane_set_flags(SSL *ssl, unsigned long flags)` — `ssl/ssl_lib.c:1278-1290`.
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_dane_set_flags(ssl: *mut Ssl, flags: c_ulong) -> c_ulong {
    guard_ffi(0, || {
        if ssl.is_null() {
            return 0;
        }
        // SAFETY: `ssl` is non-NULL and live.
        let d = unsafe { &mut (*ssl).dane };
        let orig = d.flags;
        d.flags |= flags;
        orig
    })
}

/// `unsigned long SSL_dane_clear_flags(SSL *ssl, unsigned long flags)` — `ssl/ssl_lib.c:1292-1304`.
///
/// # Safety
/// `ssl` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_dane_clear_flags(ssl: *mut Ssl, flags: c_ulong) -> c_ulong {
    guard_ffi(0, || {
        if ssl.is_null() {
            return 0;
        }
        // SAFETY: `ssl` is non-NULL and live.
        let d = unsafe { &mut (*ssl).dane };
        let orig = d.flags;
        d.flags &= !flags;
        orig
    })
}

/// `int SSL_get0_dane_authority(SSL *s, X509 **mcert, EVP_PKEY **mspki)` —
/// `ssl/ssl_lib.c:1306-1325`.
///
/// # Safety
/// `s` must be NULL or a live connection; `mcert`/`mspki` NULL or writable slots.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_dane_authority(
    s: *mut Ssl,
    mcert: *mut *mut X509,
    mspki: *mut *mut EvpPkey,
) -> c_int {
    guard_ffi(-1, || {
        if s.is_null() {
            return -1;
        }
        // SAFETY: `s` is live per the caller's contract; the out-slots are NULL or writable.
        unsafe {
            let dane = ptr::addr_of_mut!((*s).dane);
            if !danetls_enabled(dane) || (*s).verify_result != X509_V_OK {
                return -1;
            }
            if !(*dane).mtlsa.is_null() {
                if !mcert.is_null() {
                    *mcert = (*dane).mcert;
                }
                if !mspki.is_null() {
                    *mspki = if (*dane).mcert.is_null() {
                        (*(*dane).mtlsa).spki
                    } else {
                        ptr::null_mut()
                    };
                }
            }
            (*dane).mdpth
        }
    })
}

/// `int SSL_get0_dane_tlsa(SSL *s, uint8_t *usage, uint8_t *selector, uint8_t *mtype,
/// const unsigned char **data, size_t *dlen)` — `ssl/ssl_lib.c:1327-1353`.
///
/// # Safety
/// `s` must be NULL or a live connection; every out-pointer NULL or a writable slot.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_dane_tlsa(
    s: *mut Ssl,
    usage: *mut u8,
    selector: *mut u8,
    mtype: *mut u8,
    data: *mut *const u8,
    dlen: *mut usize,
) -> c_int {
    guard_ffi(-1, || {
        if s.is_null() {
            return -1;
        }
        // SAFETY: `s` is live; every out-pointer is NULL or writable per the contract.
        unsafe {
            let dane = ptr::addr_of_mut!((*s).dane);
            if !danetls_enabled(dane) || (*s).verify_result != X509_V_OK {
                return -1;
            }
            if !(*dane).mtlsa.is_null() {
                let t = (*dane).mtlsa;
                if !usage.is_null() {
                    *usage = (*t).usage;
                }
                if !selector.is_null() {
                    *selector = (*t).selector;
                }
                if !mtype.is_null() {
                    *mtype = (*t).mtype;
                }
                if !data.is_null() {
                    *data = (*t).data;
                }
                if !dlen.is_null() {
                    *dlen = (*t).dlen;
                }
            }
            (*dane).mdpth
        }
    })
}

/// `SSL_DANE *SSL_get0_dane(SSL *s)` — `ssl/ssl_lib.c:1355-1363`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get0_dane(s: *mut Ssl) -> *mut SslDane {
    guard_ffi(ptr::null_mut(), || {
        if s.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `s` is non-NULL and live.
        unsafe { ptr::addr_of_mut!((*s).dane) }
    })
}

/// `int SSL_dane_tlsa_add(SSL *s, uint8_t usage, uint8_t selector, uint8_t mtype,
/// const unsigned char *data, size_t dlen)` — `ssl/ssl_lib.c:1365-1374`.
///
/// # Safety
/// `s` must be NULL or a live connection; `data` readable for `dlen` bytes or NULL.
#[no_mangle]
pub unsafe extern "C" fn SSL_dane_tlsa_add(
    s: *mut Ssl,
    usage: u8,
    selector: u8,
    mtype: u8,
    data: *const u8,
    dlen: usize,
) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live; `data` readable for `dlen` bytes or NULL per the contract.
        unsafe {
            dane_tlsa_add(
                ptr::addr_of_mut!((*s).dane),
                usage,
                selector,
                mtype,
                data,
                dlen,
            )
        }
    })
}

/// `int SSL_CTX_dane_mtype_set(SSL_CTX *ctx, const EVP_MD *md, uint8_t mtype, uint8_t ord)` —
/// `ssl/ssl_lib.c:1376-1380`.
///
/// # Safety
/// `ctx` must be NULL or a live context; `md` NULL or a live digest.
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_dane_mtype_set(
    ctx: *mut SslCtx,
    md: *const EvpMd,
    mtype: u8,
    ord: u8,
) -> c_int {
    guard_ffi(0, || {
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: `ctx` is non-NULL and live; `md` NULL or live per the contract.
        unsafe { dane_mtype_set(ptr::addr_of_mut!((*ctx).dane), md, mtype, ord) }
    })
}

/// `int SSL_add_expected_rpk(SSL *s, EVP_PKEY *rpk)` — `ssl/ssl_lib.c:8190-8208`.
///
/// # Safety
/// `s` must be NULL or a live connection; `rpk` must be a live key.
#[no_mangle]
pub unsafe extern "C" fn SSL_add_expected_rpk(s: *mut Ssl, rpk: *mut EvpPkey) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            let dane = SSL_get0_dane(s);
            if dane.is_null() || (*dane).dctx.is_null() {
                return 0;
            }
            let mut data: *mut u8 = ptr::null_mut();
            let ret = i2d_PUBKEY(rpk, &mut data);
            if ret <= 0 {
                return 0;
            }
            let ok = SSL_dane_tlsa_add(
                s,
                DANETLS_USAGE_DANE_EE,
                DANETLS_SELECTOR_SPKI,
                DANETLS_MATCHING_FULL,
                data,
                ret as usize,
            ) > 0;
            CRYPTO_free(data.cast(), FILE, 8206);
            c_int::from(ok)
        }
    })
}

/// `SSL *SSL_dup(SSL *s)` — `ssl/ssl_lib.c:5131-5266`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_dup(s: *mut Ssl) -> *mut Ssl {
    guard_ffi(ptr::null_mut(), || {
        if s.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `s` is live per the caller's contract; every pointer this body uses is derived
        // from it or from the fresh `SSL_new` it allocates.
        unsafe {
            // If we are not quiescent, just up_ref.
            if SSL_in_init(s) == 0 || SSL_in_before(s) == 0 {
                up_ref(&(*s).references);
                return s;
            }

            let ret = SSL_new((*s).ctx);
            if ret.is_null() {
                return ptr::null_mut();
            }

            if !(*s).session.is_null() {
                if SSL_copy_session_id(ret, s) == 0 {
                    SSL_free(ret);
                    return ptr::null_mut();
                }
            } else {
                if SSL_set_ssl_method(ret, (*s).method) == 0 {
                    SSL_free(ret);
                    return ptr::null_mut();
                }
                if !(*s).cert.is_null() {
                    cert_free((*ret).cert);
                    (*ret).cert = ssl_cert_dup((*s).cert);
                    if (*ret).cert.is_null() {
                        SSL_free(ret);
                        return ptr::null_mut();
                    }
                }
                if SSL_set_session_id_context(ret, (*s).sid_ctx.as_ptr(), (*s).sid_ctx_length) == 0
                {
                    SSL_free(ret);
                    return ptr::null_mut();
                }
            }

            if ssl_dane_dup(ret, s) == 0 {
                SSL_free(ret);
                return ptr::null_mut();
            }
            (*ret).version = (*s).version;
            (*ret).options = (*s).options;
            (*ret).min_proto_version = (*s).min_proto_version;
            (*ret).max_proto_version = (*s).max_proto_version;
            (*ret).mode = (*s).mode;
            SSL_ctrl(
                ret,
                SSL_CTRL_SET_MAX_CERT_LIST,
                SSL_ctrl(s, SSL_CTRL_GET_MAX_CERT_LIST, 0, ptr::null_mut()),
                ptr::null_mut(),
            );
            SSL_set_read_ahead(ret, SSL_get_read_ahead(s));
            (*ret).msg_callback = (*s).msg_callback;
            (*ret).msg_callback_arg = (*s).msg_callback_arg;
            SSL_set_verify(ret, SSL_get_verify_mode(s), SSL_get_verify_callback(s));
            SSL_set_verify_depth(ret, SSL_get_verify_depth(s));
            (*ret).generate_session_id = (*s).generate_session_id;
            SSL_set_info_callback(ret, SSL_get_info_callback(s));

            if CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_SSL, &mut (*ret).ex_data, &(*s).ex_data) == 0 {
                SSL_free(ret);
                return ptr::null_mut();
            }

            (*ret).server = (*s).server;
            if (*s).handshake_func.is_some() {
                if (*s).server != 0 {
                    SSL_set_accept_state(ret);
                } else {
                    SSL_set_connect_state(ret);
                }
            }
            (*ret).shutdown = (*s).shutdown;
            (*ret).hit = (*s).hit;
            (*ret).default_passwd_callback = (*s).default_passwd_callback;
            (*ret).default_passwd_callback_userdata = (*s).default_passwd_callback_userdata;
            X509_VERIFY_PARAM_inherit((*ret).param, (*s).param);

            if !(*s).cipher_list.is_null() {
                (*ret).cipher_list = OPENSSL_sk_dup((*s).cipher_list);
                if (*ret).cipher_list.is_null() {
                    SSL_free(ret);
                    return ptr::null_mut();
                }
            }
            if !(*s).cipher_list_by_id.is_null() {
                (*ret).cipher_list_by_id = OPENSSL_sk_dup((*s).cipher_list_by_id);
                if (*ret).cipher_list_by_id.is_null() {
                    SSL_free(ret);
                    return ptr::null_mut();
                }
            }

            if dup_ca_names(&mut (*ret).ca_names, (*s).ca_names) == 0
                || dup_ca_names(&mut (*ret).client_ca_names, (*s).client_ca_names) == 0
            {
                SSL_free(ret);
                return ptr::null_mut();
            }

            if !(*s).server_cert_type.is_null() {
                CRYPTO_free((*ret).server_cert_type.cast(), FILE, 5237);
                (*ret).server_cert_type = CRYPTO_memdup(
                    (*s).server_cert_type.cast(),
                    (*s).server_cert_type_len,
                    FILE,
                    5238,
                )
                .cast::<u8>();
                if (*ret).server_cert_type.is_null() {
                    SSL_free(ret);
                    return ptr::null_mut();
                }
                (*ret).server_cert_type_len = (*s).server_cert_type_len;
            }
            if !(*s).client_cert_type.is_null() {
                CRYPTO_free((*ret).client_cert_type.cast(), FILE, 5246);
                (*ret).client_cert_type = CRYPTO_memdup(
                    (*s).client_cert_type.cast(),
                    (*s).client_cert_type_len,
                    FILE,
                    5247,
                )
                .cast::<u8>();
                if (*ret).client_cert_type.is_null() {
                    SSL_free(ret);
                    return ptr::null_mut();
                }
                (*ret).client_cert_type_len = (*s).client_cert_type_len;
            }

            (*ret).ct_validation_callback = (*s).ct_validation_callback;
            (*ret).ct_validation_callback_arg = (*s).ct_validation_callback_arg;
            (*ret).ext_status_type = (*s).ext_status_type;

            ret
        }
    })
}

/// `SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX *ctx)` — `ssl/ssl_lib.c:5492-5543`.
///
/// # Safety
/// `ssl` must be NULL or a live connection; `ctx` must be NULL or a live context.
#[no_mangle]
pub unsafe extern "C" fn SSL_set_SSL_CTX(ssl: *mut Ssl, ctx: *mut SslCtx) -> *mut SslCtx {
    guard_ffi(ptr::null_mut(), || {
        if ssl.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `ssl` is live per the caller's contract; `ctx` NULL or live.
        unsafe {
            if (*ssl).ctx == ctx {
                return (*ssl).ctx;
            }
            let mut ctx = ctx;
            if ctx.is_null() {
                ctx = (*ssl).session_ctx;
            }
            let new_cert = ssl_cert_dup((*ctx).cert);
            if new_cert.is_null() {
                return ptr::null_mut();
            }
            if custom_exts_copy_conn(&mut (*new_cert).custext, &(*(*ssl).cert).custext) == 0
                || custom_exts_copy_flags(&mut (*new_cert).custext, &(*(*ssl).cert).custext) == 0
            {
                cert_free(new_cert);
                return ptr::null_mut();
            }
            if (*ssl).sid_ctx_length as usize > SSL_MAX_SID_CTX_LENGTH {
                cert_free(new_cert);
                return ptr::null_mut();
            }
            if SSL_CTX_up_ref(ctx) == 0 {
                cert_free(new_cert);
                return ptr::null_mut();
            }
            let old = (*ssl).ctx;
            if !old.is_null()
                && (*ssl).sid_ctx_length == (*old).sid_ctx_length
                && memcmp(
                    (*ssl).sid_ctx.as_ptr().cast(),
                    (*old).sid_ctx.as_ptr().cast(),
                    (*ssl).sid_ctx_length as usize,
                ) == 0
            {
                (*ssl).sid_ctx_length = (*ctx).sid_ctx_length;
                (*ssl).sid_ctx = (*ctx).sid_ctx;
            }
            cert_free((*ssl).cert);
            (*ssl).cert = new_cert;
            SSL_CTX_free(old);
            (*ssl).ctx = ctx;
            (*ssl).ctx
        }
    })
}

// -------------------------------------------------------------------------------------------
// 14.7b — the byte-to-cipher-list parser and the supported-cipher filter (`ssl_lib.c`)
// -------------------------------------------------------------------------------------------

/// `int SSL_bytes_to_cipher_list(SSL *s, const unsigned char *bytes, size_t len, int isv2format,
/// STACK_OF(SSL_CIPHER) **sk, STACK_OF(SSL_CIPHER) **scsvs)` — `ssl/ssl_lib.c:7157-7170`.
///
/// # Safety
/// `s` must be NULL or a live connection; `bytes` readable for `len` bytes; `sk`/`scsvs` NULL or
/// writable stack slots.
#[no_mangle]
pub unsafe extern "C" fn SSL_bytes_to_cipher_list(
    s: *mut Ssl,
    bytes: *const u8,
    len: usize,
    isv2format: c_int,
    sk: *mut *mut OpenSslStack,
    scsvs: *mut *mut OpenSslStack,
) -> c_int {
    guard_ffi(0, || {
        if s.is_null() {
            return 0;
        }
        // SAFETY: `bytes` is readable for `len` bytes per the caller's contract.
        let Some(mut pkt) = (unsafe { Packet::buf_init(bytes, len) }) else {
            return 0;
        };
        // SAFETY: `s` is live; `sk`/`scsvs` NULL or writable per the contract.
        unsafe { ossl_bytes_to_cipher_list(s, &mut pkt, sk, scsvs, isv2format, 0) }
    })
}

/// `int ossl_bytes_to_cipher_list(SSL_CONNECTION *s, PACKET *cipher_suites,
/// STACK_OF(SSL_CIPHER) **skp, STACK_OF(SSL_CIPHER) **scsvs_out, int sslv2format, int fatal)` —
/// `ssl/ssl_lib.c:7172-7255`.
///
/// # Safety
/// `s` must be a live connection; `cipher_suites` a live packet; `skp`/`scsvs_out` NULL or writable.
unsafe fn ossl_bytes_to_cipher_list(
    s: *mut Ssl,
    cipher_suites: &mut Packet,
    skp: *mut *mut OpenSslStack,
    scsvs_out: *mut *mut OpenSslStack,
    sslv2format: c_int,
    _fatal: c_int,
) -> c_int {
    let _ = s;
    let n = if sslv2format != 0 {
        SSLV2_CIPHER_LEN
    } else {
        TLS_CIPHER_LEN
    } as usize;

    if cipher_suites.remaining() == 0 {
        // SAFETY: thread-local error state.
        unsafe { raise_ssl(SSL_R_NO_CIPHERS_SPECIFIED, 7190) };
        return 0;
    }
    if !cipher_suites.remaining().is_multiple_of(n) {
        // SAFETY: thread-local error state.
        unsafe { raise_ssl(SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST, 7199) };
        return 0;
    }

    let sk = OPENSSL_sk_new_null();
    let scsvs = OPENSSL_sk_new_null();
    if sk.is_null() || scsvs.is_null() {
        // SAFETY: thread-local error state.
        unsafe { raise_ssl(ERR_R_CRYPTO_LIB, 7209) };
        // SAFETY: each pointer is NULL or an owned stack.
        unsafe {
            OPENSSL_sk_free(sk);
            OPENSSL_sk_free(scsvs);
        }
        return 0;
    }

    // SAFETY: `cipher_suites` is a live packet; each returned span is readable for `n` bytes.
    while let Some(cptr) = unsafe { cipher_suites.get_bytes(n) } {
        // SSLv2-compatible ClientHello SSLv3 ciphers have a zero first byte; true SSLv2 ciphers
        // have a non-zero one and this library supports none of them, so they are skipped.
        // SAFETY: `cptr` is readable for `n` bytes.
        if sslv2format != 0 && unsafe { *cptr } != 0 {
            continue;
        }
        // For SSLv2-compat, ignore the leading 0-byte.
        let cptr = if sslv2format != 0 {
            // SAFETY: `n == 3`, so `cptr.add(1)` is still inside the `n`-byte span.
            unsafe { cptr.add(1) }
        } else {
            cptr
        };
        // SAFETY: `cptr` points at two readable bytes.
        let c = unsafe { ssl3_get_cipher_by_char(cptr) };
        if !c.is_null() {
            // SAFETY: `c` is a live cipher table row.
            let valid = unsafe { (*c).valid } != 0;
            // SAFETY: `sk`/`scsvs` are live stacks; `c` is a row whose lifetime is the process.
            let pushed = unsafe {
                if valid {
                    OPENSSL_sk_push(sk, c.cast())
                } else {
                    OPENSSL_sk_push(scsvs, c.cast())
                }
            };
            if pushed == 0 {
                // SAFETY: thread-local error state.
                unsafe { raise_ssl(ERR_R_CRYPTO_LIB, 7229) };
                // SAFETY: `sk`/`scsvs` are owned stacks.
                unsafe {
                    OPENSSL_sk_free(sk);
                    OPENSSL_sk_free(scsvs);
                }
                return 0;
            }
        }
    }
    if cipher_suites.remaining() > 0 {
        // SAFETY: thread-local error state.
        unsafe { raise_ssl(SSL_R_BAD_LENGTH, 7238) };
        // SAFETY: `sk`/`scsvs` are owned stacks.
        unsafe {
            OPENSSL_sk_free(sk);
            OPENSSL_sk_free(scsvs);
        }
        return 0;
    }

    if !skp.is_null() {
        // SAFETY: `skp` is writable per the contract.
        unsafe { *skp = sk };
    } else {
        // SAFETY: `sk` is an owned stack.
        unsafe { OPENSSL_sk_free(sk) };
    }
    if !scsvs_out.is_null() {
        // SAFETY: `scsvs_out` is writable per the contract.
        unsafe { *scsvs_out = scsvs };
    } else {
        // SAFETY: `scsvs` is an owned stack.
        unsafe { OPENSSL_sk_free(scsvs) };
    }
    1
}

/// `STACK_OF(SSL_CIPHER) *SSL_get1_supported_ciphers(SSL *s)` — `ssl/ssl_lib.c:3276-3304`.
///
/// # Safety
/// `s` must be NULL or a live connection.
#[no_mangle]
pub unsafe extern "C" fn SSL_get1_supported_ciphers(s: *mut Ssl) -> *mut OpenSslStack {
    guard_ffi(ptr::null_mut(), || {
        if s.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `s` is live per the caller's contract.
        unsafe {
            let ciphers = SSL_get_ciphers(s);
            if ciphers.is_null() {
                return ptr::null_mut();
            }
            if ssl_set_client_disabled(s) == 0 {
                return ptr::null_mut();
            }
            let mut sk: *mut OpenSslStack = ptr::null_mut();
            let num = OPENSSL_sk_num(ciphers);
            let mut i = 0;
            while i < num {
                let c = OPENSSL_sk_value(ciphers, i).cast::<SslCipher>();
                if ssl_cipher_disabled(s, c, SSL_SECOP_CIPHER_SUPPORTED, 0) == 0 {
                    if sk.is_null() {
                        sk = OPENSSL_sk_new_null();
                        if sk.is_null() {
                            return ptr::null_mut();
                        }
                    }
                    if OPENSSL_sk_push(sk, c.cast()) == 0 {
                        OPENSSL_sk_free(sk);
                        return ptr::null_mut();
                    }
                }
                i += 1;
            }
            sk
        }
    })
}
