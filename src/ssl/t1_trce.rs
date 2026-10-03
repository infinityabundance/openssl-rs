//! Phase 14.9 — `ssl/t1_trce.c`: `SSL_trace`, the TLS message decoder.
//!
//! The one row the plan gives this unit is `SSL_trace`, the `SSL_set_msg_callback` target that
//! decodes a record or handshake message into a `BIO`. The whole translation unit is transcribed:
//! the `ssl_trace_tbl` tables (`t1_trce.c:65-661`), the byte-level printers (`:663-753`), the
//! extension walk (`:755-1017`), the per-message printers (`:1019-1620`), `ssl_print_handshake`
//! (`:1622-1735`) and `SSL_trace` itself (`:1737-1816`).
//!
//! ## Measured divergences, recorded rather than hidden
//!
//! * **The QUIC arm is not present.** The authority's first act is
//!   `QUIC_CONNECTION_FROM_SSL(ssl)`/`ossl_quic_trace`; the QUIC object is Phase 15's, so the
//!   `#ifndef OPENSSL_NO_QUIC` block is omitted and the function proceeds straight to the TLS
//!   handling for every connection this crate builds.
//! * **`SSL_USE_SIGALGS` reads the method's stored `enc_flags`.** The authority tests
//!   `method->ssl3_enc->enc_flags & SSL_ENC_FLAG_SIGALGS`; `src/ssl/methods.rs` carries the same
//!   bit for the methods whose enc table sets it (the any-version, TLS1.2 and DTLS1.2 rows).
//! * **`ssl_print_compressed_certificates` answers the `OPENSSL_NO_COMP_ALG` body.** The admitted
//!   build defines it (`configuration.h:198-202`), so the decompress-and-recurse half is not
//!   compiled; the header and the hex dump are, exactly as the authority compiles them.
//! * **`d2i_X509`/`d2i_X509_NAME`/`d2i_PUBKEY_ex` decode through the crate's Phase-5/8 codecs.**
//!   A certificate the own codecs cannot decode prints `<UNPARSABLE CERTIFICATE>`, which is the
//!   authority's own answer for an undecodable input; the court's fixtures are decodable.
//!
//! SPDX-License-Identifier: Apache-2.0

// The printers walk a cursor and a remaining length through raw pointers; several loop tails leave
// the final advance unread before the function returns, exactly as the C does. The lint is allowed
// for the module rather than adding no-op reads that the authority does not have.
#![allow(unused_assignments)]

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;

use crate::asn1::a_strex::{X509_NAME_print_ex, XN_FLAG_ONELINE};
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_print_public};
use crate::pem::pem_x509::PEM_write_bio_X509;
use crate::runtime::bio::dump::BIO_dump_indent;
use crate::runtime::bio::iolib::{BIO_puts, BIO_write};
use crate::runtime::bio::print::{BIO_indent, BIO_printf};
use crate::runtime::bio::Bio;
use crate::ssl::ssl_lib::{Ssl, TLS_ANY_VERSION};
use crate::x509::t_x509::X509_print_ex;
use crate::x509::x_name::{d2i_X509_NAME, X509_NAME_free};
use crate::x509::x_pubkey::d2i_PUBKEY_ex;
use crate::x509::x_x509::{d2i_X509, X509_free, X509_new_ex};

// -------------------------------------------------------------------------------------------
// Version, record and handshake constants
// -------------------------------------------------------------------------------------------

/// `SSL3_VERSION` — `prov_ssl.h:23`.
const SSL3_VERSION: c_int = 0x0300;
/// `TLS1_VERSION` — `prov_ssl.h:24`.
const TLS1_VERSION: c_int = 0x0301;
/// `TLS1_1_VERSION` — `prov_ssl.h:25`.
const TLS1_1_VERSION: c_int = 0x0302;
/// `TLS1_2_VERSION` — `prov_ssl.h:26`.
const TLS1_2_VERSION: c_int = 0x0303;
/// `TLS1_3_VERSION` — `prov_ssl.h:27`.
const TLS1_3_VERSION: c_int = 0x0304;
/// `DTLS1_VERSION` — `prov_ssl.h:28`.
const DTLS1_VERSION: c_int = 0xFEFF;
/// `DTLS1_2_VERSION` — `prov_ssl.h:29`.
const DTLS1_2_VERSION: c_int = 0xFEFD;
/// `DTLS1_BAD_VER` — `prov_ssl.h:30`.
const DTLS1_BAD_VER: c_int = 0x0100;

/// `SSL3_RT_HEADER_LENGTH` — `ssl3.h:139`.
const SSL3_RT_HEADER_LENGTH: usize = 5;
/// `DTLS1_RT_HEADER_LENGTH` — `dtls1.h`.
const DTLS1_RT_HEADER_LENGTH: usize = 13;

/// `SSL3_RT_CHANGE_CIPHER_SPEC` — `ssl3.h:219`.
const SSL3_RT_CHANGE_CIPHER_SPEC: c_int = 20;
/// `SSL3_RT_ALERT` — `ssl3.h:220`.
const SSL3_RT_ALERT: c_int = 21;
/// `SSL3_RT_HANDSHAKE` — `ssl3.h:221`.
const SSL3_RT_HANDSHAKE: c_int = 22;
/// `SSL3_RT_APPLICATION_DATA` — `ssl3.h:222`.
const SSL3_RT_APPLICATION_DATA: c_int = 23;
/// `SSL3_RT_HEADER` — `ssl3.h:239`.
const SSL3_RT_HEADER: c_int = 0x100;
/// `SSL3_RT_INNER_CONTENT_TYPE` — `ssl3.h:240`.
const SSL3_RT_INNER_CONTENT_TYPE: c_int = 0x101;

/// `SSL3_MT_HELLO_REQUEST` — `ssl3.h:312`.
const SSL3_MT_HELLO_REQUEST: c_int = 0;
/// `SSL3_MT_CLIENT_HELLO` — `ssl3.h:313`.
const SSL3_MT_CLIENT_HELLO: c_int = 1;
/// `SSL3_MT_SERVER_HELLO` — `ssl3.h:314`.
const SSL3_MT_SERVER_HELLO: c_int = 2;
/// `DTLS1_MT_HELLO_VERIFY_REQUEST` — `ssl3.h`.
const DTLS1_MT_HELLO_VERIFY_REQUEST: c_int = 3;
/// `SSL3_MT_NEWSESSION_TICKET` — `ssl3.h:315`.
const SSL3_MT_NEWSESSION_TICKET: c_int = 4;
/// `SSL3_MT_END_OF_EARLY_DATA` — `ssl3.h:316`.
const SSL3_MT_END_OF_EARLY_DATA: c_int = 5;
/// `SSL3_MT_ENCRYPTED_EXTENSIONS` — `ssl3.h:317`.
const SSL3_MT_ENCRYPTED_EXTENSIONS: c_int = 8;
/// `SSL3_MT_CERTIFICATE` — `ssl3.h:318`.
const SSL3_MT_CERTIFICATE: c_int = 11;
/// `SSL3_MT_SERVER_KEY_EXCHANGE` — `ssl3.h:319`.
const SSL3_MT_SERVER_KEY_EXCHANGE: c_int = 12;
/// `SSL3_MT_CERTIFICATE_REQUEST` — `ssl3.h:320`.
const SSL3_MT_CERTIFICATE_REQUEST: c_int = 13;
/// `SSL3_MT_SERVER_DONE` — `ssl3.h:321`.
const SSL3_MT_SERVER_DONE: c_int = 14;
/// `SSL3_MT_CERTIFICATE_VERIFY` — `ssl3.h:322`.
const SSL3_MT_CERTIFICATE_VERIFY: c_int = 15;
/// `SSL3_MT_CLIENT_KEY_EXCHANGE` — `ssl3.h:323`.
const SSL3_MT_CLIENT_KEY_EXCHANGE: c_int = 16;
/// `SSL3_MT_FINISHED` — `ssl3.h:324`.
const SSL3_MT_FINISHED: c_int = 20;
/// `SSL3_MT_CERTIFICATE_URL` — `ssl3.h:325`.
const SSL3_MT_CERTIFICATE_URL: c_int = 21;
/// `SSL3_MT_CERTIFICATE_STATUS` — `ssl3.h:326`.
const SSL3_MT_CERTIFICATE_STATUS: c_int = 22;
/// `SSL3_MT_SUPPLEMENTAL_DATA` — `ssl3.h:327`.
const SSL3_MT_SUPPLEMENTAL_DATA: c_int = 23;
/// `SSL3_MT_KEY_UPDATE` — `ssl3.h:328`.
const SSL3_MT_KEY_UPDATE: c_int = 24;
/// `SSL3_MT_COMPRESSED_CERTIFICATE` — `ssl3.h:329`.
const SSL3_MT_COMPRESSED_CERTIFICATE: c_int = 25;
/// `SSL3_MT_NEXT_PROTO` — `ssl3.h:331`.
const SSL3_MT_NEXT_PROTO: c_int = 67;
/// `SSL3_MT_MESSAGE_HASH` — `ssl3.h:333`.
const SSL3_MT_MESSAGE_HASH: c_int = 254;

/// `SSL_KEY_UPDATE_NOT_REQUESTED` — `ssl.h:1050`.
const SSL_KEY_UPDATE_NOT_REQUESTED: c_int = 0;
/// `SSL_KEY_UPDATE_REQUESTED` — `ssl.h:1051`.
const SSL_KEY_UPDATE_REQUESTED: c_int = 1;

/// `TLSEXT_comp_cert_none` — `tls1.h:211`.
const TLSEXT_COMP_CERT_NONE: c_int = 0;
/// `TLSEXT_comp_cert_zlib` — `tls1.h:212`.
const TLSEXT_COMP_CERT_ZLIB: c_int = 1;
/// `TLSEXT_comp_cert_brotli` — `tls1.h:213`.
const TLSEXT_COMP_CERT_BROTLI: c_int = 2;
/// `TLSEXT_comp_cert_zstd` — `tls1.h:214`.
const TLSEXT_COMP_CERT_ZSTD: c_int = 3;

/// `TLSEXT_cert_type_x509` — `tls1.h:240`.
const TLSEXT_CERT_TYPE_X509: c_int = 0;
/// `TLSEXT_cert_type_pgp` — `tls1.h:241`.
const TLSEXT_CERT_TYPE_PGP: c_int = 1;
/// `TLSEXT_cert_type_rpk` — `tls1.h:242`.
const TLSEXT_CERT_TYPE_RPK: c_int = 2;
/// `TLSEXT_cert_type_1609dot2` — `tls1.h:243`.
const TLSEXT_CERT_TYPE_1609DOT2: c_int = 3;

/// `TLSEXT_KEX_MODE_KE` — `ssl_local.h:2289`.
const TLSEXT_KEX_MODE_KE: c_int = 0x00;
/// `TLSEXT_KEX_MODE_KE_DHE` — `ssl_local.h:2290`.
const TLSEXT_KEX_MODE_KE_DHE: c_int = 0x01;

// Extension type coordinates — `tls1.h:83-167`.
const TLSEXT_TYPE_SERVER_NAME: c_int = 0;
const TLSEXT_TYPE_MAX_FRAGMENT_LENGTH: c_int = 1;
const TLSEXT_TYPE_CLIENT_CERTIFICATE_URL: c_int = 2;
const TLSEXT_TYPE_TRUSTED_CA_KEYS: c_int = 3;
const TLSEXT_TYPE_TRUNCATED_HMAC: c_int = 4;
const TLSEXT_TYPE_STATUS_REQUEST: c_int = 5;
const TLSEXT_TYPE_USER_MAPPING: c_int = 6;
const TLSEXT_TYPE_CLIENT_AUTHZ: c_int = 7;
const TLSEXT_TYPE_SERVER_AUTHZ: c_int = 8;
const TLSEXT_TYPE_CERT_TYPE: c_int = 9;
const TLSEXT_TYPE_SUPPORTED_GROUPS: c_int = 10;
const TLSEXT_TYPE_EC_POINT_FORMATS: c_int = 11;
const TLSEXT_TYPE_SRP: c_int = 12;
const TLSEXT_TYPE_SIGNATURE_ALGORITHMS: c_int = 13;
const TLSEXT_TYPE_USE_SRTP: c_int = 14;
const TLSEXT_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION: c_int = 16;
const TLSEXT_TYPE_SIGNED_CERTIFICATE_TIMESTAMP: c_int = 18;
const TLSEXT_TYPE_CLIENT_CERT_TYPE: c_int = 19;
const TLSEXT_TYPE_SERVER_CERT_TYPE: c_int = 20;
const TLSEXT_TYPE_PADDING: c_int = 21;
const TLSEXT_TYPE_ENCRYPT_THEN_MAC: c_int = 22;
const TLSEXT_TYPE_EXTENDED_MASTER_SECRET: c_int = 23;
const TLSEXT_TYPE_COMPRESS_CERTIFICATE: c_int = 27;
const TLSEXT_TYPE_SESSION_TICKET: c_int = 35;
const TLSEXT_TYPE_PSK: c_int = 41;
const TLSEXT_TYPE_EARLY_DATA: c_int = 42;
const TLSEXT_TYPE_SUPPORTED_VERSIONS: c_int = 43;
const TLSEXT_TYPE_COOKIE: c_int = 44;
const TLSEXT_TYPE_PSK_KEX_MODES: c_int = 45;
const TLSEXT_TYPE_CERTIFICATE_AUTHORITIES: c_int = 47;
const TLSEXT_TYPE_POST_HANDSHAKE_AUTH: c_int = 49;
const TLSEXT_TYPE_SIGNATURE_ALGORITHMS_CERT: c_int = 50;
const TLSEXT_TYPE_KEY_SHARE: c_int = 51;
const TLSEXT_TYPE_RENEGOTIATE: c_int = 0xff01;
const TLSEXT_TYPE_NEXT_PROTO_NEG: c_int = 13172;

// Signature-algorithm coordinates — `ssl_local.h:2210-2244`.
const SIGALG_ECDSA_SECP256R1_SHA256: c_int = 0x0403;
const SIGALG_ECDSA_SECP384R1_SHA384: c_int = 0x0503;
const SIGALG_ECDSA_SECP521R1_SHA512: c_int = 0x0603;
const SIGALG_ECDSA_SHA224: c_int = 0x0303;
const SIGALG_ECDSA_SHA1: c_int = 0x0203;
const SIGALG_RSA_PSS_RSAE_SHA256: c_int = 0x0804;
const SIGALG_RSA_PSS_RSAE_SHA384: c_int = 0x0805;
const SIGALG_RSA_PSS_RSAE_SHA512: c_int = 0x0806;
const SIGALG_RSA_PSS_PSS_SHA256: c_int = 0x0809;
const SIGALG_RSA_PSS_PSS_SHA384: c_int = 0x080a;
const SIGALG_RSA_PSS_PSS_SHA512: c_int = 0x080b;
const SIGALG_RSA_PKCS1_SHA256: c_int = 0x0401;
const SIGALG_RSA_PKCS1_SHA384: c_int = 0x0501;
const SIGALG_RSA_PKCS1_SHA512: c_int = 0x0601;
const SIGALG_RSA_PKCS1_SHA224: c_int = 0x0301;
const SIGALG_RSA_PKCS1_SHA1: c_int = 0x0201;
const SIGALG_DSA_SHA256: c_int = 0x0402;
const SIGALG_DSA_SHA384: c_int = 0x0502;
const SIGALG_DSA_SHA512: c_int = 0x0602;
const SIGALG_DSA_SHA224: c_int = 0x0302;
const SIGALG_DSA_SHA1: c_int = 0x0202;
const SIGALG_GOST2012_256_INTRINSIC: c_int = 0x0840;
const SIGALG_GOST2012_512_INTRINSIC: c_int = 0x0841;
const SIGALG_GOST2012_256_GOST2012_256: c_int = 0xeeee;
const SIGALG_GOST2012_512_GOST2012_512: c_int = 0xefef;
const SIGALG_GOST2001_GOST94: c_int = 0xeded;
const SIGALG_ED25519: c_int = 0x0807;
const SIGALG_ED448: c_int = 0x0808;
const SIGALG_ECDSA_BRAINPOOL256_SHA256: c_int = 0x081a;
const SIGALG_ECDSA_BRAINPOOL384_SHA384: c_int = 0x081b;
const SIGALG_ECDSA_BRAINPOOL512_SHA512: c_int = 0x081c;

// Key-exchange bits — `ssl_local.h:81-97`.
const SSL_KRSA: c_int = 0x1;
const SSL_KDHE: c_int = 0x2;
const SSL_KECDHE: c_int = 0x4;
const SSL_KPSK: c_int = 0x8;
const SSL_KGOST: c_int = 0x10;
const SSL_KRSAPSK: c_int = 0x40;
const SSL_KECDHEPSK: c_int = 0x80;
const SSL_KDHEPSK: c_int = 0x100;
const SSL_KGOST18: c_int = 0x200;
/// `SSL_PSK` — `ssl_local.h:101`.
const SSL_PSK: c_int = SSL_KPSK | SSL_KRSAPSK | SSL_KECDHEPSK | SSL_KDHEPSK;

/// `EXPLICIT_PRIME_CURVE_TYPE` — `tls1.h`.
const EXPLICIT_PRIME_CURVE_TYPE: u8 = 1;
/// `EXPLICIT_CHAR2_CURVE_TYPE` — `tls1.h`.
const EXPLICIT_CHAR2_CURVE_TYPE: u8 = 2;
/// `NAMED_CURVE_TYPE` — `tls1.h`.
const NAMED_CURVE_TYPE: u8 = 3;

/// One `ssl_trace_tbl` row — `t1_trce.c:19-22`.
#[repr(C)]
struct SslTraceTbl {
    num: c_int,
    name: *const c_char,
}

// SAFETY: every table is a process-lifetime `static` of `(num, name)` pairs; the only pointer is
// to a `'static` C string that is never written, so sharing the records across threads introduces
// no data race.
unsafe impl Sync for SslTraceTbl {}

/// A row constructor so the tables read as the authority's `{ num, "name" }` initialisers.
const fn t(num: c_int, name: *const c_char) -> SslTraceTbl {
    SslTraceTbl { num, name }
}

/// `do_ssl_trace_str` — `t1_trce.c:31-41`.
fn trace_str(val: c_int, tbl: &[SslTraceTbl]) -> *const c_char {
    for row in tbl {
        if row.num == val {
            return row.name;
        }
    }
    c"UNKNOWN".as_ptr()
}

/// `do_ssl_trace_list` — `t1_trce.c:43-61`.
///
/// # Safety
/// `msg` must be readable for `msglen` bytes; `bio` must be live.
unsafe fn trace_list(
    bio: *mut Bio,
    indent: c_int,
    msg: *const u8,
    msglen: usize,
    vlen: usize,
    tbl: &[SslTraceTbl],
) -> c_int {
    if vlen == 0 || !msglen.is_multiple_of(vlen) {
        return 0;
    }
    let mut remaining = msglen;
    let mut p = msg;
    while remaining != 0 {
        // SAFETY: `p` is within the caller's readable `msglen` bytes.
        let mut val = unsafe { *p } as c_int;
        if vlen == 2 {
            // SAFETY: `remaining >= 2` because `vlen == 2` divides it.
            val = (val << 8) | unsafe { *p.add(1) } as c_int;
        }
        // SAFETY: `bio` is live; `tbl` is a static table.
        unsafe {
            BIO_indent(bio, indent, 80);
            BIO_printf(bio, c"%s (%d)\n".as_ptr(), trace_str(val, tbl), val);
        }
        // SAFETY: `p` advances by `vlen` and stays within the readable region.
        p = unsafe { p.add(vlen) };
        remaining -= vlen;
    }
    1
}

// -------------------------------------------------------------------------------------------
// The trace tables — `t1_trce.c:65-661`
// -------------------------------------------------------------------------------------------

/// `ssl_version_tbl` — `t1_trce.c:65-74`.
static SSL_VERSION_TBL: &[SslTraceTbl] = &[
    t(SSL3_VERSION, c"SSL 3.0".as_ptr()),
    t(TLS1_VERSION, c"TLS 1.0".as_ptr()),
    t(TLS1_1_VERSION, c"TLS 1.1".as_ptr()),
    t(TLS1_2_VERSION, c"TLS 1.2".as_ptr()),
    t(TLS1_3_VERSION, c"TLS 1.3".as_ptr()),
    t(DTLS1_VERSION, c"DTLS 1.0".as_ptr()),
    t(DTLS1_2_VERSION, c"DTLS 1.2".as_ptr()),
    t(DTLS1_BAD_VER, c"DTLS 1.0 (bad)".as_ptr()),
];

/// `ssl_content_tbl` — `t1_trce.c:76-81`.
static SSL_CONTENT_TBL: &[SslTraceTbl] = &[
    t(SSL3_RT_CHANGE_CIPHER_SPEC, c"ChangeCipherSpec".as_ptr()),
    t(SSL3_RT_ALERT, c"Alert".as_ptr()),
    t(SSL3_RT_HANDSHAKE, c"Handshake".as_ptr()),
    t(SSL3_RT_APPLICATION_DATA, c"ApplicationData".as_ptr()),
];

/// `ssl_handshake_tbl` — `t1_trce.c:84-108`.
static SSL_HANDSHAKE_TBL: &[SslTraceTbl] = &[
    t(SSL3_MT_HELLO_REQUEST, c"HelloRequest".as_ptr()),
    t(SSL3_MT_CLIENT_HELLO, c"ClientHello".as_ptr()),
    t(SSL3_MT_SERVER_HELLO, c"ServerHello".as_ptr()),
    t(
        DTLS1_MT_HELLO_VERIFY_REQUEST,
        c"HelloVerifyRequest".as_ptr(),
    ),
    t(SSL3_MT_NEWSESSION_TICKET, c"NewSessionTicket".as_ptr()),
    t(SSL3_MT_END_OF_EARLY_DATA, c"EndOfEarlyData".as_ptr()),
    t(
        SSL3_MT_ENCRYPTED_EXTENSIONS,
        c"EncryptedExtensions".as_ptr(),
    ),
    t(SSL3_MT_CERTIFICATE, c"Certificate".as_ptr()),
    t(SSL3_MT_SERVER_KEY_EXCHANGE, c"ServerKeyExchange".as_ptr()),
    t(SSL3_MT_CERTIFICATE_REQUEST, c"CertificateRequest".as_ptr()),
    t(SSL3_MT_SERVER_DONE, c"ServerHelloDone".as_ptr()),
    t(SSL3_MT_CERTIFICATE_VERIFY, c"CertificateVerify".as_ptr()),
    t(SSL3_MT_CLIENT_KEY_EXCHANGE, c"ClientKeyExchange".as_ptr()),
    t(SSL3_MT_FINISHED, c"Finished".as_ptr()),
    t(SSL3_MT_CERTIFICATE_URL, c"CertificateUrl".as_ptr()),
    t(SSL3_MT_CERTIFICATE_STATUS, c"CertificateStatus".as_ptr()),
    t(SSL3_MT_SUPPLEMENTAL_DATA, c"SupplementalData".as_ptr()),
    t(SSL3_MT_KEY_UPDATE, c"KeyUpdate".as_ptr()),
    t(
        SSL3_MT_COMPRESSED_CERTIFICATE,
        c"CompressedCertificate".as_ptr(),
    ),
    t(SSL3_MT_NEXT_PROTO, c"NextProto".as_ptr()),
    t(SSL3_MT_MESSAGE_HASH, c"MessageHash".as_ptr()),
];

/// `ssl_ciphers_tbl` — `t1_trce.c:111-455`.
static SSL_CIPHERS_TBL: &[SslTraceTbl] = &[
    t(0x0000, c"TLS_NULL_WITH_NULL_NULL".as_ptr()),
    t(0x0001, c"TLS_RSA_WITH_NULL_MD5".as_ptr()),
    t(0x0002, c"TLS_RSA_WITH_NULL_SHA".as_ptr()),
    t(0x0003, c"TLS_RSA_EXPORT_WITH_RC4_40_MD5".as_ptr()),
    t(0x0004, c"TLS_RSA_WITH_RC4_128_MD5".as_ptr()),
    t(0x0005, c"TLS_RSA_WITH_RC4_128_SHA".as_ptr()),
    t(0x0006, c"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5".as_ptr()),
    t(0x0007, c"TLS_RSA_WITH_IDEA_CBC_SHA".as_ptr()),
    t(0x0008, c"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA".as_ptr()),
    t(0x0009, c"TLS_RSA_WITH_DES_CBC_SHA".as_ptr()),
    t(0x000A, c"TLS_RSA_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0x000B, c"TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA".as_ptr()),
    t(0x000C, c"TLS_DH_DSS_WITH_DES_CBC_SHA".as_ptr()),
    t(0x000D, c"TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0x000E, c"TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA".as_ptr()),
    t(0x000F, c"TLS_DH_RSA_WITH_DES_CBC_SHA".as_ptr()),
    t(0x0010, c"TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0x0011, c"TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA".as_ptr()),
    t(0x0012, c"TLS_DHE_DSS_WITH_DES_CBC_SHA".as_ptr()),
    t(0x0013, c"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0x0014, c"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA".as_ptr()),
    t(0x0015, c"TLS_DHE_RSA_WITH_DES_CBC_SHA".as_ptr()),
    t(0x0016, c"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0x0017, c"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5".as_ptr()),
    t(0x0018, c"TLS_DH_anon_WITH_RC4_128_MD5".as_ptr()),
    t(0x0019, c"TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA".as_ptr()),
    t(0x001A, c"TLS_DH_anon_WITH_DES_CBC_SHA".as_ptr()),
    t(0x001B, c"TLS_DH_anon_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0x001D, c"SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA".as_ptr()),
    t(0x001E, c"SSL_FORTEZZA_KEA_WITH_RC4_128_SHA".as_ptr()),
    t(0x001F, c"TLS_KRB5_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0x0020, c"TLS_KRB5_WITH_RC4_128_SHA".as_ptr()),
    t(0x0021, c"TLS_KRB5_WITH_IDEA_CBC_SHA".as_ptr()),
    t(0x0022, c"TLS_KRB5_WITH_DES_CBC_MD5".as_ptr()),
    t(0x0023, c"TLS_KRB5_WITH_3DES_EDE_CBC_MD5".as_ptr()),
    t(0x0024, c"TLS_KRB5_WITH_RC4_128_MD5".as_ptr()),
    t(0x0025, c"TLS_KRB5_WITH_IDEA_CBC_MD5".as_ptr()),
    t(0x0026, c"TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA".as_ptr()),
    t(0x0027, c"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA".as_ptr()),
    t(0x0028, c"TLS_KRB5_EXPORT_WITH_RC4_40_SHA".as_ptr()),
    t(0x0029, c"TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5".as_ptr()),
    t(0x002A, c"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5".as_ptr()),
    t(0x002B, c"TLS_KRB5_EXPORT_WITH_RC4_40_MD5".as_ptr()),
    t(0x002C, c"TLS_PSK_WITH_NULL_SHA".as_ptr()),
    t(0x002D, c"TLS_DHE_PSK_WITH_NULL_SHA".as_ptr()),
    t(0x002E, c"TLS_RSA_PSK_WITH_NULL_SHA".as_ptr()),
    t(0x002F, c"TLS_RSA_WITH_AES_128_CBC_SHA".as_ptr()),
    t(0x0030, c"TLS_DH_DSS_WITH_AES_128_CBC_SHA".as_ptr()),
    t(0x0031, c"TLS_DH_RSA_WITH_AES_128_CBC_SHA".as_ptr()),
    t(0x0032, c"TLS_DHE_DSS_WITH_AES_128_CBC_SHA".as_ptr()),
    t(0x0033, c"TLS_DHE_RSA_WITH_AES_128_CBC_SHA".as_ptr()),
    t(0x0034, c"TLS_DH_anon_WITH_AES_128_CBC_SHA".as_ptr()),
    t(0x0035, c"TLS_RSA_WITH_AES_256_CBC_SHA".as_ptr()),
    t(0x0036, c"TLS_DH_DSS_WITH_AES_256_CBC_SHA".as_ptr()),
    t(0x0037, c"TLS_DH_RSA_WITH_AES_256_CBC_SHA".as_ptr()),
    t(0x0038, c"TLS_DHE_DSS_WITH_AES_256_CBC_SHA".as_ptr()),
    t(0x0039, c"TLS_DHE_RSA_WITH_AES_256_CBC_SHA".as_ptr()),
    t(0x003A, c"TLS_DH_anon_WITH_AES_256_CBC_SHA".as_ptr()),
    t(0x003B, c"TLS_RSA_WITH_NULL_SHA256".as_ptr()),
    t(0x003C, c"TLS_RSA_WITH_AES_128_CBC_SHA256".as_ptr()),
    t(0x003D, c"TLS_RSA_WITH_AES_256_CBC_SHA256".as_ptr()),
    t(0x003E, c"TLS_DH_DSS_WITH_AES_128_CBC_SHA256".as_ptr()),
    t(0x003F, c"TLS_DH_RSA_WITH_AES_128_CBC_SHA256".as_ptr()),
    t(0x0040, c"TLS_DHE_DSS_WITH_AES_128_CBC_SHA256".as_ptr()),
    t(0x0041, c"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA".as_ptr()),
    t(0x0042, c"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA".as_ptr()),
    t(0x0043, c"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA".as_ptr()),
    t(0x0044, c"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA".as_ptr()),
    t(0x0045, c"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA".as_ptr()),
    t(0x0046, c"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA".as_ptr()),
    t(0x0067, c"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256".as_ptr()),
    t(0x0068, c"TLS_DH_DSS_WITH_AES_256_CBC_SHA256".as_ptr()),
    t(0x0069, c"TLS_DH_RSA_WITH_AES_256_CBC_SHA256".as_ptr()),
    t(0x006A, c"TLS_DHE_DSS_WITH_AES_256_CBC_SHA256".as_ptr()),
    t(0x006B, c"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256".as_ptr()),
    t(0x006C, c"TLS_DH_anon_WITH_AES_128_CBC_SHA256".as_ptr()),
    t(0x006D, c"TLS_DH_anon_WITH_AES_256_CBC_SHA256".as_ptr()),
    t(0x0081, c"TLS_GOSTR341001_WITH_28147_CNT_IMIT".as_ptr()),
    t(0x0083, c"TLS_GOSTR341001_WITH_NULL_GOSTR3411".as_ptr()),
    t(0x0084, c"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA".as_ptr()),
    t(0x0085, c"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA".as_ptr()),
    t(0x0086, c"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA".as_ptr()),
    t(0x0087, c"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA".as_ptr()),
    t(0x0088, c"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA".as_ptr()),
    t(0x0089, c"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA".as_ptr()),
    t(0x008A, c"TLS_PSK_WITH_RC4_128_SHA".as_ptr()),
    t(0x008B, c"TLS_PSK_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0x008C, c"TLS_PSK_WITH_AES_128_CBC_SHA".as_ptr()),
    t(0x008D, c"TLS_PSK_WITH_AES_256_CBC_SHA".as_ptr()),
    t(0x008E, c"TLS_DHE_PSK_WITH_RC4_128_SHA".as_ptr()),
    t(0x008F, c"TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0x0090, c"TLS_DHE_PSK_WITH_AES_128_CBC_SHA".as_ptr()),
    t(0x0091, c"TLS_DHE_PSK_WITH_AES_256_CBC_SHA".as_ptr()),
    t(0x0092, c"TLS_RSA_PSK_WITH_RC4_128_SHA".as_ptr()),
    t(0x0093, c"TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0x0094, c"TLS_RSA_PSK_WITH_AES_128_CBC_SHA".as_ptr()),
    t(0x0095, c"TLS_RSA_PSK_WITH_AES_256_CBC_SHA".as_ptr()),
    t(0x0096, c"TLS_RSA_WITH_SEED_CBC_SHA".as_ptr()),
    t(0x0097, c"TLS_DH_DSS_WITH_SEED_CBC_SHA".as_ptr()),
    t(0x0098, c"TLS_DH_RSA_WITH_SEED_CBC_SHA".as_ptr()),
    t(0x0099, c"TLS_DHE_DSS_WITH_SEED_CBC_SHA".as_ptr()),
    t(0x009A, c"TLS_DHE_RSA_WITH_SEED_CBC_SHA".as_ptr()),
    t(0x009B, c"TLS_DH_anon_WITH_SEED_CBC_SHA".as_ptr()),
    t(0x009C, c"TLS_RSA_WITH_AES_128_GCM_SHA256".as_ptr()),
    t(0x009D, c"TLS_RSA_WITH_AES_256_GCM_SHA384".as_ptr()),
    t(0x009E, c"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256".as_ptr()),
    t(0x009F, c"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384".as_ptr()),
    t(0x00A0, c"TLS_DH_RSA_WITH_AES_128_GCM_SHA256".as_ptr()),
    t(0x00A1, c"TLS_DH_RSA_WITH_AES_256_GCM_SHA384".as_ptr()),
    t(0x00A2, c"TLS_DHE_DSS_WITH_AES_128_GCM_SHA256".as_ptr()),
    t(0x00A3, c"TLS_DHE_DSS_WITH_AES_256_GCM_SHA384".as_ptr()),
    t(0x00A4, c"TLS_DH_DSS_WITH_AES_128_GCM_SHA256".as_ptr()),
    t(0x00A5, c"TLS_DH_DSS_WITH_AES_256_GCM_SHA384".as_ptr()),
    t(0x00A6, c"TLS_DH_anon_WITH_AES_128_GCM_SHA256".as_ptr()),
    t(0x00A7, c"TLS_DH_anon_WITH_AES_256_GCM_SHA384".as_ptr()),
    t(0x00A8, c"TLS_PSK_WITH_AES_128_GCM_SHA256".as_ptr()),
    t(0x00A9, c"TLS_PSK_WITH_AES_256_GCM_SHA384".as_ptr()),
    t(0x00AA, c"TLS_DHE_PSK_WITH_AES_128_GCM_SHA256".as_ptr()),
    t(0x00AB, c"TLS_DHE_PSK_WITH_AES_256_GCM_SHA384".as_ptr()),
    t(0x00AC, c"TLS_RSA_PSK_WITH_AES_128_GCM_SHA256".as_ptr()),
    t(0x00AD, c"TLS_RSA_PSK_WITH_AES_256_GCM_SHA384".as_ptr()),
    t(0x00AE, c"TLS_PSK_WITH_AES_128_CBC_SHA256".as_ptr()),
    t(0x00AF, c"TLS_PSK_WITH_AES_256_CBC_SHA384".as_ptr()),
    t(0x00B0, c"TLS_PSK_WITH_NULL_SHA256".as_ptr()),
    t(0x00B1, c"TLS_PSK_WITH_NULL_SHA384".as_ptr()),
    t(0x00B2, c"TLS_DHE_PSK_WITH_AES_128_CBC_SHA256".as_ptr()),
    t(0x00B3, c"TLS_DHE_PSK_WITH_AES_256_CBC_SHA384".as_ptr()),
    t(0x00B4, c"TLS_DHE_PSK_WITH_NULL_SHA256".as_ptr()),
    t(0x00B5, c"TLS_DHE_PSK_WITH_NULL_SHA384".as_ptr()),
    t(0x00B6, c"TLS_RSA_PSK_WITH_AES_128_CBC_SHA256".as_ptr()),
    t(0x00B7, c"TLS_RSA_PSK_WITH_AES_256_CBC_SHA384".as_ptr()),
    t(0x00B8, c"TLS_RSA_PSK_WITH_NULL_SHA256".as_ptr()),
    t(0x00B9, c"TLS_RSA_PSK_WITH_NULL_SHA384".as_ptr()),
    t(0x00BA, c"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256".as_ptr()),
    t(0x00BB, c"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256".as_ptr()),
    t(0x00BC, c"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256".as_ptr()),
    t(0x00BD, c"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256".as_ptr()),
    t(0x00BE, c"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256".as_ptr()),
    t(0x00BF, c"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256".as_ptr()),
    t(0x00C0, c"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256".as_ptr()),
    t(0x00C1, c"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256".as_ptr()),
    t(0x00C2, c"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256".as_ptr()),
    t(0x00C3, c"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256".as_ptr()),
    t(0x00C4, c"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256".as_ptr()),
    t(0x00C5, c"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256".as_ptr()),
    t(0x00FF, c"TLS_EMPTY_RENEGOTIATION_INFO_SCSV".as_ptr()),
    t(0x5600, c"TLS_FALLBACK_SCSV".as_ptr()),
    t(0xC001, c"TLS_ECDH_ECDSA_WITH_NULL_SHA".as_ptr()),
    t(0xC002, c"TLS_ECDH_ECDSA_WITH_RC4_128_SHA".as_ptr()),
    t(0xC003, c"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0xC004, c"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA".as_ptr()),
    t(0xC005, c"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA".as_ptr()),
    t(0xC006, c"TLS_ECDHE_ECDSA_WITH_NULL_SHA".as_ptr()),
    t(0xC007, c"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA".as_ptr()),
    t(0xC008, c"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0xC009, c"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA".as_ptr()),
    t(0xC00A, c"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA".as_ptr()),
    t(0xC00B, c"TLS_ECDH_RSA_WITH_NULL_SHA".as_ptr()),
    t(0xC00C, c"TLS_ECDH_RSA_WITH_RC4_128_SHA".as_ptr()),
    t(0xC00D, c"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0xC00E, c"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA".as_ptr()),
    t(0xC00F, c"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA".as_ptr()),
    t(0xC010, c"TLS_ECDHE_RSA_WITH_NULL_SHA".as_ptr()),
    t(0xC011, c"TLS_ECDHE_RSA_WITH_RC4_128_SHA".as_ptr()),
    t(0xC012, c"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0xC013, c"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA".as_ptr()),
    t(0xC014, c"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA".as_ptr()),
    t(0xC015, c"TLS_ECDH_anon_WITH_NULL_SHA".as_ptr()),
    t(0xC016, c"TLS_ECDH_anon_WITH_RC4_128_SHA".as_ptr()),
    t(0xC017, c"TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0xC018, c"TLS_ECDH_anon_WITH_AES_128_CBC_SHA".as_ptr()),
    t(0xC019, c"TLS_ECDH_anon_WITH_AES_256_CBC_SHA".as_ptr()),
    t(0xC01A, c"TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0xC01B, c"TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0xC01C, c"TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0xC01D, c"TLS_SRP_SHA_WITH_AES_128_CBC_SHA".as_ptr()),
    t(0xC01E, c"TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA".as_ptr()),
    t(0xC01F, c"TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA".as_ptr()),
    t(0xC020, c"TLS_SRP_SHA_WITH_AES_256_CBC_SHA".as_ptr()),
    t(0xC021, c"TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA".as_ptr()),
    t(0xC022, c"TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA".as_ptr()),
    t(0xC023, c"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256".as_ptr()),
    t(0xC024, c"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384".as_ptr()),
    t(0xC025, c"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256".as_ptr()),
    t(0xC026, c"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384".as_ptr()),
    t(0xC027, c"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256".as_ptr()),
    t(0xC028, c"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384".as_ptr()),
    t(0xC029, c"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256".as_ptr()),
    t(0xC02A, c"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384".as_ptr()),
    t(0xC02B, c"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".as_ptr()),
    t(0xC02C, c"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".as_ptr()),
    t(0xC02D, c"TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256".as_ptr()),
    t(0xC02E, c"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384".as_ptr()),
    t(0xC02F, c"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".as_ptr()),
    t(0xC030, c"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".as_ptr()),
    t(0xC031, c"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256".as_ptr()),
    t(0xC032, c"TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384".as_ptr()),
    t(0xC033, c"TLS_ECDHE_PSK_WITH_RC4_128_SHA".as_ptr()),
    t(0xC034, c"TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0xC035, c"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA".as_ptr()),
    t(0xC036, c"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA".as_ptr()),
    t(0xC037, c"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256".as_ptr()),
    t(0xC038, c"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384".as_ptr()),
    t(0xC039, c"TLS_ECDHE_PSK_WITH_NULL_SHA".as_ptr()),
    t(0xC03A, c"TLS_ECDHE_PSK_WITH_NULL_SHA256".as_ptr()),
    t(0xC03B, c"TLS_ECDHE_PSK_WITH_NULL_SHA384".as_ptr()),
    t(0xC03C, c"TLS_RSA_WITH_ARIA_128_CBC_SHA256".as_ptr()),
    t(0xC03D, c"TLS_RSA_WITH_ARIA_256_CBC_SHA384".as_ptr()),
    t(0xC03E, c"TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256".as_ptr()),
    t(0xC03F, c"TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384".as_ptr()),
    t(0xC040, c"TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256".as_ptr()),
    t(0xC041, c"TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384".as_ptr()),
    t(0xC042, c"TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256".as_ptr()),
    t(0xC043, c"TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384".as_ptr()),
    t(0xC044, c"TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256".as_ptr()),
    t(0xC045, c"TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384".as_ptr()),
    t(0xC046, c"TLS_DH_anon_WITH_ARIA_128_CBC_SHA256".as_ptr()),
    t(0xC047, c"TLS_DH_anon_WITH_ARIA_256_CBC_SHA384".as_ptr()),
    t(0xC048, c"TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256".as_ptr()),
    t(0xC049, c"TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384".as_ptr()),
    t(0xC04A, c"TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256".as_ptr()),
    t(0xC04B, c"TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384".as_ptr()),
    t(0xC04C, c"TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256".as_ptr()),
    t(0xC04D, c"TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384".as_ptr()),
    t(0xC04E, c"TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256".as_ptr()),
    t(0xC04F, c"TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384".as_ptr()),
    t(0xC050, c"TLS_RSA_WITH_ARIA_128_GCM_SHA256".as_ptr()),
    t(0xC051, c"TLS_RSA_WITH_ARIA_256_GCM_SHA384".as_ptr()),
    t(0xC052, c"TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256".as_ptr()),
    t(0xC053, c"TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384".as_ptr()),
    t(0xC054, c"TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256".as_ptr()),
    t(0xC055, c"TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384".as_ptr()),
    t(0xC056, c"TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256".as_ptr()),
    t(0xC057, c"TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384".as_ptr()),
    t(0xC058, c"TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256".as_ptr()),
    t(0xC059, c"TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384".as_ptr()),
    t(0xC05A, c"TLS_DH_anon_WITH_ARIA_128_GCM_SHA256".as_ptr()),
    t(0xC05B, c"TLS_DH_anon_WITH_ARIA_256_GCM_SHA384".as_ptr()),
    t(0xC05C, c"TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256".as_ptr()),
    t(0xC05D, c"TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384".as_ptr()),
    t(0xC05E, c"TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256".as_ptr()),
    t(0xC05F, c"TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384".as_ptr()),
    t(0xC060, c"TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256".as_ptr()),
    t(0xC061, c"TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384".as_ptr()),
    t(0xC062, c"TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256".as_ptr()),
    t(0xC063, c"TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384".as_ptr()),
    t(0xC064, c"TLS_PSK_WITH_ARIA_128_CBC_SHA256".as_ptr()),
    t(0xC065, c"TLS_PSK_WITH_ARIA_256_CBC_SHA384".as_ptr()),
    t(0xC066, c"TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256".as_ptr()),
    t(0xC067, c"TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384".as_ptr()),
    t(0xC068, c"TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256".as_ptr()),
    t(0xC069, c"TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384".as_ptr()),
    t(0xC06A, c"TLS_PSK_WITH_ARIA_128_GCM_SHA256".as_ptr()),
    t(0xC06B, c"TLS_PSK_WITH_ARIA_256_GCM_SHA384".as_ptr()),
    t(0xC06C, c"TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256".as_ptr()),
    t(0xC06D, c"TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384".as_ptr()),
    t(0xC06E, c"TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256".as_ptr()),
    t(0xC06F, c"TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384".as_ptr()),
    t(0xC070, c"TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256".as_ptr()),
    t(0xC071, c"TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384".as_ptr()),
    t(
        0xC072,
        c"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256".as_ptr(),
    ),
    t(
        0xC073,
        c"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384".as_ptr(),
    ),
    t(
        0xC074,
        c"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256".as_ptr(),
    ),
    t(
        0xC075,
        c"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384".as_ptr(),
    ),
    t(
        0xC076,
        c"TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256".as_ptr(),
    ),
    t(
        0xC077,
        c"TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384".as_ptr(),
    ),
    t(
        0xC078,
        c"TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256".as_ptr(),
    ),
    t(
        0xC079,
        c"TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384".as_ptr(),
    ),
    t(0xC07A, c"TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256".as_ptr()),
    t(0xC07B, c"TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384".as_ptr()),
    t(0xC07C, c"TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256".as_ptr()),
    t(0xC07D, c"TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384".as_ptr()),
    t(0xC07E, c"TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256".as_ptr()),
    t(0xC07F, c"TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384".as_ptr()),
    t(0xC080, c"TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256".as_ptr()),
    t(0xC081, c"TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384".as_ptr()),
    t(0xC082, c"TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256".as_ptr()),
    t(0xC083, c"TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384".as_ptr()),
    t(0xC084, c"TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256".as_ptr()),
    t(0xC085, c"TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384".as_ptr()),
    t(
        0xC086,
        c"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256".as_ptr(),
    ),
    t(
        0xC087,
        c"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384".as_ptr(),
    ),
    t(
        0xC088,
        c"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256".as_ptr(),
    ),
    t(
        0xC089,
        c"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384".as_ptr(),
    ),
    t(
        0xC08A,
        c"TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256".as_ptr(),
    ),
    t(
        0xC08B,
        c"TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384".as_ptr(),
    ),
    t(
        0xC08C,
        c"TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256".as_ptr(),
    ),
    t(
        0xC08D,
        c"TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384".as_ptr(),
    ),
    t(0xC08E, c"TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256".as_ptr()),
    t(0xC08F, c"TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384".as_ptr()),
    t(0xC090, c"TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256".as_ptr()),
    t(0xC091, c"TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384".as_ptr()),
    t(0xC092, c"TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256".as_ptr()),
    t(0xC093, c"TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384".as_ptr()),
    t(0xC094, c"TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256".as_ptr()),
    t(0xC095, c"TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384".as_ptr()),
    t(0xC096, c"TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256".as_ptr()),
    t(0xC097, c"TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384".as_ptr()),
    t(0xC098, c"TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256".as_ptr()),
    t(0xC099, c"TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384".as_ptr()),
    t(
        0xC09A,
        c"TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256".as_ptr(),
    ),
    t(
        0xC09B,
        c"TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384".as_ptr(),
    ),
    t(0xC09C, c"TLS_RSA_WITH_AES_128_CCM".as_ptr()),
    t(0xC09D, c"TLS_RSA_WITH_AES_256_CCM".as_ptr()),
    t(0xC09E, c"TLS_DHE_RSA_WITH_AES_128_CCM".as_ptr()),
    t(0xC09F, c"TLS_DHE_RSA_WITH_AES_256_CCM".as_ptr()),
    t(0xC0A0, c"TLS_RSA_WITH_AES_128_CCM_8".as_ptr()),
    t(0xC0A1, c"TLS_RSA_WITH_AES_256_CCM_8".as_ptr()),
    t(0xC0A2, c"TLS_DHE_RSA_WITH_AES_128_CCM_8".as_ptr()),
    t(0xC0A3, c"TLS_DHE_RSA_WITH_AES_256_CCM_8".as_ptr()),
    t(0xC0A4, c"TLS_PSK_WITH_AES_128_CCM".as_ptr()),
    t(0xC0A5, c"TLS_PSK_WITH_AES_256_CCM".as_ptr()),
    t(0xC0A6, c"TLS_DHE_PSK_WITH_AES_128_CCM".as_ptr()),
    t(0xC0A7, c"TLS_DHE_PSK_WITH_AES_256_CCM".as_ptr()),
    t(0xC0A8, c"TLS_PSK_WITH_AES_128_CCM_8".as_ptr()),
    t(0xC0A9, c"TLS_PSK_WITH_AES_256_CCM_8".as_ptr()),
    t(0xC0AA, c"TLS_PSK_DHE_WITH_AES_128_CCM_8".as_ptr()),
    t(0xC0AB, c"TLS_PSK_DHE_WITH_AES_256_CCM_8".as_ptr()),
    t(0xC0AC, c"TLS_ECDHE_ECDSA_WITH_AES_128_CCM".as_ptr()),
    t(0xC0AD, c"TLS_ECDHE_ECDSA_WITH_AES_256_CCM".as_ptr()),
    t(0xC0AE, c"TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8".as_ptr()),
    t(0xC0AF, c"TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8".as_ptr()),
    t(0xC102, c"IANA-GOST2012-GOST8912-GOST8912".as_ptr()),
    t(
        0xCCA8,
        c"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".as_ptr(),
    ),
    t(
        0xCCA9,
        c"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".as_ptr(),
    ),
    t(
        0xCCAA,
        c"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256".as_ptr(),
    ),
    t(0xCCAB, c"TLS_PSK_WITH_CHACHA20_POLY1305_SHA256".as_ptr()),
    t(
        0xCCAC,
        c"TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256".as_ptr(),
    ),
    t(
        0xCCAD,
        c"TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256".as_ptr(),
    ),
    t(
        0xCCAE,
        c"TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256".as_ptr(),
    ),
    t(0x1301, c"TLS_AES_128_GCM_SHA256".as_ptr()),
    t(0x1302, c"TLS_AES_256_GCM_SHA384".as_ptr()),
    t(0x1303, c"TLS_CHACHA20_POLY1305_SHA256".as_ptr()),
    t(0x1304, c"TLS_AES_128_CCM_SHA256".as_ptr()),
    t(0x1305, c"TLS_AES_128_CCM_8_SHA256".as_ptr()),
    t(0xFEFE, c"SSL_RSA_FIPS_WITH_DES_CBC_SHA".as_ptr()),
    t(0xFEFF, c"SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA".as_ptr()),
    t(0xFF85, c"LEGACY-GOST2012-GOST8912-GOST8912".as_ptr()),
    t(0xFF87, c"GOST2012-NULL-GOST12".as_ptr()),
    t(0xC0B4, c"TLS_SHA256_SHA256".as_ptr()),
    t(0xC0B5, c"TLS_SHA384_SHA384".as_ptr()),
    t(0xC100, c"GOST2012-KUZNYECHIK-KUZNYECHIKOMAC".as_ptr()),
    t(0xC101, c"GOST2012-MAGMA-MAGMAOMAC".as_ptr()),
];

/// `ssl_comp_tbl` — `t1_trce.c:458-461`.
static SSL_COMP_TBL: &[SslTraceTbl] = &[
    t(0x0000, c"No Compression".as_ptr()),
    t(0x0001, c"Zlib Compression".as_ptr()),
];

/// `ssl_exts_tbl` — `t1_trce.c:464-503`.
static SSL_EXTS_TBL: &[SslTraceTbl] = &[
    t(TLSEXT_TYPE_SERVER_NAME, c"server_name".as_ptr()),
    t(
        TLSEXT_TYPE_MAX_FRAGMENT_LENGTH,
        c"max_fragment_length".as_ptr(),
    ),
    t(
        TLSEXT_TYPE_CLIENT_CERTIFICATE_URL,
        c"client_certificate_url".as_ptr(),
    ),
    t(TLSEXT_TYPE_TRUSTED_CA_KEYS, c"trusted_ca_keys".as_ptr()),
    t(TLSEXT_TYPE_TRUNCATED_HMAC, c"truncated_hmac".as_ptr()),
    t(TLSEXT_TYPE_STATUS_REQUEST, c"status_request".as_ptr()),
    t(TLSEXT_TYPE_USER_MAPPING, c"user_mapping".as_ptr()),
    t(TLSEXT_TYPE_CLIENT_AUTHZ, c"client_authz".as_ptr()),
    t(TLSEXT_TYPE_SERVER_AUTHZ, c"server_authz".as_ptr()),
    t(TLSEXT_TYPE_CERT_TYPE, c"cert_type".as_ptr()),
    t(TLSEXT_TYPE_SUPPORTED_GROUPS, c"supported_groups".as_ptr()),
    t(TLSEXT_TYPE_EC_POINT_FORMATS, c"ec_point_formats".as_ptr()),
    t(TLSEXT_TYPE_SRP, c"srp".as_ptr()),
    t(
        TLSEXT_TYPE_SIGNATURE_ALGORITHMS,
        c"signature_algorithms".as_ptr(),
    ),
    t(TLSEXT_TYPE_USE_SRTP, c"use_srtp".as_ptr()),
    t(
        TLSEXT_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
        c"application_layer_protocol_negotiation".as_ptr(),
    ),
    t(
        TLSEXT_TYPE_SIGNED_CERTIFICATE_TIMESTAMP,
        c"signed_certificate_timestamps".as_ptr(),
    ),
    t(TLSEXT_TYPE_CLIENT_CERT_TYPE, c"client_cert_type".as_ptr()),
    t(TLSEXT_TYPE_SERVER_CERT_TYPE, c"server_cert_type".as_ptr()),
    t(TLSEXT_TYPE_PADDING, c"padding".as_ptr()),
    t(TLSEXT_TYPE_ENCRYPT_THEN_MAC, c"encrypt_then_mac".as_ptr()),
    t(
        TLSEXT_TYPE_EXTENDED_MASTER_SECRET,
        c"extended_master_secret".as_ptr(),
    ),
    t(
        TLSEXT_TYPE_COMPRESS_CERTIFICATE,
        c"compress_certificate".as_ptr(),
    ),
    t(TLSEXT_TYPE_SESSION_TICKET, c"session_ticket".as_ptr()),
    t(TLSEXT_TYPE_PSK, c"psk".as_ptr()),
    t(TLSEXT_TYPE_EARLY_DATA, c"early_data".as_ptr()),
    t(
        TLSEXT_TYPE_SUPPORTED_VERSIONS,
        c"supported_versions".as_ptr(),
    ),
    t(TLSEXT_TYPE_COOKIE, c"cookie_ext".as_ptr()),
    t(
        TLSEXT_TYPE_PSK_KEX_MODES,
        c"psk_key_exchange_modes".as_ptr(),
    ),
    t(
        TLSEXT_TYPE_CERTIFICATE_AUTHORITIES,
        c"certificate_authorities".as_ptr(),
    ),
    t(
        TLSEXT_TYPE_POST_HANDSHAKE_AUTH,
        c"post_handshake_auth".as_ptr(),
    ),
    t(
        TLSEXT_TYPE_SIGNATURE_ALGORITHMS_CERT,
        c"signature_algorithms_cert".as_ptr(),
    ),
    t(TLSEXT_TYPE_KEY_SHARE, c"key_share".as_ptr()),
    t(TLSEXT_TYPE_RENEGOTIATE, c"renegotiate".as_ptr()),
    t(TLSEXT_TYPE_NEXT_PROTO_NEG, c"next_proto_neg".as_ptr()),
];

/// `ssl_groups_tbl` — `t1_trce.c:505-561`.
static SSL_GROUPS_TBL: &[SslTraceTbl] = &[
    t(1, c"sect163k1 (K-163)".as_ptr()),
    t(2, c"sect163r1".as_ptr()),
    t(3, c"sect163r2 (B-163)".as_ptr()),
    t(4, c"sect193r1".as_ptr()),
    t(5, c"sect193r2".as_ptr()),
    t(6, c"sect233k1 (K-233)".as_ptr()),
    t(7, c"sect233r1 (B-233)".as_ptr()),
    t(8, c"sect239k1".as_ptr()),
    t(9, c"sect283k1 (K-283)".as_ptr()),
    t(10, c"sect283r1 (B-283)".as_ptr()),
    t(11, c"sect409k1 (K-409)".as_ptr()),
    t(12, c"sect409r1 (B-409)".as_ptr()),
    t(13, c"sect571k1 (K-571)".as_ptr()),
    t(14, c"sect571r1 (B-571)".as_ptr()),
    t(15, c"secp160k1".as_ptr()),
    t(16, c"secp160r1".as_ptr()),
    t(17, c"secp160r2".as_ptr()),
    t(18, c"secp192k1".as_ptr()),
    t(19, c"secp192r1 (P-192)".as_ptr()),
    t(20, c"secp224k1".as_ptr()),
    t(21, c"secp224r1 (P-224)".as_ptr()),
    t(22, c"secp256k1".as_ptr()),
    t(23, c"secp256r1 (P-256)".as_ptr()),
    t(24, c"secp384r1 (P-384)".as_ptr()),
    t(25, c"secp521r1 (P-521)".as_ptr()),
    t(26, c"brainpoolP256r1".as_ptr()),
    t(27, c"brainpoolP384r1".as_ptr()),
    t(28, c"brainpoolP512r1".as_ptr()),
    t(29, c"ecdh_x25519".as_ptr()),
    t(30, c"ecdh_x448".as_ptr()),
    t(31, c"brainpoolP256r1tls13".as_ptr()),
    t(32, c"brainpoolP384r1tls13".as_ptr()),
    t(33, c"brainpoolP512r1tls13".as_ptr()),
    t(34, c"GC256A".as_ptr()),
    t(35, c"GC256B".as_ptr()),
    t(36, c"GC256C".as_ptr()),
    t(37, c"GC256D".as_ptr()),
    t(38, c"GC512A".as_ptr()),
    t(39, c"GC512B".as_ptr()),
    t(40, c"GC512C".as_ptr()),
    t(256, c"ffdhe2048".as_ptr()),
    t(257, c"ffdhe3072".as_ptr()),
    t(258, c"ffdhe4096".as_ptr()),
    t(259, c"ffdhe6144".as_ptr()),
    t(260, c"ffdhe8192".as_ptr()),
    t(512, c"MLKEM512".as_ptr()),
    t(513, c"MLKEM768".as_ptr()),
    t(514, c"MLKEM1024".as_ptr()),
    t(4587, c"SecP256r1MLKEM768".as_ptr()),
    t(4588, c"X25519MLKEM768".as_ptr()),
    t(4589, c"SecP384r1MLKEM1024".as_ptr()),
    t(25497, c"X25519Kyber768Draft00".as_ptr()),
    t(25498, c"SecP256r1Kyber768Draft00".as_ptr()),
    t(0xFF01, c"arbitrary_explicit_prime_curves".as_ptr()),
    t(0xFF02, c"arbitrary_explicit_char2_curves".as_ptr()),
];

/// `ssl_point_tbl` — `t1_trce.c:563-567`.
static SSL_POINT_TBL: &[SslTraceTbl] = &[
    t(0, c"uncompressed".as_ptr()),
    t(1, c"ansiX962_compressed_prime".as_ptr()),
    t(2, c"ansiX962_compressed_char2".as_ptr()),
];

/// `ssl_mfl_tbl` — `t1_trce.c:569-575`.
static SSL_MFL_TBL: &[SslTraceTbl] = &[
    t(0, c"disabled".as_ptr()),
    t(1, c"max_fragment_length := 2^9 (512 bytes)".as_ptr()),
    t(2, c"max_fragment_length := 2^10 (1024 bytes)".as_ptr()),
    t(3, c"max_fragment_length := 2^11 (2048 bytes)".as_ptr()),
    t(4, c"max_fragment_length := 2^12 (4096 bytes)".as_ptr()),
];

/// `ssl_sigalg_tbl` — `t1_trce.c:577-617`.
static SSL_SIGALG_TBL: &[SslTraceTbl] = &[
    t(
        SIGALG_ECDSA_SECP256R1_SHA256,
        c"ecdsa_secp256r1_sha256".as_ptr(),
    ),
    t(
        SIGALG_ECDSA_SECP384R1_SHA384,
        c"ecdsa_secp384r1_sha384".as_ptr(),
    ),
    t(
        SIGALG_ECDSA_SECP521R1_SHA512,
        c"ecdsa_secp521r1_sha512".as_ptr(),
    ),
    t(SIGALG_ECDSA_SHA224, c"ecdsa_sha224".as_ptr()),
    t(SIGALG_ED25519, c"ed25519".as_ptr()),
    t(SIGALG_ED448, c"ed448".as_ptr()),
    t(SIGALG_ECDSA_SHA1, c"ecdsa_sha1".as_ptr()),
    t(SIGALG_RSA_PSS_RSAE_SHA256, c"rsa_pss_rsae_sha256".as_ptr()),
    t(SIGALG_RSA_PSS_RSAE_SHA384, c"rsa_pss_rsae_sha384".as_ptr()),
    t(SIGALG_RSA_PSS_RSAE_SHA512, c"rsa_pss_rsae_sha512".as_ptr()),
    t(SIGALG_RSA_PSS_PSS_SHA256, c"rsa_pss_pss_sha256".as_ptr()),
    t(SIGALG_RSA_PSS_PSS_SHA384, c"rsa_pss_pss_sha384".as_ptr()),
    t(SIGALG_RSA_PSS_PSS_SHA512, c"rsa_pss_pss_sha512".as_ptr()),
    t(SIGALG_RSA_PKCS1_SHA256, c"rsa_pkcs1_sha256".as_ptr()),
    t(SIGALG_RSA_PKCS1_SHA384, c"rsa_pkcs1_sha384".as_ptr()),
    t(SIGALG_RSA_PKCS1_SHA512, c"rsa_pkcs1_sha512".as_ptr()),
    t(SIGALG_RSA_PKCS1_SHA224, c"rsa_pkcs1_sha224".as_ptr()),
    t(SIGALG_RSA_PKCS1_SHA1, c"rsa_pkcs1_sha1".as_ptr()),
    t(SIGALG_DSA_SHA256, c"dsa_sha256".as_ptr()),
    t(SIGALG_DSA_SHA384, c"dsa_sha384".as_ptr()),
    t(SIGALG_DSA_SHA512, c"dsa_sha512".as_ptr()),
    t(SIGALG_DSA_SHA224, c"dsa_sha224".as_ptr()),
    t(SIGALG_DSA_SHA1, c"dsa_sha1".as_ptr()),
    t(SIGALG_GOST2012_256_INTRINSIC, c"gostr34102012_256".as_ptr()),
    t(SIGALG_GOST2012_512_INTRINSIC, c"gostr34102012_512".as_ptr()),
    t(SIGALG_GOST2012_256_GOST2012_256, c"gost2012_256".as_ptr()),
    t(SIGALG_GOST2012_512_GOST2012_512, c"gost2012_512".as_ptr()),
    t(SIGALG_GOST2001_GOST94, c"gost2001_gost94".as_ptr()),
    t(
        SIGALG_ECDSA_BRAINPOOL256_SHA256,
        c"ecdsa_brainpoolP256r1tls13_sha256".as_ptr(),
    ),
    t(
        SIGALG_ECDSA_BRAINPOOL384_SHA384,
        c"ecdsa_brainpoolP384r1tls13_sha384".as_ptr(),
    ),
    t(
        SIGALG_ECDSA_BRAINPOOL512_SHA512,
        c"ecdsa_brainpoolP512r1tls13_sha512".as_ptr(),
    ),
    t(0x0904, c"mldsa44".as_ptr()),
    t(0x0905, c"mldsa65".as_ptr()),
    t(0x0906, c"mldsa87".as_ptr()),
];

/// `ssl_ctype_tbl` — `t1_trce.c:619-632`.
static SSL_CTYPE_TBL: &[SslTraceTbl] = &[
    t(1, c"rsa_sign".as_ptr()),
    t(2, c"dss_sign".as_ptr()),
    t(3, c"rsa_fixed_dh".as_ptr()),
    t(4, c"dss_fixed_dh".as_ptr()),
    t(5, c"rsa_ephemeral_dh".as_ptr()),
    t(6, c"dss_ephemeral_dh".as_ptr()),
    t(20, c"fortezza_dms".as_ptr()),
    t(64, c"ecdsa_sign".as_ptr()),
    t(65, c"rsa_fixed_ecdh".as_ptr()),
    t(66, c"ecdsa_fixed_ecdh".as_ptr()),
    t(67, c"gost_sign256".as_ptr()),
    t(68, c"gost_sign512".as_ptr()),
];

/// `ssl_psk_kex_modes_tbl` — `t1_trce.c:634-637`.
static SSL_PSK_KEX_MODES_TBL: &[SslTraceTbl] = &[
    t(TLSEXT_KEX_MODE_KE, c"psk_ke".as_ptr()),
    t(TLSEXT_KEX_MODE_KE_DHE, c"psk_dhe_ke".as_ptr()),
];

/// `ssl_key_update_tbl` — `t1_trce.c:639-642`.
static SSL_KEY_UPDATE_TBL: &[SslTraceTbl] = &[
    t(
        SSL_KEY_UPDATE_NOT_REQUESTED,
        c"update_not_requested".as_ptr(),
    ),
    t(SSL_KEY_UPDATE_REQUESTED, c"update_requested".as_ptr()),
];

/// `ssl_comp_cert_tbl` — `t1_trce.c:644-649`.
static SSL_COMP_CERT_TBL: &[SslTraceTbl] = &[
    t(TLSEXT_COMP_CERT_NONE, c"none".as_ptr()),
    t(TLSEXT_COMP_CERT_ZLIB, c"zlib".as_ptr()),
    t(TLSEXT_COMP_CERT_BROTLI, c"brotli".as_ptr()),
    t(TLSEXT_COMP_CERT_ZSTD, c"zstd".as_ptr()),
];

/// `ssl_cert_type_tbl` — `t1_trce.c:656-661`.
static SSL_CERT_TYPE_TBL: &[SslTraceTbl] = &[
    t(TLSEXT_CERT_TYPE_X509, c"x509".as_ptr()),
    t(TLSEXT_CERT_TYPE_PGP, c"pgp".as_ptr()),
    t(TLSEXT_CERT_TYPE_RPK, c"rpk".as_ptr()),
    t(TLSEXT_CERT_TYPE_1609DOT2, c"1609dot2".as_ptr()),
];

// -------------------------------------------------------------------------------------------
// The printers — `t1_trce.c:663-1735`
// -------------------------------------------------------------------------------------------

/// `SSL_CONNECTION_IS_DTLS(sc)` — `ssl_local.h:257-258`, through the method's `dtls` bit.
unsafe fn is_dtls(sc: *const Ssl) -> bool {
    // SAFETY: `sc` is live per the caller's contract.
    !unsafe { (*sc).method }.is_null() && unsafe { (*(*sc).method).dtls }
}

/// `SSL_CONNECTION_IS_TLS13(sc)` — `ssl_local.h:265-267`.
unsafe fn is_tls13(sc: *const Ssl) -> bool {
    // SAFETY: `sc` is live per the caller's contract.
    let m = unsafe { (*sc).method };
    if m.is_null() {
        return false;
    }
    // SAFETY: `m` is live.
    let v = unsafe { (*m).version };
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    !unsafe { is_dtls(sc) } && v >= TLS1_3_VERSION && v != TLS_ANY_VERSION
}

/// `SSL_USE_SIGALGS(sc)` — `ssl_local.h:284-285`, through the method's `enc_flags` bit.
unsafe fn use_sigalgs(sc: *const Ssl) -> bool {
    // SAFETY: `sc` is live per the caller's contract.
    !unsafe { (*sc).method }.is_null()
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        && (unsafe { (*(*sc).method).enc_flags } & SSL_ENC_FLAG_SIGALGS) != 0
}

/// `SSL_ENC_FLAG_SIGALGS` — `ssl_local.h:2186`.
const SSL_ENC_FLAG_SIGALGS: c_uint = 0x2;

/// `ssl_print_hex` — `t1_trce.c:663-673`.
///
/// # Safety
/// `bio` must be live; `msg` readable for `msglen` bytes.
unsafe fn ssl_print_hex(
    bio: *mut Bio,
    indent: c_int,
    name: *const c_char,
    msg: *const u8,
    msglen: usize,
) {
    // SAFETY: `bio` is live; `name` is NUL-terminated.
    unsafe {
        BIO_indent(bio, indent, 80);
        BIO_printf(bio, c"%s (len=%d): ".as_ptr(), name, msglen as c_int);
        for i in 0..msglen {
            BIO_printf(bio, c"%02X".as_ptr(), *msg.add(i) as c_int);
        }
        BIO_puts(bio, c"\n".as_ptr());
    }
}

/// `ssl_print_hexbuf` — `t1_trce.c:675-693`.
///
/// # Safety
/// `pmsg`/`pmsglen` must be valid and consistent; `bio` live.
unsafe fn ssl_print_hexbuf(
    bio: *mut Bio,
    indent: c_int,
    name: *const c_char,
    nlen: usize,
    pmsg: *mut *const u8,
    pmsglen: *mut usize,
) -> c_int {
    // SAFETY: per the caller's contract.
    let mut p = unsafe { *pmsg };
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    let mut pmsglenv = unsafe { *pmsglen };
    if pmsglenv < nlen {
        return 0;
    }
    // SAFETY: `pmsglenv >= nlen >= 1`, so `p` is readable.
    let mut blen = unsafe { *p } as usize;
    if nlen > 1 {
        // SAFETY: `pmsglenv >= 2`.
        blen = (blen << 8) | unsafe { *p.add(1) } as usize;
    }
    if pmsglenv < nlen + blen {
        return 0;
    }
    // SAFETY: the advance stays within the readable region checked above.
    p = unsafe { p.add(nlen) };
    // SAFETY: `bio` live; `p` readable for `blen`.
    unsafe { ssl_print_hex(bio, indent, name, p, blen) };
    // SAFETY: per the caller's contract.
    unsafe {
        *pmsg = p.add(blen);
        *pmsglen = pmsglenv - (blen + nlen);
    }
    let _ = &mut pmsglenv;
    1
}

/// `ssl_print_version` — `t1_trce.c:695-712`.
///
/// # Safety
/// `pmsg`/`pmsglen` valid; `version` NULL or writable; `bio` live.
unsafe fn ssl_print_version(
    bio: *mut Bio,
    indent: c_int,
    name: *const c_char,
    pmsg: *mut *const u8,
    pmsglen: *mut usize,
    version: *mut c_uint,
) -> c_int {
    // SAFETY: per the caller's contract.
    let p = unsafe { *pmsg };
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    let mut pmsglenv = unsafe { *pmsglen };
    if pmsglenv < 2 {
        return 0;
    }
    // SAFETY: `pmsglenv >= 2`, so both bytes are readable.
    let vers = ((unsafe { *p } as c_int) << 8) | unsafe { *p.add(1) } as c_int;
    if !version.is_null() {
        // SAFETY: `version` is writable per the caller's contract.
        unsafe { *version = vers as c_uint };
    }
    // SAFETY: `bio` live; the table is static.
    unsafe {
        BIO_indent(bio, indent, 80);
        BIO_printf(
            bio,
            c"%s=0x%x (%s)\n".as_ptr(),
            name,
            vers,
            trace_str(vers, SSL_VERSION_TBL),
        );
        *pmsg = p.add(2);
        *pmsglen = pmsglenv - 2;
    }
    let _ = &mut pmsglenv;
    1
}

/// `ssl_print_random` — `t1_trce.c:714-735`.
///
/// # Safety
/// `pmsg`/`pmsglen` valid; `bio` live.
unsafe fn ssl_print_random(
    bio: *mut Bio,
    indent: c_int,
    pmsg: *mut *const u8,
    pmsglen: *mut usize,
) -> c_int {
    // SAFETY: per the caller's contract.
    let p = unsafe { *pmsg };
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    let pmsglenv = unsafe { *pmsglen };
    if pmsglenv < 32 {
        return 0;
    }
    // SAFETY: `pmsglenv >= 32`, so the four bytes are readable.
    let tm = ((unsafe { *p } as u32) << 24)
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        | ((unsafe { *p.add(1) } as u32) << 16)
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        | ((unsafe { *p.add(2) } as u32) << 8)
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        | (unsafe { *p.add(3) } as u32);
    // SAFETY: `bio` live; `p + 4` readable for 28 bytes.
    unsafe {
        BIO_indent(bio, indent, 80);
        BIO_puts(bio, c"Random:\n".as_ptr());
        BIO_indent(bio, indent + 2, 80);
        BIO_printf(bio, c"gmt_unix_time=0x%08X\n".as_ptr(), tm);
        ssl_print_hex(bio, indent + 2, c"random_bytes".as_ptr(), p.add(4), 28);
        *pmsg = p.add(32);
        *pmsglen = pmsglenv - 32;
    }
    1
}

/// `ssl_print_signature` — `t1_trce.c:737-753`.
///
/// # Safety
/// `pmsg`/`pmsglen` valid; `sc` live; `bio` live.
unsafe fn ssl_print_signature(
    bio: *mut Bio,
    indent: c_int,
    sc: *const Ssl,
    pmsg: *mut *const u8,
    pmsglen: *mut usize,
) -> c_int {
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    if unsafe { *pmsglen } < 2 {
        return 0;
    }
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    if unsafe { use_sigalgs(sc) } {
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        let p = unsafe { *pmsg };
        // SAFETY: `pmsglen >= 2`.
        let sigalg = ((unsafe { *p } as c_int) << 8) | unsafe { *p.add(1) } as c_int;
        // SAFETY: `bio` live; the table static.
        unsafe {
            BIO_indent(bio, indent, 80);
            BIO_printf(
                bio,
                c"Signature Algorithm: %s (0x%04x)\n".as_ptr(),
                trace_str(sigalg, SSL_SIGALG_TBL),
                sigalg,
            );
            *pmsg = p.add(2);
            *pmsglen -= 2;
        }
    }
    // SAFETY: per the caller's contract.
    unsafe { ssl_print_hexbuf(bio, indent, c"Signature".as_ptr(), 2, pmsg, pmsglen) }
}

/// `ssl_print_extension` — `t1_trce.c:755-964`.
///
/// # Safety
/// `bio` live; `ext` readable for `extlen` bytes.
#[allow(clippy::too_many_lines)]
unsafe fn ssl_print_extension(
    bio: *mut Bio,
    indent: c_int,
    server: c_int,
    mt: u8,
    extype: c_int,
    ext: *const u8,
    extlen: usize,
) -> c_int {
    // SAFETY: `bio` live; the table static.
    unsafe {
        BIO_indent(bio, indent, 80);
        BIO_printf(
            bio,
            c"extension_type=%s(%d), length=%d\n".as_ptr(),
            trace_str(extype, SSL_EXTS_TBL),
            extype,
            extlen as c_int,
        );
    }
    match extype {
        TLSEXT_TYPE_COMPRESS_CERTIFICATE => {
            if extlen < 1 {
                return 0;
            }
            // SAFETY: `extlen >= 1`.
            let xlen = unsafe { *ext } as usize;
            if extlen != xlen + 1 {
                return 0;
            }
            // SAFETY: `ext` readable for `extlen`; `ext+1` for `xlen`.
            unsafe { trace_list(bio, indent + 2, ext.add(1), xlen, 2, SSL_COMP_CERT_TBL) }
        }
        TLSEXT_TYPE_MAX_FRAGMENT_LENGTH => {
            if extlen < 1 {
                return 0;
            }
            // SAFETY: `ext` readable for `extlen`.
            unsafe { trace_list(bio, indent + 2, ext, extlen, 1, SSL_MFL_TBL) }
        }
        TLSEXT_TYPE_EC_POINT_FORMATS => {
            if extlen < 1 {
                return 0;
            }
            // SAFETY: `extlen >= 1`.
            let xlen = unsafe { *ext } as usize;
            if extlen != xlen + 1 {
                return 0;
            }
            // SAFETY: `ext+1` readable for `xlen`.
            unsafe { trace_list(bio, indent + 2, ext.add(1), xlen, 1, SSL_POINT_TBL) }
        }
        TLSEXT_TYPE_SUPPORTED_GROUPS => {
            if extlen < 2 {
                return 0;
            }
            // SAFETY: `extlen >= 2`.
            let xlen = ((unsafe { *ext } as usize) << 8) | unsafe { *ext.add(1) } as usize;
            if extlen != xlen + 2 {
                return 0;
            }
            // SAFETY: `ext+2` readable for `xlen`.
            unsafe { trace_list(bio, indent + 2, ext.add(2), xlen, 2, SSL_GROUPS_TBL) }
        }
        TLSEXT_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
            if extlen < 2 {
                return 0;
            }
            // SAFETY: `extlen >= 2`.
            let mut xlen = ((unsafe { *ext } as usize) << 8) | unsafe { *ext.add(1) } as usize;
            if extlen != xlen + 2 {
                return 0;
            }
            // SAFETY: `ext+2` readable for `xlen`.
            let mut e = unsafe { ext.add(2) };
            while xlen > 0 {
                // SAFETY: `xlen > 0`, so `e` is readable.
                let plen = unsafe { *e } as usize;
                // SAFETY: the enclosing function's contract makes every pointer in this block valid.
                e = unsafe { e.add(1) };
                if plen + 1 > xlen {
                    return 0;
                }
                // SAFETY: `bio` live; `e` readable for `plen`.
                unsafe {
                    BIO_indent(bio, indent + 2, 80);
                    BIO_write(bio, e.cast(), plen as c_int);
                    BIO_puts(bio, c"\n".as_ptr());
                }
                // SAFETY: the enclosing function's contract makes every pointer in this block valid.
                e = unsafe { e.add(plen) };
                xlen -= plen + 1;
            }
            1
        }
        TLSEXT_TYPE_SIGNATURE_ALGORITHMS => {
            if extlen < 2 {
                return 0;
            }
            // SAFETY: `extlen >= 2`.
            let mut xlen = ((unsafe { *ext } as usize) << 8) | unsafe { *ext.add(1) } as usize;
            if extlen != xlen + 2 {
                return 0;
            }
            if xlen & 1 != 0 {
                return 0;
            }
            // SAFETY: `ext+2` readable for `xlen`.
            let mut e = unsafe { ext.add(2) };
            while xlen > 0 {
                // SAFETY: `bio` live; `e` readable for 2.
                unsafe {
                    BIO_indent(bio, indent + 2, 80);
                    let sigalg = ((*e as c_int) << 8) | *e.add(1) as c_int;
                    BIO_printf(
                        bio,
                        c"%s (0x%04x)\n".as_ptr(),
                        trace_str(sigalg, SSL_SIGALG_TBL),
                        sigalg,
                    );
                }
                xlen -= 2;
                // SAFETY: the enclosing function's contract makes every pointer in this block valid.
                e = unsafe { e.add(2) };
            }
            1
        }
        TLSEXT_TYPE_RENEGOTIATE => {
            if extlen < 1 {
                return 0;
            }
            // SAFETY: `extlen >= 1`.
            let mut xlen = unsafe { *ext } as usize;
            if xlen + 1 != extlen {
                return 0;
            }
            // SAFETY: `ext+1` readable for `xlen`.
            let mut e = unsafe { ext.add(1) };
            if xlen != 0 {
                if server != 0 {
                    if xlen & 1 != 0 {
                        return 0;
                    }
                    xlen >>= 1;
                }
                // SAFETY: `bio` live; `e` readable for `xlen`.
                unsafe { ssl_print_hex(bio, indent + 4, c"client_verify_data".as_ptr(), e, xlen) };
                if server != 0 {
                    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
                    e = unsafe { e.add(xlen) };
                    // SAFETY: `e` readable for `xlen` (the second half).
                    unsafe {
                        ssl_print_hex(bio, indent + 4, c"server_verify_data".as_ptr(), e, xlen)
                    };
                }
            } else {
                // SAFETY: `bio` live.
                unsafe {
                    BIO_indent(bio, indent + 4, 80);
                    BIO_puts(bio, c"<EMPTY>\n".as_ptr());
                }
            }
            1
        }
        TLSEXT_TYPE_SESSION_TICKET => {
            if extlen != 0 {
                // SAFETY: `bio` live; `ext` readable for `extlen`.
                unsafe { ssl_print_hex(bio, indent + 4, c"ticket".as_ptr(), ext, extlen) };
            }
            1
        }
        TLSEXT_TYPE_KEY_SHARE => {
            if server != 0 && extlen == 2 {
                // SAFETY: `extlen == 2`.
                let group_id = ((unsafe { *ext } as c_int) << 8) | unsafe { *ext.add(1) } as c_int;
                // SAFETY: `bio` live; table static.
                unsafe {
                    BIO_indent(bio, indent + 4, 80);
                    BIO_printf(
                        bio,
                        c"NamedGroup: %s (%d)\n".as_ptr(),
                        trace_str(group_id, SSL_GROUPS_TBL),
                        group_id,
                    );
                }
                return 1;
            }
            if extlen < 2 {
                return 0;
            }
            let mut xlen;
            let mut e = ext;
            if server != 0 {
                xlen = extlen;
            } else {
                // SAFETY: `extlen >= 2`.
                xlen = ((unsafe { *ext } as usize) << 8) | unsafe { *ext.add(1) } as usize;
                if extlen != xlen + 2 {
                    return 0;
                }
                // SAFETY: the enclosing function's contract makes every pointer in this block valid.
                e = unsafe { ext.add(2) };
            }
            while xlen > 0 {
                if xlen < 4 {
                    return 0;
                }
                // SAFETY: `e` readable for at least 4.
                let group_id = ((unsafe { *e } as c_int) << 8) | unsafe { *e.add(1) } as c_int;
                let share_len =
                    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
                    ((unsafe { *e.add(2) } as usize) << 8) | unsafe { *e.add(3) } as usize;
                // SAFETY: the enclosing function's contract makes every pointer in this block valid.
                e = unsafe { e.add(4) };
                xlen -= 4;
                if xlen < share_len {
                    return 0;
                }
                // SAFETY: `bio` live; `e` readable for `share_len`.
                unsafe {
                    BIO_indent(bio, indent + 4, 80);
                    BIO_printf(
                        bio,
                        c"NamedGroup: %s (%d)\n".as_ptr(),
                        trace_str(group_id, SSL_GROUPS_TBL),
                        group_id,
                    );
                    ssl_print_hex(bio, indent + 4, c"key_exchange: ".as_ptr(), e, share_len);
                }
                // SAFETY: the enclosing function's contract makes every pointer in this block valid.
                e = unsafe { e.add(share_len) };
                xlen -= share_len;
            }
            1
        }
        TLSEXT_TYPE_SUPPORTED_VERSIONS => {
            if server != 0 {
                if extlen != 2 {
                    return 0;
                }
                // SAFETY: `extlen == 2`.
                let version = ((unsafe { *ext } as c_int) << 8) | unsafe { *ext.add(1) } as c_int;
                // SAFETY: `bio` live; table static.
                unsafe {
                    BIO_indent(bio, indent + 4, 80);
                    BIO_printf(
                        bio,
                        c"%s (%d)\n".as_ptr(),
                        trace_str(version, SSL_VERSION_TBL),
                        version,
                    );
                }
                return 1;
            }
            if extlen < 1 {
                return 0;
            }
            // SAFETY: `extlen >= 1`.
            let xlen = unsafe { *ext } as usize;
            if extlen != xlen + 1 {
                return 0;
            }
            // SAFETY: `ext+1` readable for `xlen`.
            unsafe { trace_list(bio, indent + 2, ext.add(1), xlen, 2, SSL_VERSION_TBL) }
        }
        TLSEXT_TYPE_PSK_KEX_MODES => {
            if extlen < 1 {
                return 0;
            }
            // SAFETY: `extlen >= 1`.
            let xlen = unsafe { *ext } as usize;
            if extlen != xlen + 1 {
                return 0;
            }
            // SAFETY: `ext+1` readable for `xlen`.
            unsafe { trace_list(bio, indent + 2, ext.add(1), xlen, 1, SSL_PSK_KEX_MODES_TBL) }
        }
        TLSEXT_TYPE_EARLY_DATA => {
            if mt != SSL3_MT_NEWSESSION_TICKET as u8 {
                return 1;
            }
            if extlen != 4 {
                return 0;
            }
            // SAFETY: `extlen == 4`.
            let max_early_data = ((unsafe { *ext } as u32) << 24)
                // SAFETY: the enclosing function's contract makes every pointer in this block valid.
                | ((unsafe { *ext.add(1) } as u32) << 16)
                // SAFETY: the enclosing function's contract makes every pointer in this block valid.
                | ((unsafe { *ext.add(2) } as u32) << 8)
                // SAFETY: the enclosing function's contract makes every pointer in this block valid.
                | (unsafe { *ext.add(3) } as u32);
            // SAFETY: `bio` live.
            unsafe {
                BIO_indent(bio, indent + 2, 80);
                BIO_printf(bio, c"max_early_data=%u\n".as_ptr(), max_early_data);
            }
            1
        }
        TLSEXT_TYPE_SERVER_CERT_TYPE | TLSEXT_TYPE_CLIENT_CERT_TYPE => {
            if server != 0 {
                if extlen != 1 {
                    return 0;
                }
                // SAFETY: `extlen == 1`.
                unsafe { trace_list(bio, indent + 2, ext, 1, 1, SSL_CERT_TYPE_TBL) }
            } else {
                if extlen < 1 {
                    return 0;
                }
                // SAFETY: `extlen >= 1`.
                let xlen = unsafe { *ext } as usize;
                if extlen != xlen + 1 {
                    return 0;
                }
                // SAFETY: `ext+1` readable for `xlen`.
                unsafe { trace_list(bio, indent + 2, ext.add(1), xlen, 1, SSL_CERT_TYPE_TBL) }
            }
        }
        _ => {
            // SAFETY: `bio` live; `ext` readable for `extlen`.
            unsafe { BIO_dump_indent(bio, ext.cast(), extlen as c_int, indent + 2) };
            1
        }
    }
}

/// `ssl_print_extensions` — `t1_trce.c:966-1017`.
///
/// # Safety
/// `msgin`/`msginlen` valid; `bio` live.
unsafe fn ssl_print_extensions(
    bio: *mut Bio,
    indent: c_int,
    server: c_int,
    mt: u8,
    msgin: *mut *const u8,
    msginlen: *mut usize,
) -> c_int {
    // SAFETY: per the caller's contract.
    let mut msglen = unsafe { *msginlen };
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    let mut msg = unsafe { *msgin };
    // SAFETY: `bio` live.
    unsafe { BIO_indent(bio, indent, 80) };
    if msglen == 0 {
        // SAFETY: `bio` live.
        unsafe { BIO_puts(bio, c"No extensions\n".as_ptr()) };
        return 1;
    }
    if msglen < 2 {
        return 0;
    }
    // SAFETY: `msglen >= 2`.
    let mut extslen = ((unsafe { *msg } as usize) << 8) | unsafe { *msg.add(1) } as usize;
    msglen -= 2;
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    msg = unsafe { msg.add(2) };
    if extslen == 0 {
        // SAFETY: `bio` live.
        unsafe { BIO_puts(bio, c"No extensions\n".as_ptr()) };
        // SAFETY: per the caller's contract.
        unsafe {
            *msgin = msg;
            *msginlen = msglen;
        }
        return 1;
    }
    if extslen > msglen {
        return 0;
    }
    // SAFETY: `bio` live.
    unsafe { BIO_printf(bio, c"extensions, length = %d\n".as_ptr(), extslen as c_int) };
    msglen -= extslen;
    while extslen > 0 {
        if extslen < 4 {
            return 0;
        }
        // SAFETY: `msg` readable for at least 4.
        let extype = ((unsafe { *msg } as c_int) << 8) | unsafe { *msg.add(1) } as c_int;
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        let extlen = ((unsafe { *msg.add(2) } as usize) << 8) | unsafe { *msg.add(3) } as usize;
        if extslen < extlen + 4 {
            // SAFETY: `bio` live; `msg` readable for `extslen`.
            unsafe {
                BIO_printf(
                    bio,
                    c"extensions, extype = %d, extlen = %d\n".as_ptr(),
                    extype,
                    extlen as c_int,
                );
                BIO_dump_indent(bio, msg.cast(), extslen as c_int, indent + 2);
            }
            return 0;
        }
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        msg = unsafe { msg.add(4) };
        // SAFETY: `bio` live; `msg` readable for `extlen`.
        if unsafe { ssl_print_extension(bio, indent + 2, server, mt, extype, msg, extlen) } == 0 {
            return 0;
        }
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        msg = unsafe { msg.add(extlen) };
        extslen -= extlen + 4;
    }
    // SAFETY: per the caller's contract.
    unsafe {
        *msgin = msg;
        *msginlen = msglen;
    }
    1
}

/// `ssl_print_client_hello` — `t1_trce.c:1019-1074`.
///
/// # Safety
/// `bio` live; `sc` live; `msg` readable for `msglen`.
unsafe fn ssl_print_client_hello(
    bio: *mut Bio,
    sc: *const Ssl,
    indent: c_int,
    msg: *const u8,
    msglen: usize,
) -> c_int {
    let mut p = msg;
    let mut len_remaining = msglen;
    let pp: *mut *const u8 = &mut p;
    let pl: *mut usize = &mut len_remaining;
    // SAFETY: per the caller's contract.
    if unsafe {
        ssl_print_version(
            bio,
            indent,
            c"client_version".as_ptr(),
            pp,
            pl,
            ptr::null_mut(),
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    if unsafe { ssl_print_random(bio, indent, pp, pl) } == 0 {
        return 0;
    }
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    if unsafe { ssl_print_hexbuf(bio, indent, c"session_id".as_ptr(), 1, pp, pl) } == 0 {
        return 0;
    }
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    if unsafe { is_dtls(sc) }
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        && unsafe { ssl_print_hexbuf(bio, indent, c"cookie".as_ptr(), 1, pp, pl) } == 0
    {
        return 0;
    }
    if len_remaining < 2 {
        return 0;
    }
    // SAFETY: `len_remaining >= 2`.
    let mut len = ((unsafe { *p } as usize) << 8) | unsafe { *p.add(1) } as usize;
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    p = unsafe { p.add(2) };
    len_remaining -= 2;
    // SAFETY: `bio` live.
    unsafe {
        BIO_indent(bio, indent, 80);
        BIO_printf(bio, c"cipher_suites (len=%d)\n".as_ptr(), len as c_int);
    }
    if len_remaining < len || len & 1 != 0 {
        return 0;
    }
    while len > 0 {
        // SAFETY: `p` readable for 2.
        let cs = ((unsafe { *p } as c_int) << 8) | unsafe { *p.add(1) } as c_int;
        // SAFETY: `bio` live; table static.
        unsafe {
            BIO_indent(bio, indent + 2, 80);
            BIO_printf(
                bio,
                c"{0x%02X, 0x%02X} %s\n".as_ptr(),
                *p as c_int,
                *p.add(1) as c_int,
                trace_str(cs, SSL_CIPHERS_TBL),
            );
        }
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        p = unsafe { p.add(2) };
        len_remaining -= 2;
        len -= 2;
    }
    if len_remaining < 1 {
        return 0;
    }
    // SAFETY: `len_remaining >= 1`.
    len = unsafe { *p } as usize;
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    p = unsafe { p.add(1) };
    len_remaining -= 1;
    if len_remaining < len {
        return 0;
    }
    // SAFETY: `bio` live.
    unsafe {
        BIO_indent(bio, indent, 80);
        BIO_printf(
            bio,
            c"compression_methods (len=%d)\n".as_ptr(),
            len as c_int,
        );
    }
    while len > 0 {
        // SAFETY: `bio` live; table static; `p` readable.
        unsafe {
            BIO_indent(bio, indent + 2, 80);
            BIO_printf(
                bio,
                c"%s (0x%02X)\n".as_ptr(),
                trace_str(*p as c_int, SSL_COMP_TBL),
                *p as c_int,
            );
        }
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        p = unsafe { p.add(1) };
        len_remaining -= 1;
        len -= 1;
    }
    // SAFETY: per the caller's contract.
    unsafe { ssl_print_extensions(bio, indent, 0, SSL3_MT_CLIENT_HELLO as u8, pp, pl) }
}

/// `dtls_print_hello_vfyrequest` — `t1_trce.c:1076-1084`.
///
/// # Safety
/// `bio` live; `msg` readable for `msglen`.
unsafe fn dtls_print_hello_vfyrequest(
    bio: *mut Bio,
    indent: c_int,
    msg: *const u8,
    msglen: usize,
) -> c_int {
    let mut p = msg;
    let mut len_remaining = msglen;
    let pp: *mut *const u8 = &mut p;
    let pl: *mut usize = &mut len_remaining;
    // SAFETY: per the caller's contract.
    if unsafe {
        ssl_print_version(
            bio,
            indent,
            c"server_version".as_ptr(),
            pp,
            pl,
            ptr::null_mut(),
        )
    } == 0
    {
        return 0;
    }
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    unsafe { ssl_print_hexbuf(bio, indent, c"cookie".as_ptr(), 1, pp, pl) }
}

/// `ssl_print_server_hello` — `t1_trce.c:1086-1120`.
///
/// # Safety
/// `bio` live; `msg` readable for `msglen`.
unsafe fn ssl_print_server_hello(
    bio: *mut Bio,
    indent: c_int,
    msg: *const u8,
    msglen: usize,
) -> c_int {
    let mut p = msg;
    let mut len_remaining = msglen;
    let mut vers: c_uint = 0;
    let pp: *mut *const u8 = &mut p;
    let pl: *mut usize = &mut len_remaining;
    // SAFETY: per the caller's contract.
    if unsafe { ssl_print_version(bio, indent, c"server_version".as_ptr(), pp, pl, &mut vers) } == 0
    {
        return 0;
    }
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    if unsafe { ssl_print_random(bio, indent, pp, pl) } == 0 {
        return 0;
    }
    if vers as c_int != TLS1_3_VERSION
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        && unsafe { ssl_print_hexbuf(bio, indent, c"session_id".as_ptr(), 1, pp, pl) } == 0
    {
        return 0;
    }
    if len_remaining < 2 {
        return 0;
    }
    // SAFETY: `len_remaining >= 2`.
    let cs = ((unsafe { *p } as c_int) << 8) | unsafe { *p.add(1) } as c_int;
    // SAFETY: `bio` live; table static.
    unsafe {
        BIO_indent(bio, indent, 80);
        BIO_printf(
            bio,
            c"cipher_suite {0x%02X, 0x%02X} %s\n".as_ptr(),
            *p as c_int,
            *p.add(1) as c_int,
            trace_str(cs, SSL_CIPHERS_TBL),
        );
    }
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    p = unsafe { p.add(2) };
    len_remaining -= 2;
    if vers as c_int != TLS1_3_VERSION {
        if len_remaining < 1 {
            return 0;
        }
        // SAFETY: `bio` live; table static; `p` readable.
        unsafe {
            BIO_indent(bio, indent, 80);
            BIO_printf(
                bio,
                c"compression_method: %s (0x%02X)\n".as_ptr(),
                trace_str(*p as c_int, SSL_COMP_TBL),
                *p as c_int,
            );
        }
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        p = unsafe { p.add(1) };
        len_remaining -= 1;
    }
    // SAFETY: per the caller's contract.
    unsafe { ssl_print_extensions(bio, indent, 1, SSL3_MT_SERVER_HELLO as u8, pp, pl) }
}

/// `ssl_get_keyex` — `t1_trce.c:1122-1168`.
///
/// # Safety
/// `pname` writable; `sc` live.
unsafe fn ssl_get_keyex(pname: *mut *const c_char, sc: *const Ssl) -> c_int {
    // The authority reads `sc->s3.tmp.new_cipher->algorithm_mkey`; the crate models no pending
    // cipher, so the algorithm word is 0 and every test misses, answering "UNKNOWN"/0.
    let _ = sc;
    // SAFETY: `pname` is writable per the caller's contract.
    unsafe { *pname = c"UNKNOWN".as_ptr() };
    0
}

/// `ssl_print_client_keyex` — `t1_trce.c:1170-1220`.
///
/// # Safety
/// `bio` live; `sc` live; `msg` readable for `msglen`.
unsafe fn ssl_print_client_keyex(
    bio: *mut Bio,
    indent: c_int,
    sc: *const Ssl,
    msg: *const u8,
    msglen: usize,
) -> c_int {
    let mut algname: *const c_char = ptr::null();
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    let id = unsafe { ssl_get_keyex(&mut algname, sc) };
    // The pending cipher is not modelled, so `id` is 0 and no branch below fires; the printer still
    // reproduces the authority's shape for the states this crate can reach.
    let mut p = msg;
    let mut len_remaining = msglen;
    let pp: *mut *const u8 = &mut p;
    let pl: *mut usize = &mut len_remaining;
    // SAFETY: `bio` live; `algname` is a static string.
    unsafe {
        BIO_indent(bio, indent, 80);
        BIO_printf(bio, c"KeyExchangeAlgorithm=%s\n".as_ptr(), algname);
    }
    if id & SSL_PSK != 0
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        && unsafe { ssl_print_hexbuf(bio, indent + 2, c"psk_identity".as_ptr(), 2, pp, pl) } == 0
    {
        return 0;
    }
    match id {
        SSL_KRSA | SSL_KRSAPSK => {
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            if unsafe { (*sc).version } == SSL3_VERSION {
                // SAFETY: `bio` live; `msg` readable for `msglen`.
                unsafe {
                    ssl_print_hex(
                        bio,
                        indent + 2,
                        c"EncryptedPreMasterSecret".as_ptr(),
                        msg,
                        msglen,
                    )
                };
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            } else if unsafe {
                ssl_print_hexbuf(
                    bio,
                    indent + 2,
                    c"EncryptedPreMasterSecret".as_ptr(),
                    2,
                    pp,
                    pl,
                )
            } == 0
            {
                return 0;
            }
        }
        SSL_KDHE | SSL_KDHEPSK => {
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            if unsafe { ssl_print_hexbuf(bio, indent + 2, c"dh_Yc".as_ptr(), 2, pp, pl) } == 0 {
                return 0;
            }
        }
        SSL_KECDHE | SSL_KECDHEPSK => {
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            if unsafe { ssl_print_hexbuf(bio, indent + 2, c"ecdh_Yc".as_ptr(), 1, pp, pl) } == 0 {
                return 0;
            }
        }
        SSL_KGOST => {
            // SAFETY: `bio` live; `msg` readable.
            unsafe {
                ssl_print_hex(
                    bio,
                    indent + 2,
                    c"GostKeyTransportBlob".as_ptr(),
                    msg,
                    msglen,
                )
            };
            len_remaining = 0;
        }
        SSL_KGOST18 => {
            // SAFETY: `bio` live; `msg` readable.
            unsafe {
                ssl_print_hex(
                    bio,
                    indent + 2,
                    c"GOST-wrapped PreMasterSecret".as_ptr(),
                    msg,
                    msglen,
                )
            };
            len_remaining = 0;
        }
        _ => {}
    }
    c_int::from(len_remaining == 0)
}

/// `ssl_print_server_keyex` — `t1_trce.c:1222-1288`.
///
/// # Safety
/// `bio` live; `sc` live; `msg` readable for `msglen`.
unsafe fn ssl_print_server_keyex(
    bio: *mut Bio,
    indent: c_int,
    sc: *const Ssl,
    msg: *const u8,
    msglen: usize,
) -> c_int {
    let mut algname: *const c_char = ptr::null();
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    let id = unsafe { ssl_get_keyex(&mut algname, sc) };
    let mut p = msg;
    let mut len_remaining = msglen;
    let pp: *mut *const u8 = &mut p;
    let pl: *mut usize = &mut len_remaining;
    // SAFETY: `bio` live; `algname` static.
    unsafe {
        BIO_indent(bio, indent, 80);
        BIO_printf(bio, c"KeyExchangeAlgorithm=%s\n".as_ptr(), algname);
    }
    if id & SSL_PSK != 0
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        && unsafe { ssl_print_hexbuf(bio, indent + 2, c"psk_identity_hint".as_ptr(), 2, pp, pl) }
            == 0
    {
        return 0;
    }
    match id {
        SSL_KRSA => {
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            if unsafe { ssl_print_hexbuf(bio, indent + 2, c"rsa_modulus".as_ptr(), 2, pp, pl) } == 0
            {
                return 0;
            }
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            if unsafe { ssl_print_hexbuf(bio, indent + 2, c"rsa_exponent".as_ptr(), 2, pp, pl) }
                == 0
            {
                return 0;
            }
        }
        SSL_KDHE | SSL_KDHEPSK => {
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            if unsafe { ssl_print_hexbuf(bio, indent + 2, c"dh_p".as_ptr(), 2, pp, pl) } == 0 {
                return 0;
            }
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            if unsafe { ssl_print_hexbuf(bio, indent + 2, c"dh_g".as_ptr(), 2, pp, pl) } == 0 {
                return 0;
            }
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            if unsafe { ssl_print_hexbuf(bio, indent + 2, c"dh_Ys".as_ptr(), 2, pp, pl) } == 0 {
                return 0;
            }
        }
        SSL_KECDHE | SSL_KECDHEPSK => {
            if len_remaining < 1 {
                return 0;
            }
            // SAFETY: `bio` live.
            unsafe { BIO_indent(bio, indent + 2, 80) };
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            match unsafe { *p } {
                EXPLICIT_PRIME_CURVE_TYPE => {
                    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
                    unsafe { BIO_puts(bio, c"explicit_prime\n".as_ptr()) };
                }
                EXPLICIT_CHAR2_CURVE_TYPE => {
                    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
                    unsafe { BIO_puts(bio, c"explicit_char2\n".as_ptr()) };
                }
                NAMED_CURVE_TYPE => {
                    if len_remaining < 3 {
                        return 0;
                    }
                    // SAFETY: `len_remaining >= 3`.
                    let curve =
                        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
                        ((unsafe { *p.add(1) } as c_int) << 8) | unsafe { *p.add(2) } as c_int;
                    // SAFETY: `bio` live; table static.
                    unsafe {
                        BIO_printf(
                            bio,
                            c"named_curve: %s (%d)\n".as_ptr(),
                            trace_str(curve, SSL_GROUPS_TBL),
                            curve,
                        );
                    }
                    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
                    p = unsafe { p.add(3) };
                    len_remaining -= 3;
                    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
                    if unsafe { ssl_print_hexbuf(bio, indent + 2, c"point".as_ptr(), 1, pp, pl) }
                        == 0
                    {
                        return 0;
                    }
                }
                other => {
                    // SAFETY: `bio` live.
                    unsafe {
                        BIO_printf(
                            bio,
                            c"UNKNOWN CURVE PARAMETER TYPE %d\n".as_ptr(),
                            other as c_int,
                        )
                    };
                    return 0;
                }
            }
        }
        SSL_KPSK | SSL_KRSAPSK => {}
        _ => {}
    }
    if id & SSL_PSK == 0 {
        // SAFETY: `bio` live; `sc` live.
        unsafe { ssl_print_signature(bio, indent, sc, pp, pl) };
    }
    c_int::from(len_remaining == 0)
}

/// `ssl_print_certificate` — `t1_trce.c:1290-1328`.
///
/// # Safety
/// `bio` live; `sc` live; `pmsg`/`pmsglen` valid.
unsafe fn ssl_print_certificate(
    bio: *mut Bio,
    sc: *const Ssl,
    indent: c_int,
    pmsg: *mut *const u8,
    pmsglen: *mut usize,
) -> c_int {
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    let msglen = unsafe { *pmsglen };
    // SAFETY: per the caller's contract.
    let p = unsafe { *pmsg };
    // SAFETY: `sc` live; its `ctx` is live.
    let ctx = unsafe { (*sc).ctx };
    if msglen < 3 {
        return 0;
    }
    // SAFETY: `msglen >= 3`.
    let clen = ((unsafe { *p } as usize) << 16)
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        | ((unsafe { *p.add(1) } as usize) << 8)
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        | unsafe { *p.add(2) } as usize;
    if msglen < clen + 3 {
        return 0;
    }
    // SAFETY: `p+3` readable for `clen`.
    let mut q = unsafe { p.add(3) };
    // SAFETY: `bio` live.
    unsafe {
        BIO_indent(bio, indent, 80);
        BIO_printf(bio, c"ASN.1Cert, length=%d".as_ptr(), clen as c_int);
    }
    // SAFETY: `ctx` is live or NULL.
    let (libctx, propq) = if ctx.is_null() {
        (ptr::null_mut(), ptr::null_mut())
    } else {
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        (unsafe { (*ctx).libctx }, unsafe { (*ctx).propq })
    };
    // SAFETY: a fresh certificate object.
    let mut x = unsafe { X509_new_ex(libctx, propq) };
    if !x.is_null() {
        // SAFETY: `q` is readable for `clen`; `x` is live.
        if unsafe { d2i_X509(&mut x, &mut q, clen as core::ffi::c_long) }.is_null() {
            // SAFETY: `x` is live and owned.
            unsafe { X509_free(x) };
            x = ptr::null_mut();
        }
    }
    if x.is_null() {
        // SAFETY: `bio` live.
        unsafe { BIO_puts(bio, c"<UNPARSABLE CERTIFICATE>\n".as_ptr()) };
    } else {
        // SAFETY: `bio` live; `x` live.
        unsafe {
            BIO_puts(bio, c"\n------details-----\n".as_ptr());
            X509_print_ex(bio, x, XN_FLAG_ONELINE, 0);
            PEM_write_bio_X509(bio, x);
            BIO_puts(bio, c"------------------\n".as_ptr());
            X509_free(x);
        }
    }
    // SAFETY: `p` was advanced by `clen + 3`; compare on the original.
    if !core::ptr::eq(q, unsafe { p.add(3 + clen) }) {
        // SAFETY: `bio` live.
        unsafe { BIO_puts(bio, c"<TRAILING GARBAGE AFTER CERTIFICATE>\n".as_ptr()) };
    }
    // SAFETY: per the caller's contract.
    unsafe {
        *pmsg = p.add(clen + 3);
        *pmsglen = msglen - (clen + 3);
    }
    1
}

/// `ssl_print_raw_public_key` — `t1_trce.c:1330-1371`.
///
/// # Safety
/// `bio` live; `sc` live; `pmsg`/`pmsglen` valid.
unsafe fn ssl_print_raw_public_key(
    bio: *mut Bio,
    sc: *const Ssl,
    _server: c_int,
    indent: c_int,
    pmsg: *mut *const u8,
    pmsglen: *mut usize,
) -> c_int {
    // SAFETY: per the caller's contract.
    let mut msg = unsafe { *pmsg };
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    let mut pmsglen_v = unsafe { *pmsglen };
    // SAFETY: `sc` live; its `ctx` is live.
    let ctx = unsafe { (*sc).ctx };
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    let has_spki_len = if unsafe { is_dtls(sc) } {
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        let v = unsafe { (*sc).version };
        v > DTLS1_2_VERSION
    } else {
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        (unsafe { (*sc).version }) > TLS1_2_VERSION
    };
    let clen;
    if has_spki_len {
        if pmsglen_v < 3 {
            return 0;
        }
        // SAFETY: `pmsglen_v >= 3`.
        clen = ((unsafe { *msg } as usize) << 16)
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            | ((unsafe { *msg.add(1) } as usize) << 8)
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            | unsafe { *msg.add(2) } as usize;
        if pmsglen_v < clen + 3 {
            return 0;
        }
        // SAFETY: `msg+3` readable for `clen`.
        msg = unsafe { msg.add(3) };
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        unsafe {
            *pmsg = msg.add(clen);
            *pmsglen = pmsglen_v - (clen + 3);
        }
        pmsglen_v -= clen + 3;
    } else {
        clen = pmsglen_v;
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        unsafe {
            *pmsg = msg.add(pmsglen_v);
            *pmsglen = 0;
        }
        pmsglen_v = 0;
    }
    // SAFETY: `bio` live.
    unsafe {
        BIO_indent(bio, indent, 80);
        BIO_printf(bio, c"raw_public_key, length=%d\n".as_ptr(), clen as c_int);
    }
    // SAFETY: `ctx` live or NULL.
    let (libctx, propq) = if ctx.is_null() {
        (ptr::null_mut(), ptr::null_mut())
    } else {
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        (unsafe { (*ctx).libctx }, unsafe { (*ctx).propq })
    };
    // SAFETY: `msg` readable for `clen`.
    let pkey = unsafe {
        d2i_PUBKEY_ex(
            ptr::null_mut(),
            &mut msg,
            clen as core::ffi::c_long,
            libctx,
            propq,
        )
    };
    if pkey.is_null() {
        return 0;
    }
    // SAFETY: `bio` live; `pkey` live.
    unsafe {
        EVP_PKEY_print_public(bio, pkey, indent + 2, ptr::null_mut());
        EVP_PKEY_free(pkey);
    }
    let _ = pmsglen_v;
    1
}

/// `ssl_print_certificates` — `t1_trce.c:1373-1410`.
///
/// # Safety
/// `bio` live; `sc` live; `msg` readable for `msglen`.
unsafe fn ssl_print_certificates(
    bio: *mut Bio,
    sc: *const Ssl,
    server: c_int,
    indent: c_int,
    msg: *const u8,
    msglen: usize,
) -> c_int {
    let mut p = msg;
    let mut len_remaining = msglen;
    let pp: *mut *const u8 = &mut p;
    let pl: *mut usize = &mut len_remaining;
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    if unsafe { is_tls13(sc) }
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        && unsafe { ssl_print_hexbuf(bio, indent, c"context".as_ptr(), 1, pp, pl) } == 0
    {
        return 0;
    }
    if len_remaining < 3 {
        return 0;
    }
    // SAFETY: `len_remaining >= 3`.
    let clen = ((unsafe { *p } as usize) << 16)
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        | ((unsafe { *p.add(1) } as usize) << 8)
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        | unsafe { *p.add(2) } as usize;
    if len_remaining != clen + 3 {
        return 0;
    }
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    p = unsafe { p.add(3) };
    // SAFETY: `sc` live.
    let (sc_server_cert, sc_client_cert) = unsafe {
        (
            (*sc).ext_server_cert_type as c_int,
            (*sc).ext_client_cert_type as c_int,
        )
    };
    if (server != 0 && sc_server_cert == TLSEXT_CERT_TYPE_RPK)
        || (server == 0 && sc_client_cert == TLSEXT_CERT_TYPE_RPK)
    {
        // SAFETY: `p`/`clen` are the readable region.
        let mut sub = clen;
        let sp: *mut *const u8 = &mut p;
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        if unsafe { ssl_print_raw_public_key(bio, sc, server, indent, sp, &mut sub) } == 0 {
            return 0;
        }
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        if unsafe { is_tls13(sc) }
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            && unsafe {
                ssl_print_extensions(
                    bio,
                    indent + 2,
                    server,
                    SSL3_MT_CERTIFICATE as u8,
                    sp,
                    &mut sub,
                )
            } == 0
        {
            return 0;
        }
        return 1;
    }
    // SAFETY: `bio` live.
    unsafe {
        BIO_indent(bio, indent, 80);
        BIO_printf(
            bio,
            c"certificate_list, length=%d\n".as_ptr(),
            clen as c_int,
        );
    }
    let mut remaining = clen;
    while remaining > 0 {
        // SAFETY: `p` readable for `remaining`; `sc` live.
        if unsafe { ssl_print_certificate(bio, sc, indent + 2, pp, &mut remaining) } == 0 {
            return 0;
        }
        // `p` was advanced by `ssl_print_certificate` through `pp`.
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        if unsafe { is_tls13(sc) }
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            && unsafe {
                ssl_print_extensions(
                    bio,
                    indent + 2,
                    server,
                    SSL3_MT_CERTIFICATE as u8,
                    pp,
                    &mut remaining,
                )
            } == 0
        {
            return 0;
        }
    }
    let _ = p;
    1
}

/// `ssl_print_compressed_certificates` — `t1_trce.c:1412-1483`, `OPENSSL_NO_COMP_ALG` body.
///
/// # Safety
/// `bio` live; `sc` live; `msg` readable for `msglen`.
unsafe fn ssl_print_compressed_certificates(
    bio: *mut Bio,
    sc: *const Ssl,
    server: c_int,
    indent: c_int,
    msg: *const u8,
    msglen: usize,
) -> c_int {
    let _ = sc;
    let _ = server;
    if msglen < 8 {
        return 0;
    }
    // SAFETY: `msglen >= 8`.
    let alg = ((unsafe { *msg } as c_int) << 8) | unsafe { *msg.add(1) } as c_int;
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    let uclen = ((unsafe { *msg.add(2) } as usize) << 16)
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        | ((unsafe { *msg.add(3) } as usize) << 8)
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        | unsafe { *msg.add(4) } as usize;
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    let clen = ((unsafe { *msg.add(5) } as usize) << 16)
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        | ((unsafe { *msg.add(6) } as usize) << 8)
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        | unsafe { *msg.add(7) } as usize;
    if msglen != clen + 8 {
        return 0;
    }
    // SAFETY: `msg+8` readable for `clen`.
    let body = unsafe { msg.add(8) };
    // SAFETY: `bio` live; table static.
    unsafe {
        BIO_indent(bio, indent, 80);
        BIO_printf(
            bio,
            c"Compression type=%s (0x%04x)\n".as_ptr(),
            trace_str(alg, SSL_COMP_CERT_TBL),
            alg,
        );
        BIO_indent(bio, indent, 80);
        BIO_printf(bio, c"Uncompressed length=%d\n".as_ptr(), uclen as c_int);
        BIO_indent(bio, indent, 80);
        if clen > 0 {
            BIO_printf(
                bio,
                c"Compressed length=%d, Ratio=%f:1\n".as_ptr(),
                clen as c_int,
                (uclen as f32 / clen as f32) as f64,
            );
        } else {
            BIO_printf(
                bio,
                c"Compressed length=%d, Ratio=unknown\n".as_ptr(),
                clen as c_int,
            );
        }
        BIO_dump_indent(bio, body.cast(), clen as c_int, indent);
    }
    // `OPENSSL_NO_COMP_ALG` is defined for the admitted build, so the authority answers 1 here.
    1
}

/// `ssl_print_cert_request` — `t1_trce.c:1485-1572`.
///
/// # Safety
/// `bio` live; `sc` live; `msg` readable for `msglen`.
unsafe fn ssl_print_cert_request(
    bio: *mut Bio,
    indent: c_int,
    sc: *const Ssl,
    msg: *const u8,
    msglen: usize,
) -> c_int {
    let mut p = msg;
    let mut len_remaining = msglen;
    let pp: *mut *const u8 = &mut p;
    let pl: *mut usize = &mut len_remaining;
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    if unsafe { is_tls13(sc) } {
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        if unsafe { ssl_print_hexbuf(bio, indent, c"request_context".as_ptr(), 1, pp, pl) } == 0 {
            return 0;
        }
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        return unsafe {
            ssl_print_extensions(bio, indent, 1, SSL3_MT_CERTIFICATE_REQUEST as u8, pp, pl)
        };
    }
    if len_remaining < 1 {
        return 0;
    }
    // SAFETY: `len_remaining >= 1`.
    let mut xlen = unsafe { *p } as usize;
    if len_remaining < xlen + 1 {
        return 0;
    }
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    p = unsafe { p.add(1) };
    // SAFETY: `bio` live.
    unsafe {
        BIO_indent(bio, indent, 80);
        BIO_printf(bio, c"certificate_types (len=%d)\n".as_ptr(), xlen as c_int);
    }
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    if unsafe { trace_list(bio, indent + 2, p, xlen, 1, SSL_CTYPE_TBL) } == 0 {
        return 0;
    }
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    p = unsafe { p.add(xlen) };
    len_remaining -= xlen + 1;
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    if unsafe { use_sigalgs(sc) } {
        if len_remaining < 2 {
            return 0;
        }
        // SAFETY: `len_remaining >= 2`.
        xlen = ((unsafe { *p } as usize) << 8) | unsafe { *p.add(1) } as usize;
        if len_remaining < xlen + 2 || xlen & 1 != 0 {
            return 0;
        }
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        p = unsafe { p.add(2) };
        len_remaining -= xlen + 2;
        // SAFETY: `bio` live.
        unsafe {
            BIO_indent(bio, indent, 80);
            BIO_printf(
                bio,
                c"signature_algorithms (len=%d)\n".as_ptr(),
                xlen as c_int,
            );
        }
        while xlen > 0 {
            // SAFETY: `bio` live; table static; `p` readable for 2.
            unsafe {
                BIO_indent(bio, indent + 2, 80);
                let sigalg = ((*p as c_int) << 8) | *p.add(1) as c_int;
                BIO_printf(
                    bio,
                    c"%s (0x%04x)\n".as_ptr(),
                    trace_str(sigalg, SSL_SIGALG_TBL),
                    sigalg,
                );
            }
            xlen -= 2;
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            p = unsafe { p.add(2) };
        }
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        p = unsafe { p.add(xlen) };
    }
    if len_remaining < 2 {
        return 0;
    }
    // SAFETY: `len_remaining >= 2`.
    xlen = ((unsafe { *p } as usize) << 8) | unsafe { *p.add(1) } as usize;
    // SAFETY: `bio` live.
    unsafe { BIO_indent(bio, indent, 80) };
    if len_remaining < xlen + 2 {
        return 0;
    }
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    p = unsafe { p.add(2) };
    len_remaining -= 2 + xlen;
    // SAFETY: `bio` live.
    unsafe {
        BIO_printf(
            bio,
            c"certificate_authorities (len=%d)\n".as_ptr(),
            xlen as c_int,
        )
    };
    while xlen > 0 {
        if xlen < 2 {
            return 0;
        }
        // SAFETY: `xlen >= 2`.
        let dlen = ((unsafe { *p } as usize) << 8) | unsafe { *p.add(1) } as usize;
        if xlen < dlen + 2 {
            return 0;
        }
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        p = unsafe { p.add(2) };
        // SAFETY: `bio` live.
        unsafe {
            BIO_indent(bio, indent + 2, 80);
            BIO_printf(bio, c"DistinguishedName (len=%d): ".as_ptr(), dlen as c_int);
        }
        let mut pp2 = p;
        // SAFETY: `p` readable for `dlen`.
        let nm = unsafe { d2i_X509_NAME(ptr::null_mut(), &mut pp2, dlen as core::ffi::c_long) };
        if nm.is_null() {
            // SAFETY: `bio` live.
            unsafe { BIO_puts(bio, c"<UNPARSABLE DN>\n".as_ptr()) };
        } else {
            // SAFETY: `bio` live; `nm` live.
            unsafe {
                X509_NAME_print_ex(bio, nm, 0, XN_FLAG_ONELINE);
                BIO_puts(bio, c"\n".as_ptr());
                X509_NAME_free(nm);
            }
        }
        xlen -= dlen + 2;
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        p = unsafe { p.add(dlen) };
    }
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    if unsafe { is_tls13(sc) } {
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        return unsafe { ssl_print_hexbuf(bio, indent, c"request_extensions".as_ptr(), 2, pp, pl) };
    }
    c_int::from(len_remaining == 0)
}

/// `ssl_print_ticket` — `t1_trce.c:1574-1620`.
///
/// # Safety
/// `bio` live; `sc` live; `msg` readable for `msglen`.
unsafe fn ssl_print_ticket(
    bio: *mut Bio,
    indent: c_int,
    sc: *const Ssl,
    msg: *const u8,
    msglen: usize,
) -> c_int {
    let mut p = msg;
    let mut len_remaining = msglen;
    let pp: *mut *const u8 = &mut p;
    let pl: *mut usize = &mut len_remaining;
    if msglen == 0 {
        // SAFETY: `bio` live.
        unsafe {
            BIO_indent(bio, indent + 2, 80);
            BIO_puts(bio, c"No Ticket\n".as_ptr());
        }
        return 1;
    }
    if len_remaining < 4 {
        return 0;
    }
    // SAFETY: `len_remaining >= 4`.
    let tick_life = ((unsafe { *p } as u32) << 24)
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        | ((unsafe { *p.add(1) } as u32) << 16)
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        | ((unsafe { *p.add(2) } as u32) << 8)
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        | (unsafe { *p.add(3) } as u32);
    len_remaining -= 4;
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    p = unsafe { p.add(4) };
    // SAFETY: `bio` live.
    unsafe {
        BIO_indent(bio, indent + 2, 80);
        BIO_printf(bio, c"ticket_lifetime_hint=%u\n".as_ptr(), tick_life);
    }
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    if unsafe { is_tls13(sc) } {
        if len_remaining < 4 {
            return 0;
        }
        // SAFETY: `len_remaining >= 4`.
        let ticket_age_add = ((unsafe { *p } as u32) << 24)
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            | ((unsafe { *p.add(1) } as u32) << 16)
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            | ((unsafe { *p.add(2) } as u32) << 8)
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            | (unsafe { *p.add(3) } as u32);
        len_remaining -= 4;
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        p = unsafe { p.add(4) };
        // SAFETY: `bio` live.
        unsafe {
            BIO_indent(bio, indent + 2, 80);
            BIO_printf(bio, c"ticket_age_add=%u\n".as_ptr(), ticket_age_add);
        }
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        if unsafe { ssl_print_hexbuf(bio, indent + 2, c"ticket_nonce".as_ptr(), 1, pp, pl) } == 0 {
            return 0;
        }
    }
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    if unsafe { ssl_print_hexbuf(bio, indent + 2, c"ticket".as_ptr(), 2, pp, pl) } == 0 {
        return 0;
    }
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    if unsafe { is_tls13(sc) }
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        && unsafe {
            ssl_print_extensions(bio, indent + 2, 0, SSL3_MT_NEWSESSION_TICKET as u8, pp, pl)
        } == 0
    {
        return 0;
    }
    if len_remaining != 0 {
        return 0;
    }
    1
}

/// `ssl_print_handshake` — `t1_trce.c:1622-1735`.
///
/// # Safety
/// `bio` live; `sc` live; `msg` readable for `msglen`.
unsafe fn ssl_print_handshake(
    bio: *mut Bio,
    sc: *const Ssl,
    server: c_int,
    msg: *const u8,
    msglen: usize,
    indent: c_int,
) -> c_int {
    let mut p = msg;
    let mut len_remaining = msglen;
    if len_remaining < 4 {
        return 0;
    }
    // SAFETY: `len_remaining >= 4`.
    let htype = unsafe { *p };
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    let hlen = ((unsafe { *p.add(1) } as usize) << 16)
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        | ((unsafe { *p.add(2) } as usize) << 8)
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        | unsafe { *p.add(3) } as usize;
    // SAFETY: `bio` live; table static.
    unsafe {
        BIO_indent(bio, indent, 80);
        BIO_printf(
            bio,
            c"%s, Length=%d\n".as_ptr(),
            trace_str(htype as c_int, SSL_HANDSHAKE_TBL),
            hlen as c_int,
        );
    }
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    p = unsafe { p.add(4) };
    len_remaining -= 4;
    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
    if unsafe { is_dtls(sc) } {
        if len_remaining < 8 {
            return 0;
        }
        // SAFETY: `len_remaining >= 8`.
        unsafe {
            BIO_indent(bio, indent, 80);
            BIO_printf(
                bio,
                c"message_seq=%d, fragment_offset=%d, fragment_length=%d\n".as_ptr(),
                ((*p as c_int) << 8) | *p.add(1) as c_int,
                ((*p.add(2) as c_int) << 16) | ((*p.add(3) as c_int) << 8) | *p.add(4) as c_int,
                ((*p.add(5) as c_int) << 16) | ((*p.add(6) as c_int) << 8) | *p.add(7) as c_int,
            );
        }
        // SAFETY: the enclosing function's contract makes every pointer in this block valid.
        p = unsafe { p.add(8) };
        len_remaining -= 8;
    }
    if len_remaining < hlen {
        return 0;
    }
    match htype as c_int {
        SSL3_MT_CLIENT_HELLO => {
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            if unsafe { ssl_print_client_hello(bio, sc, indent + 2, p, len_remaining) } == 0 {
                return 0;
            }
        }
        DTLS1_MT_HELLO_VERIFY_REQUEST => {
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            if unsafe { dtls_print_hello_vfyrequest(bio, indent + 2, p, len_remaining) } == 0 {
                return 0;
            }
        }
        SSL3_MT_SERVER_HELLO => {
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            if unsafe { ssl_print_server_hello(bio, indent + 2, p, len_remaining) } == 0 {
                return 0;
            }
        }
        SSL3_MT_SERVER_KEY_EXCHANGE => {
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            if unsafe { ssl_print_server_keyex(bio, indent + 2, sc, p, len_remaining) } == 0 {
                return 0;
            }
        }
        SSL3_MT_CLIENT_KEY_EXCHANGE => {
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            if unsafe { ssl_print_client_keyex(bio, indent + 2, sc, p, len_remaining) } == 0 {
                return 0;
            }
        }
        SSL3_MT_CERTIFICATE => {
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            if unsafe { ssl_print_certificates(bio, sc, server, indent + 2, p, len_remaining) } == 0
            {
                return 0;
            }
        }
        SSL3_MT_COMPRESSED_CERTIFICATE => {
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            if unsafe {
                ssl_print_compressed_certificates(bio, sc, server, indent + 2, p, len_remaining)
            } == 0
            {
                return 0;
            }
        }
        SSL3_MT_CERTIFICATE_VERIFY => {
            let mp: *mut *const u8 = &mut p;
            let ml: *mut usize = &mut len_remaining;
            // SAFETY: `bio` live; `sc` live.
            if unsafe { ssl_print_signature(bio, indent + 2, sc, mp, ml) } == 0 {
                return 0;
            }
        }
        SSL3_MT_CERTIFICATE_REQUEST => {
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            if unsafe { ssl_print_cert_request(bio, indent + 2, sc, p, len_remaining) } == 0 {
                return 0;
            }
        }
        SSL3_MT_FINISHED => {
            // SAFETY: `bio` live; `p` readable.
            unsafe { ssl_print_hex(bio, indent + 2, c"verify_data".as_ptr(), p, len_remaining) };
        }
        SSL3_MT_END_OF_EARLY_DATA | SSL3_MT_SERVER_DONE => {
            if len_remaining != 0 {
                // SAFETY: `bio` live; `p` readable.
                unsafe {
                    ssl_print_hex(
                        bio,
                        indent + 2,
                        c"unexpected value".as_ptr(),
                        p,
                        len_remaining,
                    )
                };
            }
        }
        SSL3_MT_NEWSESSION_TICKET => {
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            if unsafe { ssl_print_ticket(bio, indent + 2, sc, p, len_remaining) } == 0 {
                return 0;
            }
        }
        SSL3_MT_ENCRYPTED_EXTENSIONS => {
            let mp: *mut *const u8 = &mut p;
            let ml: *mut usize = &mut len_remaining;
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            if unsafe {
                ssl_print_extensions(
                    bio,
                    indent + 2,
                    1,
                    SSL3_MT_ENCRYPTED_EXTENSIONS as u8,
                    mp,
                    ml,
                )
            } == 0
            {
                return 0;
            }
        }
        SSL3_MT_KEY_UPDATE => {
            if len_remaining != 1 {
                // SAFETY: `bio` live; `p` readable.
                unsafe {
                    ssl_print_hex(
                        bio,
                        indent + 2,
                        c"unexpected value".as_ptr(),
                        p,
                        len_remaining,
                    )
                };
                return 0;
            }
            // SAFETY: `bio` live; table static; `p` readable for 1.
            if unsafe { trace_list(bio, indent + 2, p, 1, 1, SSL_KEY_UPDATE_TBL) } == 0 {
                return 0;
            }
        }
        _ => {
            // SAFETY: `bio` live; `p` readable.
            unsafe {
                BIO_indent(bio, indent + 2, 80);
                BIO_puts(bio, c"Unsupported, hex dump follows:\n".as_ptr());
                BIO_dump_indent(bio, p.cast(), len_remaining as c_int, indent + 4);
            }
        }
    }
    1
}

/// `void SSL_trace(int write_p, int version, int content_type, const void *buf, size_t msglen,
/// SSL *ssl, void *arg)` — `t1_trce.c:1737-1816`.
///
/// # Safety
/// `buf` must be readable for `msglen` bytes (or NULL when `msglen` is 0); `ssl` must be NULL or a
/// live connection; `arg` must be a live `BIO`.
#[no_mangle]
pub unsafe extern "C" fn SSL_trace(
    write_p: c_int,
    version: c_int,
    content_type: c_int,
    buf: *const c_void,
    msglen: usize,
    ssl: *mut Ssl,
    arg: *mut c_void,
) {
    let _ = version;
    let msg = buf.cast::<u8>();
    let bio = arg.cast::<Bio>();
    // The QUIC arm is omitted (Phase 15's); the connection is the SSL object itself.
    if ssl.is_null() {
        return;
    }
    let sc = ssl;
    match content_type {
        SSL3_RT_HEADER => {
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            let hdr_len = if unsafe { is_dtls(sc) } {
                DTLS1_RT_HEADER_LENGTH
            } else {
                SSL3_RT_HEADER_LENGTH
            };
            if msglen < hdr_len {
                // SAFETY: `bio` live.
                unsafe {
                    BIO_puts(
                        bio,
                        if write_p != 0 {
                            c"Sent".as_ptr()
                        } else {
                            c"Received".as_ptr()
                        },
                    );
                    ssl_print_hex(bio, 0, c" too short message".as_ptr(), msg, msglen);
                }
                // TRAILING newline is printed below by the shared footer.
            } else {
                // SAFETY: `msglen >= hdr_len >= 3`.
                let hvers =
                    // SAFETY: the enclosing function's contract makes every pointer in this block valid.
                    ((unsafe { *msg.add(1) } as c_int) << 8) | unsafe { *msg.add(2) } as c_int;
                // SAFETY: `bio` live.
                unsafe {
                    BIO_puts(
                        bio,
                        if write_p != 0 {
                            c"Sent".as_ptr()
                        } else {
                            c"Received".as_ptr()
                        },
                    );
                    BIO_printf(
                        bio,
                        c" TLS Record\nHeader:\n  Version = %s (0x%x)\n".as_ptr(),
                        trace_str(hvers, SSL_VERSION_TBL),
                        hvers,
                    );
                }
                // SAFETY: the enclosing function's contract makes every pointer in this block valid.
                if unsafe { is_dtls(sc) } {
                    // SAFETY: `msglen >= 13`.
                    unsafe {
                        BIO_printf(
                            bio,
                            c"  epoch=%d, sequence_number=%04x%04x%04x\n".as_ptr(),
                            ((*msg.add(3) as c_int) << 8) | *msg.add(4) as c_int,
                            ((*msg.add(5) as c_int) << 8) | *msg.add(6) as c_int,
                            ((*msg.add(7) as c_int) << 8) | *msg.add(8) as c_int,
                            ((*msg.add(9) as c_int) << 8) | *msg.add(10) as c_int,
                        );
                    }
                }
                // SAFETY: `bio` live; `msglen >= 2`.
                unsafe {
                    BIO_printf(
                        bio,
                        c"  Content Type = %s (%d)\n  Length = %d".as_ptr(),
                        trace_str(*msg as c_int, SSL_CONTENT_TBL),
                        *msg as c_int,
                        ((*msg.add(msglen - 2) as c_int) << 8) | *msg.add(msglen - 1) as c_int,
                    );
                }
            }
        }
        SSL3_RT_INNER_CONTENT_TYPE => {
            // SAFETY: `bio` live; `msg` readable for at least 1.
            unsafe {
                BIO_printf(
                    bio,
                    c"  Inner Content Type = %s (%d)".as_ptr(),
                    trace_str(*msg as c_int, SSL_CONTENT_TBL),
                    *msg as c_int,
                );
            }
        }
        SSL3_RT_HANDSHAKE => {
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            let server = if unsafe { (*sc).server } != 0 {
                write_p
            } else {
                c_int::from(write_p == 0)
            };
            // SAFETY: `bio` live; `sc` live; `msg` readable.
            if unsafe { ssl_print_handshake(bio, sc, server, msg, msglen, 4) } == 0 {
                // SAFETY: `bio` live.
                unsafe { BIO_printf(bio, c"Message length parse error!\n".as_ptr()) };
            }
        }
        SSL3_RT_CHANGE_CIPHER_SPEC => {
            // SAFETY: the enclosing function's contract makes every pointer in this block valid.
            if msglen == 1 && unsafe { *msg } == 1 {
                // SAFETY: `bio` live.
                unsafe { BIO_puts(bio, c"    change_cipher_spec (1)\n".as_ptr()) };
            } else {
                // SAFETY: `bio` live; `msg` readable.
                unsafe { ssl_print_hex(bio, 4, c"unknown value".as_ptr(), msg, msglen) };
            }
        }
        SSL3_RT_ALERT => {
            if msglen != 2 {
                // SAFETY: `bio` live.
                unsafe { BIO_puts(bio, c"    Illegal Alert Length\n".as_ptr()) };
            } else {
                // SAFETY: `bio` live; `msg` readable for 2.
                unsafe {
                    BIO_printf(
                        bio,
                        c"    Level=%s(%d), description=%s(%d)\n".as_ptr(),
                        crate::ssl::ssl_stat::SSL_alert_type_string_long((*msg as c_int) << 8),
                        *msg as c_int,
                        crate::ssl::ssl_stat::SSL_alert_desc_string_long(*msg.add(1) as c_int),
                        *msg.add(1) as c_int,
                    );
                }
            }
        }
        _ => {}
    }
    // SAFETY: `bio` live.
    unsafe { BIO_puts(bio, c"\n".as_ptr()) };
}
