//! Phase 4 — BIO, the I/O abstraction.
//!
//! `BIO` is OpenSSL's universal I/O object: every read, write, buffer, filter,
//! socket, file and memory buffer in the library is one. It is deliberately built
//! before the object database's consumers, the key parsers and the protocol
//! state machines, because all of them are *expressed* in BIOs.
//!
//! ## What this module is, and what it is not
//!
//! This is the core object model and the dispatch layer: the [`Bio`] structure,
//! the method table ([`BioMethod`]), reference counting, chain management,
//! callbacks, flags, retry state, `ex_data`, and the read/write/ctrl entry points
//! that route through a method. The concrete methods live in the sibling modules
//! (`bss_mem`, `bss_file`, `bf_buff`, …).
//!
//! ## Opacity
//!
//! `BIO` and `BIO_METHOD` are opaque in the installed headers — `bio.h` carries
//! only `typedef struct bio_st BIO;` and `typedef struct bio_method_st
//! BIO_METHOD;`. Their layout is therefore *not* ABI, and this module takes
//! advantage of that: the reference count is a real atomic, the slots are
//! ordinary Rust fields, and the chain is raw pointers because the C API hands
//! them out. What *is* ABI is every function's signature, every constant, and
//! every observable behaviour, and those are reproduced exactly.
//!
//! ## Why the behaviours are measured
//!
//! BIO has an unusually large amount of "what happens if this call is made now?"
//! contract: `BIO_read` on an empty memory BIO, `BIO_write` to a full pair,
//! `BIO_ctrl` on a method with no ctrl, `BIO_free` invoking the free callback,
//! `BIO_push`/`BIO_pop` rewiring `next`/`prev`, `BIO_copy_next_retry`, and the
//! `num_read`/`num_write` counters. None of that is derivable from the header, so
//! `courts/phase4/rt_bio*_probe.c` measure it differentially and the
//! `RT-BIO*` courts compare the two executions. Where the authority *faults*
//! (`BIO_free(BIO_new(BIO_s_core()))`) the probe records a
//! `NOT_MEASURED_AUTHORITY_FAULTS` marker and the safer behaviour is recorded in
//! `docs/SECURITY_DIVERGENCE_POLICY.md` rather than reproduced.
//!
//! ## No panic may cross the boundary
//!
//! Every exported function wraps its body in [`guard_ffi`], so a defect returns
//! the documented failure value instead of unwinding into C
//! (`docs/UNSAFE.md` §3). The `// SAFETY:` comments on each `unsafe` block state
//! the invariant the caller must hold; they are not decoration
//! (`docs/UNSAFE.md` §4).

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::ffi::guard_ffi;
use crate::runtime::ex_data::{
    CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data, CRYPTO_set_ex_data, CryptoExData,
    CRYPTO_EX_INDEX_BIO,
};

pub mod addr;
pub mod addr_info;
pub mod bf_null;
pub mod bio_cb;
pub mod bio_sock2;
pub mod bss_mem;
pub mod bss_null;
pub mod bss_sock;
pub mod comp;
pub mod dump;
pub mod iolib;
pub mod legacy_host;
pub mod method;
pub mod print;
pub mod retry;
pub mod sys;

// ---------------------------------------------------------------------------
// Constants, from the installed `bio.h`
// ---------------------------------------------------------------------------

/// `BIO_TYPE_DESCRIPTOR`.
pub const BIO_TYPE_DESCRIPTOR: c_int = 0x0100;
/// `BIO_TYPE_FILTER`.
pub const BIO_TYPE_FILTER: c_int = 0x0200;
/// `BIO_TYPE_SOURCE_SINK`.
pub const BIO_TYPE_SOURCE_SINK: c_int = 0x0400;
/// `BIO_TYPE_NONE`.
pub const BIO_TYPE_NONE: c_int = 0;
/// `BIO_TYPE_START` — where custom method types begin.
pub const BIO_TYPE_START: c_int = 128;
/// `BIO_TYPE_MASK` — the largest value `BIO_get_new_index` will return.
pub const BIO_TYPE_MASK: c_int = 0xFF;

/// `BIO_TYPE_MEM`.
pub const BIO_TYPE_MEM: c_int = 1 | BIO_TYPE_SOURCE_SINK;
/// `BIO_TYPE_FILE`.
pub const BIO_TYPE_FILE: c_int = 2 | BIO_TYPE_SOURCE_SINK;
/// `BIO_TYPE_FD`.
pub const BIO_TYPE_FD: c_int = 4 | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR;
/// `BIO_TYPE_SOCKET`.
pub const BIO_TYPE_SOCKET: c_int = 5 | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR;
/// `BIO_TYPE_NULL`.
pub const BIO_TYPE_NULL: c_int = 6 | BIO_TYPE_SOURCE_SINK;
/// `BIO_TYPE_SSL`.
pub const BIO_TYPE_SSL: c_int = 7 | BIO_TYPE_FILTER;
/// `BIO_TYPE_MD`.
pub const BIO_TYPE_MD: c_int = 8 | BIO_TYPE_FILTER;
/// `BIO_TYPE_BUFFER`.
pub const BIO_TYPE_BUFFER: c_int = 9 | BIO_TYPE_FILTER;
/// `BIO_TYPE_CIPHER`.
pub const BIO_TYPE_CIPHER: c_int = 10 | BIO_TYPE_FILTER;
/// `BIO_TYPE_BASE64`.
pub const BIO_TYPE_BASE64: c_int = 11 | BIO_TYPE_FILTER;
/// `BIO_TYPE_CONNECT`.
pub const BIO_TYPE_CONNECT: c_int = 12 | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR;
/// `BIO_TYPE_ACCEPT`.
pub const BIO_TYPE_ACCEPT: c_int = 13 | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR;
/// `BIO_TYPE_NBIO_TEST`.
pub const BIO_TYPE_NBIO_TEST: c_int = 16 | BIO_TYPE_FILTER;
/// `BIO_TYPE_NULL_FILTER`.
pub const BIO_TYPE_NULL_FILTER: c_int = 17 | BIO_TYPE_FILTER;
/// `BIO_TYPE_BIO`.
pub const BIO_TYPE_BIO: c_int = 19 | BIO_TYPE_SOURCE_SINK;
/// `BIO_TYPE_LINEBUFFER`.
pub const BIO_TYPE_LINEBUFFER: c_int = 20 | BIO_TYPE_FILTER;
/// `BIO_TYPE_DGRAM`.
pub const BIO_TYPE_DGRAM: c_int = 21 | BIO_TYPE_SOURCE_SINK | BIO_TYPE_DESCRIPTOR;
/// `BIO_TYPE_ASN1`.
pub const BIO_TYPE_ASN1: c_int = 22 | BIO_TYPE_FILTER;
/// `BIO_TYPE_COMP`.
pub const BIO_TYPE_COMP: c_int = 23 | BIO_TYPE_FILTER;
/// `BIO_TYPE_CORE_TO_PROV`.
pub const BIO_TYPE_CORE_TO_PROV: c_int = 25 | BIO_TYPE_SOURCE_SINK;
/// `BIO_TYPE_DGRAM_PAIR`.
pub const BIO_TYPE_DGRAM_PAIR: c_int = 26 | BIO_TYPE_SOURCE_SINK;
/// `BIO_TYPE_DGRAM_MEM`.
pub const BIO_TYPE_DGRAM_MEM: c_int = 27 | BIO_TYPE_SOURCE_SINK;

/// `BIO_NOCLOSE`.
pub const BIO_NOCLOSE: c_int = 0x00;
/// `BIO_CLOSE`.
pub const BIO_CLOSE: c_int = 0x01;

/// `BIO_FLAGS_READ`.
pub const BIO_FLAGS_READ: c_int = 0x01;
/// `BIO_FLAGS_WRITE`.
pub const BIO_FLAGS_WRITE: c_int = 0x02;
/// `BIO_FLAGS_IO_SPECIAL`.
pub const BIO_FLAGS_IO_SPECIAL: c_int = 0x04;
/// `BIO_FLAGS_RWS`.
pub const BIO_FLAGS_RWS: c_int = BIO_FLAGS_READ | BIO_FLAGS_WRITE | BIO_FLAGS_IO_SPECIAL;
/// `BIO_FLAGS_SHOULD_RETRY`.
pub const BIO_FLAGS_SHOULD_RETRY: c_int = 0x08;
/// `BIO_FLAGS_BASE64_NO_NL`.
pub const BIO_FLAGS_BASE64_NO_NL: c_int = 0x100;
/// `BIO_FLAGS_MEM_RDONLY`.
pub const BIO_FLAGS_MEM_RDONLY: c_int = 0x200;
/// `BIO_FLAGS_NONCLEAR_RST`.
pub const BIO_FLAGS_NONCLEAR_RST: c_int = 0x400;
/// `BIO_FLAGS_IN_EOF`.
pub const BIO_FLAGS_IN_EOF: c_int = 0x800;
/// `BIO_FLAGS_DGRAM` — the flag a datagram BIO sets on its method data.
pub const BIO_FLAGS_DGRAM: c_int = 0x20;

/// `BIO_CTRL_RESET`.
pub const BIO_CTRL_RESET: c_int = 1;
/// `BIO_CTRL_EOF`.
pub const BIO_CTRL_EOF: c_int = 2;
/// `BIO_CTRL_INFO`.
pub const BIO_CTRL_INFO: c_int = 3;
/// `BIO_CTRL_SET`.
pub const BIO_CTRL_SET: c_int = 4;
/// `BIO_CTRL_GET`.
pub const BIO_CTRL_GET: c_int = 5;
/// `BIO_CTRL_PUSH`.
pub const BIO_CTRL_PUSH: c_int = 6;
/// `BIO_CTRL_POP`.
pub const BIO_CTRL_POP: c_int = 7;
/// `BIO_CTRL_GET_CLOSE`.
pub const BIO_CTRL_GET_CLOSE: c_int = 8;
/// `BIO_CTRL_SET_CLOSE`.
pub const BIO_CTRL_SET_CLOSE: c_int = 9;
/// `BIO_CTRL_PENDING`.
pub const BIO_CTRL_PENDING: c_int = 10;
/// `BIO_CTRL_FLUSH`.
pub const BIO_CTRL_FLUSH: c_int = 11;
/// `BIO_CTRL_DUP`.
pub const BIO_CTRL_DUP: c_int = 12;
/// `BIO_CTRL_WPENDING`.
pub const BIO_CTRL_WPENDING: c_int = 13;
/// `BIO_CTRL_SET_CALLBACK`.
pub const BIO_CTRL_SET_CALLBACK: c_int = 14;
/// `BIO_CTRL_GET_CALLBACK`.
pub const BIO_CTRL_GET_CALLBACK: c_int = 15;
/// `BIO_CTRL_PEEK`.
pub const BIO_CTRL_PEEK: c_int = 29;
/// `BIO_CTRL_SET_FILENAME`.
pub const BIO_CTRL_SET_FILENAME: c_int = 30;

/// `BIO_CTRL_DGRAM_CONNECT`.
pub const BIO_CTRL_DGRAM_CONNECT: c_int = 31;
/// `BIO_CTRL_DGRAM_SET_CONNECTED`.
pub const BIO_CTRL_DGRAM_SET_CONNECTED: c_int = 32;
/// `BIO_CTRL_DGRAM_SET_RECV_TIMEOUT`.
pub const BIO_CTRL_DGRAM_SET_RECV_TIMEOUT: c_int = 33;
/// `BIO_CTRL_DGRAM_GET_RECV_TIMEOUT`.
pub const BIO_CTRL_DGRAM_GET_RECV_TIMEOUT: c_int = 34;
/// `BIO_CTRL_DGRAM_SET_SEND_TIMEOUT`.
pub const BIO_CTRL_DGRAM_SET_SEND_TIMEOUT: c_int = 35;
/// `BIO_CTRL_DGRAM_GET_SEND_TIMEOUT`.
pub const BIO_CTRL_DGRAM_GET_SEND_TIMEOUT: c_int = 36;
/// `BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP`.
pub const BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP: c_int = 37;
/// `BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP`.
pub const BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP: c_int = 38;
/// `BIO_CTRL_DGRAM_MTU_DISCOVER`.
pub const BIO_CTRL_DGRAM_MTU_DISCOVER: c_int = 39;
/// `BIO_CTRL_DGRAM_QUERY_MTU`.
pub const BIO_CTRL_DGRAM_QUERY_MTU: c_int = 40;
/// `BIO_CTRL_DGRAM_GET_MTU`.
pub const BIO_CTRL_DGRAM_GET_MTU: c_int = 41;
/// `BIO_CTRL_DGRAM_SET_MTU`.
pub const BIO_CTRL_DGRAM_SET_MTU: c_int = 42;
/// `BIO_CTRL_DGRAM_MTU_EXCEEDED`.
pub const BIO_CTRL_DGRAM_MTU_EXCEEDED: c_int = 43;
/// `BIO_CTRL_DGRAM_SET_PEER`.
pub const BIO_CTRL_DGRAM_SET_PEER: c_int = 44;
/// `BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT`.
pub const BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT: c_int = 45;
/// `BIO_CTRL_DGRAM_GET_PEER`.
pub const BIO_CTRL_DGRAM_GET_PEER: c_int = 46;
/// `BIO_CTRL_DGRAM_GET_FALLBACK_MTU`.
pub const BIO_CTRL_DGRAM_GET_FALLBACK_MTU: c_int = 47;
/// `BIO_CTRL_DGRAM_SET_DONT_FRAG`.
pub const BIO_CTRL_DGRAM_SET_DONT_FRAG: c_int = 48;
/// `BIO_CTRL_DGRAM_GET_MTU_OVERHEAD`.
pub const BIO_CTRL_DGRAM_GET_MTU_OVERHEAD: c_int = 49;
/// `BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE`.
pub const BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE: c_int = 50;
/// `BIO_CTRL_DGRAM_SET_PEEK_MODE`.
pub const BIO_CTRL_DGRAM_SET_PEEK_MODE: c_int = 71;
/// `BIO_CTRL_GET_KTLS_SEND`.
pub const BIO_CTRL_GET_KTLS_SEND: c_int = 73;
/// `BIO_CTRL_GET_KTLS_RECV`.
pub const BIO_CTRL_GET_KTLS_RECV: c_int = 76;
/// `BIO_CTRL_SET_PREFIX`.
pub const BIO_CTRL_SET_PREFIX: c_int = 79;
/// `BIO_CTRL_SET_INDENT`.
pub const BIO_CTRL_SET_INDENT: c_int = 80;
/// `BIO_CTRL_GET_INDENT`.
pub const BIO_CTRL_GET_INDENT: c_int = 81;
/// `BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP`.
pub const BIO_CTRL_DGRAM_GET_LOCAL_ADDR_CAP: c_int = 82;
/// `BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE`.
pub const BIO_CTRL_DGRAM_GET_LOCAL_ADDR_ENABLE: c_int = 83;
/// `BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE`.
pub const BIO_CTRL_DGRAM_SET_LOCAL_ADDR_ENABLE: c_int = 84;
/// `BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS`.
pub const BIO_CTRL_DGRAM_GET_EFFECTIVE_CAPS: c_int = 85;
/// `BIO_CTRL_DGRAM_GET_CAPS`.
pub const BIO_CTRL_DGRAM_GET_CAPS: c_int = 86;
/// `BIO_CTRL_DGRAM_SET_CAPS`.
pub const BIO_CTRL_DGRAM_SET_CAPS: c_int = 87;
/// `BIO_CTRL_DGRAM_GET_NO_TRUNC`.
pub const BIO_CTRL_DGRAM_GET_NO_TRUNC: c_int = 88;
/// `BIO_CTRL_DGRAM_SET_NO_TRUNC`.
pub const BIO_CTRL_DGRAM_SET_NO_TRUNC: c_int = 89;
/// `BIO_CTRL_GET_RPOLL_DESCRIPTOR`.
pub const BIO_CTRL_GET_RPOLL_DESCRIPTOR: c_int = 91;
/// `BIO_CTRL_GET_WPOLL_DESCRIPTOR`.
pub const BIO_CTRL_GET_WPOLL_DESCRIPTOR: c_int = 92;
/// `BIO_CTRL_DGRAM_DETECT_PEER_ADDR`.
pub const BIO_CTRL_DGRAM_DETECT_PEER_ADDR: c_int = 93;
/// `BIO_CTRL_DGRAM_SET0_LOCAL_ADDR`.
pub const BIO_CTRL_DGRAM_SET0_LOCAL_ADDR: c_int = 94;

/// `BIO_CB_FREE`.
pub const BIO_CB_FREE: c_int = 0x01;
/// `BIO_CB_READ`.
pub const BIO_CB_READ: c_int = 0x02;
/// `BIO_CB_WRITE`.
pub const BIO_CB_WRITE: c_int = 0x03;
/// `BIO_CB_PUTS`.
pub const BIO_CB_PUTS: c_int = 0x04;
/// `BIO_CB_GETS`.
pub const BIO_CB_GETS: c_int = 0x05;
/// `BIO_CB_CTRL`.
pub const BIO_CB_CTRL: c_int = 0x06;
/// `BIO_CB_RECVMMSG`.
pub const BIO_CB_RECVMMSG: c_int = 0x07;
/// `BIO_CB_SENDMMSG`.
pub const BIO_CB_SENDMMSG: c_int = 0x08;
/// `BIO_CB_RETURN`.
pub const BIO_CB_RETURN: c_int = 0x80;

/// `BIO_RR_SSL_X509_LOOKUP`.
pub const BIO_RR_SSL_X509_LOOKUP: c_int = 0x01;
/// `BIO_RR_CONNECT`.
pub const BIO_RR_CONNECT: c_int = 0x02;
/// `BIO_RR_ACCEPT`.
pub const BIO_RR_ACCEPT: c_int = 0x03;

// ---------------------------------------------------------------------------
// The control commands that carry an argument, from `bio.h`.
// ---------------------------------------------------------------------------

/// `BIO_C_SET_CONNECT`.
pub const BIO_C_SET_CONNECT: c_int = 100;
/// `BIO_C_DO_STATE_MACHINE`.
pub const BIO_C_DO_STATE_MACHINE: c_int = 101;
/// `BIO_C_SET_NBIO`.
pub const BIO_C_SET_NBIO: c_int = 102;
/// `BIO_C_SET_FD`.
pub const BIO_C_SET_FD: c_int = 104;
/// `BIO_C_GET_FD`.
pub const BIO_C_GET_FD: c_int = 105;
/// `BIO_C_SET_FILE_PTR`.
pub const BIO_C_SET_FILE_PTR: c_int = 106;
/// `BIO_C_GET_FILE_PTR`.
pub const BIO_C_GET_FILE_PTR: c_int = 107;
/// `BIO_C_SET_FILENAME`.
pub const BIO_C_SET_FILENAME: c_int = 108;
/// `BIO_C_SET_SSL`.
pub const BIO_C_SET_SSL: c_int = 109;
/// `BIO_C_GET_SSL`.
pub const BIO_C_GET_SSL: c_int = 110;
/// `BIO_C_SET_MD`.
pub const BIO_C_SET_MD: c_int = 111;
/// `BIO_C_GET_MD`.
pub const BIO_C_GET_MD: c_int = 112;
/// `BIO_C_GET_CIPHER_STATUS`.
pub const BIO_C_GET_CIPHER_STATUS: c_int = 113;
/// `BIO_C_SET_BUF_MEM`.
pub const BIO_C_SET_BUF_MEM: c_int = 114;
/// `BIO_C_GET_BUF_MEM_PTR`.
pub const BIO_C_GET_BUF_MEM_PTR: c_int = 115;
/// `BIO_C_GET_BUFF_NUM_LINES`.
pub const BIO_C_GET_BUFF_NUM_LINES: c_int = 116;
/// `BIO_C_SET_BUFF_SIZE`.
pub const BIO_C_SET_BUFF_SIZE: c_int = 117;
/// `BIO_C_SET_ACCEPT`.
pub const BIO_C_SET_ACCEPT: c_int = 118;
/// `BIO_C_SSL_MODE`.
pub const BIO_C_SSL_MODE: c_int = 119;
/// `BIO_C_GET_MD_CTX`.
pub const BIO_C_GET_MD_CTX: c_int = 120;
/// `BIO_C_SET_BUFF_READ_DATA`.
pub const BIO_C_SET_BUFF_READ_DATA: c_int = 122;
/// `BIO_C_GET_CONNECT`.
pub const BIO_C_GET_CONNECT: c_int = 123;
/// `BIO_C_GET_ACCEPT`.
pub const BIO_C_GET_ACCEPT: c_int = 124;
/// `BIO_C_SET_SSL_RENEGOTIATE_BYTES`.
pub const BIO_C_SET_SSL_RENEGOTIATE_BYTES: c_int = 125;
/// `BIO_C_GET_SSL_NUM_RENEGOTIATES`.
pub const BIO_C_GET_SSL_NUM_RENEGOTIATES: c_int = 126;
/// `BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT`.
pub const BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT: c_int = 127;
/// `BIO_C_FILE_SEEK`.
pub const BIO_C_FILE_SEEK: c_int = 128;
/// `BIO_C_GET_CIPHER_CTX`.
pub const BIO_C_GET_CIPHER_CTX: c_int = 129;
/// `BIO_C_SET_BUF_MEM_EOF_RETURN`.
pub const BIO_C_SET_BUF_MEM_EOF_RETURN: c_int = 130;
/// `BIO_C_SET_BIND_MODE`.
pub const BIO_C_SET_BIND_MODE: c_int = 131;
/// `BIO_C_GET_BIND_MODE`.
pub const BIO_C_GET_BIND_MODE: c_int = 132;
/// `BIO_C_FILE_TELL`.
pub const BIO_C_FILE_TELL: c_int = 133;
/// `BIO_C_GET_SOCKS`.
pub const BIO_C_GET_SOCKS: c_int = 134;
/// `BIO_C_SET_SOCKS`.
pub const BIO_C_SET_SOCKS: c_int = 135;
/// `BIO_C_SET_WRITE_BUF_SIZE`.
pub const BIO_C_SET_WRITE_BUF_SIZE: c_int = 136;
/// `BIO_C_GET_WRITE_BUF_SIZE`.
pub const BIO_C_GET_WRITE_BUF_SIZE: c_int = 137;
/// `BIO_C_MAKE_BIO_PAIR`.
pub const BIO_C_MAKE_BIO_PAIR: c_int = 138;
/// `BIO_C_DESTROY_BIO_PAIR`.
pub const BIO_C_DESTROY_BIO_PAIR: c_int = 139;
/// `BIO_C_GET_WRITE_GUARANTEE`.
pub const BIO_C_GET_WRITE_GUARANTEE: c_int = 140;
/// `BIO_C_GET_READ_REQUEST`.
pub const BIO_C_GET_READ_REQUEST: c_int = 141;
/// `BIO_C_SHUTDOWN_WR`.
pub const BIO_C_SHUTDOWN_WR: c_int = 142;
/// `BIO_C_NREAD0`.
pub const BIO_C_NREAD0: c_int = 143;
/// `BIO_C_NREAD`.
pub const BIO_C_NREAD: c_int = 144;
/// `BIO_C_NWRITE0`.
pub const BIO_C_NWRITE0: c_int = 145;
/// `BIO_C_NWRITE`.
pub const BIO_C_NWRITE: c_int = 146;
/// `BIO_C_RESET_READ_REQUEST`.
pub const BIO_C_RESET_READ_REQUEST: c_int = 147;
/// `BIO_C_SET_MD_CTX`.
pub const BIO_C_SET_MD_CTX: c_int = 148;
/// `BIO_C_SET_PREFIX`.
pub const BIO_C_SET_PREFIX: c_int = 149;
/// `BIO_C_GET_PREFIX`.
pub const BIO_C_GET_PREFIX: c_int = 150;
/// `BIO_C_SET_SUFFIX`.
pub const BIO_C_SET_SUFFIX: c_int = 151;
/// `BIO_C_GET_SUFFIX`.
pub const BIO_C_GET_SUFFIX: c_int = 152;
/// `BIO_C_SET_EX_ARG`.
pub const BIO_C_SET_EX_ARG: c_int = 153;
/// `BIO_C_GET_EX_ARG`.
pub const BIO_C_GET_EX_ARG: c_int = 154;
/// `BIO_C_SET_CONNECT_MODE`.
pub const BIO_C_SET_CONNECT_MODE: c_int = 155;
/// `BIO_C_SET_TFO`.
pub const BIO_C_SET_TFO: c_int = 156;
/// `BIO_C_SET_SOCK_TYPE`.
pub const BIO_C_SET_SOCK_TYPE: c_int = 157;
/// `BIO_C_GET_SOCK_TYPE`.
pub const BIO_C_GET_SOCK_TYPE: c_int = 158;
/// `BIO_C_GET_DGRAM_BIO`.
pub const BIO_C_GET_DGRAM_BIO: c_int = 159;

/// `BIO_CTRL_GET_WRITE_GUARANTEE` — the BIO-pair spelling of
/// `BIO_C_GET_WRITE_GUARANTEE`.
pub const BIO_CTRL_GET_WRITE_GUARANTEE: c_int = BIO_C_GET_WRITE_GUARANTEE;
/// `BIO_CTRL_GET_READ_REQUEST` — the BIO-pair spelling of
/// `BIO_C_GET_READ_REQUEST`.
pub const BIO_CTRL_GET_READ_REQUEST: c_int = BIO_C_GET_READ_REQUEST;
/// `BIO_CTRL_RESET_READ_REQUEST` — the BIO-pair spelling of
/// `BIO_C_RESET_READ_REQUEST`.
pub const BIO_CTRL_RESET_READ_REQUEST: c_int = BIO_C_RESET_READ_REQUEST;

// ---------------------------------------------------------------------------
// Error classes, from `bioerr.h`, `err.h` and `cryptoerr.h`.
// ---------------------------------------------------------------------------

/// `ERR_LIB_SYS`.
pub const ERR_LIB_SYS: c_int = 2;
/// `ERR_LIB_BIO`.
pub const BIO_LIB_CODE: c_int = 32;
/// `ERR_RFLAG_COMMON`.
pub const ERR_RFLAG_COMMON: c_int = 0x2 << 18;
/// `ERR_R_SYS_LIB` — the syscall-error reason, carrying `ERR_RFLAG_COMMON`.
pub const ERR_R_SYS_LIB: c_int = ERR_LIB_SYS | ERR_RFLAG_COMMON;
/// `ERR_R_MALLOC_FAILURE` (`cryptoerr.h`).
pub const ERR_R_MALLOC_FAILURE: c_int = 1;
/// `ERR_R_INIT_FAIL` (`cryptoerr.h`).
pub const ERR_R_INIT_FAIL: c_int = 154;
/// `ERR_R_PASSED_NULL_PARAMETER` (`cryptoerr.h`).
pub const ERR_R_PASSED_NULL_PARAMETER: c_int = 106;
/// `ERR_R_INTERNAL_ERROR` (`cryptoerr.h`).
pub const ERR_R_INTERNAL_ERROR: c_int = 114;
/// `ERR_R_CRYPTO_LIB` (`cryptoerr.h`).
pub const ERR_R_CRYPTO_LIB: c_int = 42;

/// `BIO_R_ACCEPT_ERROR`.
pub const BIO_R_ACCEPT_ERROR: c_int = 100;
/// `BIO_R_BAD_FOPEN_MODE`.
pub const BIO_R_BAD_FOPEN_MODE: c_int = 101;
/// `BIO_R_LENGTH_TOO_LONG`.
pub const BIO_R_LENGTH_TOO_LONG: c_int = 102;
/// `BIO_R_CONNECT_ERROR`.
pub const BIO_R_CONNECT_ERROR: c_int = 103;
/// `BIO_R_TRANSFER_ERROR`.
pub const BIO_R_TRANSFER_ERROR: c_int = 104;
/// `BIO_R_TRANSFER_TIMEOUT`.
pub const BIO_R_TRANSFER_TIMEOUT: c_int = 105;
/// `BIO_R_NBIO_CONNECT_ERROR`.
pub const BIO_R_NBIO_CONNECT_ERROR: c_int = 110;
/// `BIO_R_NON_FATAL`.
pub const BIO_R_NON_FATAL: c_int = 112;
/// `BIO_R_NO_PORT_DEFINED`.
pub const BIO_R_NO_PORT_DEFINED: c_int = 113;
/// `BIO_R_UNABLE_TO_BIND_SOCKET`.
pub const BIO_R_UNABLE_TO_BIND_SOCKET: c_int = 117;
/// `BIO_R_UNABLE_TO_CREATE_SOCKET`.
pub const BIO_R_UNABLE_TO_CREATE_SOCKET: c_int = 118;
/// `BIO_R_UNABLE_TO_LISTEN_SOCKET`.
pub const BIO_R_UNABLE_TO_LISTEN_SOCKET: c_int = 119;
/// `BIO_R_UNINITIALIZED`.
pub const BIO_R_UNINITIALIZED: c_int = 120;
/// `BIO_R_UNSUPPORTED_METHOD`.
pub const BIO_R_UNSUPPORTED_METHOD: c_int = 121;
/// `BIO_R_WSASTARTUP`.
pub const BIO_R_WSASTARTUP: c_int = 122;
/// `BIO_R_IN_USE`.
pub const BIO_R_IN_USE: c_int = 123;
/// `BIO_R_BROKEN_PIPE`.
pub const BIO_R_BROKEN_PIPE: c_int = 124;
/// `BIO_R_INVALID_ARGUMENT`.
pub const BIO_R_INVALID_ARGUMENT: c_int = 125;
/// `BIO_R_WRITE_TO_READ_ONLY_BIO`.
pub const BIO_R_WRITE_TO_READ_ONLY_BIO: c_int = 126;
/// `BIO_R_NO_SUCH_FILE`.
pub const BIO_R_NO_SUCH_FILE: c_int = 128;
/// `BIO_R_AMBIGUOUS_HOST_OR_SERVICE`.
pub const BIO_R_AMBIGUOUS_HOST_OR_SERVICE: c_int = 129;
/// `BIO_R_MALFORMED_HOST_OR_SERVICE`.
pub const BIO_R_MALFORMED_HOST_OR_SERVICE: c_int = 130;
/// `BIO_R_UNSUPPORTED_PROTOCOL_FAMILY`.
pub const BIO_R_UNSUPPORTED_PROTOCOL_FAMILY: c_int = 131;
/// `BIO_R_GETSOCKNAME_ERROR`.
pub const BIO_R_GETSOCKNAME_ERROR: c_int = 132;
/// `BIO_R_GETSOCKNAME_TRUNCATED_ADDRESS`.
pub const BIO_R_GETSOCKNAME_TRUNCATED_ADDRESS: c_int = 133;
/// `BIO_R_GETTING_SOCKTYPE`.
pub const BIO_R_GETTING_SOCKTYPE: c_int = 134;
/// `BIO_R_INVALID_SOCKET`.
pub const BIO_R_INVALID_SOCKET: c_int = 135;
/// `BIO_R_LISTEN_V6_ONLY`.
pub const BIO_R_LISTEN_V6_ONLY: c_int = 136;
/// `BIO_R_UNABLE_TO_KEEPALIVE`.
pub const BIO_R_UNABLE_TO_KEEPALIVE: c_int = 137;
/// `BIO_R_UNABLE_TO_NODELAY`.
pub const BIO_R_UNABLE_TO_NODELAY: c_int = 138;
/// `BIO_R_UNABLE_TO_REUSEADDR`.
pub const BIO_R_UNABLE_TO_REUSEADDR: c_int = 139;
/// `BIO_R_UNKNOWN_INFO_TYPE`.
pub const BIO_R_UNKNOWN_INFO_TYPE: c_int = 140;
/// `BIO_R_ADDRINFO_ADDR_IS_NOT_AF_INET`.
pub const BIO_R_ADDRINFO_ADDR_IS_NOT_AF_INET: c_int = 141;
/// `BIO_R_LOOKUP_RETURNED_NOTHING`.
pub const BIO_R_LOOKUP_RETURNED_NOTHING: c_int = 142;
/// `BIO_R_NO_ACCEPT_ADDR_OR_SERVICE_SPECIFIED`.
pub const BIO_R_NO_ACCEPT_ADDR_OR_SERVICE_SPECIFIED: c_int = 143;
/// `BIO_R_NO_HOSTNAME_OR_SERVICE_SPECIFIED`.
pub const BIO_R_NO_HOSTNAME_OR_SERVICE_SPECIFIED: c_int = 144;
/// `BIO_R_UNAVAILABLE_IP_FAMILY`.
pub const BIO_R_UNAVAILABLE_IP_FAMILY: c_int = 145;
/// `BIO_R_UNSUPPORTED_IP_FAMILY`.
pub const BIO_R_UNSUPPORTED_IP_FAMILY: c_int = 146;
/// `BIO_R_CONNECT_TIMEOUT`.
pub const BIO_R_CONNECT_TIMEOUT: c_int = 147;
/// `BIO_R_PORT_MISMATCH`.
pub const BIO_R_PORT_MISMATCH: c_int = 150;
/// `BIO_R_PEER_ADDR_NOT_AVAILABLE`.
pub const BIO_R_PEER_ADDR_NOT_AVAILABLE: c_int = 151;

/// `BIO_SOCK_REUSEADDR`.
pub const BIO_SOCK_REUSEADDR: c_int = 0x01;
/// `BIO_SOCK_V6_ONLY`.
pub const BIO_SOCK_V6_ONLY: c_int = 0x02;
/// `BIO_SOCK_KEEPALIVE`.
pub const BIO_SOCK_KEEPALIVE: c_int = 0x04;
/// `BIO_SOCK_NONBLOCK`.
pub const BIO_SOCK_NONBLOCK: c_int = 0x08;
/// `BIO_SOCK_NODELAY`.
pub const BIO_SOCK_NODELAY: c_int = 0x10;
/// `BIO_SOCK_TFO`.
pub const BIO_SOCK_TFO: c_int = 0x20;

/// `BIO_FP_READ`.
pub const BIO_FP_READ: c_int = 0x02;
/// `BIO_FP_WRITE`.
pub const BIO_FP_WRITE: c_int = 0x04;
/// `BIO_FP_APPEND`.
pub const BIO_FP_APPEND: c_int = 0x08;
/// `BIO_FP_TEXT`.
pub const BIO_FP_TEXT: c_int = 0x10;

/// `BIO_PARSE_PRIO_HOST`.
pub const BIO_PARSE_PRIO_HOST: c_int = 0;
/// `BIO_PARSE_PRIO_SERV`.
pub const BIO_PARSE_PRIO_SERV: c_int = 1;
/// `BIO_LOOKUP_CLIENT`.
pub const BIO_LOOKUP_CLIENT: c_int = 0;
/// `BIO_LOOKUP_SERVER`.
pub const BIO_LOOKUP_SERVER: c_int = 1;

/// `BIO_DGRAM_CAP_HANDLES_SRC_ADDR`.
pub const BIO_DGRAM_CAP_HANDLES_SRC_ADDR: c_int = 1 << 0;
/// `BIO_DGRAM_CAP_HANDLES_DST_ADDR`.
pub const BIO_DGRAM_CAP_HANDLES_DST_ADDR: c_int = 1 << 1;
/// `BIO_DGRAM_CAP_PROVIDES_SRC_ADDR`.
pub const BIO_DGRAM_CAP_PROVIDES_SRC_ADDR: c_int = 1 << 2;
/// `BIO_DGRAM_CAP_PROVIDES_DST_ADDR`.
pub const BIO_DGRAM_CAP_PROVIDES_DST_ADDR: c_int = 1 << 3;

// ---------------------------------------------------------------------------
// The public opaque types
// ---------------------------------------------------------------------------

/// The C `BIO_MSG` structure (`bio.h`), used by `BIO_sendmmsg`/`BIO_recvmmsg`.
#[repr(C)]
pub struct BioMsg {
    /// Payload pointer.
    pub data: *mut c_void,
    /// Payload length.
    pub data_len: usize,
    /// Peer address.
    pub peer: *mut c_void,
    /// Local address.
    pub local: *mut c_void,
    /// Per-message flags.
    pub flags: u64,
}

/// The C `BIO_MMSG_CB_ARGS` structure (`bio.h`).
#[repr(C)]
pub struct BioMmsgCbArgs {
    /// Array of messages.
    pub msg: *mut BioMsg,
    /// Stride between messages.
    pub stride: usize,
    /// Number of messages.
    pub num_msg: usize,
    /// Operation flags.
    pub flags: u64,
    /// Out-parameter: messages processed.
    pub msgs_processed: *mut usize,
}

/// The union inside the C `BIO_POLL_DESCRIPTOR`.
///
/// `repr(C)` union, matching the header's `union { int fd; void *custom;
/// uintptr_t custom_ui; SSL *ssl; }`.
#[repr(C)]
pub union BioPollValue {
    /// A socket descriptor.
    pub fd: c_int,
    /// A custom descriptor.
    pub custom: *mut c_void,
    /// A custom descriptor as an integer.
    pub custom_ui: usize,
    /// An `SSL *`, for the SSL BIO.
    pub ssl: *mut c_void,
}

/// The C `BIO_POLL_DESCRIPTOR` structure (`bio.h`).
///
/// The `value` union is 8-byte aligned in C, so it sits at offset 8 rather than
/// 4; that is why this is a real union and not a byte array.
#[repr(C)]
pub struct BioPollDescriptor {
    /// One of the `BIO_POLL_DESCRIPTOR_TYPE_*` values.
    pub r#type: u32,
    /// The descriptor.
    pub value: BioPollValue,
}

/// `BIO_POLL_DESCRIPTOR_TYPE_NONE`.
pub const BIO_POLL_DESCRIPTOR_TYPE_NONE: u32 = 0;
/// `BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD`.
pub const BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD: u32 = 1;
/// `BIO_POLL_DESCRIPTOR_TYPE_SSL`.
pub const BIO_POLL_DESCRIPTOR_TYPE_SSL: u32 = 2;

/// The `bio_info_cb` callback type: `int (*)(BIO *, int, int)`.
pub type BioInfoCb = unsafe extern "C" fn(*mut Bio, c_int, c_int) -> c_int;

/// The deprecated `BIO_callback_fn`.
pub type BioCallbackFn =
    unsafe extern "C" fn(*mut Bio, c_int, *const c_char, c_int, c_long, c_long) -> c_long;

/// The modern `BIO_callback_fn_ex`.
#[allow(clippy::type_complexity)]
pub type BioCallbackExFn = unsafe extern "C" fn(
    *mut Bio,
    c_int,
    *const c_char,
    usize,
    c_int,
    c_long,
    c_int,
    *mut usize,
) -> c_long;

/// `int (*)(BIO *, const char *, int)` — `BIO_meth_set_write`.
pub type BioWriteFn = unsafe extern "C" fn(*mut Bio, *const c_char, c_int) -> c_int;
/// `int (*)(BIO *, const char *, size_t, size_t *)` — `BIO_meth_set_write_ex`.
pub type BioWriteExFn = unsafe extern "C" fn(*mut Bio, *const c_char, usize, *mut usize) -> c_int;
/// `int (*)(BIO *, char *, int)` — `BIO_meth_set_read`.
pub type BioReadFn = unsafe extern "C" fn(*mut Bio, *mut c_char, c_int) -> c_int;
/// `int (*)(BIO *, char *, size_t, size_t *)` — `BIO_meth_set_read_ex`.
pub type BioReadExFn = unsafe extern "C" fn(*mut Bio, *mut c_char, usize, *mut usize) -> c_int;
/// `int (*)(BIO *, const char *)` — `BIO_meth_set_puts`.
pub type BioPutsFn = unsafe extern "C" fn(*mut Bio, *const c_char) -> c_int;
/// `int (*)(BIO *, char *, int)` — `BIO_meth_set_gets`.
pub type BioGetsFn = unsafe extern "C" fn(*mut Bio, *mut c_char, c_int) -> c_int;
/// `long (*)(BIO *, int, long, void *)` — `BIO_meth_set_ctrl`.
pub type BioCtrlFn = unsafe extern "C" fn(*mut Bio, c_int, c_long, *mut c_void) -> c_long;
/// `int (*)(BIO *)` — `BIO_meth_set_create`.
pub type BioCreateFn = unsafe extern "C" fn(*mut Bio) -> c_int;
/// `int (*)(BIO *)` — `BIO_meth_set_destroy`.
pub type BioDestroyFn = unsafe extern "C" fn(*mut Bio) -> c_int;
/// `long (*)(BIO *, int, BIO_info_cb *)` — `BIO_meth_set_callback_ctrl`.
pub type BioCallbackCtrlFn = unsafe extern "C" fn(*mut Bio, c_int, *mut BioInfoCb) -> c_long;
/// `int (*)(BIO *, BIO_MSG *, size_t, size_t, uint64_t, size_t *)` — `BIO_meth_set_sendmmsg`.
#[allow(clippy::type_complexity)]
pub type BioSendmmsgFn =
    unsafe extern "C" fn(*mut Bio, *mut BioMsg, usize, usize, u64, *mut usize) -> c_int;
/// `int (*)(BIO *, BIO_MSG *, size_t, size_t, uint64_t, size_t *)` — `BIO_meth_set_recvmmsg`.
pub type BioRecvmmsgFn = BioSendmmsgFn;

/// A `BIO_METHOD`, the vtable every BIO instance points at.
///
/// Opaque to callers (`bio.h` only forward-declares `struct bio_method_st`), so
/// the field order is ours; what matters is that `BIO_meth_new`/`BIO_meth_set_*`
/// and `BIO_meth_get_*` round-trip through it, and that methods built by
/// `BIO_meth_new` and the built-in ones behave identically.
#[repr(C)]
pub struct BioMethod {
    /// The `BIO_TYPE_*` value, including the class bits.
    pub type_: c_int,
    /// The human-readable method name returned by `BIO_method_name`.
    pub name: *const c_char,
    /// Modern write: `int (*)(BIO *, const char *, size_t, size_t *)`.
    pub bwrite: Option<BioWriteExFn>,
    /// Legacy write, installed by `BIO_meth_set_write`.
    pub bwrite_old: Option<BioWriteFn>,
    /// Modern read: `int (*)(BIO *, char *, size_t, size_t *)`.
    pub bread: Option<BioReadExFn>,
    /// Legacy read, installed by `BIO_meth_set_read`.
    pub bread_old: Option<BioReadFn>,
    /// `BIO_puts`.
    pub bputs: Option<BioPutsFn>,
    /// `BIO_gets`.
    pub bgets: Option<BioGetsFn>,
    /// `BIO_ctrl`.
    pub ctrl: Option<BioCtrlFn>,
    /// Called by `BIO_new` after allocation.
    pub create: Option<BioCreateFn>,
    /// Called by `BIO_free` before `ex_data` is torn down.
    pub destroy: Option<BioDestroyFn>,
    /// `BIO_callback_ctrl`.
    pub callback_ctrl: Option<BioCallbackCtrlFn>,
    /// `BIO_sendmmsg`.
    pub sendmmsg: Option<BioSendmmsgFn>,
    /// `BIO_recvmmsg`.
    pub recvmmsg: Option<BioRecvmmsgFn>,
}

// The method table is immutable after construction and its contents are either
// integers, static strings or function pointers, all of which may be shared
// across threads.
unsafe impl Sync for BioMethod {}

impl BioMethod {
    /// An all-zero method table with the given type and name.
    pub const fn new(type_: c_int, name: *const c_char) -> Self {
        Self {
            type_,
            name,
            bwrite: None,
            bwrite_old: None,
            bread: None,
            bread_old: None,
            bputs: None,
            bgets: None,
            ctrl: None,
            create: None,
            destroy: None,
            callback_ctrl: None,
            sendmmsg: None,
            recvmmsg: None,
        }
    }
}

/// A `BIO`.
///
/// Opaque to callers (`bio.h` forward-declares `struct bio_st`), so this layout
/// is not ABI. The reference count is a real atomic because `BIO_up_ref` and
/// `BIO_free` are documented to be thread-safe; the chain links are raw pointers
/// because `BIO_push`/`BIO_pop`/`BIO_next` hand them to C.
#[repr(C)]
pub struct Bio {
    /// The method this BIO dispatches to.
    pub method: *const BioMethod,
    /// `BIO_set_callback_ex` handler.
    pub callback_ex: Option<BioCallbackExFn>,
    /// `BIO_set_callback` handler (deprecated).
    pub callback: Option<BioCallbackFn>,
    /// `BIO_set_callback_arg` payload.
    pub cb_arg: *mut c_char,
    /// Set by a method's `create`; `BIO_get_init`/`BIO_set_init`.
    pub init: c_int,
    /// Whether `BIO_free` should close the underlying resource.
    pub shutdown: c_int,
    /// The `BIO_FLAGS_*` word.
    pub flags: c_int,
    /// The `BIO_RR_*` reason for an I/O-special retry.
    pub retry_reason: c_int,
    /// The method's `int` slot (file descriptor, socket, …).
    pub num: c_int,
    /// The method's private data.
    pub ptr: *mut c_void,
    /// The next BIO in the chain.
    pub next_bio: *mut Bio,
    /// The previous BIO in the chain.
    pub prev_bio: *mut Bio,
    /// Reference count.
    pub references: AtomicI32,
    /// Bytes read through this BIO.
    pub num_read: u64,
    /// Bytes written through this BIO.
    pub num_write: u64,
    /// Per-object extension data.
    pub ex_data: CryptoExData,
}

impl Bio {
    /// The method table, or `None` when the BIO has no method.
    ///
    /// # Safety
    /// `self.method`, when non-NULL, points at a live [`BioMethod`].
    #[inline]
    pub unsafe fn method(&self) -> Option<&'static BioMethod> {
        // SAFETY: the caller guarantees `method` is either NULL or a live table,
        // and built-in tables are `'static`.
        unsafe { self.method.as_ref() }
    }
}

// ---------------------------------------------------------------------------
// Creation and destruction
// ---------------------------------------------------------------------------

/// `BIO *BIO_new_ex(OSSL_LIB_CTX *libctx, const BIO_METHOD *method)`
///
/// Allocates a BIO, installs `method`, sets the reference count to 1 and
/// `shutdown` to 1, initialises `ex_data`, and calls the method's `create`.
/// `libctx` selects a per-context registry in the authority; this crate has no
/// `OSSL_LIB_CTX` yet (Phase 6), so it is accepted and ignored, which is
/// recorded as a Phase 6 obligation rather than silently dropped.
#[no_mangle]
pub unsafe extern "C" fn BIO_new_ex(_libctx: *mut c_void, method: *const BioMethod) -> *mut Bio {
    guard_ffi(ptr::null_mut(), || {
        if method.is_null() {
            return ptr::null_mut();
        }
        let mut bio = Box::new(Bio {
            method,
            callback_ex: None,
            callback: None,
            cb_arg: ptr::null_mut(),
            init: 0,
            shutdown: 1,
            flags: 0,
            retry_reason: 0,
            num: 0,
            ptr: ptr::null_mut(),
            next_bio: ptr::null_mut(),
            prev_bio: ptr::null_mut(),
            references: AtomicI32::new(1),
            num_read: 0,
            num_write: 0,
            ex_data: CryptoExData {
                ctx: ptr::null_mut(),
                sk: ptr::null_mut(),
            },
        });
        // SAFETY: `bio` is a live object; `CRYPTO_new_ex_data` only stores through
        // the `ex_data` pointer it is given and may invoke registered callbacks.
        let ex_ok = unsafe {
            CRYPTO_new_ex_data(
                CRYPTO_EX_INDEX_BIO,
                core::ptr::from_mut(&mut *bio).cast::<c_void>(),
                &mut bio.ex_data,
            )
        };
        if ex_ok == 0 {
            return ptr::null_mut();
        }
        // SAFETY: the method pointer is live, so `create` (if any) is callable
        // with a BIO that is fully initialised.
        let created = match unsafe { method.as_ref() } {
            Some(m) => match m.create {
                // SAFETY: `bio` is a live, initialised BIO; the method contract
                // is that `create` may read and write it but not free it.
                Some(create) => unsafe { create(&mut *bio) },
                // A method with no `create` is initialised by the core; the
                // authority sets `init = 1` here, which is what makes
                // `BIO_read` on such a BIO skip the `BIO_R_UNINITIALIZED` path.
                None => {
                    bio.init = 1;
                    1
                }
            },
            None => 0,
        };
        if created == 0 {
            // The authority reports a `create` failure as an initialisation
            // failure before tearing the partial object down.
            // SAFETY: the site is a compile-time constant.
            unsafe { crate::runtime::err::raise_site(&crate::runtime::err::err_sites::BIO_LIB_99) };
            // SAFETY: `bio` was initialised by `CRYPTO_new_ex_data` above and is
            // about to be released, so its slots must be torn down.
            unsafe {
                CRYPTO_free_ex_data(
                    CRYPTO_EX_INDEX_BIO,
                    core::ptr::from_mut(&mut *bio).cast::<c_void>(),
                    &mut bio.ex_data,
                );
            }
            return ptr::null_mut();
        }
        Box::into_raw(bio)
    })
}

/// `BIO *BIO_new(const BIO_METHOD *type)`
///
/// `BIO_new` is `BIO_new_ex(NULL, type)`.
#[no_mangle]
pub unsafe extern "C" fn BIO_new(method: *const BioMethod) -> *mut Bio {
    guard_ffi(ptr::null_mut(), || {
        // SAFETY: forwarded; `BIO_new_ex` checks `method` for NULL.
        unsafe { BIO_new_ex(ptr::null_mut(), method) }
    })
}

/// `int BIO_up_ref(BIO *a)`
///
/// Increments the reference count. Returns 1 on success and 0 for a NULL BIO,
/// which is the authority's behaviour (it does not raise).
#[no_mangle]
pub unsafe extern "C" fn BIO_up_ref(bio: *mut Bio) -> c_int {
    guard_ffi(0, || {
        if bio.is_null() {
            return 0;
        }
        // SAFETY: `bio` is non-NULL and live; `references` is an atomic owned by
        // this object.
        let now = unsafe { &*bio }.references.fetch_add(1, Ordering::AcqRel) + 1;
        if now > 1 {
            1
        } else {
            0
        }
    })
}

/// `int BIO_free(BIO *a)`
///
/// Drops one reference. When it reaches zero the free callback (if any) runs,
/// `ex_data` is torn down, the method's `destroy` runs, and the object is
/// released. A failing (`<= 0`) free callback suppresses destruction and returns
/// 0, which is the authority's contract for using the callback as a veto.
#[no_mangle]
pub unsafe extern "C" fn BIO_free(bio: *mut Bio) -> c_int {
    guard_ffi(0, || {
        if bio.is_null() {
            return 0;
        }
        // SAFETY: `bio` is non-NULL and live for the caller's reference.
        let b = unsafe { &mut *bio };
        // The count is decremented once whatever the outcome. The authority's
        // down-ref yields the *previous* value, and a count above one means other
        // references remain, so the object survives.
        if b.references.fetch_sub(1, Ordering::AcqRel) != 1 {
            return 1;
        }
        if b.callback_ex.is_some() || b.callback.is_some() {
            // SAFETY: the callback was installed by the caller for this BIO class
            // and is invoked with the documented argument shape.
            let ret = unsafe {
                iolib::bio_call_callback(bio, BIO_CB_FREE, ptr::null(), 0, 0, 0, 1, ptr::null_mut())
            };
            if ret <= 0 {
                return 0;
            }
        }
        // SAFETY: `method` is either NULL or a live table; `destroy` is called on
        // a still-allocated BIO, per the method contract. The authority destroys
        // the method data *before* tearing down `ex_data`.
        if let Some(m) = unsafe { b.method.as_ref() } {
            if let Some(destroy) = m.destroy {
                // SAFETY: as above; the method may clear `ptr` but must not free
                // the BIO itself.
                unsafe { destroy(b) };
            }
        }
        // SAFETY: the object is being destroyed exactly once, so tearing down its
        // ex_data is correct and occurs before the memory is released.
        unsafe {
            CRYPTO_free_ex_data(
                CRYPTO_EX_INDEX_BIO,
                core::ptr::from_mut(b).cast::<c_void>(),
                &mut b.ex_data,
            );
        }
        // SAFETY: the reference count reached zero, so the caller's pointer is
        // the only one and reclaiming it is correct.
        drop(unsafe { Box::from_raw(bio) });
        1
    })
}

/// `void BIO_vfree(BIO *a)`
#[no_mangle]
pub unsafe extern "C" fn BIO_vfree(bio: *mut Bio) {
    guard_ffi((), || {
        // SAFETY: forwarded; `BIO_free` accepts NULL.
        let _ = unsafe { BIO_free(bio) };
    })
}

/// `void BIO_free_all(BIO *a)`
///
/// Walks the chain, releasing one reference on each element. If an element's
/// reference count is above one the walk **stops**: the authority treats a shared
/// BIO as evidence that the rest of the chain belongs to someone else, which is
/// why this is not simply "BIO_free each".
#[no_mangle]
pub unsafe extern "C" fn BIO_free_all(bio: *mut Bio) {
    guard_ffi((), || {
        let mut current = bio;
        while !current.is_null() {
            // SAFETY: `current` is a live BIO in the chain.
            let refs = unsafe { &*current }.references.load(Ordering::Acquire);
            // SAFETY: `current` is non-NULL and live.
            let next = unsafe { (*current).next_bio };
            // SAFETY: the reference count is at least one, so this releases it
            // when it is the last one.
            let _ = unsafe { BIO_free(current) };
            if refs > 1 {
                break;
            }
            current = next;
        }
    })
}

// ---------------------------------------------------------------------------
// Accessors: data, init, shutdown, flags, retry
// ---------------------------------------------------------------------------

/// `void BIO_set_data(BIO *a, void *ptr)`
#[no_mangle]
pub unsafe extern "C" fn BIO_set_data(bio: *mut Bio, val: *mut c_void) {
    guard_ffi((), || {
        if let Some(b) = unsafe { bio.as_mut() } {
            b.ptr = val;
        }
    })
}

/// `void *BIO_get_data(BIO *a)`
#[no_mangle]
pub unsafe extern "C" fn BIO_get_data(bio: *mut Bio) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || match unsafe { bio.as_ref() } {
        Some(b) => b.ptr,
        None => ptr::null_mut(),
    })
}

/// `void BIO_set_init(BIO *a, int init)`
#[no_mangle]
pub unsafe extern "C" fn BIO_set_init(bio: *mut Bio, init: c_int) {
    guard_ffi((), || {
        if let Some(b) = unsafe { bio.as_mut() } {
            b.init = init;
        }
    })
}

/// `int BIO_get_init(BIO *a)`
#[no_mangle]
pub unsafe extern "C" fn BIO_get_init(bio: *mut Bio) -> c_int {
    guard_ffi(0, || match unsafe { bio.as_ref() } {
        Some(b) => b.init,
        None => 0,
    })
}

/// `void BIO_set_shutdown(BIO *a, int shut)`
#[no_mangle]
pub unsafe extern "C" fn BIO_set_shutdown(bio: *mut Bio, shut: c_int) {
    guard_ffi((), || {
        if let Some(b) = unsafe { bio.as_mut() } {
            b.shutdown = shut;
        }
    })
}

/// `int BIO_get_shutdown(BIO *a)`
#[no_mangle]
pub unsafe extern "C" fn BIO_get_shutdown(bio: *mut Bio) -> c_int {
    guard_ffi(0, || match unsafe { bio.as_ref() } {
        Some(b) => b.shutdown,
        None => 0,
    })
}

/// `void BIO_set_flags(BIO *b, int flags)`
#[no_mangle]
pub unsafe extern "C" fn BIO_set_flags(bio: *mut Bio, flags: c_int) {
    guard_ffi((), || {
        if let Some(b) = unsafe { bio.as_mut() } {
            b.flags |= flags;
        }
    })
}

/// `int BIO_test_flags(const BIO *b, int flags)`
#[no_mangle]
pub unsafe extern "C" fn BIO_test_flags(bio: *const Bio, flags: c_int) -> c_int {
    guard_ffi(0, || match unsafe { bio.as_ref() } {
        Some(b) => b.flags & flags,
        None => 0,
    })
}

/// `void BIO_clear_flags(BIO *b, int flags)`
#[no_mangle]
pub unsafe extern "C" fn BIO_clear_flags(bio: *mut Bio, flags: c_int) {
    guard_ffi((), || {
        if let Some(b) = unsafe { bio.as_mut() } {
            b.flags &= !flags;
        }
    })
}

/// `int BIO_get_retry_reason(BIO *bio)`
#[no_mangle]
pub unsafe extern "C" fn BIO_get_retry_reason(bio: *mut Bio) -> c_int {
    guard_ffi(0, || match unsafe { bio.as_ref() } {
        Some(b) => b.retry_reason,
        None => 0,
    })
}

/// `void BIO_set_retry_reason(BIO *bio, int reason)`
#[no_mangle]
pub unsafe extern "C" fn BIO_set_retry_reason(bio: *mut Bio, reason: c_int) {
    guard_ffi((), || {
        if let Some(b) = unsafe { bio.as_mut() } {
            b.retry_reason = reason;
        }
    })
}

/// `BIO *BIO_get_retry_BIO(BIO *bio, int *reason)`
///
/// Walks while each BIO reports `BIO_should_retry`, and returns the **last** one
/// that did, reporting its retry reason. `last` starts as `bio`, so a chain whose
/// head does not want a retry returns the head rather than NULL.
#[no_mangle]
pub unsafe extern "C" fn BIO_get_retry_BIO(bio: *mut Bio, reason: *mut c_int) -> *mut Bio {
    guard_ffi(ptr::null_mut(), || {
        let mut b = bio;
        let mut last = bio;
        loop {
            if b.is_null() {
                break;
            }
            // SAFETY: `b` is a live BIO in the chain.
            let should_retry = unsafe { (*b).flags } & BIO_FLAGS_SHOULD_RETRY != 0;
            if !should_retry {
                break;
            }
            last = b;
            // SAFETY: `b` is live.
            b = unsafe { (*b).next_bio };
            if b.is_null() {
                break;
            }
        }
        if !reason.is_null() {
            // SAFETY: `reason` is non-NULL and writable per the C prototype; a
            // NULL `last` cannot occur because `last` is `bio`, and `bio` was
            // non-NULL when it became `last`... except when `bio` itself is NULL.
            if !last.is_null() {
                unsafe { *reason = (*last).retry_reason };
            } else {
                unsafe { *reason = 0 };
            }
        }
        last
    })
}

/// `void BIO_copy_next_retry(BIO *b)`
///
/// Copies the retry flags and reason from the next BIO in the chain, which is
/// how a filter propagates a source/sink's retry state upward. `b` must have a
/// next BIO; the authority dereferences it unconditionally, so a NULL `next_bio`
/// is a caller defect. This implementation returns without raising rather than
/// faulting, which is recorded as a safety divergence.
#[no_mangle]
pub unsafe extern "C" fn BIO_copy_next_retry(bio: *mut Bio) {
    guard_ffi((), || {
        let Some(b) = (unsafe { bio.as_mut() }) else {
            return;
        };
        if b.next_bio.is_null() {
            return;
        }
        // SAFETY: `next_bio` is non-NULL and live.
        let next = unsafe { &*b.next_bio };
        b.flags |= next.flags & (BIO_FLAGS_RWS | BIO_FLAGS_SHOULD_RETRY);
        b.retry_reason = next.retry_reason;
    })
}

// ---------------------------------------------------------------------------
// Chain management
// ---------------------------------------------------------------------------

/// `BIO *BIO_push(BIO *b, BIO *append)`
///
/// Appends `append` after `b` and returns the head of the resulting chain.
/// A NULL `b` makes `append` the head.
#[no_mangle]
pub unsafe extern "C" fn BIO_push(bio: *mut Bio, append: *mut Bio) -> *mut Bio {
    guard_ffi(ptr::null_mut(), || {
        if bio.is_null() {
            return append;
        }
        // SAFETY: `bio` is non-NULL; walk to the tail of its chain.
        let mut tail = bio;
        while unsafe { (*tail).next_bio } != ptr::null_mut() {
            // SAFETY: `tail` is a live BIO whose `next_bio` is non-NULL.
            tail = unsafe { (*tail).next_bio };
        }
        if !append.is_null() {
            // SAFETY: `tail` and `append` are both live, distinct objects.
            unsafe {
                (*tail).next_bio = append;
                (*append).prev_bio = tail;
            }
        }
        // The head is told the chain grew, with the old tail as the argument;
        // filters use this to acquire state before the first transfer.
        // SAFETY: `bio` is non-NULL and live.
        unsafe { BIO_ctrl(bio, BIO_CTRL_PUSH, 0, tail.cast()) };
        bio
    })
}

/// `BIO *BIO_pop(BIO *b)`
///
/// Removes `b` from its chain and returns the element that followed it. `b` is
/// told it is being removed, both directions of the link are repaired, and `b`'s
/// own links are cleared — including when it was the tail, in which case the
/// return value is NULL but the control still runs.
#[no_mangle]
pub unsafe extern "C" fn BIO_pop(bio: *mut Bio) -> *mut Bio {
    guard_ffi(ptr::null_mut(), || {
        let Some(b) = (unsafe { bio.as_mut() }) else {
            return ptr::null_mut();
        };
        let ret = b.next_bio;
        // SAFETY: `bio` is live; the control may inspect its neighbours.
        unsafe { BIO_ctrl(bio, BIO_CTRL_POP, 0, bio.cast()) };
        if !b.prev_bio.is_null() {
            // SAFETY: `prev_bio` is a live BIO in the same chain.
            unsafe { (*b.prev_bio).next_bio = b.next_bio };
        }
        if !b.next_bio.is_null() {
            // SAFETY: `next_bio` is a live BIO in the same chain.
            unsafe { (*b.next_bio).prev_bio = b.prev_bio };
        }
        b.next_bio = ptr::null_mut();
        b.prev_bio = ptr::null_mut();
        ret
    })
}

/// `BIO *BIO_next(BIO *b)`
#[no_mangle]
pub unsafe extern "C" fn BIO_next(bio: *mut Bio) -> *mut Bio {
    guard_ffi(ptr::null_mut(), || match unsafe { bio.as_ref() } {
        Some(b) => b.next_bio,
        None => ptr::null_mut(),
    })
}

/// `void BIO_set_next(BIO *b, BIO *next)`
///
/// Replaces only the forward link, leaving `next`'s backward link alone. That is
/// the authority's behaviour and is why this is not `BIO_push`.
#[no_mangle]
pub unsafe extern "C" fn BIO_set_next(bio: *mut Bio, next: *mut Bio) {
    guard_ffi((), || {
        if let Some(b) = unsafe { bio.as_mut() } {
            b.next_bio = next;
        }
    })
}

/// `BIO *BIO_find_type(BIO *b, int bio_type)`
///
/// `mask` is `bio_type & 0xFF`. When the mask is zero the search matches on any
/// shared class bit (`method_type & bio_type`); otherwise it requires an exact
/// equality of the whole type word. A NULL BIO raises
/// `ERR_R_PASSED_NULL_PARAMETER` rather than returning quietly.
#[no_mangle]
pub unsafe extern "C" fn BIO_find_type(bio: *mut Bio, bio_type: c_int) -> *mut Bio {
    guard_ffi(ptr::null_mut(), || {
        if bio.is_null() {
            // SAFETY: the site is a compile-time constant.
            unsafe {
                crate::runtime::err::raise_site(&crate::runtime::err::err_sites::BIO_LIB_813)
            };
            return ptr::null_mut();
        }
        let mask = bio_type & BIO_TYPE_MASK;
        let mut current = bio;
        while !current.is_null() {
            // SAFETY: `current` is a live BIO in the chain.
            let b = unsafe { &*current };
            // SAFETY: `b.method` is NULL or a live table.
            if let Some(m) = unsafe { b.method.as_ref() } {
                let mt = m.type_;
                if mask == 0 {
                    if mt & bio_type != 0 {
                        return current;
                    }
                } else if mt == bio_type {
                    return current;
                }
            }
            current = b.next_bio;
        }
        ptr::null_mut()
    })
}

/// `BIO *BIO_dup_chain(BIO *in)`
///
/// Deep-copies a chain. Each element is created from the same method, then the
/// directly-observable fields (`callback`, `callback_ex`, `cb_arg`, `init`,
/// `shutdown`, `flags`, `num`) are copied, the source is asked to duplicate its
/// own state through `BIO_CTRL_DUP` with the *new* object as the argument, and
/// finally `ex_data` is duplicated through the `CRYPTO_EX_INDEX_BIO` dup
/// callbacks. Any failure releases the partial copy and returns NULL.
#[no_mangle]
pub unsafe extern "C" fn BIO_dup_chain(bio: *mut Bio) -> *mut Bio {
    guard_ffi(ptr::null_mut(), || {
        let mut head: *mut Bio = ptr::null_mut();
        let mut eoc: *mut Bio = ptr::null_mut();
        let mut current = bio;
        while !current.is_null() {
            // SAFETY: `current` is a live BIO in the source chain.
            let src = unsafe { &*current };
            // SAFETY: `BIO_new` allocates a fresh object and calls `create`.
            let new_bio = unsafe { BIO_new(src.method) };
            if new_bio.is_null() {
                if !head.is_null() {
                    // SAFETY: `head` heads the partial copy.
                    unsafe { BIO_free_all(head) };
                }
                return ptr::null_mut();
            }
            // SAFETY: `new_bio` is a fresh, live BIO whose fields are writable.
            let dst = unsafe { &mut *new_bio };
            dst.callback = src.callback;
            dst.callback_ex = src.callback_ex;
            dst.cb_arg = src.cb_arg;
            dst.init = src.init;
            dst.shutdown = src.shutdown;
            dst.flags = src.flags;
            dst.num = src.num;
            // `BIO_dup_state(b, (char *)new_bio)` is `BIO_ctrl(b, BIO_CTRL_DUP,
            // 0, new_bio)`; it runs *before* the object is linked.
            // SAFETY: `current` is live and `new_bio` is a live parg.
            if unsafe { BIO_ctrl(current, BIO_CTRL_DUP, 0, new_bio.cast()) } <= 0 {
                // SAFETY: `new_bio` is not yet reachable from `head`.
                let _ = unsafe { BIO_free(new_bio) };
                if !head.is_null() {
                    // SAFETY: `head` heads the partial copy.
                    unsafe { BIO_free_all(head) };
                }
                return ptr::null_mut();
            }
            // SAFETY: `dst`'s ex_data is live; the source's is live.
            let dup_ok = unsafe {
                crate::runtime::ex_data::CRYPTO_dup_ex_data(
                    CRYPTO_EX_INDEX_BIO,
                    &mut dst.ex_data,
                    &src.ex_data,
                )
            };
            if dup_ok == 0 {
                // SAFETY: `new_bio` is not yet reachable from `head`.
                let _ = unsafe { BIO_free(new_bio) };
                if !head.is_null() {
                    // SAFETY: `head` heads the partial copy.
                    unsafe { BIO_free_all(head) };
                }
                return ptr::null_mut();
            }
            if head.is_null() {
                head = new_bio;
                eoc = new_bio;
            } else {
                // SAFETY: `eoc` is the current tail of the copy and `new_bio` is
                // a fresh, unlinked object.
                unsafe { BIO_push(eoc, new_bio) };
                eoc = new_bio;
            }
            current = src.next_bio;
        }
        head
    })
}

// ---------------------------------------------------------------------------
// ex_data
// ---------------------------------------------------------------------------

/// Convenience alias so the `BIO_set_ex_data` body reads like the header.
type ExData = CryptoExData;

/// `int BIO_set_ex_data(BIO *bio, int idx, void *data)`
#[no_mangle]
pub unsafe extern "C" fn BIO_set_ex_data(bio: *mut Bio, idx: c_int, data: *mut c_void) -> c_int {
    guard_ffi(0, || {
        let Some(b) = (unsafe { bio.as_mut() }) else {
            return 0;
        };
        let ad: *mut ExData = &mut b.ex_data;
        // SAFETY: `ad` points at the BIO's own ex_data, which is live.
        unsafe { CRYPTO_set_ex_data(ad, idx, data) }
    })
}

/// `void *BIO_get_ex_data(const BIO *bio, int idx)`
#[no_mangle]
pub unsafe extern "C" fn BIO_get_ex_data(bio: *const Bio, idx: c_int) -> *mut c_void {
    guard_ffi(ptr::null_mut(), || {
        let Some(b) = (unsafe { bio.as_ref() }) else {
            return ptr::null_mut();
        };
        let ad: *const ExData = &b.ex_data;
        // SAFETY: `ad` points at the BIO's own ex_data, which is live.
        unsafe { CRYPTO_get_ex_data(ad, idx) }
    })
}

// ---------------------------------------------------------------------------
// Counters, method identity, callback plumbing
// ---------------------------------------------------------------------------

/// `uint64_t BIO_number_read(BIO *bio)`
#[no_mangle]
pub unsafe extern "C" fn BIO_number_read(bio: *mut Bio) -> u64 {
    guard_ffi(0, || match unsafe { bio.as_ref() } {
        Some(b) => b.num_read,
        None => 0,
    })
}

/// `uint64_t BIO_number_written(BIO *bio)`
#[no_mangle]
pub unsafe extern "C" fn BIO_number_written(bio: *mut Bio) -> u64 {
    guard_ffi(0, || match unsafe { bio.as_ref() } {
        Some(b) => b.num_write,
        None => 0,
    })
}

/// `const char *BIO_method_name(const BIO *b)`
#[no_mangle]
pub unsafe extern "C" fn BIO_method_name(bio: *const Bio) -> *const c_char {
    guard_ffi(ptr::null(), || {
        let Some(b) = (unsafe { bio.as_ref() }) else {
            return ptr::null();
        };
        // SAFETY: `b.method` is NULL or a live table whose `name` is static.
        unsafe { b.method.as_ref() }.map_or(ptr::null(), |m| m.name)
    })
}

/// `int BIO_method_type(const BIO *b)`
#[no_mangle]
pub unsafe extern "C" fn BIO_method_type(bio: *const Bio) -> c_int {
    guard_ffi(0, || {
        let Some(b) = (unsafe { bio.as_ref() }) else {
            return 0;
        };
        // SAFETY: `b.method` is NULL or a live table.
        unsafe { b.method.as_ref() }.map_or(BIO_TYPE_NONE, |m| m.type_)
    })
}

/// `BIO_callback_fn_ex BIO_get_callback_ex(const BIO *b)`
#[no_mangle]
pub unsafe extern "C" fn BIO_get_callback_ex(bio: *const Bio) -> Option<BioCallbackExFn> {
    guard_ffi(None, || unsafe { bio.as_ref() }.and_then(|b| b.callback_ex))
}

/// `void BIO_set_callback_ex(BIO *b, BIO_callback_fn_ex callback)`
#[no_mangle]
pub unsafe extern "C" fn BIO_set_callback_ex(bio: *mut Bio, callback: Option<BioCallbackExFn>) {
    guard_ffi((), || {
        if let Some(b) = unsafe { bio.as_mut() } {
            b.callback_ex = callback;
        }
    })
}

/// `BIO_callback_fn BIO_get_callback(const BIO *b)`
#[no_mangle]
pub unsafe extern "C" fn BIO_get_callback(bio: *const Bio) -> Option<BioCallbackFn> {
    guard_ffi(None, || unsafe { bio.as_ref() }.and_then(|b| b.callback))
}

/// `void BIO_set_callback(BIO *b, BIO_callback_fn callback)`
#[no_mangle]
pub unsafe extern "C" fn BIO_set_callback(bio: *mut Bio, callback: Option<BioCallbackFn>) {
    guard_ffi((), || {
        if let Some(b) = unsafe { bio.as_mut() } {
            b.callback = callback;
        }
    })
}

/// `char *BIO_get_callback_arg(const BIO *b)`
#[no_mangle]
pub unsafe extern "C" fn BIO_get_callback_arg(bio: *const Bio) -> *mut c_char {
    guard_ffi(ptr::null_mut(), || match unsafe { bio.as_ref() } {
        Some(b) => b.cb_arg,
        None => ptr::null_mut(),
    })
}

/// `void BIO_set_callback_arg(BIO *b, char *arg)`
#[no_mangle]
pub unsafe extern "C" fn BIO_set_callback_arg(bio: *mut Bio, arg: *mut c_char) {
    guard_ffi((), || {
        if let Some(b) = unsafe { bio.as_mut() } {
            b.cb_arg = arg;
        }
    })
}

/// `int BIO_get_new_index(void)`
///
/// Hands out custom method types starting at `BIO_TYPE_START + 1`. Values above
/// `BIO_TYPE_MASK` are exhausted, so the function then returns -1 rather than
/// wrapping into the reserved range.
#[no_mangle]
pub extern "C" fn BIO_get_new_index() -> c_int {
    guard_ffi(-1, || {
        static NEXT: AtomicI32 = AtomicI32::new(BIO_TYPE_START);
        let v = NEXT.fetch_add(1, Ordering::AcqRel) + 1;
        if v > BIO_TYPE_MASK {
            -1
        } else {
            v
        }
    })
}

// The `BIO_ctrl` family and the read/write/gets/puts entry points live in
// `iolib.rs`; the method-table API lives in `method.rs`; the opaque address value
// type lives in `addr.rs`. All are re-exported from this module so a reader sees
// one entry point.
pub use addr::{
    BIO_ADDR_clear, BIO_ADDR_copy, BIO_ADDR_dup, BIO_ADDR_family, BIO_ADDR_free,
    BIO_ADDR_hostname_string, BIO_ADDR_new, BIO_ADDR_path_string, BIO_ADDR_rawaddress,
    BIO_ADDR_rawmake, BIO_ADDR_rawport, BIO_ADDR_service_string,
};
pub use addr_info::{
    BIO_ADDRINFO_address, BIO_ADDRINFO_family, BIO_ADDRINFO_free, BIO_ADDRINFO_next,
    BIO_ADDRINFO_protocol, BIO_ADDRINFO_socktype, BIO_lookup, BIO_lookup_ex, BIO_parse_hostserv,
};
pub use bio_cb::{BIO_debug_callback, BIO_debug_callback_ex};
pub use bio_sock2::{
    BIO_accept, BIO_accept_ex, BIO_bind, BIO_connect, BIO_get_accept_socket, BIO_listen,
    BIO_set_tcp_ndelay, BIO_sock_info, BIO_socket,
};
pub use comp::{BIO_f_brotli, BIO_f_zlib, BIO_f_zstd};
pub use dump::{
    BIO_dump, BIO_dump_cb, BIO_dump_fp, BIO_dump_indent, BIO_dump_indent_cb, BIO_dump_indent_fp,
    BIO_hex_string,
};
pub use iolib::{
    BIO_callback_ctrl, BIO_ctrl, BIO_ctrl_get_read_request, BIO_ctrl_get_write_guarantee,
    BIO_ctrl_pending, BIO_ctrl_reset_read_request, BIO_ctrl_wpending, BIO_get_line, BIO_gets,
    BIO_int_ctrl, BIO_nread, BIO_nread0, BIO_nwrite, BIO_nwrite0, BIO_ptr_ctrl, BIO_puts, BIO_read,
    BIO_read_ex, BIO_recvmmsg, BIO_sendmmsg, BIO_write, BIO_write_ex,
};
pub use legacy_host::{BIO_get_host_ip, BIO_get_port, BIO_gethostbyname};
pub use method::{
    BIO_meth_free, BIO_meth_get_callback_ctrl, BIO_meth_get_create, BIO_meth_get_ctrl,
    BIO_meth_get_gets, BIO_meth_get_puts, BIO_meth_get_read, BIO_meth_get_read_ex,
    BIO_meth_get_recvmmsg, BIO_meth_get_sendmmsg, BIO_meth_get_write, BIO_meth_get_write_ex,
    BIO_meth_new, BIO_meth_set_callback_ctrl, BIO_meth_set_create, BIO_meth_set_ctrl,
    BIO_meth_set_gets, BIO_meth_set_puts, BIO_meth_set_read, BIO_meth_set_read_ex,
    BIO_meth_set_recvmmsg, BIO_meth_set_sendmmsg, BIO_meth_set_write, BIO_meth_set_write_ex,
};
pub use print::BIO_indent;
pub use retry::{BIO_dgram_non_fatal_error, BIO_fd_non_fatal_error, BIO_fd_should_retry};
