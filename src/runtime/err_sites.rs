//! Authority `ERR_raise*` coordinates — GENERATED, do not edit.
//!
//! Regenerate with `forensics/tools/gen_err_raise_sites.py` inside the
//! court container. See `forensics/atlas/err-raise-sites.json` for the
//! machine-readable form and `docs/ERROR_MODEL.md` for why these strings
//! are part of the contract rather than private archaeology.
//!
//! Authority: `openssl-3.6.4-production`; `__FILE__` prefix `../../src/openssl-3.6.4/`.

use core::ffi::{c_int, CStr};

/// One recorded authority raise site: where `ERR_raise*` ran, and with what.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ErrSite {
    /// `OPENSSL_FILE` — the authority's translation unit, as the compiler
    /// spelled it. Derived from the admitted build record, never hand-typed.
    pub file: &'static CStr,
    /// `OPENSSL_LINE`.
    pub line: c_int,
    /// `OPENSSL_FUNC`.
    pub func: &'static CStr,
    /// `ERR_GET_LIB` of the raised code.
    pub lib: c_int,
    /// The raised reason, including any `ERR_RFLAG_*` bits.
    pub reason: c_int,
    /// True when the authority supplies the reason at run time (a syscall
    /// error or a computed value) rather than from a header constant; the
    /// `reason` field is then 0 and the caller passes the real value to
    /// `raise_site_dynamic`.
    pub dynamic_reason: bool,
}

/// `sk_reserve` at `crypto/stack/stack.c:186` (CRYPTO_R_TOO_MANY_RECORDS).
pub(crate) const STACK_186: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/stack/stack.c",
    line: 186,
    func: c"sk_reserve",
    lib: 15,
    reason: 114,
    dynamic_reason: false,
};

/// `sk_reserve` at `crypto/stack/stack.c:212` (CRYPTO_R_TOO_MANY_RECORDS).
pub(crate) const STACK_212: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/stack/stack.c",
    line: 212,
    func: c"sk_reserve",
    lib: 15,
    reason: 114,
    dynamic_reason: false,
};

/// `OPENSSL_sk_reserve` at `crypto/stack/stack.c:251` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const STACK_251: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/stack/stack.c",
    line: 251,
    func: c"OPENSSL_sk_reserve",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OPENSSL_sk_insert` at `crypto/stack/stack.c:271` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const STACK_271: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/stack/stack.c",
    line: 271,
    func: c"OPENSSL_sk_insert",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OPENSSL_sk_insert` at `crypto/stack/stack.c:275` (CRYPTO_R_TOO_MANY_RECORDS).
pub(crate) const STACK_275: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/stack/stack.c",
    line: 275,
    func: c"OPENSSL_sk_insert",
    lib: 15,
    reason: 114,
    dynamic_reason: false,
};

/// `OPENSSL_sk_set` at `crypto/stack/stack.c:482` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const STACK_482: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/stack/stack.c",
    line: 482,
    func: c"OPENSSL_sk_set",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OPENSSL_sk_set` at `crypto/stack/stack.c:486` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const STACK_486: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/stack/stack.c",
    line: 486,
    func: c"OPENSSL_sk_set",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `get_and_lock` at `crypto/ex_data.c:37` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const EX_DATA_37: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/ex_data.c",
    line: 37,
    func: c"get_and_lock",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `ossl_crypto_get_ex_new_index_ex` at `crypto/ex_data.c:175` (ERR_R_CRYPTO_LIB).
pub(crate) const EX_DATA_175: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/ex_data.c",
    line: 175,
    func: c"ossl_crypto_get_ex_new_index_ex",
    lib: 15,
    reason: 524303,
    dynamic_reason: false,
};

/// `ossl_crypto_get_ex_new_index_ex` at `crypto/ex_data.c:191` (ERR_R_CRYPTO_LIB).
pub(crate) const EX_DATA_191: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/ex_data.c",
    line: 191,
    func: c"ossl_crypto_get_ex_new_index_ex",
    lib: 15,
    reason: 524303,
    dynamic_reason: false,
};

/// `CRYPTO_set_ex_data` at `crypto/ex_data.c:474` (ERR_R_CRYPTO_LIB).
pub(crate) const EX_DATA_474: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/ex_data.c",
    line: 474,
    func: c"CRYPTO_set_ex_data",
    lib: 15,
    reason: 524303,
    dynamic_reason: false,
};

/// `CRYPTO_set_ex_data` at `crypto/ex_data.c:481` (ERR_R_CRYPTO_LIB).
pub(crate) const EX_DATA_481: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/ex_data.c",
    line: 481,
    func: c"CRYPTO_set_ex_data",
    lib: 15,
    reason: 524303,
    dynamic_reason: false,
};

/// `CRYPTO_set_ex_data` at `crypto/ex_data.c:487` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const EX_DATA_487: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/ex_data.c",
    line: 487,
    func: c"CRYPTO_set_ex_data",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OPENSSL_init_crypto` at `crypto/init.c:504` (ERR_R_INIT_FAIL).
pub(crate) const INIT_504: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/init.c",
    line: 504,
    func: c"OPENSSL_init_crypto",
    lib: 15,
    reason: 786693,
    dynamic_reason: false,
};

/// `BIO_new_ex` at `crypto/bio/bio_lib.c:99` (ERR_R_INIT_FAIL).
pub(crate) const BIO_LIB_99: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 99,
    func: c"BIO_new_ex",
    lib: 32,
    reason: 786693,
    dynamic_reason: false,
};

/// `bio_read_intern` at `crypto/bio/bio_lib.c:267` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const BIO_LIB_267: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 267,
    func: c"bio_read_intern",
    lib: 32,
    reason: 786690,
    dynamic_reason: false,
};

/// `bio_read_intern` at `crypto/bio/bio_lib.c:271` (BIO_R_UNSUPPORTED_METHOD).
pub(crate) const BIO_LIB_271: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 271,
    func: c"bio_read_intern",
    lib: 32,
    reason: 121,
    dynamic_reason: false,
};

/// `bio_read_intern` at `crypto/bio/bio_lib.c:279` (BIO_R_UNINITIALIZED).
pub(crate) const BIO_LIB_279: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 279,
    func: c"bio_read_intern",
    lib: 32,
    reason: 120,
    dynamic_reason: false,
};

/// `bio_read_intern` at `crypto/bio/bio_lib.c:294` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_LIB_294: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 294,
    func: c"bio_read_intern",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `bio_write_intern` at `crypto/bio/bio_lib.c:340` (BIO_R_UNSUPPORTED_METHOD).
pub(crate) const BIO_LIB_340: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 340,
    func: c"bio_write_intern",
    lib: 32,
    reason: 121,
    dynamic_reason: false,
};

/// `bio_write_intern` at `crypto/bio/bio_lib.c:348` (BIO_R_UNINITIALIZED).
pub(crate) const BIO_LIB_348: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 348,
    func: c"bio_write_intern",
    lib: 32,
    reason: 120,
    dynamic_reason: false,
};

/// `BIO_sendmmsg` at `crypto/bio/bio_lib.c:399` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const BIO_LIB_399: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 399,
    func: c"BIO_sendmmsg",
    lib: 32,
    reason: 786690,
    dynamic_reason: false,
};

/// `BIO_sendmmsg` at `crypto/bio/bio_lib.c:405` (BIO_R_UNSUPPORTED_METHOD).
pub(crate) const BIO_LIB_405: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 405,
    func: c"BIO_sendmmsg",
    lib: 32,
    reason: 121,
    dynamic_reason: false,
};

/// `BIO_sendmmsg` at `crypto/bio/bio_lib.c:424` (BIO_R_UNINITIALIZED).
pub(crate) const BIO_LIB_424: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 424,
    func: c"BIO_sendmmsg",
    lib: 32,
    reason: 120,
    dynamic_reason: false,
};

/// `BIO_recvmmsg` at `crypto/bio/bio_lib.c:446` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const BIO_LIB_446: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 446,
    func: c"BIO_recvmmsg",
    lib: 32,
    reason: 786690,
    dynamic_reason: false,
};

/// `BIO_recvmmsg` at `crypto/bio/bio_lib.c:452` (BIO_R_UNSUPPORTED_METHOD).
pub(crate) const BIO_LIB_452: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 452,
    func: c"BIO_recvmmsg",
    lib: 32,
    reason: 121,
    dynamic_reason: false,
};

/// `BIO_recvmmsg` at `crypto/bio/bio_lib.c:471` (BIO_R_UNINITIALIZED).
pub(crate) const BIO_LIB_471: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 471,
    func: c"BIO_recvmmsg",
    lib: 32,
    reason: 120,
    dynamic_reason: false,
};

/// `BIO_puts` at `crypto/bio/bio_lib.c:500` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const BIO_LIB_500: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 500,
    func: c"BIO_puts",
    lib: 32,
    reason: 786690,
    dynamic_reason: false,
};

/// `BIO_puts` at `crypto/bio/bio_lib.c:504` (BIO_R_UNSUPPORTED_METHOD).
pub(crate) const BIO_LIB_504: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 504,
    func: c"BIO_puts",
    lib: 32,
    reason: 121,
    dynamic_reason: false,
};

/// `BIO_puts` at `crypto/bio/bio_lib.c:515` (BIO_R_UNINITIALIZED).
pub(crate) const BIO_LIB_515: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 515,
    func: c"BIO_puts",
    lib: 32,
    reason: 120,
    dynamic_reason: false,
};

/// `BIO_puts` at `crypto/bio/bio_lib.c:533` (BIO_R_LENGTH_TOO_LONG).
pub(crate) const BIO_LIB_533: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 533,
    func: c"BIO_puts",
    lib: 32,
    reason: 102,
    dynamic_reason: false,
};

/// `BIO_gets` at `crypto/bio/bio_lib.c:549` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const BIO_LIB_549: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 549,
    func: c"BIO_gets",
    lib: 32,
    reason: 786690,
    dynamic_reason: false,
};

/// `BIO_gets` at `crypto/bio/bio_lib.c:553` (BIO_R_UNSUPPORTED_METHOD).
pub(crate) const BIO_LIB_553: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 553,
    func: c"BIO_gets",
    lib: 32,
    reason: 121,
    dynamic_reason: false,
};

/// `BIO_gets` at `crypto/bio/bio_lib.c:558` (BIO_R_INVALID_ARGUMENT).
pub(crate) const BIO_LIB_558: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 558,
    func: c"BIO_gets",
    lib: 32,
    reason: 125,
    dynamic_reason: false,
};

/// `BIO_gets` at `crypto/bio/bio_lib.c:569` (BIO_R_UNINITIALIZED).
pub(crate) const BIO_LIB_569: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 569,
    func: c"BIO_gets",
    lib: 32,
    reason: 120,
    dynamic_reason: false,
};

/// `BIO_get_line` at `crypto/bio/bio_lib.c:601` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const BIO_LIB_601: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 601,
    func: c"BIO_get_line",
    lib: 32,
    reason: 786690,
    dynamic_reason: false,
};

/// `BIO_get_line` at `crypto/bio/bio_lib.c:605` (BIO_R_INVALID_ARGUMENT).
pub(crate) const BIO_LIB_605: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 605,
    func: c"BIO_get_line",
    lib: 32,
    reason: 125,
    dynamic_reason: false,
};

/// `BIO_get_line` at `crypto/bio/bio_lib.c:611` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const BIO_LIB_611: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 611,
    func: c"BIO_get_line",
    lib: 32,
    reason: 786690,
    dynamic_reason: false,
};

/// `BIO_get_line` at `crypto/bio/bio_lib.c:615` (BIO_R_UNINITIALIZED).
pub(crate) const BIO_LIB_615: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 615,
    func: c"BIO_get_line",
    lib: 32,
    reason: 120,
    dynamic_reason: false,
};

/// `BIO_ctrl` at `crypto/bio/bio_lib.c:663` (BIO_R_UNSUPPORTED_METHOD).
pub(crate) const BIO_LIB_663: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 663,
    func: c"BIO_ctrl",
    lib: 32,
    reason: 121,
    dynamic_reason: false,
};

/// `BIO_callback_ctrl` at `crypto/bio/bio_lib.c:690` (BIO_R_UNSUPPORTED_METHOD).
pub(crate) const BIO_LIB_690: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 690,
    func: c"BIO_callback_ctrl",
    lib: 32,
    reason: 121,
    dynamic_reason: false,
};

/// `BIO_find_type` at `crypto/bio/bio_lib.c:813` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const BIO_LIB_813: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 813,
    func: c"BIO_find_type",
    lib: 32,
    reason: 786690,
    dynamic_reason: false,
};

/// `BIO_wait` at `crypto/bio/bio_lib.c:1002` (ERR_raise dynamic reason).
pub(crate) const BIO_LIB_1002: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 1002,
    func: c"BIO_wait",
    lib: 32,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_do_connect_retry` at `crypto/bio/bio_lib.c:1022` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const BIO_LIB_1022: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 1022,
    func: c"BIO_do_connect_retry",
    lib: 32,
    reason: 786690,
    dynamic_reason: false,
};

/// `BIO_do_connect_retry` at `crypto/bio/bio_lib.c:1064` (ERR_raise dynamic reason).
pub(crate) const BIO_LIB_1064: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 1064,
    func: c"BIO_do_connect_retry",
    lib: 32,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_do_connect_retry` at `crypto/bio/bio_lib.c:1071` (BIO_R_CONNECT_ERROR).
pub(crate) const BIO_LIB_1071: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_lib.c",
    line: 1071,
    func: c"BIO_do_connect_retry",
    lib: 32,
    reason: 103,
    dynamic_reason: false,
};

/// `BIO_get_new_index` at `crypto/bio/bio_meth.c:27` (ERR_R_CRYPTO_LIB).
pub(crate) const BIO_METH_27: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_meth.c",
    line: 27,
    func: c"BIO_get_new_index",
    lib: 32,
    reason: 524303,
    dynamic_reason: false,
};

/// `addr_strings` at `crypto/bio/bio_addr.c:251` (ERR_raise_data dynamic reason).
pub(crate) const BIO_ADDR_251: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_addr.c",
    line: 251,
    func: c"addr_strings",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `addr_strings` at `crypto/bio/bio_addr.c:256` (ERR_R_SYS_LIB).
pub(crate) const BIO_ADDR_256: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_addr.c",
    line: 256,
    func: c"addr_strings",
    lib: 32,
    reason: 524290,
    dynamic_reason: false,
};

/// `BIO_parse_hostserv` at `crypto/bio/bio_addr.c:590` (BIO_R_AMBIGUOUS_HOST_OR_SERVICE).
pub(crate) const BIO_ADDR_590: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_addr.c",
    line: 590,
    func: c"BIO_parse_hostserv",
    lib: 32,
    reason: 129,
    dynamic_reason: false,
};

/// `BIO_parse_hostserv` at `crypto/bio/bio_addr.c:593` (BIO_R_MALFORMED_HOST_OR_SERVICE).
pub(crate) const BIO_ADDR_593: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_addr.c",
    line: 593,
    func: c"BIO_parse_hostserv",
    lib: 32,
    reason: 130,
    dynamic_reason: false,
};

/// `BIO_lookup_ex` at `crypto/bio/bio_addr.c:698` (BIO_R_UNSUPPORTED_PROTOCOL_FAMILY).
pub(crate) const BIO_ADDR_698: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_addr.c",
    line: 698,
    func: c"BIO_lookup_ex",
    lib: 32,
    reason: 131,
    dynamic_reason: false,
};

/// `BIO_lookup_ex` at `crypto/bio/bio_addr.c:707` (ERR_R_BIO_LIB).
pub(crate) const BIO_ADDR_707: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_addr.c",
    line: 707,
    func: c"BIO_lookup_ex",
    lib: 32,
    reason: 524320,
    dynamic_reason: false,
};

/// `BIO_lookup_ex` at `crypto/bio/bio_addr.c:744` (ERR_raise_data dynamic reason).
pub(crate) const BIO_ADDR_744: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_addr.c",
    line: 744,
    func: c"BIO_lookup_ex",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_lookup_ex` at `crypto/bio/bio_addr.c:746` (ERR_R_SYS_LIB).
pub(crate) const BIO_ADDR_746: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_addr.c",
    line: 746,
    func: c"BIO_lookup_ex",
    lib: 32,
    reason: 524290,
    dynamic_reason: false,
};

/// `BIO_lookup_ex` at `crypto/bio/bio_addr.c:751` (ERR_R_SYS_LIB).
pub(crate) const BIO_ADDR_751: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_addr.c",
    line: 751,
    func: c"BIO_lookup_ex",
    lib: 32,
    reason: 524290,
    dynamic_reason: false,
};

/// `BIO_lookup_ex` at `crypto/bio/bio_addr.c:767` (ERR_R_SYS_LIB).
pub(crate) const BIO_ADDR_767: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_addr.c",
    line: 767,
    func: c"BIO_lookup_ex",
    lib: 32,
    reason: 524290,
    dynamic_reason: false,
};

/// `BIO_lookup_ex` at `crypto/bio/bio_addr.c:813` (ERR_R_CRYPTO_LIB).
pub(crate) const BIO_ADDR_813: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_addr.c",
    line: 813,
    func: c"BIO_lookup_ex",
    lib: 32,
    reason: 524303,
    dynamic_reason: false,
};

/// `BIO_lookup_ex` at `crypto/bio/bio_addr.c:833` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_ADDR_833: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_addr.c",
    line: 833,
    func: c"BIO_lookup_ex",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `BIO_lookup_ex` at `crypto/bio/bio_addr.c:855` (ERR_raise_data dynamic reason).
pub(crate) const BIO_ADDR_855: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_addr.c",
    line: 855,
    func: c"BIO_lookup_ex",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_lookup_ex` at `crypto/bio/bio_addr.c:858` (ERR_raise_data dynamic reason).
pub(crate) const BIO_ADDR_858: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_addr.c",
    line: 858,
    func: c"BIO_lookup_ex",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_lookup_ex` at `crypto/bio/bio_addr.c:862` (ERR_raise_data dynamic reason).
pub(crate) const BIO_ADDR_862: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_addr.c",
    line: 862,
    func: c"BIO_lookup_ex",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_lookup_ex` at `crypto/bio/bio_addr.c:909` (ERR_raise_data dynamic reason).
pub(crate) const BIO_ADDR_909: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_addr.c",
    line: 909,
    func: c"BIO_lookup_ex",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_lookup_ex` at `crypto/bio/bio_addr.c:914` (BIO_R_MALFORMED_HOST_OR_SERVICE).
pub(crate) const BIO_ADDR_914: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_addr.c",
    line: 914,
    func: c"BIO_lookup_ex",
    lib: 32,
    reason: 130,
    dynamic_reason: false,
};

/// `BIO_lookup_ex` at `crypto/bio/bio_addr.c:956` (ERR_R_BIO_LIB).
pub(crate) const BIO_ADDR_956: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_addr.c",
    line: 956,
    func: c"BIO_lookup_ex",
    lib: 32,
    reason: 524320,
    dynamic_reason: false,
};

/// `_dopr` at `crypto/bio/bio_print.c:369` (ERR_R_UNSUPPORTED).
pub(crate) const BIO_PRINT_369: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_print.c",
    line: 369,
    func: c"_dopr",
    lib: 32,
    reason: 524556,
    dynamic_reason: false,
};

/// `BIO_get_host_ip` at `crypto/bio/bio_sock.c:57` (BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET).
pub(crate) const BIO_SOCK_57: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock.c",
    line: 57,
    func: c"BIO_get_host_ip",
    lib: 32,
    reason: 107,
    dynamic_reason: false,
};

/// `BIO_get_port` at `crypto/bio/bio_sock.c:80` (BIO_R_NO_PORT_DEFINED).
pub(crate) const BIO_SOCK_80: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock.c",
    line: 80,
    func: c"BIO_get_port",
    lib: 32,
    reason: 113,
    dynamic_reason: false,
};

/// `BIO_get_port` at `crypto/bio/bio_sock.c:89` (BIO_R_ADDRINFO_ADDR_IS_NOT_AF_INET).
pub(crate) const BIO_SOCK_89: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock.c",
    line: 89,
    func: c"BIO_get_port",
    lib: 32,
    reason: 141,
    dynamic_reason: false,
};

/// `BIO_sock_init` at `crypto/bio/bio_sock.c:152` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK_152: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock.c",
    line: 152,
    func: c"BIO_sock_init",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_sock_init` at `crypto/bio/bio_sock.c:154` (BIO_R_WSASTARTUP).
pub(crate) const BIO_SOCK_154: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock.c",
    line: 154,
    func: c"BIO_sock_init",
    lib: 32,
    reason: 122,
    dynamic_reason: false,
};

/// `BIO_socket_ioctl` at `crypto/bio/bio_sock.c:248` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK_248: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock.c",
    line: 248,
    func: c"BIO_socket_ioctl",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_accept` at `crypto/bio/bio_sock.c:301` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK_301: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock.c",
    line: 301,
    func: c"BIO_accept",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_accept` at `crypto/bio/bio_sock.c:303` (BIO_R_ACCEPT_ERROR).
pub(crate) const BIO_SOCK_303: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock.c",
    line: 303,
    func: c"BIO_accept",
    lib: 32,
    reason: 100,
    dynamic_reason: false,
};

/// `BIO_accept` at `crypto/bio/bio_sock.c:314` (ERR_R_BIO_LIB).
pub(crate) const BIO_SOCK_314: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock.c",
    line: 314,
    func: c"BIO_accept",
    lib: 32,
    reason: 524320,
    dynamic_reason: false,
};

/// `BIO_socket_nbio` at `crypto/bio/bio_sock.c:368` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK_368: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock.c",
    line: 368,
    func: c"BIO_socket_nbio",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_socket_nbio` at `crypto/bio/bio_sock.c:387` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK_387: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock.c",
    line: 387,
    func: c"BIO_socket_nbio",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_socket_nbio` at `crypto/bio/bio_sock.c:393` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const BIO_SOCK_393: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock.c",
    line: 393,
    func: c"BIO_socket_nbio",
    lib: 32,
    reason: 524550,
    dynamic_reason: false,
};

/// `BIO_sock_info` at `crypto/bio/bio_sock.c:410` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK_410: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock.c",
    line: 410,
    func: c"BIO_sock_info",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_sock_info` at `crypto/bio/bio_sock.c:412` (BIO_R_GETSOCKNAME_ERROR).
pub(crate) const BIO_SOCK_412: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock.c",
    line: 412,
    func: c"BIO_sock_info",
    lib: 32,
    reason: 132,
    dynamic_reason: false,
};

/// `BIO_sock_info` at `crypto/bio/bio_sock.c:416` (BIO_R_GETSOCKNAME_TRUNCATED_ADDRESS).
pub(crate) const BIO_SOCK_416: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock.c",
    line: 416,
    func: c"BIO_sock_info",
    lib: 32,
    reason: 133,
    dynamic_reason: false,
};

/// `BIO_sock_info` at `crypto/bio/bio_sock.c:421` (BIO_R_UNKNOWN_INFO_TYPE).
pub(crate) const BIO_SOCK_421: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock.c",
    line: 421,
    func: c"BIO_sock_info",
    lib: 32,
    reason: 140,
    dynamic_reason: false,
};

/// `BIO_socket` at `crypto/bio/bio_sock2.c:51` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK2_51: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 51,
    func: c"BIO_socket",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_socket` at `crypto/bio/bio_sock2.c:53` (BIO_R_UNABLE_TO_CREATE_SOCKET).
pub(crate) const BIO_SOCK2_53: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 53,
    func: c"BIO_socket",
    lib: 32,
    reason: 118,
    dynamic_reason: false,
};

/// `BIO_connect` at `crypto/bio/bio_sock2.c:86` (BIO_R_INVALID_SOCKET).
pub(crate) const BIO_SOCK2_86: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 86,
    func: c"BIO_connect",
    lib: 32,
    reason: 135,
    dynamic_reason: false,
};

/// `BIO_connect` at `crypto/bio/bio_sock2.c:97` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK2_97: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 97,
    func: c"BIO_connect",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_connect` at `crypto/bio/bio_sock2.c:99` (BIO_R_UNABLE_TO_KEEPALIVE).
pub(crate) const BIO_SOCK2_99: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 99,
    func: c"BIO_connect",
    lib: 32,
    reason: 137,
    dynamic_reason: false,
};

/// `BIO_connect` at `crypto/bio/bio_sock2.c:108` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK2_108: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 108,
    func: c"BIO_connect",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_connect` at `crypto/bio/bio_sock2.c:110` (BIO_R_UNABLE_TO_NODELAY).
pub(crate) const BIO_SOCK2_110: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 110,
    func: c"BIO_connect",
    lib: 32,
    reason: 138,
    dynamic_reason: false,
};

/// `BIO_connect` at `crypto/bio/bio_sock2.c:122` (BIO_R_TFO_NO_KERNEL_SUPPORT).
pub(crate) const BIO_SOCK2_122: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 122,
    func: c"BIO_connect",
    lib: 32,
    reason: 108,
    dynamic_reason: false,
};

/// `BIO_connect` at `crypto/bio/bio_sock2.c:127` (BIO_R_TFO_DISABLED).
pub(crate) const BIO_SOCK2_127: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 127,
    func: c"BIO_connect",
    lib: 32,
    reason: 106,
    dynamic_reason: false,
};

/// `BIO_connect` at `crypto/bio/bio_sock2.c:136` (BIO_R_TFO_NO_KERNEL_SUPPORT).
pub(crate) const BIO_SOCK2_136: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 136,
    func: c"BIO_connect",
    lib: 32,
    reason: 108,
    dynamic_reason: false,
};

/// `BIO_connect` at `crypto/bio/bio_sock2.c:141` (BIO_R_TFO_DISABLED).
pub(crate) const BIO_SOCK2_141: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 141,
    func: c"BIO_connect",
    lib: 32,
    reason: 106,
    dynamic_reason: false,
};

/// `BIO_connect` at `crypto/bio/bio_sock2.c:157` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK2_157: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 157,
    func: c"BIO_connect",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_connect` at `crypto/bio/bio_sock2.c:159` (BIO_R_CONNECT_ERROR).
pub(crate) const BIO_SOCK2_159: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 159,
    func: c"BIO_connect",
    lib: 32,
    reason: 103,
    dynamic_reason: false,
};

/// `BIO_connect` at `crypto/bio/bio_sock2.c:168` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK2_168: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 168,
    func: c"BIO_connect",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_connect` at `crypto/bio/bio_sock2.c:170` (BIO_R_UNABLE_TO_TFO).
pub(crate) const BIO_SOCK2_170: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 170,
    func: c"BIO_connect",
    lib: 32,
    reason: 109,
    dynamic_reason: false,
};

/// `BIO_connect` at `crypto/bio/bio_sock2.c:183` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK2_183: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 183,
    func: c"BIO_connect",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_connect` at `crypto/bio/bio_sock2.c:185` (BIO_R_CONNECT_ERROR).
pub(crate) const BIO_SOCK2_185: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 185,
    func: c"BIO_connect",
    lib: 32,
    reason: 103,
    dynamic_reason: false,
};

/// `BIO_bind` at `crypto/bio/bio_sock2.c:215` (BIO_R_INVALID_SOCKET).
pub(crate) const BIO_SOCK2_215: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 215,
    func: c"BIO_bind",
    lib: 32,
    reason: 135,
    dynamic_reason: false,
};

/// `BIO_bind` at `crypto/bio/bio_sock2.c:228` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK2_228: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 228,
    func: c"BIO_bind",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_bind` at `crypto/bio/bio_sock2.c:230` (BIO_R_UNABLE_TO_REUSEADDR).
pub(crate) const BIO_SOCK2_230: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 230,
    func: c"BIO_bind",
    lib: 32,
    reason: 139,
    dynamic_reason: false,
};

/// `BIO_bind` at `crypto/bio/bio_sock2.c:237` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK2_237: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 237,
    func: c"BIO_bind",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_bind` at `crypto/bio/bio_sock2.c:239` (BIO_R_UNABLE_TO_BIND_SOCKET).
pub(crate) const BIO_SOCK2_239: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 239,
    func: c"BIO_bind",
    lib: 32,
    reason: 117,
    dynamic_reason: false,
};

/// `BIO_listen` at `crypto/bio/bio_sock2.c:291` (BIO_R_INVALID_SOCKET).
pub(crate) const BIO_SOCK2_291: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 291,
    func: c"BIO_listen",
    lib: 32,
    reason: 135,
    dynamic_reason: false,
};

/// `BIO_listen` at `crypto/bio/bio_sock2.c:299` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK2_299: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 299,
    func: c"BIO_listen",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_listen` at `crypto/bio/bio_sock2.c:301` (BIO_R_GETTING_SOCKTYPE).
pub(crate) const BIO_SOCK2_301: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 301,
    func: c"BIO_listen",
    lib: 32,
    reason: 134,
    dynamic_reason: false,
};

/// `BIO_listen` at `crypto/bio/bio_sock2.c:312` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK2_312: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 312,
    func: c"BIO_listen",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_listen` at `crypto/bio/bio_sock2.c:314` (BIO_R_UNABLE_TO_KEEPALIVE).
pub(crate) const BIO_SOCK2_314: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 314,
    func: c"BIO_listen",
    lib: 32,
    reason: 137,
    dynamic_reason: false,
};

/// `BIO_listen` at `crypto/bio/bio_sock2.c:323` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK2_323: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 323,
    func: c"BIO_listen",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_listen` at `crypto/bio/bio_sock2.c:325` (BIO_R_UNABLE_TO_NODELAY).
pub(crate) const BIO_SOCK2_325: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 325,
    func: c"BIO_listen",
    lib: 32,
    reason: 138,
    dynamic_reason: false,
};

/// `BIO_listen` at `crypto/bio/bio_sock2.c:341` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK2_341: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 341,
    func: c"BIO_listen",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_listen` at `crypto/bio/bio_sock2.c:343` (BIO_R_LISTEN_V6_ONLY).
pub(crate) const BIO_SOCK2_343: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 343,
    func: c"BIO_listen",
    lib: 32,
    reason: 136,
    dynamic_reason: false,
};

/// `BIO_listen` at `crypto/bio/bio_sock2.c:353` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK2_353: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 353,
    func: c"BIO_listen",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_listen` at `crypto/bio/bio_sock2.c:355` (BIO_R_UNABLE_TO_LISTEN_SOCKET).
pub(crate) const BIO_SOCK2_355: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 355,
    func: c"BIO_listen",
    lib: 32,
    reason: 119,
    dynamic_reason: false,
};

/// `BIO_listen` at `crypto/bio/bio_sock2.c:373` (BIO_R_TFO_NO_KERNEL_SUPPORT).
pub(crate) const BIO_SOCK2_373: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 373,
    func: c"BIO_listen",
    lib: 32,
    reason: 108,
    dynamic_reason: false,
};

/// `BIO_listen` at `crypto/bio/bio_sock2.c:378` (BIO_R_TFO_DISABLED).
pub(crate) const BIO_SOCK2_378: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 378,
    func: c"BIO_listen",
    lib: 32,
    reason: 106,
    dynamic_reason: false,
};

/// `BIO_listen` at `crypto/bio/bio_sock2.c:387` (BIO_R_TFO_NO_KERNEL_SUPPORT).
pub(crate) const BIO_SOCK2_387: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 387,
    func: c"BIO_listen",
    lib: 32,
    reason: 108,
    dynamic_reason: false,
};

/// `BIO_listen` at `crypto/bio/bio_sock2.c:392` (BIO_R_TFO_DISABLED).
pub(crate) const BIO_SOCK2_392: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 392,
    func: c"BIO_listen",
    lib: 32,
    reason: 106,
    dynamic_reason: false,
};

/// `BIO_listen` at `crypto/bio/bio_sock2.c:400` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK2_400: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 400,
    func: c"BIO_listen",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_listen` at `crypto/bio/bio_sock2.c:402` (BIO_R_UNABLE_TO_TFO).
pub(crate) const BIO_SOCK2_402: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 402,
    func: c"BIO_listen",
    lib: 32,
    reason: 109,
    dynamic_reason: false,
};

/// `BIO_accept_ex` at `crypto/bio/bio_sock2.c:430` (ERR_raise_data dynamic reason).
pub(crate) const BIO_SOCK2_430: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 430,
    func: c"BIO_accept_ex",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_accept_ex` at `crypto/bio/bio_sock2.c:432` (BIO_R_ACCEPT_ERROR).
pub(crate) const BIO_SOCK2_432: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bio_sock2.c",
    line: 432,
    func: c"BIO_accept_ex",
    lib: 32,
    reason: 100,
    dynamic_reason: false,
};

/// `acpt_state` at `crypto/bio/bss_acpt.c:157` (BIO_R_NO_ACCEPT_ADDR_OR_SERVICE_SPECIFIED).
pub(crate) const BSS_ACPT_157: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_acpt.c",
    line: 157,
    func: c"acpt_state",
    lib: 32,
    reason: 143,
    dynamic_reason: false,
};

/// `acpt_state` at `crypto/bio/bss_acpt.c:192` (BIO_R_UNAVAILABLE_IP_FAMILY).
pub(crate) const BSS_ACPT_192: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_acpt.c",
    line: 192,
    func: c"acpt_state",
    lib: 32,
    reason: 145,
    dynamic_reason: false,
};

/// `acpt_state` at `crypto/bio/bss_acpt.c:203` (BIO_R_UNSUPPORTED_IP_FAMILY).
pub(crate) const BSS_ACPT_203: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_acpt.c",
    line: 203,
    func: c"acpt_state",
    lib: 32,
    reason: 146,
    dynamic_reason: false,
};

/// `acpt_state` at `crypto/bio/bss_acpt.c:212` (BIO_R_LOOKUP_RETURNED_NOTHING).
pub(crate) const BSS_ACPT_212: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_acpt.c",
    line: 212,
    func: c"acpt_state",
    lib: 32,
    reason: 142,
    dynamic_reason: false,
};

/// `acpt_state` at `crypto/bio/bss_acpt.c:233` (ERR_raise_data dynamic reason).
pub(crate) const BSS_ACPT_233: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_acpt.c",
    line: 233,
    func: c"acpt_state",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `acpt_state` at `crypto/bio/bss_acpt.c:236` (BIO_R_UNABLE_TO_CREATE_SOCKET).
pub(crate) const BSS_ACPT_236: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_acpt.c",
    line: 236,
    func: c"acpt_state",
    lib: 32,
    reason: 118,
    dynamic_reason: false,
};

/// `bio_write` at `crypto/bio/bss_bio.c:286` (BIO_R_BROKEN_PIPE).
pub(crate) const BSS_BIO_286: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_bio.c",
    line: 286,
    func: c"bio_write",
    lib: 32,
    reason: 124,
    dynamic_reason: false,
};

/// `bio_nwrite0` at `crypto/bio/bss_bio.c:361` (BIO_R_BROKEN_PIPE).
pub(crate) const BSS_BIO_361: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_bio.c",
    line: 361,
    func: c"bio_nwrite0",
    lib: 32,
    reason: 124,
    dynamic_reason: false,
};

/// `bio_ctrl` at `crypto/bio/bss_bio.c:426` (BIO_R_IN_USE).
pub(crate) const BSS_BIO_426: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_bio.c",
    line: 426,
    func: c"bio_ctrl",
    lib: 32,
    reason: 123,
    dynamic_reason: false,
};

/// `bio_ctrl` at `crypto/bio/bss_bio.c:429` (BIO_R_INVALID_ARGUMENT).
pub(crate) const BSS_BIO_429: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_bio.c",
    line: 429,
    func: c"bio_ctrl",
    lib: 32,
    reason: 125,
    dynamic_reason: false,
};

/// `bio_make_pair` at `crypto/bio/bss_bio.c:617` (BIO_R_IN_USE).
pub(crate) const BSS_BIO_617: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_bio.c",
    line: 617,
    func: c"bio_make_pair",
    lib: 32,
    reason: 123,
    dynamic_reason: false,
};

/// `BIO_nread0` at `crypto/bio/bss_bio.c:750` (BIO_R_UNINITIALIZED).
pub(crate) const BSS_BIO_750: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_bio.c",
    line: 750,
    func: c"BIO_nread0",
    lib: 32,
    reason: 120,
    dynamic_reason: false,
};

/// `BIO_nread` at `crypto/bio/bss_bio.c:766` (BIO_R_UNINITIALIZED).
pub(crate) const BSS_BIO_766: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_bio.c",
    line: 766,
    func: c"BIO_nread",
    lib: 32,
    reason: 120,
    dynamic_reason: false,
};

/// `BIO_nwrite0` at `crypto/bio/bss_bio.c:781` (BIO_R_UNINITIALIZED).
pub(crate) const BSS_BIO_781: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_bio.c",
    line: 781,
    func: c"BIO_nwrite0",
    lib: 32,
    reason: 120,
    dynamic_reason: false,
};

/// `BIO_nwrite` at `crypto/bio/bss_bio.c:797` (BIO_R_UNINITIALIZED).
pub(crate) const BSS_BIO_797: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_bio.c",
    line: 797,
    func: c"BIO_nwrite",
    lib: 32,
    reason: 120,
    dynamic_reason: false,
};

/// `conn_state` at `crypto/bio/bss_conn.c:123` (BIO_R_NO_HOSTNAME_OR_SERVICE_SPECIFIED).
pub(crate) const BSS_CONN_123: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_conn.c",
    line: 123,
    func: c"conn_state",
    lib: 32,
    reason: 144,
    dynamic_reason: false,
};

/// `conn_state` at `crypto/bio/bss_conn.c:144` (BIO_R_UNAVAILABLE_IP_FAMILY).
pub(crate) const BSS_CONN_144: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_conn.c",
    line: 144,
    func: c"conn_state",
    lib: 32,
    reason: 145,
    dynamic_reason: false,
};

/// `conn_state` at `crypto/bio/bss_conn.c:155` (BIO_R_UNSUPPORTED_IP_FAMILY).
pub(crate) const BSS_CONN_155: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_conn.c",
    line: 155,
    func: c"conn_state",
    lib: 32,
    reason: 146,
    dynamic_reason: false,
};

/// `conn_state` at `crypto/bio/bss_conn.c:166` (BIO_R_LOOKUP_RETURNED_NOTHING).
pub(crate) const BSS_CONN_166: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_conn.c",
    line: 166,
    func: c"conn_state",
    lib: 32,
    reason: 142,
    dynamic_reason: false,
};

/// `conn_state` at `crypto/bio/bss_conn.c:178` (ERR_raise_data dynamic reason).
pub(crate) const BSS_CONN_178: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_conn.c",
    line: 178,
    func: c"conn_state",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `conn_state` at `crypto/bio/bss_conn.c:181` (BIO_R_UNABLE_TO_CREATE_SOCKET).
pub(crate) const BSS_CONN_181: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_conn.c",
    line: 181,
    func: c"conn_state",
    lib: 32,
    reason: 118,
    dynamic_reason: false,
};

/// `conn_state` at `crypto/bio/bss_conn.c:215` (ERR_raise_data dynamic reason).
pub(crate) const BSS_CONN_215: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_conn.c",
    line: 215,
    func: c"conn_state",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `conn_state` at `crypto/bio/bss_conn.c:245` (ERR_raise_data dynamic reason).
pub(crate) const BSS_CONN_245: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_conn.c",
    line: 245,
    func: c"conn_state",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `conn_state` at `crypto/bio/bss_conn.c:248` (BIO_R_NBIO_CONNECT_ERROR).
pub(crate) const BSS_CONN_248: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_conn.c",
    line: 248,
    func: c"conn_state",
    lib: 32,
    reason: 110,
    dynamic_reason: false,
};

/// `conn_state` at `crypto/bio/bss_conn.c:259` (BIO_R_CONNECT_ERROR).
pub(crate) const BSS_CONN_259: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_conn.c",
    line: 259,
    func: c"conn_state",
    lib: 32,
    reason: 103,
    dynamic_reason: false,
};

/// `conn_gets` at `crypto/bio/bss_conn.c:754` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const BSS_CONN_754: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_conn.c",
    line: 754,
    func: c"conn_gets",
    lib: 32,
    reason: 786690,
    dynamic_reason: false,
};

/// `conn_gets` at `crypto/bio/bss_conn.c:758` (BIO_R_INVALID_ARGUMENT).
pub(crate) const BSS_CONN_758: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_conn.c",
    line: 758,
    func: c"conn_gets",
    lib: 32,
    reason: 125,
    dynamic_reason: false,
};

/// `conn_gets` at `crypto/bio/bss_conn.c:764` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const BSS_CONN_764: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_conn.c",
    line: 764,
    func: c"conn_gets",
    lib: 32,
    reason: 786690,
    dynamic_reason: false,
};

/// `conn_gets` at `crypto/bio/bss_conn.c:775` (ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
pub(crate) const BSS_CONN_775: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_conn.c",
    line: 775,
    func: c"conn_gets",
    lib: 32,
    reason: 786689,
    dynamic_reason: false,
};

/// `conn_sendmmsg` at `crypto/bio/bss_conn.c:810` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const BSS_CONN_810: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_conn.c",
    line: 810,
    func: c"conn_sendmmsg",
    lib: 32,
    reason: 786690,
    dynamic_reason: false,
};

/// `conn_sendmmsg` at `crypto/bio/bss_conn.c:825` (ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
pub(crate) const BSS_CONN_825: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_conn.c",
    line: 825,
    func: c"conn_sendmmsg",
    lib: 32,
    reason: 786689,
    dynamic_reason: false,
};

/// `conn_recvmmsg` at `crypto/bio/bss_conn.c:841` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const BSS_CONN_841: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_conn.c",
    line: 841,
    func: c"conn_recvmmsg",
    lib: 32,
    reason: 786690,
    dynamic_reason: false,
};

/// `conn_recvmmsg` at `crypto/bio/bss_conn.c:856` (ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
pub(crate) const BSS_CONN_856: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_conn.c",
    line: 856,
    func: c"conn_recvmmsg",
    lib: 32,
    reason: 786689,
    dynamic_reason: false,
};

/// `dgram_adjust_rcv_timeout` at `crypto/bio/bss_dgram.c:328` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_328: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 328,
    func: c"dgram_adjust_rcv_timeout",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_adjust_rcv_timeout` at `crypto/bio/bss_dgram.c:337` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_337: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 337,
    func: c"dgram_adjust_rcv_timeout",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_adjust_rcv_timeout` at `crypto/bio/bss_dgram.c:359` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_359: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 359,
    func: c"dgram_adjust_rcv_timeout",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_adjust_rcv_timeout` at `crypto/bio/bss_dgram.c:366` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_366: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 366,
    func: c"dgram_adjust_rcv_timeout",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_reset_rcv_timeout` at `crypto/bio/bss_dgram.c:408` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_408: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 408,
    func: c"dgram_reset_rcv_timeout",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_reset_rcv_timeout` at `crypto/bio/bss_dgram.c:414` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_414: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 414,
    func: c"dgram_reset_rcv_timeout",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_ctrl` at `crypto/bio/bss_dgram.c:650` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_650: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 650,
    func: c"dgram_ctrl",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_ctrl` at `crypto/bio/bss_dgram.c:659` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_659: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 659,
    func: c"dgram_ctrl",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_ctrl` at `crypto/bio/bss_dgram.c:799` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_799: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 799,
    func: c"dgram_ctrl",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_ctrl` at `crypto/bio/bss_dgram.c:806` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_806: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 806,
    func: c"dgram_ctrl",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_ctrl` at `crypto/bio/bss_dgram.c:820` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_820: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 820,
    func: c"dgram_ctrl",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_ctrl` at `crypto/bio/bss_dgram.c:833` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_833: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 833,
    func: c"dgram_ctrl",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_ctrl` at `crypto/bio/bss_dgram.c:836` (ERR_R_INTERNAL_ERROR).
pub(crate) const BSS_DGRAM_836: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 836,
    func: c"dgram_ctrl",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `dgram_ctrl` at `crypto/bio/bss_dgram.c:855` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_855: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 855,
    func: c"dgram_ctrl",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_ctrl` at `crypto/bio/bss_dgram.c:862` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_862: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 862,
    func: c"dgram_ctrl",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_ctrl` at `crypto/bio/bss_dgram.c:876` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_876: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 876,
    func: c"dgram_ctrl",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_ctrl` at `crypto/bio/bss_dgram.c:889` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_889: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 889,
    func: c"dgram_ctrl",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_ctrl` at `crypto/bio/bss_dgram.c:892` (ERR_R_INTERNAL_ERROR).
pub(crate) const BSS_DGRAM_892: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 892,
    func: c"dgram_ctrl",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `dgram_ctrl` at `crypto/bio/bss_dgram.c:932` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_932: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 932,
    func: c"dgram_ctrl",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_ctrl` at `crypto/bio/bss_dgram.c:939` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_939: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 939,
    func: c"dgram_ctrl",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_ctrl` at `crypto/bio/bss_dgram.c:947` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_947: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 947,
    func: c"dgram_ctrl",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_ctrl` at `crypto/bio/bss_dgram.c:961` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_961: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 961,
    func: c"dgram_ctrl",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_ctrl` at `crypto/bio/bss_dgram.c:969` (ERR_raise_data dynamic reason).
pub(crate) const BSS_DGRAM_969: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 969,
    func: c"dgram_ctrl",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `pack_local` at `crypto/bio/bss_dgram.c:1231` (BIO_R_PORT_MISMATCH).
pub(crate) const BSS_DGRAM_1231: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1231,
    func: c"pack_local",
    lib: 32,
    reason: 150,
    dynamic_reason: false,
};

/// `pack_local` at `crypto/bio/bss_dgram.c:1269` (BIO_R_PORT_MISMATCH).
pub(crate) const BSS_DGRAM_1269: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1269,
    func: c"pack_local",
    lib: 32,
    reason: 150,
    dynamic_reason: false,
};

/// `pack_local` at `crypto/bio/bss_dgram.c:1301` (BIO_R_PORT_MISMATCH).
pub(crate) const BSS_DGRAM_1301: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1301,
    func: c"pack_local",
    lib: 32,
    reason: 150,
    dynamic_reason: false,
};

/// `pack_local` at `crypto/bio/bss_dgram.c:1307` (BIO_R_PORT_MISMATCH).
pub(crate) const BSS_DGRAM_1307: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1307,
    func: c"pack_local",
    lib: 32,
    reason: 150,
    dynamic_reason: false,
};

/// `dgram_sendmmsg` at `crypto/bio/bss_dgram.c:1402` (BIO_R_LOCAL_ADDR_NOT_AVAILABLE).
pub(crate) const BSS_DGRAM_1402: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1402,
    func: c"dgram_sendmmsg",
    lib: 32,
    reason: 111,
    dynamic_reason: false,
};

/// `dgram_sendmmsg` at `crypto/bio/bss_dgram.c:1410` (BIO_R_LOCAL_ADDR_NOT_AVAILABLE).
pub(crate) const BSS_DGRAM_1410: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1410,
    func: c"dgram_sendmmsg",
    lib: 32,
    reason: 111,
    dynamic_reason: false,
};

/// `dgram_sendmmsg` at `crypto/bio/bss_dgram.c:1420` (ERR_raise dynamic reason).
pub(crate) const BSS_DGRAM_1420: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1420,
    func: c"dgram_sendmmsg",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_sendmmsg` at `crypto/bio/bss_dgram.c:1441` (BIO_R_LOCAL_ADDR_NOT_AVAILABLE).
pub(crate) const BSS_DGRAM_1441: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1441,
    func: c"dgram_sendmmsg",
    lib: 32,
    reason: 111,
    dynamic_reason: false,
};

/// `dgram_sendmmsg` at `crypto/bio/bss_dgram.c:1447` (BIO_R_LOCAL_ADDR_NOT_AVAILABLE).
pub(crate) const BSS_DGRAM_1447: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1447,
    func: c"dgram_sendmmsg",
    lib: 32,
    reason: 111,
    dynamic_reason: false,
};

/// `dgram_sendmmsg` at `crypto/bio/bss_dgram.c:1455` (ERR_raise dynamic reason).
pub(crate) const BSS_DGRAM_1455: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1455,
    func: c"dgram_sendmmsg",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_sendmmsg` at `crypto/bio/bss_dgram.c:1473` (BIO_R_LOCAL_ADDR_NOT_AVAILABLE).
pub(crate) const BSS_DGRAM_1473: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1473,
    func: c"dgram_sendmmsg",
    lib: 32,
    reason: 111,
    dynamic_reason: false,
};

/// `dgram_sendmmsg` at `crypto/bio/bss_dgram.c:1479` (BIO_R_LOCAL_ADDR_NOT_AVAILABLE).
pub(crate) const BSS_DGRAM_1479: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1479,
    func: c"dgram_sendmmsg",
    lib: 32,
    reason: 111,
    dynamic_reason: false,
};

/// `dgram_sendmmsg` at `crypto/bio/bss_dgram.c:1487` (ERR_raise dynamic reason).
pub(crate) const BSS_DGRAM_1487: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1487,
    func: c"dgram_sendmmsg",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_sendmmsg` at `crypto/bio/bss_dgram.c:1507` (BIO_R_LOCAL_ADDR_NOT_AVAILABLE).
pub(crate) const BSS_DGRAM_1507: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1507,
    func: c"dgram_sendmmsg",
    lib: 32,
    reason: 111,
    dynamic_reason: false,
};

/// `dgram_sendmmsg` at `crypto/bio/bss_dgram.c:1522` (ERR_raise dynamic reason).
pub(crate) const BSS_DGRAM_1522: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1522,
    func: c"dgram_sendmmsg",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_sendmmsg` at `crypto/bio/bss_dgram.c:1533` (BIO_R_UNSUPPORTED_METHOD).
pub(crate) const BSS_DGRAM_1533: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1533,
    func: c"dgram_sendmmsg",
    lib: 32,
    reason: 121,
    dynamic_reason: false,
};

/// `dgram_recvmmsg` at `crypto/bio/bss_dgram.c:1604` (BIO_R_LOCAL_ADDR_NOT_AVAILABLE).
pub(crate) const BSS_DGRAM_1604: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1604,
    func: c"dgram_recvmmsg",
    lib: 32,
    reason: 111,
    dynamic_reason: false,
};

/// `dgram_recvmmsg` at `crypto/bio/bss_dgram.c:1613` (ERR_raise dynamic reason).
pub(crate) const BSS_DGRAM_1613: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1613,
    func: c"dgram_recvmmsg",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_recvmmsg` at `crypto/bio/bss_dgram.c:1653` (BIO_R_LOCAL_ADDR_NOT_AVAILABLE).
pub(crate) const BSS_DGRAM_1653: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1653,
    func: c"dgram_recvmmsg",
    lib: 32,
    reason: 111,
    dynamic_reason: false,
};

/// `dgram_recvmmsg` at `crypto/bio/bss_dgram.c:1660` (ERR_raise dynamic reason).
pub(crate) const BSS_DGRAM_1660: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1660,
    func: c"dgram_recvmmsg",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_recvmmsg` at `crypto/bio/bss_dgram.c:1704` (BIO_R_LOCAL_ADDR_NOT_AVAILABLE).
pub(crate) const BSS_DGRAM_1704: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1704,
    func: c"dgram_recvmmsg",
    lib: 32,
    reason: 111,
    dynamic_reason: false,
};

/// `dgram_recvmmsg` at `crypto/bio/bss_dgram.c:1711` (ERR_raise dynamic reason).
pub(crate) const BSS_DGRAM_1711: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1711,
    func: c"dgram_recvmmsg",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_recvmmsg` at `crypto/bio/bss_dgram.c:1751` (BIO_R_LOCAL_ADDR_NOT_AVAILABLE).
pub(crate) const BSS_DGRAM_1751: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1751,
    func: c"dgram_recvmmsg",
    lib: 32,
    reason: 111,
    dynamic_reason: false,
};

/// `dgram_recvmmsg` at `crypto/bio/bss_dgram.c:1767` (ERR_raise dynamic reason).
pub(crate) const BSS_DGRAM_1767: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1767,
    func: c"dgram_recvmmsg",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_recvmmsg` at `crypto/bio/bss_dgram.c:1778` (BIO_R_UNSUPPORTED_METHOD).
pub(crate) const BSS_DGRAM_1778: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1778,
    func: c"dgram_recvmmsg",
    lib: 32,
    reason: 121,
    dynamic_reason: false,
};

/// `BIO_new_dgram_sctp` at `crypto/bio/bss_dgram.c:1818` (ERR_R_SYS_LIB).
pub(crate) const BSS_DGRAM_1818: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1818,
    func: c"BIO_new_dgram_sctp",
    lib: 32,
    reason: 524290,
    dynamic_reason: false,
};

/// `BIO_new_dgram_sctp` at `crypto/bio/bss_dgram.c:1827` (ERR_R_SYS_LIB).
pub(crate) const BSS_DGRAM_1827: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1827,
    func: c"BIO_new_dgram_sctp",
    lib: 32,
    reason: 524290,
    dynamic_reason: false,
};

/// `BIO_new_dgram_sctp` at `crypto/bio/bss_dgram.c:1865` (ERR_R_SYS_LIB).
pub(crate) const BSS_DGRAM_1865: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 1865,
    func: c"BIO_new_dgram_sctp",
    lib: 32,
    reason: 524290,
    dynamic_reason: false,
};

/// `dgram_sctp_read` at `crypto/bio/bss_dgram.c:2181` (BIO_R_CONNECT_ERROR).
pub(crate) const BSS_DGRAM_2181: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram.c",
    line: 2181,
    func: c"dgram_sctp_read",
    lib: 32,
    reason: 103,
    dynamic_reason: false,
};

/// `dgram_mem_init` at `crypto/bio/bss_dgram_pair.c:309` (ERR_R_BIO_LIB).
pub(crate) const BSS_DGRAM_PAIR_309: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 309,
    func: c"dgram_mem_init",
    lib: 32,
    reason: 524320,
    dynamic_reason: false,
};

/// `dgram_pair_ctrl_make_bio_pair` at `crypto/bio/bss_dgram_pair.c:345` (BIO_R_INVALID_ARGUMENT).
pub(crate) const BSS_DGRAM_PAIR_345: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 345,
    func: c"dgram_pair_ctrl_make_bio_pair",
    lib: 32,
    reason: 125,
    dynamic_reason: false,
};

/// `dgram_pair_ctrl_make_bio_pair` at `crypto/bio/bss_dgram_pair.c:351` (BIO_R_INVALID_ARGUMENT).
pub(crate) const BSS_DGRAM_PAIR_351: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 351,
    func: c"dgram_pair_ctrl_make_bio_pair",
    lib: 32,
    reason: 125,
    dynamic_reason: false,
};

/// `dgram_pair_ctrl_make_bio_pair` at `crypto/bio/bss_dgram_pair.c:360` (BIO_R_UNINITIALIZED).
pub(crate) const BSS_DGRAM_PAIR_360: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 360,
    func: c"dgram_pair_ctrl_make_bio_pair",
    lib: 32,
    reason: 120,
    dynamic_reason: false,
};

/// `dgram_pair_ctrl_make_bio_pair` at `crypto/bio/bss_dgram_pair.c:369` (BIO_R_IN_USE).
pub(crate) const BSS_DGRAM_PAIR_369: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 369,
    func: c"dgram_pair_ctrl_make_bio_pair",
    lib: 32,
    reason: 123,
    dynamic_reason: false,
};

/// `dgram_pair_ctrl_make_bio_pair` at `crypto/bio/bss_dgram_pair.c:376` (BIO_R_UNINITIALIZED).
pub(crate) const BSS_DGRAM_PAIR_376: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 376,
    func: c"dgram_pair_ctrl_make_bio_pair",
    lib: 32,
    reason: 120,
    dynamic_reason: false,
};

/// `dgram_pair_ctrl_make_bio_pair` at `crypto/bio/bss_dgram_pair.c:382` (ERR_R_BIO_LIB).
pub(crate) const BSS_DGRAM_PAIR_382: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 382,
    func: c"dgram_pair_ctrl_make_bio_pair",
    lib: 32,
    reason: 524320,
    dynamic_reason: false,
};

/// `dgram_pair_ctrl_make_bio_pair` at `crypto/bio/bss_dgram_pair.c:388` (ERR_R_BIO_LIB).
pub(crate) const BSS_DGRAM_PAIR_388: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 388,
    func: c"dgram_pair_ctrl_make_bio_pair",
    lib: 32,
    reason: 524320,
    dynamic_reason: false,
};

/// `dgram_pair_ctrl_set_write_buf_size` at `crypto/bio/bss_dgram_pair.c:465` (BIO_R_IN_USE).
pub(crate) const BSS_DGRAM_PAIR_465: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 465,
    func: c"dgram_pair_ctrl_set_write_buf_size",
    lib: 32,
    reason: 123,
    dynamic_reason: false,
};

/// `dgram_pair_read` at `crypto/bio/bss_dgram_pair.c:1018` (BIO_R_INVALID_ARGUMENT).
pub(crate) const BSS_DGRAM_PAIR_1018: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 1018,
    func: c"dgram_pair_read",
    lib: 32,
    reason: 125,
    dynamic_reason: false,
};

/// `dgram_pair_read` at `crypto/bio/bss_dgram_pair.c:1023` (BIO_R_BROKEN_PIPE).
pub(crate) const BSS_DGRAM_PAIR_1023: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 1023,
    func: c"dgram_pair_read",
    lib: 32,
    reason: 124,
    dynamic_reason: false,
};

/// `dgram_pair_read` at `crypto/bio/bss_dgram_pair.c:1035` (ERR_R_UNABLE_TO_GET_WRITE_LOCK).
pub(crate) const BSS_DGRAM_PAIR_1035: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 1035,
    func: c"dgram_pair_read",
    lib: 32,
    reason: 786704,
    dynamic_reason: false,
};

/// `dgram_pair_read` at `crypto/bio/bss_dgram_pair.c:1042` (ERR_raise dynamic reason).
pub(crate) const BSS_DGRAM_PAIR_1042: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 1042,
    func: c"dgram_pair_read",
    lib: 32,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_pair_recvmmsg` at `crypto/bio/bss_dgram_pair.c:1070` (BIO_R_BROKEN_PIPE).
pub(crate) const BSS_DGRAM_PAIR_1070: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 1070,
    func: c"dgram_pair_recvmmsg",
    lib: 32,
    reason: 124,
    dynamic_reason: false,
};

/// `dgram_pair_recvmmsg` at `crypto/bio/bss_dgram_pair.c:1081` (ERR_R_UNABLE_TO_GET_WRITE_LOCK).
pub(crate) const BSS_DGRAM_PAIR_1081: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 1081,
    func: c"dgram_pair_recvmmsg",
    lib: 32,
    reason: 786704,
    dynamic_reason: false,
};

/// `dgram_pair_recvmmsg` at `crypto/bio/bss_dgram_pair.c:1095` (ERR_raise dynamic reason).
pub(crate) const BSS_DGRAM_PAIR_1095: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 1095,
    func: c"dgram_pair_recvmmsg",
    lib: 32,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_mem_read` at `crypto/bio/bss_dgram_pair.c:1120` (BIO_R_INVALID_ARGUMENT).
pub(crate) const BSS_DGRAM_PAIR_1120: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 1120,
    func: c"dgram_mem_read",
    lib: 32,
    reason: 125,
    dynamic_reason: false,
};

/// `dgram_mem_read` at `crypto/bio/bss_dgram_pair.c:1125` (ERR_R_UNABLE_TO_GET_WRITE_LOCK).
pub(crate) const BSS_DGRAM_PAIR_1125: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 1125,
    func: c"dgram_mem_read",
    lib: 32,
    reason: 786704,
    dynamic_reason: false,
};

/// `dgram_mem_read` at `crypto/bio/bss_dgram_pair.c:1132` (ERR_raise dynamic reason).
pub(crate) const BSS_DGRAM_PAIR_1132: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 1132,
    func: c"dgram_mem_read",
    lib: 32,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_pair_write` at `crypto/bio/bss_dgram_pair.c:1283` (BIO_R_INVALID_ARGUMENT).
pub(crate) const BSS_DGRAM_PAIR_1283: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 1283,
    func: c"dgram_pair_write",
    lib: 32,
    reason: 125,
    dynamic_reason: false,
};

/// `dgram_pair_write` at `crypto/bio/bss_dgram_pair.c:1288` (ERR_R_UNABLE_TO_GET_WRITE_LOCK).
pub(crate) const BSS_DGRAM_PAIR_1288: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 1288,
    func: c"dgram_pair_write",
    lib: 32,
    reason: 786704,
    dynamic_reason: false,
};

/// `dgram_pair_write` at `crypto/bio/bss_dgram_pair.c:1294` (ERR_raise dynamic reason).
pub(crate) const BSS_DGRAM_PAIR_1294: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 1294,
    func: c"dgram_pair_write",
    lib: 32,
    reason: 0,
    dynamic_reason: true,
};

/// `dgram_pair_sendmmsg` at `crypto/bio/bss_dgram_pair.c:1321` (ERR_R_UNABLE_TO_GET_WRITE_LOCK).
pub(crate) const BSS_DGRAM_PAIR_1321: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 1321,
    func: c"dgram_pair_sendmmsg",
    lib: 32,
    reason: 786704,
    dynamic_reason: false,
};

/// `dgram_pair_sendmmsg` at `crypto/bio/bss_dgram_pair.c:1335` (ERR_raise dynamic reason).
pub(crate) const BSS_DGRAM_PAIR_1335: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_dgram_pair.c",
    line: 1335,
    func: c"dgram_pair_sendmmsg",
    lib: 32,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_new_file` at `crypto/bio/bss_file.c:67` (ERR_raise_data dynamic reason).
pub(crate) const BSS_FILE_67: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_file.c",
    line: 67,
    func: c"BIO_new_file",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `BIO_new_file` at `crypto/bio/bss_file.c:75` (BIO_R_NO_SUCH_FILE).
pub(crate) const BSS_FILE_75: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_file.c",
    line: 75,
    func: c"BIO_new_file",
    lib: 32,
    reason: 128,
    dynamic_reason: false,
};

/// `BIO_new_file` at `crypto/bio/bss_file.c:77` (ERR_R_SYS_LIB).
pub(crate) const BSS_FILE_77: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_file.c",
    line: 77,
    func: c"BIO_new_file",
    lib: 32,
    reason: 524290,
    dynamic_reason: false,
};

/// `file_read` at `crypto/bio/bss_file.c:149` (ERR_raise_data dynamic reason).
pub(crate) const BSS_FILE_149: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_file.c",
    line: 149,
    func: c"file_read",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `file_read` at `crypto/bio/bss_file.c:151` (ERR_R_SYS_LIB).
pub(crate) const BSS_FILE_151: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_file.c",
    line: 151,
    func: c"file_read",
    lib: 32,
    reason: 524290,
    dynamic_reason: false,
};

/// `file_ctrl` at `crypto/bio/bss_file.c:284` (BIO_R_BAD_FOPEN_MODE).
pub(crate) const BSS_FILE_284: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_file.c",
    line: 284,
    func: c"file_ctrl",
    lib: 32,
    reason: 101,
    dynamic_reason: false,
};

/// `file_ctrl` at `crypto/bio/bss_file.c:299` (ERR_raise_data dynamic reason).
pub(crate) const BSS_FILE_299: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_file.c",
    line: 299,
    func: c"file_ctrl",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `file_ctrl` at `crypto/bio/bss_file.c:302` (ERR_R_SYS_LIB).
pub(crate) const BSS_FILE_302: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_file.c",
    line: 302,
    func: c"file_ctrl",
    lib: 32,
    reason: 524290,
    dynamic_reason: false,
};

/// `file_ctrl` at `crypto/bio/bss_file.c:335` (ERR_raise_data dynamic reason).
pub(crate) const BSS_FILE_335: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_file.c",
    line: 335,
    func: c"file_ctrl",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `file_ctrl` at `crypto/bio/bss_file.c:337` (ERR_R_SYS_LIB).
pub(crate) const BSS_FILE_337: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_file.c",
    line: 337,
    func: c"file_ctrl",
    lib: 32,
    reason: 524290,
    dynamic_reason: false,
};

/// `BIO_new_mem_buf` at `crypto/bio/bss_mem.c:90` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const BSS_MEM_90: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_mem.c",
    line: 90,
    func: c"BIO_new_mem_buf",
    lib: 32,
    reason: 786690,
    dynamic_reason: false,
};

/// `mem_write` at `crypto/bio/bss_mem.c:221` (BIO_R_WRITE_TO_READ_ONLY_BIO).
pub(crate) const BSS_MEM_221: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_mem.c",
    line: 221,
    func: c"mem_write",
    lib: 32,
    reason: 126,
    dynamic_reason: false,
};

/// `mem_write` at `crypto/bio/bss_mem.c:228` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const BSS_MEM_228: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bio/bss_mem.c",
    line: 228,
    func: c"mem_write",
    lib: 32,
    reason: 786690,
    dynamic_reason: false,
};

/// `def_load` at `crypto/conf/conf_def.c:179` (CONF_R_NO_SUCH_FILE).
pub(crate) const CONF_DEF_179: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 179,
    func: c"def_load",
    lib: 14,
    reason: 114,
    dynamic_reason: false,
};

/// `def_load` at `crypto/conf/conf_def.c:181` (ERR_R_SYS_LIB).
pub(crate) const CONF_DEF_181: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 181,
    func: c"def_load",
    lib: 14,
    reason: 524290,
    dynamic_reason: false,
};

/// `parsebool` at `crypto/conf/conf_def.c:201` (CONF_R_INVALID_PRAGMA).
pub(crate) const CONF_DEF_201: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 201,
    func: c"parsebool",
    lib: 14,
    reason: 122,
    dynamic_reason: false,
};

/// `def_load_bio` at `crypto/conf/conf_def.c:233` (ERR_R_BUF_LIB).
pub(crate) const CONF_DEF_233: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 233,
    func: c"def_load_bio",
    lib: 14,
    reason: 524295,
    dynamic_reason: false,
};

/// `def_load_bio` at `crypto/conf/conf_def.c:242` (ERR_R_CONF_LIB).
pub(crate) const CONF_DEF_242: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 242,
    func: c"def_load_bio",
    lib: 14,
    reason: 524302,
    dynamic_reason: false,
};

/// `def_load_bio` at `crypto/conf/conf_def.c:248` (CONF_R_UNABLE_TO_CREATE_NEW_SECTION).
pub(crate) const CONF_DEF_248: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 248,
    func: c"def_load_bio",
    lib: 14,
    reason: 103,
    dynamic_reason: false,
};

/// `def_load_bio` at `crypto/conf/conf_def.c:256` (ERR_R_BUF_LIB).
pub(crate) const CONF_DEF_256: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 256,
    func: c"def_load_bio",
    lib: 14,
    reason: 524295,
    dynamic_reason: false,
};

/// `def_load_bio` at `crypto/conf/conf_def.c:366` (CONF_R_MISSING_CLOSE_SQUARE_BRACKET).
pub(crate) const CONF_DEF_366: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 366,
    func: c"def_load_bio",
    lib: 14,
    reason: 100,
    dynamic_reason: false,
};

/// `def_load_bio` at `crypto/conf/conf_def.c:375` (CONF_R_UNABLE_TO_CREATE_NEW_SECTION).
pub(crate) const CONF_DEF_375: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 375,
    func: c"def_load_bio",
    lib: 14,
    reason: 103,
    dynamic_reason: false,
};

/// `def_load_bio` at `crypto/conf/conf_def.c:405` (CONF_R_INVALID_PRAGMA).
pub(crate) const CONF_DEF_405: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 405,
    func: c"def_load_bio",
    lib: 14,
    reason: 122,
    dynamic_reason: false,
};

/// `def_load_bio` at `crypto/conf/conf_def.c:488` (CONF_R_RELATIVE_PATH).
pub(crate) const CONF_DEF_488: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 488,
    func: c"def_load_bio",
    lib: 14,
    reason: 125,
    dynamic_reason: false,
};

/// `def_load_bio` at `crypto/conf/conf_def.c:509` (ERR_R_CRYPTO_LIB).
pub(crate) const CONF_DEF_509: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 509,
    func: c"def_load_bio",
    lib: 14,
    reason: 524303,
    dynamic_reason: false,
};

/// `def_load_bio` at `crypto/conf/conf_def.c:515` (ERR_R_CRYPTO_LIB).
pub(crate) const CONF_DEF_515: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 515,
    func: c"def_load_bio",
    lib: 14,
    reason: 524303,
    dynamic_reason: false,
};

/// `def_load_bio` at `crypto/conf/conf_def.c:524` (CONF_R_MISSING_EQUAL_SIGN).
pub(crate) const CONF_DEF_524: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 524,
    func: c"def_load_bio",
    lib: 14,
    reason: 101,
    dynamic_reason: false,
};

/// `def_load_bio` at `crypto/conf/conf_def.c:547` (CONF_R_UNABLE_TO_CREATE_NEW_SECTION).
pub(crate) const CONF_DEF_547: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 547,
    func: c"def_load_bio",
    lib: 14,
    reason: 103,
    dynamic_reason: false,
};

/// `def_load_bio` at `crypto/conf/conf_def.c:554` (ERR_R_CONF_LIB).
pub(crate) const CONF_DEF_554: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 554,
    func: c"def_load_bio",
    lib: 14,
    reason: 524302,
    dynamic_reason: false,
};

/// `str_copy` at `crypto/conf/conf_def.c:737` (CONF_R_NO_CLOSE_BRACE).
pub(crate) const CONF_DEF_737: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 737,
    func: c"str_copy",
    lib: 14,
    reason: 102,
    dynamic_reason: false,
};

/// `str_copy` at `crypto/conf/conf_def.c:757` (CONF_R_VARIABLE_HAS_NO_VALUE).
pub(crate) const CONF_DEF_757: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 757,
    func: c"str_copy",
    lib: 14,
    reason: 104,
    dynamic_reason: false,
};

/// `str_copy` at `crypto/conf/conf_def.c:762` (CONF_R_VARIABLE_EXPANSION_TOO_LONG).
pub(crate) const CONF_DEF_762: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 762,
    func: c"str_copy",
    lib: 14,
    reason: 116,
    dynamic_reason: false,
};

/// `str_copy` at `crypto/conf/conf_def.c:766` (ERR_R_BUF_LIB).
pub(crate) const CONF_DEF_766: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 766,
    func: c"str_copy",
    lib: 14,
    reason: 524295,
    dynamic_reason: false,
};

/// `process_include` at `crypto/conf/conf_def.c:806` (ERR_raise_data dynamic reason).
pub(crate) const CONF_DEF_806: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 806,
    func: c"process_include",
    lib: 2,
    reason: 0,
    dynamic_reason: true,
};

/// `process_include` at `crypto/conf/conf_def.c:813` (CONF_R_RECURSIVE_DIRECTORY_INCLUDE).
pub(crate) const CONF_DEF_813: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_def.c",
    line: 813,
    func: c"process_include",
    lib: 14,
    reason: 111,
    dynamic_reason: false,
};

/// `CONF_load` at `crypto/conf/conf_lib.c:58` (ERR_R_SYS_LIB).
pub(crate) const CONF_LIB_58: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_lib.c",
    line: 58,
    func: c"CONF_load",
    lib: 14,
    reason: 524290,
    dynamic_reason: false,
};

/// `CONF_load_fp` at `crypto/conf/conf_lib.c:75` (ERR_R_BUF_LIB).
pub(crate) const CONF_LIB_75: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_lib.c",
    line: 75,
    func: c"CONF_load_fp",
    lib: 14,
    reason: 524295,
    dynamic_reason: false,
};

/// `CONF_dump_fp` at `crypto/conf/conf_lib.c:157` (ERR_R_BUF_LIB).
pub(crate) const CONF_LIB_157: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_lib.c",
    line: 157,
    func: c"CONF_dump_fp",
    lib: 14,
    reason: 524295,
    dynamic_reason: false,
};

/// `NCONF_new_ex` at `crypto/conf/conf_lib.c:191` (ERR_R_CONF_LIB).
pub(crate) const CONF_LIB_191: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_lib.c",
    line: 191,
    func: c"NCONF_new_ex",
    lib: 14,
    reason: 524302,
    dynamic_reason: false,
};

/// `NCONF_load` at `crypto/conf/conf_lib.c:254` (CONF_R_NO_CONF).
pub(crate) const CONF_LIB_254: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_lib.c",
    line: 254,
    func: c"NCONF_load",
    lib: 14,
    reason: 105,
    dynamic_reason: false,
};

/// `NCONF_load_fp` at `crypto/conf/conf_lib.c:267` (ERR_R_BUF_LIB).
pub(crate) const CONF_LIB_267: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_lib.c",
    line: 267,
    func: c"NCONF_load_fp",
    lib: 14,
    reason: 524295,
    dynamic_reason: false,
};

/// `NCONF_load_bio` at `crypto/conf/conf_lib.c:279` (CONF_R_NO_CONF).
pub(crate) const CONF_LIB_279: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_lib.c",
    line: 279,
    func: c"NCONF_load_bio",
    lib: 14,
    reason: 105,
    dynamic_reason: false,
};

/// `NCONF_get_section` at `crypto/conf/conf_lib.c:289` (CONF_R_NO_CONF).
pub(crate) const CONF_LIB_289: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_lib.c",
    line: 289,
    func: c"NCONF_get_section",
    lib: 14,
    reason: 105,
    dynamic_reason: false,
};

/// `NCONF_get_section` at `crypto/conf/conf_lib.c:294` (CONF_R_NO_SECTION).
pub(crate) const CONF_LIB_294: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_lib.c",
    line: 294,
    func: c"NCONF_get_section",
    lib: 14,
    reason: 107,
    dynamic_reason: false,
};

/// `NCONF_get_string` at `crypto/conf/conf_lib.c:313` (CONF_R_NO_CONF_OR_ENVIRONMENT_VARIABLE).
pub(crate) const CONF_LIB_313: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_lib.c",
    line: 313,
    func: c"NCONF_get_string",
    lib: 14,
    reason: 106,
    dynamic_reason: false,
};

/// `NCONF_get_string` at `crypto/conf/conf_lib.c:316` (CONF_R_NO_VALUE).
pub(crate) const CONF_LIB_316: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_lib.c",
    line: 316,
    func: c"NCONF_get_string",
    lib: 14,
    reason: 108,
    dynamic_reason: false,
};

/// `NCONF_get_number_e` at `crypto/conf/conf_lib.c:340` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const CONF_LIB_340: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_lib.c",
    line: 340,
    func: c"NCONF_get_number_e",
    lib: 14,
    reason: 786690,
    dynamic_reason: false,
};

/// `NCONF_get_number_e` at `crypto/conf/conf_lib.c:359` (CONF_R_NUMBER_TOO_LARGE).
pub(crate) const CONF_LIB_359: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_lib.c",
    line: 359,
    func: c"NCONF_get_number_e",
    lib: 14,
    reason: 121,
    dynamic_reason: false,
};

/// `NCONF_dump_fp` at `crypto/conf/conf_lib.c:387` (ERR_R_BUF_LIB).
pub(crate) const CONF_LIB_387: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_lib.c",
    line: 387,
    func: c"NCONF_dump_fp",
    lib: 14,
    reason: 524295,
    dynamic_reason: false,
};

/// `NCONF_dump_bio` at `crypto/conf/conf_lib.c:399` (CONF_R_NO_CONF).
pub(crate) const CONF_LIB_399: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_lib.c",
    line: 399,
    func: c"NCONF_dump_bio",
    lib: 14,
    reason: 105,
    dynamic_reason: false,
};

/// `do_init_module_list_lock` at `crypto/conf/conf_mod.c:104` (ERR_R_CRYPTO_LIB).
pub(crate) const CONF_MOD_104: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_mod.c",
    line: 104,
    func: c"do_init_module_list_lock",
    lib: 14,
    reason: 524303,
    dynamic_reason: false,
};

/// `CONF_modules_load` at `crypto/conf/conf_mod.c:163` (CONF_R_OPENSSL_CONF_REFERENCES_MISSING_SECTION).
pub(crate) const CONF_MOD_163: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_mod.c",
    line: 163,
    func: c"CONF_modules_load",
    lib: 14,
    reason: 124,
    dynamic_reason: false,
};

/// `module_run` at `crypto/conf/conf_mod.c:276` (CONF_R_UNKNOWN_MODULE_NAME).
pub(crate) const CONF_MOD_276: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_mod.c",
    line: 276,
    func: c"module_run",
    lib: 14,
    reason: 113,
    dynamic_reason: false,
};

/// `module_run` at `crypto/conf/conf_mod.c:286` (CONF_R_MODULE_INITIALIZATION_ERROR).
pub(crate) const CONF_MOD_286: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_mod.c",
    line: 286,
    func: c"module_run",
    lib: 14,
    reason: 109,
    dynamic_reason: false,
};

/// `module_load_dso` at `crypto/conf/conf_mod.c:331` (ERR_raise_data dynamic reason).
pub(crate) const CONF_MOD_331: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_mod.c",
    line: 331,
    func: c"module_load_dso",
    lib: 14,
    reason: 0,
    dynamic_reason: true,
};

/// `module_init` at `crypto/conf/conf_mod.c:475` (ERR_R_CRYPTO_LIB).
pub(crate) const CONF_MOD_475: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_mod.c",
    line: 475,
    func: c"module_init",
    lib: 14,
    reason: 524303,
    dynamic_reason: false,
};

/// `module_init` at `crypto/conf/conf_mod.c:482` (ERR_R_CRYPTO_LIB).
pub(crate) const CONF_MOD_482: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_mod.c",
    line: 482,
    func: c"module_init",
    lib: 14,
    reason: 524303,
    dynamic_reason: false,
};

/// `CONF_parse_list` at `crypto/conf/conf_mod.c:734` (CONF_R_LIST_CANNOT_BE_NULL).
pub(crate) const CONF_MOD_734: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_mod.c",
    line: 734,
    func: c"CONF_parse_list",
    lib: 14,
    reason: 115,
    dynamic_reason: false,
};

/// `ssl_module_init` at `crypto/conf/conf_ssl.c:75` (ERR_raise_data dynamic reason).
pub(crate) const CONF_SSL_75: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_ssl.c",
    line: 75,
    func: c"ssl_module_init",
    lib: 14,
    reason: 0,
    dynamic_reason: true,
};

/// `ssl_module_init` at `crypto/conf/conf_ssl.c:94` (ERR_raise_data dynamic reason).
pub(crate) const CONF_SSL_94: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/conf/conf_ssl.c",
    line: 94,
    func: c"ssl_module_init",
    lib: 14,
    reason: 0,
    dynamic_reason: true,
};

/// `OBJ_nid2obj` at `crypto/objects/obj_dat.c:270` (ERR_R_UNABLE_TO_GET_READ_LOCK).
pub(crate) const OBJ_DAT_270: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/objects/obj_dat.c",
    line: 270,
    func: c"OBJ_nid2obj",
    lib: 8,
    reason: 786703,
    dynamic_reason: false,
};

/// `OBJ_nid2obj` at `crypto/objects/obj_dat.c:278` (OBJ_R_UNKNOWN_NID).
pub(crate) const OBJ_DAT_278: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/objects/obj_dat.c",
    line: 278,
    func: c"OBJ_nid2obj",
    lib: 8,
    reason: 101,
    dynamic_reason: false,
};

/// `ossl_obj_obj2nid` at `crypto/objects/obj_dat.c:329` (ERR_R_UNABLE_TO_GET_READ_LOCK).
pub(crate) const OBJ_DAT_329: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/objects/obj_dat.c",
    line: 329,
    func: c"ossl_obj_obj2nid",
    lib: 8,
    reason: 786703,
    dynamic_reason: false,
};

/// `OBJ_txt2obj` at `crypto/objects/obj_dat.c:362` (OBJ_R_UNKNOWN_OBJECT_NAME).
pub(crate) const OBJ_DAT_362: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/objects/obj_dat.c",
    line: 362,
    func: c"OBJ_txt2obj",
    lib: 8,
    reason: 103,
    dynamic_reason: false,
};

/// `OBJ_ln2nid` at `crypto/objects/obj_dat.c:573` (ERR_R_UNABLE_TO_GET_READ_LOCK).
pub(crate) const OBJ_DAT_573: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/objects/obj_dat.c",
    line: 573,
    func: c"OBJ_ln2nid",
    lib: 8,
    reason: 786703,
    dynamic_reason: false,
};

/// `OBJ_sn2nid` at `crypto/objects/obj_dat.c:598` (ERR_R_UNABLE_TO_GET_READ_LOCK).
pub(crate) const OBJ_DAT_598: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/objects/obj_dat.c",
    line: 598,
    func: c"OBJ_sn2nid",
    lib: 8,
    reason: 786703,
    dynamic_reason: false,
};

/// `OBJ_create` at `crypto/objects/obj_dat.c:706` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const OBJ_DAT_706: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/objects/obj_dat.c",
    line: 706,
    func: c"OBJ_create",
    lib: 8,
    reason: 524550,
    dynamic_reason: false,
};

/// `OBJ_create` at `crypto/objects/obj_dat.c:713` (OBJ_R_OID_EXISTS).
pub(crate) const OBJ_DAT_713: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/objects/obj_dat.c",
    line: 713,
    func: c"OBJ_create",
    lib: 8,
    reason: 102,
    dynamic_reason: false,
};

/// `OBJ_create` at `crypto/objects/obj_dat.c:726` (ERR_R_ASN1_LIB).
pub(crate) const OBJ_DAT_726: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/objects/obj_dat.c",
    line: 726,
    func: c"OBJ_create",
    lib: 8,
    reason: 524301,
    dynamic_reason: false,
};

/// `OBJ_create` at `crypto/objects/obj_dat.c:734` (OBJ_R_OID_EXISTS).
pub(crate) const OBJ_DAT_734: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/objects/obj_dat.c",
    line: 734,
    func: c"OBJ_create",
    lib: 8,
    reason: 102,
    dynamic_reason: false,
};

/// `add_object` at `crypto/objects/obj_dat.c:806` (ERR_R_UNABLE_TO_GET_WRITE_LOCK).
pub(crate) const OBJ_DAT_806: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/objects/obj_dat.c",
    line: 806,
    func: c"add_object",
    lib: 8,
    reason: 786704,
    dynamic_reason: false,
};

/// `add_object` at `crypto/objects/obj_dat.c:844` (ERR_R_CRYPTO_LIB).
pub(crate) const OBJ_DAT_844: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/objects/obj_dat.c",
    line: 844,
    func: c"add_object",
    lib: 8,
    reason: 524303,
    dynamic_reason: false,
};

/// `a2d_ASN1_OBJECT` at `crypto/asn1/a_object.c:66` (ASN1_R_LENGTH_TOO_LONG).
pub(crate) const A_OBJECT_66: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_object.c",
    line: 66,
    func: c"a2d_ASN1_OBJECT",
    lib: 13,
    reason: 231,
    dynamic_reason: false,
};

/// `a2d_ASN1_OBJECT` at `crypto/asn1/a_object.c:78` (ASN1_R_FIRST_NUM_TOO_LARGE).
pub(crate) const A_OBJECT_78: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_object.c",
    line: 78,
    func: c"a2d_ASN1_OBJECT",
    lib: 13,
    reason: 122,
    dynamic_reason: false,
};

/// `a2d_ASN1_OBJECT` at `crypto/asn1/a_object.c:83` (ASN1_R_MISSING_SECOND_NUMBER).
pub(crate) const A_OBJECT_83: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_object.c",
    line: 83,
    func: c"a2d_ASN1_OBJECT",
    lib: 13,
    reason: 138,
    dynamic_reason: false,
};

/// `a2d_ASN1_OBJECT` at `crypto/asn1/a_object.c:92` (ASN1_R_INVALID_SEPARATOR).
pub(crate) const A_OBJECT_92: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_object.c",
    line: 92,
    func: c"a2d_ASN1_OBJECT",
    lib: 13,
    reason: 131,
    dynamic_reason: false,
};

/// `a2d_ASN1_OBJECT` at `crypto/asn1/a_object.c:105` (ASN1_R_INVALID_DIGIT).
pub(crate) const A_OBJECT_105: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_object.c",
    line: 105,
    func: c"a2d_ASN1_OBJECT",
    lib: 13,
    reason: 130,
    dynamic_reason: false,
};

/// `a2d_ASN1_OBJECT` at `crypto/asn1/a_object.c:124` (ASN1_R_SECOND_NUMBER_TOO_LARGE).
pub(crate) const A_OBJECT_124: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_object.c",
    line: 124,
    func: c"a2d_ASN1_OBJECT",
    lib: 13,
    reason: 147,
    dynamic_reason: false,
};

/// `a2d_ASN1_OBJECT` at `crypto/asn1/a_object.c:163` (ASN1_R_BUFFER_TOO_SMALL).
pub(crate) const A_OBJECT_163: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_object.c",
    line: 163,
    func: c"a2d_ASN1_OBJECT",
    lib: 13,
    reason: 107,
    dynamic_reason: false,
};

/// `i2a_ASN1_OBJECT` at `crypto/asn1/a_object.c:198` (ASN1_R_LENGTH_TOO_LONG).
pub(crate) const A_OBJECT_198: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_object.c",
    line: 198,
    func: c"i2a_ASN1_OBJECT",
    lib: 13,
    reason: 231,
    dynamic_reason: false,
};

/// `d2i_ASN1_OBJECT` at `crypto/asn1/a_object.c:241` (ERR_raise dynamic reason).
pub(crate) const A_OBJECT_241: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_object.c",
    line: 241,
    func: c"d2i_ASN1_OBJECT",
    lib: 13,
    reason: 0,
    dynamic_reason: true,
};

/// `ossl_c2i_ASN1_OBJECT` at `crypto/asn1/a_object.c:259` (ASN1_R_INVALID_OBJECT_ENCODING).
pub(crate) const A_OBJECT_259: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_object.c",
    line: 259,
    func: c"ossl_c2i_ASN1_OBJECT",
    lib: 13,
    reason: 216,
    dynamic_reason: false,
};

/// `ossl_c2i_ASN1_OBJECT` at `crypto/asn1/a_object.c:289` (ASN1_R_INVALID_OBJECT_ENCODING).
pub(crate) const A_OBJECT_289: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_object.c",
    line: 289,
    func: c"ossl_c2i_ASN1_OBJECT",
    lib: 13,
    reason: 216,
    dynamic_reason: false,
};

/// `ossl_c2i_ASN1_OBJECT` at `crypto/asn1/a_object.c:334` (ERR_raise dynamic reason).
pub(crate) const A_OBJECT_334: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_object.c",
    line: 334,
    func: c"ossl_c2i_ASN1_OBJECT",
    lib: 13,
    reason: 0,
    dynamic_reason: true,
};

/// `BUF_MEM_grow` at `crypto/buffer/buffer.c:88` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const BUFFER_88: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/buffer/buffer.c",
    line: 88,
    func: c"BUF_MEM_grow",
    lib: 7,
    reason: 524550,
    dynamic_reason: false,
};

/// `BUF_MEM_grow_clean` at `crypto/buffer/buffer.c:125` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const BUFFER_125: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/buffer/buffer.c",
    line: 125,
    func: c"BUF_MEM_grow_clean",
    lib: 7,
    reason: 524550,
    dynamic_reason: false,
};

/// `hexstr2buf_sep` at `crypto/o_str.c:229` (CRYPTO_R_ODD_NUMBER_OF_DIGITS).
pub(crate) const O_STR_229: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/o_str.c",
    line: 229,
    func: c"hexstr2buf_sep",
    lib: 15,
    reason: 103,
    dynamic_reason: false,
};

/// `hexstr2buf_sep` at `crypto/o_str.c:235` (CRYPTO_R_ILLEGAL_HEX_DIGIT).
pub(crate) const O_STR_235: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/o_str.c",
    line: 235,
    func: c"hexstr2buf_sep",
    lib: 15,
    reason: 102,
    dynamic_reason: false,
};

/// `hexstr2buf_sep` at `crypto/o_str.c:241` (CRYPTO_R_TOO_SMALL_BUFFER).
pub(crate) const O_STR_241: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/o_str.c",
    line: 241,
    func: c"hexstr2buf_sep",
    lib: 15,
    reason: 116,
    dynamic_reason: false,
};

/// `ossl_hexstr2buf_sep` at `crypto/o_str.c:270` (CRYPTO_R_HEX_STRING_TOO_SHORT).
pub(crate) const O_STR_270: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/o_str.c",
    line: 270,
    func: c"ossl_hexstr2buf_sep",
    lib: 15,
    reason: 121,
    dynamic_reason: false,
};

/// `buf2hexstr_sep` at `crypto/o_str.c:303` (CRYPTO_R_TOO_MANY_BYTES).
pub(crate) const O_STR_303: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/o_str.c",
    line: 303,
    func: c"buf2hexstr_sep",
    lib: 15,
    reason: 113,
    dynamic_reason: false,
};

/// `buf2hexstr_sep` at `crypto/o_str.c:315` (CRYPTO_R_TOO_SMALL_BUFFER).
pub(crate) const O_STR_315: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/o_str.c",
    line: 315,
    func: c"buf2hexstr_sep",
    lib: 15,
    reason: 116,
    dynamic_reason: false,
};

/// `ossl_buf2hexstr_sep` at `crypto/o_str.c:352` (CRYPTO_R_TOO_MANY_BYTES).
pub(crate) const O_STR_352: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/o_str.c",
    line: 352,
    func: c"ossl_buf2hexstr_sep",
    lib: 15,
    reason: 113,
    dynamic_reason: false,
};

/// `BN_usub` at `crypto/bn/bn_add.c:142` (BN_R_ARG2_LT_ARG3).
pub(crate) const BN_ADD_142: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_add.c",
    line: 142,
    func: c"BN_usub",
    lib: 3,
    reason: 100,
    dynamic_reason: false,
};

/// `BN_BLINDING_new` at `crypto/bn/bn_blind.c:41` (ERR_R_CRYPTO_LIB).
pub(crate) const BN_BLIND_41: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_blind.c",
    line: 41,
    func: c"BN_BLINDING_new",
    lib: 3,
    reason: 524303,
    dynamic_reason: false,
};

/// `BN_BLINDING_update` at `crypto/bn/bn_blind.c:96` (BN_R_NOT_INITIALIZED).
pub(crate) const BN_BLIND_96: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_blind.c",
    line: 96,
    func: c"BN_BLINDING_update",
    lib: 3,
    reason: 107,
    dynamic_reason: false,
};

/// `BN_BLINDING_convert_ex` at `crypto/bn/bn_blind.c:138` (BN_R_NOT_INITIALIZED).
pub(crate) const BN_BLIND_138: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_blind.c",
    line: 138,
    func: c"BN_BLINDING_convert_ex",
    lib: 3,
    reason: 107,
    dynamic_reason: false,
};

/// `BN_BLINDING_invert_ex` at `crypto/bn/bn_blind.c:172` (BN_R_NOT_INITIALIZED).
pub(crate) const BN_BLIND_172: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_blind.c",
    line: 172,
    func: c"BN_BLINDING_invert_ex",
    lib: 3,
    reason: 107,
    dynamic_reason: false,
};

/// `BN_BLINDING_create_param` at `crypto/bn/bn_blind.c:283` (BN_R_TOO_MANY_ITERATIONS).
pub(crate) const BN_BLIND_283: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_blind.c",
    line: 283,
    func: c"BN_BLINDING_create_param",
    lib: 3,
    reason: 113,
    dynamic_reason: false,
};

/// `BN_hex2bn` at `crypto/bn/bn_conv.c:151` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const BN_CONV_151: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_conv.c",
    line: 151,
    func: c"BN_hex2bn",
    lib: 3,
    reason: 524550,
    dynamic_reason: false,
};

/// `BN_CTX_start` at `crypto/bn/bn_ctx.c:193` (BN_R_TOO_MANY_TEMPORARY_VARIABLES).
pub(crate) const BN_CTX_193: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_ctx.c",
    line: 193,
    func: c"BN_CTX_start",
    lib: 3,
    reason: 109,
    dynamic_reason: false,
};

/// `BN_CTX_get` at `crypto/bn/bn_ctx.c:231` (BN_R_TOO_MANY_TEMPORARY_VARIABLES).
pub(crate) const BN_CTX_231: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_ctx.c",
    line: 231,
    func: c"BN_CTX_get",
    lib: 3,
    reason: 109,
    dynamic_reason: false,
};

/// `BN_div` at `crypto/bn/bn_div.c:27` (BN_R_DIV_BY_ZERO).
pub(crate) const BN_DIV_27: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_div.c",
    line: 27,
    func: c"BN_div",
    lib: 3,
    reason: 103,
    dynamic_reason: false,
};

/// `BN_div` at `crypto/bn/bn_div.c:217` (BN_R_DIV_BY_ZERO).
pub(crate) const BN_DIV_217: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_div.c",
    line: 217,
    func: c"BN_div",
    lib: 3,
    reason: 103,
    dynamic_reason: false,
};

/// `BN_div` at `crypto/bn/bn_div.c:227` (BN_R_NOT_INITIALIZED).
pub(crate) const BN_DIV_227: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_div.c",
    line: 227,
    func: c"BN_div",
    lib: 3,
    reason: 107,
    dynamic_reason: false,
};

/// `BN_exp` at `crypto/bn/bn_exp.c:57` (ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
pub(crate) const BN_EXP_57: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_exp.c",
    line: 57,
    func: c"BN_exp",
    lib: 3,
    reason: 786689,
    dynamic_reason: false,
};

/// `BN_mod_exp_recp` at `crypto/bn/bn_exp.c:183` (ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
pub(crate) const BN_EXP_183: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_exp.c",
    line: 183,
    func: c"BN_mod_exp_recp",
    lib: 3,
    reason: 786689,
    dynamic_reason: false,
};

/// `BN_mod_exp_mont` at `crypto/bn/bn_exp.c:327` (BN_R_CALLED_WITH_EVEN_MODULUS).
pub(crate) const BN_EXP_327: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_exp.c",
    line: 327,
    func: c"BN_mod_exp_mont",
    lib: 3,
    reason: 102,
    dynamic_reason: false,
};

/// `bn_mod_exp_mont_fixed_top` at `crypto/bn/bn_exp.c:622` (BN_R_CALLED_WITH_EVEN_MODULUS).
pub(crate) const BN_EXP_622: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_exp.c",
    line: 622,
    func: c"bn_mod_exp_mont_fixed_top",
    lib: 3,
    reason: 102,
    dynamic_reason: false,
};

/// `BN_mod_exp_mont_word` at `crypto/bn/bn_exp.c:1187` (ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
pub(crate) const BN_EXP_1187: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_exp.c",
    line: 1187,
    func: c"BN_mod_exp_mont_word",
    lib: 3,
    reason: 786689,
    dynamic_reason: false,
};

/// `BN_mod_exp_mont_word` at `crypto/bn/bn_exp.c:1195` (BN_R_CALLED_WITH_EVEN_MODULUS).
pub(crate) const BN_EXP_1195: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_exp.c",
    line: 1195,
    func: c"BN_mod_exp_mont_word",
    lib: 3,
    reason: 102,
    dynamic_reason: false,
};

/// `BN_mod_exp_simple` at `crypto/bn/bn_exp.c:1319` (ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
pub(crate) const BN_EXP_1319: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_exp.c",
    line: 1319,
    func: c"BN_mod_exp_simple",
    lib: 3,
    reason: 786689,
    dynamic_reason: false,
};

/// `BN_mod_exp_simple` at `crypto/bn/bn_exp.c:1324` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const BN_EXP_1324: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_exp.c",
    line: 1324,
    func: c"BN_mod_exp_simple",
    lib: 3,
    reason: 524550,
    dynamic_reason: false,
};

/// `BN_mod_exp2_mont` at `crypto/bn/bn_exp2.c:35` (BN_R_CALLED_WITH_EVEN_MODULUS).
pub(crate) const BN_EXP2_35: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_exp2.c",
    line: 35,
    func: c"BN_mod_exp2_mont",
    lib: 3,
    reason: 102,
    dynamic_reason: false,
};

/// `BN_mod_inverse` at `crypto/bn/bn_gcd.c:525` (ERR_R_BN_LIB).
pub(crate) const BN_GCD_525: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_gcd.c",
    line: 525,
    func: c"BN_mod_inverse",
    lib: 3,
    reason: 524291,
    dynamic_reason: false,
};

/// `BN_mod_inverse` at `crypto/bn/bn_gcd.c:532` (BN_R_NO_INVERSE).
pub(crate) const BN_GCD_532: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_gcd.c",
    line: 532,
    func: c"BN_mod_inverse",
    lib: 3,
    reason: 108,
    dynamic_reason: false,
};

/// `BN_GF2m_mod` at `crypto/bn/bn_gf2m.c:389` (BN_R_INVALID_LENGTH).
pub(crate) const BN_GF2M_389: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_gf2m.c",
    line: 389,
    func: c"BN_GF2m_mod",
    lib: 3,
    reason: 106,
    dynamic_reason: false,
};

/// `BN_GF2m_mod_mul` at `crypto/bn/bn_gf2m.c:472` (BN_R_INVALID_LENGTH).
pub(crate) const BN_GF2M_472: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_gf2m.c",
    line: 472,
    func: c"BN_GF2m_mod_mul",
    lib: 3,
    reason: 106,
    dynamic_reason: false,
};

/// `BN_GF2m_mod_sqr` at `crypto/bn/bn_gf2m.c:532` (BN_R_INVALID_LENGTH).
pub(crate) const BN_GF2M_532: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_gf2m.c",
    line: 532,
    func: c"BN_GF2m_mod_sqr",
    lib: 3,
    reason: 106,
    dynamic_reason: false,
};

/// `BN_GF2m_mod_exp` at `crypto/bn/bn_gf2m.c:915` (BN_R_INVALID_LENGTH).
pub(crate) const BN_GF2M_915: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_gf2m.c",
    line: 915,
    func: c"BN_GF2m_mod_exp",
    lib: 3,
    reason: 106,
    dynamic_reason: false,
};

/// `BN_GF2m_mod_sqrt` at `crypto/bn/bn_gf2m.c:977` (BN_R_INVALID_LENGTH).
pub(crate) const BN_GF2M_977: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_gf2m.c",
    line: 977,
    func: c"BN_GF2m_mod_sqrt",
    lib: 3,
    reason: 106,
    dynamic_reason: false,
};

/// `BN_GF2m_mod_solve_quad_arr` at `crypto/bn/bn_gf2m.c:1065` (BN_R_TOO_MANY_ITERATIONS).
pub(crate) const BN_GF2M_1065: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_gf2m.c",
    line: 1065,
    func: c"BN_GF2m_mod_solve_quad_arr",
    lib: 3,
    reason: 113,
    dynamic_reason: false,
};

/// `BN_GF2m_mod_solve_quad_arr` at `crypto/bn/bn_gf2m.c:1075` (BN_R_NO_SOLUTION).
pub(crate) const BN_GF2M_1075: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_gf2m.c",
    line: 1075,
    func: c"BN_GF2m_mod_solve_quad_arr",
    lib: 3,
    reason: 116,
    dynamic_reason: false,
};

/// `BN_GF2m_mod_solve_quad` at `crypto/bn/bn_gf2m.c:1111` (BN_R_INVALID_LENGTH).
pub(crate) const BN_GF2M_1111: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_gf2m.c",
    line: 1111,
    func: c"BN_GF2m_mod_solve_quad",
    lib: 3,
    reason: 106,
    dynamic_reason: false,
};

/// `bn_compute_wNAF` at `crypto/bn/bn_intern.c:41` (ERR_R_INTERNAL_ERROR).
pub(crate) const BN_INTERN_41: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_intern.c",
    line: 41,
    func: c"bn_compute_wNAF",
    lib: 3,
    reason: 786691,
    dynamic_reason: false,
};

/// `bn_compute_wNAF` at `crypto/bn/bn_intern.c:53` (ERR_R_INTERNAL_ERROR).
pub(crate) const BN_INTERN_53: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_intern.c",
    line: 53,
    func: c"bn_compute_wNAF",
    lib: 3,
    reason: 786691,
    dynamic_reason: false,
};

/// `bn_compute_wNAF` at `crypto/bn/bn_intern.c:97` (ERR_R_INTERNAL_ERROR).
pub(crate) const BN_INTERN_97: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_intern.c",
    line: 97,
    func: c"bn_compute_wNAF",
    lib: 3,
    reason: 786691,
    dynamic_reason: false,
};

/// `bn_compute_wNAF` at `crypto/bn/bn_intern.c:109` (ERR_R_INTERNAL_ERROR).
pub(crate) const BN_INTERN_109: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_intern.c",
    line: 109,
    func: c"bn_compute_wNAF",
    lib: 3,
    reason: 786691,
    dynamic_reason: false,
};

/// `bn_compute_wNAF` at `crypto/bn/bn_intern.c:120` (ERR_R_INTERNAL_ERROR).
pub(crate) const BN_INTERN_120: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_intern.c",
    line: 120,
    func: c"bn_compute_wNAF",
    lib: 3,
    reason: 786691,
    dynamic_reason: false,
};

/// `bn_compute_wNAF` at `crypto/bn/bn_intern.c:126` (ERR_R_INTERNAL_ERROR).
pub(crate) const BN_INTERN_126: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_intern.c",
    line: 126,
    func: c"bn_compute_wNAF",
    lib: 3,
    reason: 786691,
    dynamic_reason: false,
};

/// `bn_set_words` at `crypto/bn/bn_intern.c:187` (ERR_R_BN_LIB).
pub(crate) const BN_INTERN_187: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_intern.c",
    line: 187,
    func: c"bn_set_words",
    lib: 3,
    reason: 524291,
    dynamic_reason: false,
};

/// `bn_expand_internal` at `crypto/bn/bn_lib.c:269` (BN_R_BIGNUM_TOO_LONG).
pub(crate) const BN_LIB_269: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_lib.c",
    line: 269,
    func: c"bn_expand_internal",
    lib: 3,
    reason: 114,
    dynamic_reason: false,
};

/// `bn_expand_internal` at `crypto/bn/bn_lib.c:273` (BN_R_EXPAND_ON_STATIC_BIGNUM_DATA).
pub(crate) const BN_LIB_273: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_lib.c",
    line: 273,
    func: c"bn_expand_internal",
    lib: 3,
    reason: 105,
    dynamic_reason: false,
};

/// `BN_nnmod` at `crypto/bn/bn_mod.c:22` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const BN_MOD_22: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_mod.c",
    line: 22,
    func: c"BN_nnmod",
    lib: 3,
    reason: 524550,
    dynamic_reason: false,
};

/// `BN_mod_sub_quick` at `crypto/bn/bn_mod.c:194` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const BN_MOD_194: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_mod.c",
    line: 194,
    func: c"BN_mod_sub_quick",
    lib: 3,
    reason: 524550,
    dynamic_reason: false,
};

/// `BN_mod_lshift_quick` at `crypto/bn/bn_mod.c:307` (BN_R_INPUT_NOT_REDUCED).
pub(crate) const BN_MOD_307: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_mod.c",
    line: 307,
    func: c"BN_mod_lshift_quick",
    lib: 3,
    reason: 110,
    dynamic_reason: false,
};

/// `BN_mpi2bn` at `crypto/bn/bn_mpi.c:49` (BN_R_INVALID_LENGTH).
pub(crate) const BN_MPI_49: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_mpi.c",
    line: 49,
    func: c"BN_mpi2bn",
    lib: 3,
    reason: 106,
    dynamic_reason: false,
};

/// `BN_mpi2bn` at `crypto/bn/bn_mpi.c:54` (BN_R_ENCODING_ERROR).
pub(crate) const BN_MPI_54: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_mpi.c",
    line: 54,
    func: c"BN_mpi2bn",
    lib: 3,
    reason: 104,
    dynamic_reason: false,
};

/// `BN_generate_prime_ex2` at `crypto/bn/bn_prime.c:135` (BN_R_BITS_TOO_SMALL).
pub(crate) const BN_PRIME_135: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_prime.c",
    line: 135,
    func: c"BN_generate_prime_ex2",
    lib: 3,
    reason: 118,
    dynamic_reason: false,
};

/// `BN_generate_prime_ex2` at `crypto/bn/bn_prime.c:143` (BN_R_BITS_TOO_SMALL).
pub(crate) const BN_PRIME_143: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_prime.c",
    line: 143,
    func: c"BN_generate_prime_ex2",
    lib: 3,
    reason: 118,
    dynamic_reason: false,
};

/// `bnrand` at `crypto/bn/bn_rand.c:98` (BN_R_BITS_TOO_SMALL).
pub(crate) const BN_RAND_98: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_rand.c",
    line: 98,
    func: c"bnrand",
    lib: 3,
    reason: 118,
    dynamic_reason: false,
};

/// `bnrand_range` at `crypto/bn/bn_rand.c:140` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const BN_RAND_140: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_rand.c",
    line: 140,
    func: c"bnrand_range",
    lib: 3,
    reason: 786690,
    dynamic_reason: false,
};

/// `bnrand_range` at `crypto/bn/bn_rand.c:145` (BN_R_INVALID_RANGE).
pub(crate) const BN_RAND_145: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_rand.c",
    line: 145,
    func: c"bnrand_range",
    lib: 3,
    reason: 115,
    dynamic_reason: false,
};

/// `bnrand_range` at `crypto/bn/bn_rand.c:180` (BN_R_TOO_MANY_ITERATIONS).
pub(crate) const BN_RAND_180: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_rand.c",
    line: 180,
    func: c"bnrand_range",
    lib: 3,
    reason: 113,
    dynamic_reason: false,
};

/// `bnrand_range` at `crypto/bn/bn_rand.c:193` (BN_R_TOO_MANY_ITERATIONS).
pub(crate) const BN_RAND_193: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_rand.c",
    line: 193,
    func: c"bnrand_range",
    lib: 3,
    reason: 113,
    dynamic_reason: false,
};

/// `ossl_bn_priv_rand_range_fixed_top` at `crypto/bn/bn_rand.c:248` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const BN_RAND_248: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_rand.c",
    line: 248,
    func: c"ossl_bn_priv_rand_range_fixed_top",
    lib: 3,
    reason: 786690,
    dynamic_reason: false,
};

/// `ossl_bn_priv_rand_range_fixed_top` at `crypto/bn/bn_rand.c:253` (BN_R_INVALID_RANGE).
pub(crate) const BN_RAND_253: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_rand.c",
    line: 253,
    func: c"ossl_bn_priv_rand_range_fixed_top",
    lib: 3,
    reason: 115,
    dynamic_reason: false,
};

/// `ossl_bn_priv_rand_range_fixed_top` at `crypto/bn/bn_rand.c:271` (BN_R_TOO_MANY_ITERATIONS).
pub(crate) const BN_RAND_271: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_rand.c",
    line: 271,
    func: c"ossl_bn_priv_rand_range_fixed_top",
    lib: 3,
    reason: 113,
    dynamic_reason: false,
};

/// `ossl_bn_gen_dsa_nonce_fixed_top` at `crypto/bn/bn_rand.c:332` (BN_R_PRIVATE_KEY_TOO_LARGE).
pub(crate) const BN_RAND_332: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_rand.c",
    line: 332,
    func: c"ossl_bn_gen_dsa_nonce_fixed_top",
    lib: 3,
    reason: 117,
    dynamic_reason: false,
};

/// `ossl_bn_gen_dsa_nonce_fixed_top` at `crypto/bn/bn_rand.c:338` (BN_R_NO_SUITABLE_DIGEST).
pub(crate) const BN_RAND_338: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_rand.c",
    line: 338,
    func: c"ossl_bn_gen_dsa_nonce_fixed_top",
    lib: 3,
    reason: 120,
    dynamic_reason: false,
};

/// `ossl_bn_gen_dsa_nonce_fixed_top` at `crypto/bn/bn_rand.c:385` (ERR_R_INTERNAL_ERROR).
pub(crate) const BN_RAND_385: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_rand.c",
    line: 385,
    func: c"ossl_bn_gen_dsa_nonce_fixed_top",
    lib: 3,
    reason: 786691,
    dynamic_reason: false,
};

/// `BN_div_recp` at `crypto/bn/bn_recp.c:147` (BN_R_BAD_RECIPROCAL).
pub(crate) const BN_RECP_147: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_recp.c",
    line: 147,
    func: c"BN_div_recp",
    lib: 3,
    reason: 101,
    dynamic_reason: false,
};

/// `ossl_bn_rsa_fips186_4_derive_prime` at `crypto/bn/bn_rsa_fips186_4.c:391` (BN_R_NO_PRIME_CANDIDATE).
pub(crate) const BN_RSA_FIPS186_4_391: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_rsa_fips186_4.c",
    line: 391,
    func: c"ossl_bn_rsa_fips186_4_derive_prime",
    lib: 3,
    reason: 121,
    dynamic_reason: false,
};

/// `BN_lshift` at `crypto/bn/bn_shift.c:86` (BN_R_INVALID_SHIFT).
pub(crate) const BN_SHIFT_86: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_shift.c",
    line: 86,
    func: c"BN_lshift",
    lib: 3,
    reason: 119,
    dynamic_reason: false,
};

/// `BN_rshift` at `crypto/bn/bn_shift.c:155` (BN_R_INVALID_SHIFT).
pub(crate) const BN_SHIFT_155: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_shift.c",
    line: 155,
    func: c"BN_rshift",
    lib: 3,
    reason: 119,
    dynamic_reason: false,
};

/// `BN_mod_sqrt` at `crypto/bn/bn_sqrt.c:43` (BN_R_P_IS_NOT_PRIME).
pub(crate) const BN_SQRT_43: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_sqrt.c",
    line: 43,
    func: c"BN_mod_sqrt",
    lib: 3,
    reason: 112,
    dynamic_reason: false,
};

/// `BN_mod_sqrt` at `crypto/bn/bn_sqrt.c:203` (BN_R_P_IS_NOT_PRIME).
pub(crate) const BN_SQRT_203: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_sqrt.c",
    line: 203,
    func: c"BN_mod_sqrt",
    lib: 3,
    reason: 112,
    dynamic_reason: false,
};

/// `BN_mod_sqrt` at `crypto/bn/bn_sqrt.c:214` (BN_R_TOO_MANY_ITERATIONS).
pub(crate) const BN_SQRT_214: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_sqrt.c",
    line: 214,
    func: c"BN_mod_sqrt",
    lib: 3,
    reason: 113,
    dynamic_reason: false,
};

/// `BN_mod_sqrt` at `crypto/bn/bn_sqrt.c:229` (BN_R_P_IS_NOT_PRIME).
pub(crate) const BN_SQRT_229: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_sqrt.c",
    line: 229,
    func: c"BN_mod_sqrt",
    lib: 3,
    reason: 112,
    dynamic_reason: false,
};

/// `BN_mod_sqrt` at `crypto/bn/bn_sqrt.c:321` (BN_R_NOT_A_SQUARE).
pub(crate) const BN_SQRT_321: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_sqrt.c",
    line: 321,
    func: c"BN_mod_sqrt",
    lib: 3,
    reason: 111,
    dynamic_reason: false,
};

/// `BN_mod_sqrt` at `crypto/bn/bn_sqrt.c:352` (BN_R_NOT_A_SQUARE).
pub(crate) const BN_SQRT_352: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/bn/bn_sqrt.c",
    line: 352,
    func: c"BN_mod_sqrt",
    lib: 3,
    reason: 111,
    dynamic_reason: false,
};

/// `ossl_c2i_ASN1_BIT_STRING` at `crypto/asn1/a_bitstr.c:139` (ERR_raise dynamic reason).
pub(crate) const A_BITSTR_139: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_bitstr.c",
    line: 139,
    func: c"ossl_c2i_ASN1_BIT_STRING",
    lib: 13,
    reason: 0,
    dynamic_reason: true,
};

/// `ASN1_d2i_fp` at `crypto/asn1/a_d2i_fp.c:28` (ERR_R_BUF_LIB).
pub(crate) const A_D2I_FP_28: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_d2i_fp.c",
    line: 28,
    func: c"ASN1_d2i_fp",
    lib: 13,
    reason: 524295,
    dynamic_reason: false,
};

/// `ASN1_item_d2i_fp_ex` at `crypto/asn1/a_d2i_fp.c:92` (ERR_R_BUF_LIB).
pub(crate) const A_D2I_FP_92: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_d2i_fp.c",
    line: 92,
    func: c"ASN1_item_d2i_fp_ex",
    lib: 13,
    reason: 524295,
    dynamic_reason: false,
};

/// `asn1_d2i_read_bio` at `crypto/asn1/a_d2i_fp.c:125` (ERR_R_BUF_LIB).
pub(crate) const A_D2I_FP_125: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_d2i_fp.c",
    line: 125,
    func: c"asn1_d2i_read_bio",
    lib: 13,
    reason: 524295,
    dynamic_reason: false,
};

/// `asn1_d2i_read_bio` at `crypto/asn1/a_d2i_fp.c:138` (ERR_R_BUF_LIB).
pub(crate) const A_D2I_FP_138: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_d2i_fp.c",
    line: 138,
    func: c"asn1_d2i_read_bio",
    lib: 13,
    reason: 524295,
    dynamic_reason: false,
};

/// `asn1_d2i_read_bio` at `crypto/asn1/a_d2i_fp.c:156` (ASN1_R_NOT_ENOUGH_DATA).
pub(crate) const A_D2I_FP_156: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_d2i_fp.c",
    line: 156,
    func: c"asn1_d2i_read_bio",
    lib: 13,
    reason: 142,
    dynamic_reason: false,
};

/// `asn1_d2i_read_bio` at `crypto/asn1/a_d2i_fp.c:161` (ASN1_R_TOO_LONG).
pub(crate) const A_D2I_FP_161: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_d2i_fp.c",
    line: 161,
    func: c"asn1_d2i_read_bio",
    lib: 13,
    reason: 155,
    dynamic_reason: false,
};

/// `asn1_d2i_read_bio` at `crypto/asn1/a_d2i_fp.c:177` (ASN1_R_NOT_ENOUGH_DATA).
pub(crate) const A_D2I_FP_177: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_d2i_fp.c",
    line: 177,
    func: c"asn1_d2i_read_bio",
    lib: 13,
    reason: 142,
    dynamic_reason: false,
};

/// `asn1_d2i_read_bio` at `crypto/asn1/a_d2i_fp.c:188` (ASN1_R_HEADER_TOO_LONG).
pub(crate) const A_D2I_FP_188: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_d2i_fp.c",
    line: 188,
    func: c"asn1_d2i_read_bio",
    lib: 13,
    reason: 123,
    dynamic_reason: false,
};

/// `asn1_d2i_read_bio` at `crypto/asn1/a_d2i_fp.c:214` (ASN1_R_TOO_LONG).
pub(crate) const A_D2I_FP_214: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_d2i_fp.c",
    line: 214,
    func: c"asn1_d2i_read_bio",
    lib: 13,
    reason: 155,
    dynamic_reason: false,
};

/// `asn1_d2i_read_bio` at `crypto/asn1/a_d2i_fp.c:244` (ASN1_R_HEADER_TOO_LONG).
pub(crate) const A_D2I_FP_244: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_d2i_fp.c",
    line: 244,
    func: c"asn1_d2i_read_bio",
    lib: 13,
    reason: 123,
    dynamic_reason: false,
};

/// `asn1_d2i_read_bio` at `crypto/asn1/a_d2i_fp.c:264` (ASN1_R_TOO_LONG).
pub(crate) const A_D2I_FP_264: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_d2i_fp.c",
    line: 264,
    func: c"asn1_d2i_read_bio",
    lib: 13,
    reason: 155,
    dynamic_reason: false,
};

/// `asn1_d2i_read_bio` at `crypto/asn1/a_d2i_fp.c:278` (ERR_R_BUF_LIB).
pub(crate) const A_D2I_FP_278: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_d2i_fp.c",
    line: 278,
    func: c"asn1_d2i_read_bio",
    lib: 13,
    reason: 524295,
    dynamic_reason: false,
};

/// `asn1_d2i_read_bio` at `crypto/asn1/a_d2i_fp.c:285` (ASN1_R_NOT_ENOUGH_DATA).
pub(crate) const A_D2I_FP_285: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_d2i_fp.c",
    line: 285,
    func: c"asn1_d2i_read_bio",
    lib: 13,
    reason: 142,
    dynamic_reason: false,
};

/// `asn1_d2i_read_bio` at `crypto/asn1/a_d2i_fp.c:300` (ASN1_R_TOO_LONG).
pub(crate) const A_D2I_FP_300: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_d2i_fp.c",
    line: 300,
    func: c"asn1_d2i_read_bio",
    lib: 13,
    reason: 155,
    dynamic_reason: false,
};

/// `asn1_d2i_read_bio` at `crypto/asn1/a_d2i_fp.c:312` (ASN1_R_TOO_LONG).
pub(crate) const A_D2I_FP_312: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_d2i_fp.c",
    line: 312,
    func: c"asn1_d2i_read_bio",
    lib: 13,
    reason: 155,
    dynamic_reason: false,
};

/// `ASN1_item_dup` at `crypto/asn1/a_dup.c:79` (ERR_R_ASN1_LIB).
pub(crate) const A_DUP_79: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_dup.c",
    line: 79,
    func: c"ASN1_item_dup",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `ASN1_item_dup` at `crypto/asn1/a_dup.c:93` (ASN1_R_AUX_ERROR).
pub(crate) const A_DUP_93: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_dup.c",
    line: 93,
    func: c"ASN1_item_dup",
    lib: 13,
    reason: 100,
    dynamic_reason: false,
};

/// `ASN1_i2d_fp` at `crypto/asn1/a_i2d_fp.c:24` (ERR_R_BUF_LIB).
pub(crate) const A_I2D_FP_24: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_i2d_fp.c",
    line: 24,
    func: c"ASN1_i2d_fp",
    lib: 13,
    reason: 524295,
    dynamic_reason: false,
};

/// `ASN1_item_i2d_fp` at `crypto/asn1/a_i2d_fp.c:75` (ERR_R_BUF_LIB).
pub(crate) const A_I2D_FP_75: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_i2d_fp.c",
    line: 75,
    func: c"ASN1_item_i2d_fp",
    lib: 13,
    reason: 524295,
    dynamic_reason: false,
};

/// `ASN1_item_i2d_bio` at `crypto/asn1/a_i2d_fp.c:92` (ERR_R_ASN1_LIB).
pub(crate) const A_I2D_FP_92: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_i2d_fp.c",
    line: 92,
    func: c"ASN1_item_i2d_bio",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `ASN1_item_i2d_mem_bio` at `crypto/asn1/a_i2d_fp.c:116` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const A_I2D_FP_116: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_i2d_fp.c",
    line: 116,
    func: c"ASN1_item_i2d_mem_bio",
    lib: 13,
    reason: 786690,
    dynamic_reason: false,
};

/// `c2i_ibuf` at `crypto/asn1/a_int.c:160` (ASN1_R_ILLEGAL_ZERO_CONTENT).
pub(crate) const A_INT_160: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_int.c",
    line: 160,
    func: c"c2i_ibuf",
    lib: 13,
    reason: 222,
    dynamic_reason: false,
};

/// `c2i_ibuf` at `crypto/asn1/a_int.c:193` (ASN1_R_ILLEGAL_PADDING).
pub(crate) const A_INT_193: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_int.c",
    line: 193,
    func: c"c2i_ibuf",
    lib: 13,
    reason: 221,
    dynamic_reason: false,
};

/// `ossl_i2c_ASN1_INTEGER` at `crypto/asn1/a_int.c:213` (ASN1_R_TOO_LARGE).
pub(crate) const A_INT_213: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_int.c",
    line: 213,
    func: c"ossl_i2c_ASN1_INTEGER",
    lib: 13,
    reason: 223,
    dynamic_reason: false,
};

/// `asn1_get_uint64` at `crypto/asn1/a_int.c:228` (ASN1_R_TOO_LARGE).
pub(crate) const A_INT_228: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_int.c",
    line: 228,
    func: c"asn1_get_uint64",
    lib: 13,
    reason: 223,
    dynamic_reason: false,
};

/// `asn1_get_int64` at `crypto/asn1/a_int.c:284` (ASN1_R_TOO_SMALL).
pub(crate) const A_INT_284: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_int.c",
    line: 284,
    func: c"asn1_get_int64",
    lib: 13,
    reason: 224,
    dynamic_reason: false,
};

/// `asn1_get_int64` at `crypto/asn1/a_int.c:291` (ASN1_R_TOO_LARGE).
pub(crate) const A_INT_291: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_int.c",
    line: 291,
    func: c"asn1_get_int64",
    lib: 13,
    reason: 223,
    dynamic_reason: false,
};

/// `ossl_c2i_ASN1_INTEGER` at `crypto/asn1/a_int.c:320` (ERR_R_ASN1_LIB).
pub(crate) const A_INT_320: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_int.c",
    line: 320,
    func: c"ossl_c2i_ASN1_INTEGER",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `asn1_string_get_int64` at `crypto/asn1/a_int.c:344` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const A_INT_344: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_int.c",
    line: 344,
    func: c"asn1_string_get_int64",
    lib: 13,
    reason: 786690,
    dynamic_reason: false,
};

/// `asn1_string_get_int64` at `crypto/asn1/a_int.c:348` (ASN1_R_WRONG_INTEGER_TYPE).
pub(crate) const A_INT_348: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_int.c",
    line: 348,
    func: c"asn1_string_get_int64",
    lib: 13,
    reason: 225,
    dynamic_reason: false,
};

/// `asn1_string_get_uint64` at `crypto/asn1/a_int.c:381` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const A_INT_381: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_int.c",
    line: 381,
    func: c"asn1_string_get_uint64",
    lib: 13,
    reason: 786690,
    dynamic_reason: false,
};

/// `asn1_string_get_uint64` at `crypto/asn1/a_int.c:385` (ASN1_R_WRONG_INTEGER_TYPE).
pub(crate) const A_INT_385: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_int.c",
    line: 385,
    func: c"asn1_string_get_uint64",
    lib: 13,
    reason: 225,
    dynamic_reason: false,
};

/// `asn1_string_get_uint64` at `crypto/asn1/a_int.c:389` (ASN1_R_ILLEGAL_NEGATIVE_VALUE).
pub(crate) const A_INT_389: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_int.c",
    line: 389,
    func: c"asn1_string_get_uint64",
    lib: 13,
    reason: 226,
    dynamic_reason: false,
};

/// `d2i_ASN1_UINTEGER` at `crypto/asn1/a_int.c:468` (ERR_raise dynamic reason).
pub(crate) const A_INT_468: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_int.c",
    line: 468,
    func: c"d2i_ASN1_UINTEGER",
    lib: 13,
    reason: 0,
    dynamic_reason: true,
};

/// `bn_to_asn1_string` at `crypto/asn1/a_int.c:488` (ERR_R_NESTED_ASN1_ERROR).
pub(crate) const A_INT_488: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_int.c",
    line: 488,
    func: c"bn_to_asn1_string",
    lib: 13,
    reason: 524554,
    dynamic_reason: false,
};

/// `bn_to_asn1_string` at `crypto/asn1/a_int.c:501` (ERR_R_ASN1_LIB).
pub(crate) const A_INT_501: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_int.c",
    line: 501,
    func: c"bn_to_asn1_string",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `asn1_string_to_bn` at `crypto/asn1/a_int.c:524` (ASN1_R_WRONG_INTEGER_TYPE).
pub(crate) const A_INT_524: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_int.c",
    line: 524,
    func: c"asn1_string_to_bn",
    lib: 13,
    reason: 225,
    dynamic_reason: false,
};

/// `asn1_string_to_bn` at `crypto/asn1/a_int.c:530` (ASN1_R_BN_LIB).
pub(crate) const A_INT_530: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_int.c",
    line: 530,
    func: c"asn1_string_to_bn",
    lib: 13,
    reason: 105,
    dynamic_reason: false,
};

/// `ossl_c2i_uint64_int` at `crypto/asn1/a_int.c:641` (ASN1_R_TOO_LARGE).
pub(crate) const A_INT_641: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_int.c",
    line: 641,
    func: c"ossl_c2i_uint64_int",
    lib: 13,
    reason: 223,
    dynamic_reason: false,
};

/// `ASN1_mbstring_ncopy` at `crypto/asn1/a_mbstr.c:58` (ASN1_R_STRING_TOO_LONG).
pub(crate) const A_MBSTR_58: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_mbstr.c",
    line: 58,
    func: c"ASN1_mbstring_ncopy",
    lib: 13,
    reason: 151,
    dynamic_reason: false,
};

/// `ASN1_mbstring_ncopy` at `crypto/asn1/a_mbstr.c:66` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const A_MBSTR_66: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_mbstr.c",
    line: 66,
    func: c"ASN1_mbstring_ncopy",
    lib: 13,
    reason: 524550,
    dynamic_reason: false,
};

/// `ASN1_mbstring_ncopy` at `crypto/asn1/a_mbstr.c:69` (ASN1_R_STRING_TOO_LONG).
pub(crate) const A_MBSTR_69: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_mbstr.c",
    line: 69,
    func: c"ASN1_mbstring_ncopy",
    lib: 13,
    reason: 151,
    dynamic_reason: false,
};

/// `ASN1_mbstring_ncopy` at `crypto/asn1/a_mbstr.c:78` (ASN1_R_INVALID_BMPSTRING_LENGTH).
pub(crate) const A_MBSTR_78: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_mbstr.c",
    line: 78,
    func: c"ASN1_mbstring_ncopy",
    lib: 13,
    reason: 129,
    dynamic_reason: false,
};

/// `ASN1_mbstring_ncopy` at `crypto/asn1/a_mbstr.c:86` (ASN1_R_INVALID_UNIVERSALSTRING_LENGTH).
pub(crate) const A_MBSTR_86: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_mbstr.c",
    line: 86,
    func: c"ASN1_mbstring_ncopy",
    lib: 13,
    reason: 133,
    dynamic_reason: false,
};

/// `ASN1_mbstring_ncopy` at `crypto/asn1/a_mbstr.c:97` (ASN1_R_INVALID_UTF8STRING).
pub(crate) const A_MBSTR_97: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_mbstr.c",
    line: 97,
    func: c"ASN1_mbstring_ncopy",
    lib: 13,
    reason: 134,
    dynamic_reason: false,
};

/// `ASN1_mbstring_ncopy` at `crypto/asn1/a_mbstr.c:107` (ASN1_R_UNKNOWN_FORMAT).
pub(crate) const A_MBSTR_107: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_mbstr.c",
    line: 107,
    func: c"ASN1_mbstring_ncopy",
    lib: 13,
    reason: 160,
    dynamic_reason: false,
};

/// `ASN1_mbstring_ncopy` at `crypto/asn1/a_mbstr.c:112` (ASN1_R_STRING_TOO_SHORT).
pub(crate) const A_MBSTR_112: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_mbstr.c",
    line: 112,
    func: c"ASN1_mbstring_ncopy",
    lib: 13,
    reason: 152,
    dynamic_reason: false,
};

/// `ASN1_mbstring_ncopy` at `crypto/asn1/a_mbstr.c:118` (ASN1_R_STRING_TOO_LONG).
pub(crate) const A_MBSTR_118: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_mbstr.c",
    line: 118,
    func: c"ASN1_mbstring_ncopy",
    lib: 13,
    reason: 151,
    dynamic_reason: false,
};

/// `ASN1_mbstring_ncopy` at `crypto/asn1/a_mbstr.c:125` (ASN1_R_ILLEGAL_CHARACTERS).
pub(crate) const A_MBSTR_125: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_mbstr.c",
    line: 125,
    func: c"ASN1_mbstring_ncopy",
    lib: 13,
    reason: 124,
    dynamic_reason: false,
};

/// `ASN1_mbstring_ncopy` at `crypto/asn1/a_mbstr.c:163` (ERR_R_ASN1_LIB).
pub(crate) const A_MBSTR_163: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_mbstr.c",
    line: 163,
    func: c"ASN1_mbstring_ncopy",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `ASN1_mbstring_ncopy` at `crypto/asn1/a_mbstr.c:175` (ERR_R_ASN1_LIB).
pub(crate) const A_MBSTR_175: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_mbstr.c",
    line: 175,
    func: c"ASN1_mbstring_ncopy",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `ASN1_mbstring_ncopy` at `crypto/asn1/a_mbstr.c:190` (ASN1_R_STRING_TOO_LONG).
pub(crate) const A_MBSTR_190: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_mbstr.c",
    line: 190,
    func: c"ASN1_mbstring_ncopy",
    lib: 13,
    reason: 151,
    dynamic_reason: false,
};

/// `ASN1_mbstring_ncopy` at `crypto/asn1/a_mbstr.c:203` (ASN1_R_STRING_TOO_LONG).
pub(crate) const A_MBSTR_203: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_mbstr.c",
    line: 203,
    func: c"ASN1_mbstring_ncopy",
    lib: 13,
    reason: 151,
    dynamic_reason: false,
};

/// `out_utf8` at `crypto/asn1/a_mbstr.c:305` (ASN1_R_INVALID_UTF8STRING).
pub(crate) const A_MBSTR_305: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_mbstr.c",
    line: 305,
    func: c"out_utf8",
    lib: 13,
    reason: 134,
    dynamic_reason: false,
};

/// `out_utf8` at `crypto/asn1/a_mbstr.c:310` (ASN1_R_STRING_TOO_LONG).
pub(crate) const A_MBSTR_310: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_mbstr.c",
    line: 310,
    func: c"out_utf8",
    lib: 13,
    reason: 151,
    dynamic_reason: false,
};

/// `ASN1_STRING_TABLE_get` at `crypto/asn1/a_strnid.c:133` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const A_STRNID_133: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_strnid.c",
    line: 133,
    func: c"ASN1_STRING_TABLE_get",
    lib: 13,
    reason: 524550,
    dynamic_reason: false,
};

/// `ASN1_STRING_TABLE_add` at `crypto/asn1/a_strnid.c:199` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const A_STRNID_199: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_strnid.c",
    line: 199,
    func: c"ASN1_STRING_TABLE_add",
    lib: 13,
    reason: 524550,
    dynamic_reason: false,
};

/// `ASN1_STRING_TABLE_add` at `crypto/asn1/a_strnid.c:205` (ERR_R_ASN1_LIB).
pub(crate) const A_STRNID_205: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_strnid.c",
    line: 205,
    func: c"ASN1_STRING_TABLE_add",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `do_buf` at `crypto/asn1/a_strex.c:150` (ASN1_R_INVALID_UNIVERSALSTRING_LENGTH).
pub(crate) const A_STREX_150: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_strex.c",
    line: 150,
    func: c"do_buf",
    lib: 13,
    reason: 133,
    dynamic_reason: false,
};

/// `do_buf` at `crypto/asn1/a_strex.c:156` (ASN1_R_INVALID_BMPSTRING_LENGTH).
pub(crate) const A_STREX_156: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_strex.c",
    line: 156,
    func: c"do_buf",
    lib: 13,
    reason: 129,
    dynamic_reason: false,
};

/// `ASN1_TIME_adj` at `crypto/asn1/a_time.c:336` (ASN1_R_ERROR_GETTING_TIME).
pub(crate) const A_TIME_336: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/a_time.c",
    line: 336,
    func: c"ASN1_TIME_adj",
    lib: 13,
    reason: 173,
    dynamic_reason: false,
};

/// `ASN1_generate_v3` at `crypto/asn1/asn1_gen.c:95` (ERR_raise dynamic reason).
pub(crate) const ASN1_GEN_95: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 95,
    func: c"ASN1_generate_v3",
    lib: 13,
    reason: 0,
    dynamic_reason: true,
};

/// `asn1_cb` at `crypto/asn1/asn1_gen.c:275` (ASN1_R_UNKNOWN_TAG).
pub(crate) const ASN1_GEN_275: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 275,
    func: c"asn1_cb",
    lib: 13,
    reason: 194,
    dynamic_reason: false,
};

/// `asn1_cb` at `crypto/asn1/asn1_gen.c:285` (ASN1_R_MISSING_VALUE).
pub(crate) const ASN1_GEN_285: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 285,
    func: c"asn1_cb",
    lib: 13,
    reason: 189,
    dynamic_reason: false,
};

/// `asn1_cb` at `crypto/asn1/asn1_gen.c:296` (ASN1_R_ILLEGAL_NESTED_TAGGING).
pub(crate) const ASN1_GEN_296: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 296,
    func: c"asn1_cb",
    lib: 13,
    reason: 181,
    dynamic_reason: false,
};

/// `asn1_cb` at `crypto/asn1/asn1_gen.c:333` (ASN1_R_UNKNOWN_FORMAT).
pub(crate) const ASN1_GEN_333: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 333,
    func: c"asn1_cb",
    lib: 13,
    reason: 160,
    dynamic_reason: false,
};

/// `asn1_cb` at `crypto/asn1/asn1_gen.c:345` (ASN1_R_UNKNOWN_FORMAT).
pub(crate) const ASN1_GEN_345: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 345,
    func: c"asn1_cb",
    lib: 13,
    reason: 160,
    dynamic_reason: false,
};

/// `parse_tagging` at `crypto/asn1/asn1_gen.c:365` (ASN1_R_INVALID_NUMBER).
pub(crate) const ASN1_GEN_365: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 365,
    func: c"parse_tagging",
    lib: 13,
    reason: 187,
    dynamic_reason: false,
};

/// `parse_tagging` at `crypto/asn1/asn1_gen.c:394` (ASN1_R_INVALID_MODIFIER).
pub(crate) const ASN1_GEN_394: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 394,
    func: c"parse_tagging",
    lib: 13,
    reason: 186,
    dynamic_reason: false,
};

/// `append_exp` at `crypto/asn1/asn1_gen.c:475` (ASN1_R_ILLEGAL_IMPLICIT_TAG).
pub(crate) const ASN1_GEN_475: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 475,
    func: c"append_exp",
    lib: 13,
    reason: 179,
    dynamic_reason: false,
};

/// `append_exp` at `crypto/asn1/asn1_gen.c:480` (ASN1_R_DEPTH_EXCEEDED).
pub(crate) const ASN1_GEN_480: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 480,
    func: c"append_exp",
    lib: 13,
    reason: 174,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:592` (ERR_R_ASN1_LIB).
pub(crate) const ASN1_GEN_592: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 592,
    func: c"asn1_str2type",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:603` (ASN1_R_ILLEGAL_NULL_VALUE).
pub(crate) const ASN1_GEN_603: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 603,
    func: c"asn1_str2type",
    lib: 13,
    reason: 182,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:610` (ASN1_R_NOT_ASCII_FORMAT).
pub(crate) const ASN1_GEN_610: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 610,
    func: c"asn1_str2type",
    lib: 13,
    reason: 190,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:617` (ASN1_R_ILLEGAL_BOOLEAN).
pub(crate) const ASN1_GEN_617: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 617,
    func: c"asn1_str2type",
    lib: 13,
    reason: 176,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:625` (ASN1_R_INTEGER_NOT_ASCII_FORMAT).
pub(crate) const ASN1_GEN_625: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 625,
    func: c"asn1_str2type",
    lib: 13,
    reason: 185,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:631` (ASN1_R_ILLEGAL_INTEGER).
pub(crate) const ASN1_GEN_631: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 631,
    func: c"asn1_str2type",
    lib: 13,
    reason: 180,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:638` (ASN1_R_OBJECT_NOT_ASCII_FORMAT).
pub(crate) const ASN1_GEN_638: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 638,
    func: c"asn1_str2type",
    lib: 13,
    reason: 191,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:642` (ASN1_R_ILLEGAL_OBJECT).
pub(crate) const ASN1_GEN_642: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 642,
    func: c"asn1_str2type",
    lib: 13,
    reason: 183,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:650` (ASN1_R_TIME_NOT_ASCII_FORMAT).
pub(crate) const ASN1_GEN_650: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 650,
    func: c"asn1_str2type",
    lib: 13,
    reason: 193,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:654` (ERR_R_ASN1_LIB).
pub(crate) const ASN1_GEN_654: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 654,
    func: c"asn1_str2type",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:658` (ERR_R_ASN1_LIB).
pub(crate) const ASN1_GEN_658: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 658,
    func: c"asn1_str2type",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:663` (ASN1_R_ILLEGAL_TIME_VALUE).
pub(crate) const ASN1_GEN_663: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 663,
    func: c"asn1_str2type",
    lib: 13,
    reason: 184,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:683` (ASN1_R_ILLEGAL_FORMAT).
pub(crate) const ASN1_GEN_683: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 683,
    func: c"asn1_str2type",
    lib: 13,
    reason: 177,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:690` (ERR_R_ASN1_LIB).
pub(crate) const ASN1_GEN_690: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 690,
    func: c"asn1_str2type",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:699` (ERR_R_ASN1_LIB).
pub(crate) const ASN1_GEN_699: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 699,
    func: c"asn1_str2type",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:705` (ASN1_R_ILLEGAL_HEX).
pub(crate) const ASN1_GEN_705: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 705,
    func: c"asn1_str2type",
    lib: 13,
    reason: 178,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:713` (ERR_R_ASN1_LIB).
pub(crate) const ASN1_GEN_713: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 713,
    func: c"asn1_str2type",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:719` (ASN1_R_LIST_ERROR).
pub(crate) const ASN1_GEN_719: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 719,
    func: c"asn1_str2type",
    lib: 13,
    reason: 188,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:725` (ASN1_R_ILLEGAL_BITSTRING_FORMAT).
pub(crate) const ASN1_GEN_725: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 725,
    func: c"asn1_str2type",
    lib: 13,
    reason: 175,
    dynamic_reason: false,
};

/// `asn1_str2type` at `crypto/asn1/asn1_gen.c:735` (ASN1_R_UNSUPPORTED_TYPE).
pub(crate) const ASN1_GEN_735: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 735,
    func: c"asn1_str2type",
    lib: 13,
    reason: 196,
    dynamic_reason: false,
};

/// `bitstr_cb` at `crypto/asn1/asn1_gen.c:760` (ASN1_R_INVALID_NUMBER).
pub(crate) const ASN1_GEN_760: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 760,
    func: c"bitstr_cb",
    lib: 13,
    reason: 187,
    dynamic_reason: false,
};

/// `bitstr_cb` at `crypto/asn1/asn1_gen.c:764` (ERR_R_ASN1_LIB).
pub(crate) const ASN1_GEN_764: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_gen.c",
    line: 764,
    func: c"bitstr_cb",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `ASN1_get_object` at `crypto/asn1/asn1_lib.c:56` (ASN1_R_TOO_SMALL).
pub(crate) const ASN1_LIB_56: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_lib.c",
    line: 56,
    func: c"ASN1_get_object",
    lib: 13,
    reason: 224,
    dynamic_reason: false,
};

/// `ASN1_get_object` at `crypto/asn1/asn1_lib.c:95` (ASN1_R_TOO_LONG).
pub(crate) const ASN1_LIB_95: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_lib.c",
    line: 95,
    func: c"ASN1_get_object",
    lib: 13,
    reason: 155,
    dynamic_reason: false,
};

/// `ASN1_get_object` at `crypto/asn1/asn1_lib.c:105` (ASN1_R_HEADER_TOO_LONG).
pub(crate) const ASN1_LIB_105: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_lib.c",
    line: 105,
    func: c"ASN1_get_object",
    lib: 13,
    reason: 123,
    dynamic_reason: false,
};

/// `ASN1_STRING_set` at `crypto/asn1/asn1_lib.c:305` (ASN1_R_TOO_LARGE).
pub(crate) const ASN1_LIB_305: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn1_lib.c",
    line: 305,
    func: c"ASN1_STRING_set",
    lib: 13,
    reason: 223,
    dynamic_reason: false,
};

/// `oid_module_init` at `crypto/asn1/asn_moid.c:32` (ASN1_R_ERROR_LOADING_SECTION).
pub(crate) const ASN_MOID_32: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_moid.c",
    line: 32,
    func: c"oid_module_init",
    lib: 13,
    reason: 172,
    dynamic_reason: false,
};

/// `oid_module_init` at `crypto/asn1/asn_moid.c:38` (ASN1_R_ADDING_OBJECT).
pub(crate) const ASN_MOID_38: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_moid.c",
    line: 38,
    func: c"oid_module_init",
    lib: 13,
    reason: 171,
    dynamic_reason: false,
};

/// `stbl_module_init` at `crypto/asn1/asn_mstbl.c:29` (ASN1_R_ERROR_LOADING_SECTION).
pub(crate) const ASN_MSTBL_29: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mstbl.c",
    line: 29,
    func: c"stbl_module_init",
    lib: 13,
    reason: 172,
    dynamic_reason: false,
};

/// `stbl_module_init` at `crypto/asn1/asn_mstbl.c:35` (ASN1_R_INVALID_VALUE).
pub(crate) const ASN_MSTBL_35: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mstbl.c",
    line: 35,
    func: c"stbl_module_init",
    lib: 13,
    reason: 219,
    dynamic_reason: false,
};

/// `do_tcreate` at `crypto/asn1/asn_mstbl.c:102` (ASN1_R_INVALID_STRING_TABLE_VALUE).
pub(crate) const ASN_MSTBL_102: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mstbl.c",
    line: 102,
    func: c"do_tcreate",
    lib: 13,
    reason: 218,
    dynamic_reason: false,
};

/// `do_tcreate` at `crypto/asn1/asn_mstbl.c:107` (ASN1_R_INVALID_STRING_TABLE_VALUE).
pub(crate) const ASN_MSTBL_107: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mstbl.c",
    line: 107,
    func: c"do_tcreate",
    lib: 13,
    reason: 218,
    dynamic_reason: false,
};

/// `do_tcreate` at `crypto/asn1/asn_mstbl.c:113` (ERR_R_ASN1_LIB).
pub(crate) const ASN_MSTBL_113: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mstbl.c",
    line: 113,
    func: c"do_tcreate",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `ASN1_item_pack` at `crypto/asn1/asn_pack.c:22` (ERR_R_ASN1_LIB).
pub(crate) const ASN_PACK_22: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_pack.c",
    line: 22,
    func: c"ASN1_item_pack",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `ASN1_item_pack` at `crypto/asn1/asn_pack.c:32` (ASN1_R_ENCODE_ERROR).
pub(crate) const ASN_PACK_32: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_pack.c",
    line: 32,
    func: c"ASN1_item_pack",
    lib: 13,
    reason: 112,
    dynamic_reason: false,
};

/// `ASN1_item_pack` at `crypto/asn1/asn_pack.c:36` (ERR_R_ASN1_LIB).
pub(crate) const ASN_PACK_36: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_pack.c",
    line: 36,
    func: c"ASN1_item_pack",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `ASN1_item_unpack` at `crypto/asn1/asn_pack.c:59` (ASN1_R_DECODE_ERROR).
pub(crate) const ASN_PACK_59: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_pack.c",
    line: 59,
    func: c"ASN1_item_unpack",
    lib: 13,
    reason: 110,
    dynamic_reason: false,
};

/// `ASN1_item_unpack_ex` at `crypto/asn1/asn_pack.c:73` (ASN1_R_DECODE_ERROR).
pub(crate) const ASN_PACK_73: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_pack.c",
    line: 73,
    func: c"ASN1_item_unpack_ex",
    lib: 13,
    reason: 110,
    dynamic_reason: false,
};

/// `asn1_bio_init` at `crypto/asn1/bio_asn1.c:118` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const BIO_ASN1_118: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/bio_asn1.c",
    line: 118,
    func: c"asn1_bio_init",
    lib: 13,
    reason: 524550,
    dynamic_reason: false,
};

/// `BIO_new_NDEF` at `crypto/asn1/bio_ndef.c:67` (ASN1_R_STREAMING_NOT_SUPPORTED).
pub(crate) const BIO_NDEF_67: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/bio_ndef.c",
    line: 67,
    func: c"BIO_new_NDEF",
    lib: 13,
    reason: 202,
    dynamic_reason: false,
};

/// `ASN1_TYPE_get_octetstring` at `crypto/asn1/evp_asn1.c:40` (ASN1_R_DATA_IS_WRONG).
pub(crate) const EVP_ASN1_40: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/evp_asn1.c",
    line: 40,
    func: c"ASN1_TYPE_get_octetstring",
    lib: 13,
    reason: 109,
    dynamic_reason: false,
};

/// `ASN1_TYPE_get_int_octetstring` at `crypto/asn1/evp_asn1.c:141` (ASN1_R_DATA_IS_WRONG).
pub(crate) const EVP_ASN1_141: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/evp_asn1.c",
    line: 141,
    func: c"ASN1_TYPE_get_int_octetstring",
    lib: 13,
    reason: 109,
    dynamic_reason: false,
};

/// `ossl_asn1_type_get_octetstring_int` at `crypto/asn1/evp_asn1.c:203` (ASN1_R_DATA_IS_WRONG).
pub(crate) const EVP_ASN1_203: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/evp_asn1.c",
    line: 203,
    func: c"ossl_asn1_type_get_octetstring_int",
    lib: 13,
    reason: 109,
    dynamic_reason: false,
};

/// `a2i_ASN1_INTEGER` at `crypto/asn1/f_int.c:100` (ASN1_R_ODD_NUMBER_OF_CHARS).
pub(crate) const F_INT_100: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/f_int.c",
    line: 100,
    func: c"a2i_ASN1_INTEGER",
    lib: 13,
    reason: 145,
    dynamic_reason: false,
};

/// `a2i_ASN1_INTEGER` at `crypto/asn1/f_int.c:118` (ASN1_R_NON_HEX_CHARACTERS).
pub(crate) const F_INT_118: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/f_int.c",
    line: 118,
    func: c"a2i_ASN1_INTEGER",
    lib: 13,
    reason: 141,
    dynamic_reason: false,
};

/// `a2i_ASN1_INTEGER` at `crypto/asn1/f_int.c:135` (ASN1_R_SHORT_LINE).
pub(crate) const F_INT_135: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/f_int.c",
    line: 135,
    func: c"a2i_ASN1_INTEGER",
    lib: 13,
    reason: 150,
    dynamic_reason: false,
};

/// `a2i_ASN1_STRING` at `crypto/asn1/f_string.c:92` (ASN1_R_ODD_NUMBER_OF_CHARS).
pub(crate) const F_STRING_92: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/f_string.c",
    line: 92,
    func: c"a2i_ASN1_STRING",
    lib: 13,
    reason: 145,
    dynamic_reason: false,
};

/// `a2i_ASN1_STRING` at `crypto/asn1/f_string.c:110` (ASN1_R_NON_HEX_CHARACTERS).
pub(crate) const F_STRING_110: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/f_string.c",
    line: 110,
    func: c"a2i_ASN1_STRING",
    lib: 13,
    reason: 141,
    dynamic_reason: false,
};

/// `a2i_ASN1_STRING` at `crypto/asn1/f_string.c:129` (ASN1_R_SHORT_LINE).
pub(crate) const F_STRING_129: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/f_string.c",
    line: 129,
    func: c"a2i_ASN1_STRING",
    lib: 13,
    reason: 150,
    dynamic_reason: false,
};

/// `asn1_item_ex_d2i_intern` at `crypto/asn1/tasn_dec.c:140` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const TASN_DEC_140: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 140,
    func: c"asn1_item_ex_d2i_intern",
    lib: 13,
    reason: 786690,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:208` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const TASN_DEC_208: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 208,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 786690,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:212` (ASN1_R_TOO_SMALL).
pub(crate) const TASN_DEC_212: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 212,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 224,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:222` (ASN1_R_NESTED_TOO_DEEP).
pub(crate) const TASN_DEC_222: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 222,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 201,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:236` (ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE).
pub(crate) const TASN_DEC_236: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 236,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 170,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:252` (ASN1_R_BAD_TEMPLATE).
pub(crate) const TASN_DEC_252: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 252,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 230,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:261` (ERR_R_NESTED_ASN1_ERROR).
pub(crate) const TASN_DEC_261: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 261,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 524554,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:270` (ASN1_R_MSTRING_NOT_UNIVERSAL).
pub(crate) const TASN_DEC_270: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 270,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 139,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:279` (ASN1_R_MSTRING_WRONG_TAG).
pub(crate) const TASN_DEC_279: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 279,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 140,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:298` (ASN1_R_BAD_TEMPLATE).
pub(crate) const TASN_DEC_298: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 298,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 230,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:314` (ERR_R_NESTED_ASN1_ERROR).
pub(crate) const TASN_DEC_314: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 314,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 524554,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:338` (ERR_R_NESTED_ASN1_ERROR).
pub(crate) const TASN_DEC_338: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 338,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 524554,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:350` (ASN1_R_NO_MATCHING_CHOICE_TYPE).
pub(crate) const TASN_DEC_350: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 350,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 143,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:375` (ERR_R_NESTED_ASN1_ERROR).
pub(crate) const TASN_DEC_375: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 375,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 524554,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:387` (ASN1_R_SEQUENCE_NOT_CONSTRUCTED).
pub(crate) const TASN_DEC_387: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 387,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 149,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:393` (ERR_R_NESTED_ASN1_ERROR).
pub(crate) const TASN_DEC_393: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 393,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 524554,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:427` (ASN1_R_UNEXPECTED_EOC).
pub(crate) const TASN_DEC_427: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 427,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 159,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:466` (ASN1_R_MISSING_EOC).
pub(crate) const TASN_DEC_466: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 466,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 137,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:471` (ASN1_R_SEQUENCE_LENGTH_MISMATCH).
pub(crate) const TASN_DEC_471: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 471,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 148,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:491` (ASN1_R_FIELD_MISSING).
pub(crate) const TASN_DEC_491: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 491,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 121,
    dynamic_reason: false,
};

/// `asn1_item_embed_d2i` at `crypto/asn1/tasn_dec.c:507` (ASN1_R_AUX_ERROR).
pub(crate) const TASN_DEC_507: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 507,
    func: c"asn1_item_embed_d2i",
    lib: 13,
    reason: 100,
    dynamic_reason: false,
};

/// `asn1_template_ex_d2i` at `crypto/asn1/tasn_dec.c:551` (ERR_R_NESTED_ASN1_ERROR).
pub(crate) const TASN_DEC_551: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 551,
    func: c"asn1_template_ex_d2i",
    lib: 13,
    reason: 524554,
    dynamic_reason: false,
};

/// `asn1_template_ex_d2i` at `crypto/asn1/tasn_dec.c:556` (ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED).
pub(crate) const TASN_DEC_556: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 556,
    func: c"asn1_template_ex_d2i",
    lib: 13,
    reason: 120,
    dynamic_reason: false,
};

/// `asn1_template_ex_d2i` at `crypto/asn1/tasn_dec.c:563` (ERR_R_NESTED_ASN1_ERROR).
pub(crate) const TASN_DEC_563: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 563,
    func: c"asn1_template_ex_d2i",
    lib: 13,
    reason: 524554,
    dynamic_reason: false,
};

/// `asn1_template_ex_d2i` at `crypto/asn1/tasn_dec.c:571` (ASN1_R_MISSING_EOC).
pub(crate) const TASN_DEC_571: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 571,
    func: c"asn1_template_ex_d2i",
    lib: 13,
    reason: 137,
    dynamic_reason: false,
};

/// `asn1_template_ex_d2i` at `crypto/asn1/tasn_dec.c:579` (ASN1_R_EXPLICIT_LENGTH_MISMATCH).
pub(crate) const TASN_DEC_579: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 579,
    func: c"asn1_template_ex_d2i",
    lib: 13,
    reason: 119,
    dynamic_reason: false,
};

/// `asn1_template_noexp_d2i` at `crypto/asn1/tasn_dec.c:639` (ERR_R_NESTED_ASN1_ERROR).
pub(crate) const TASN_DEC_639: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 639,
    func: c"asn1_template_noexp_d2i",
    lib: 13,
    reason: 524554,
    dynamic_reason: false,
};

/// `asn1_template_noexp_d2i` at `crypto/asn1/tasn_dec.c:658` (ERR_R_CRYPTO_LIB).
pub(crate) const TASN_DEC_658: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 658,
    func: c"asn1_template_noexp_d2i",
    lib: 13,
    reason: 524303,
    dynamic_reason: false,
};

/// `asn1_template_noexp_d2i` at `crypto/asn1/tasn_dec.c:669` (ASN1_R_UNEXPECTED_EOC).
pub(crate) const TASN_DEC_669: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 669,
    func: c"asn1_template_noexp_d2i",
    lib: 13,
    reason: 159,
    dynamic_reason: false,
};

/// `asn1_template_noexp_d2i` at `crypto/asn1/tasn_dec.c:681` (ERR_R_NESTED_ASN1_ERROR).
pub(crate) const TASN_DEC_681: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 681,
    func: c"asn1_template_noexp_d2i",
    lib: 13,
    reason: 524554,
    dynamic_reason: false,
};

/// `asn1_template_noexp_d2i` at `crypto/asn1/tasn_dec.c:688` (ERR_R_CRYPTO_LIB).
pub(crate) const TASN_DEC_688: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 688,
    func: c"asn1_template_noexp_d2i",
    lib: 13,
    reason: 524303,
    dynamic_reason: false,
};

/// `asn1_template_noexp_d2i` at `crypto/asn1/tasn_dec.c:694` (ASN1_R_MISSING_EOC).
pub(crate) const TASN_DEC_694: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 694,
    func: c"asn1_template_noexp_d2i",
    lib: 13,
    reason: 137,
    dynamic_reason: false,
};

/// `asn1_template_noexp_d2i` at `crypto/asn1/tasn_dec.c:703` (ERR_R_NESTED_ASN1_ERROR).
pub(crate) const TASN_DEC_703: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 703,
    func: c"asn1_template_noexp_d2i",
    lib: 13,
    reason: 524554,
    dynamic_reason: false,
};

/// `asn1_template_noexp_d2i` at `crypto/asn1/tasn_dec.c:712` (ERR_R_NESTED_ASN1_ERROR).
pub(crate) const TASN_DEC_712: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 712,
    func: c"asn1_template_noexp_d2i",
    lib: 13,
    reason: 524554,
    dynamic_reason: false,
};

/// `asn1_d2i_ex_primitive` at `crypto/asn1/tasn_dec.c:739` (ASN1_R_ILLEGAL_NULL).
pub(crate) const TASN_DEC_739: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 739,
    func: c"asn1_d2i_ex_primitive",
    lib: 13,
    reason: 125,
    dynamic_reason: false,
};

/// `asn1_d2i_ex_primitive` at `crypto/asn1/tasn_dec.c:753` (ASN1_R_ILLEGAL_TAGGED_ANY).
pub(crate) const TASN_DEC_753: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 753,
    func: c"asn1_d2i_ex_primitive",
    lib: 13,
    reason: 127,
    dynamic_reason: false,
};

/// `asn1_d2i_ex_primitive` at `crypto/asn1/tasn_dec.c:757` (ASN1_R_ILLEGAL_OPTIONAL_ANY).
pub(crate) const TASN_DEC_757: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 757,
    func: c"asn1_d2i_ex_primitive",
    lib: 13,
    reason: 126,
    dynamic_reason: false,
};

/// `asn1_d2i_ex_primitive` at `crypto/asn1/tasn_dec.c:764` (ERR_R_NESTED_ASN1_ERROR).
pub(crate) const TASN_DEC_764: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 764,
    func: c"asn1_d2i_ex_primitive",
    lib: 13,
    reason: 524554,
    dynamic_reason: false,
};

/// `asn1_d2i_ex_primitive` at `crypto/asn1/tasn_dec.c:779` (ERR_R_NESTED_ASN1_ERROR).
pub(crate) const TASN_DEC_779: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 779,
    func: c"asn1_d2i_ex_primitive",
    lib: 13,
    reason: 524554,
    dynamic_reason: false,
};

/// `asn1_d2i_ex_primitive` at `crypto/asn1/tasn_dec.c:796` (ASN1_R_TYPE_NOT_CONSTRUCTED).
pub(crate) const TASN_DEC_796: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 796,
    func: c"asn1_d2i_ex_primitive",
    lib: 13,
    reason: 156,
    dynamic_reason: false,
};

/// `asn1_d2i_ex_primitive` at `crypto/asn1/tasn_dec.c:814` (ASN1_R_TYPE_NOT_PRIMITIVE).
pub(crate) const TASN_DEC_814: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 814,
    func: c"asn1_d2i_ex_primitive",
    lib: 13,
    reason: 195,
    dynamic_reason: false,
};

/// `asn1_d2i_ex_primitive` at `crypto/asn1/tasn_dec.c:832` (ERR_R_BUF_LIB).
pub(crate) const TASN_DEC_832: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 832,
    func: c"asn1_d2i_ex_primitive",
    lib: 13,
    reason: 524295,
    dynamic_reason: false,
};

/// `asn1_ex_c2i` at `crypto/asn1/tasn_dec.c:873` (ASN1_R_TOO_LONG).
pub(crate) const TASN_DEC_873: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 873,
    func: c"asn1_ex_c2i",
    lib: 13,
    reason: 155,
    dynamic_reason: false,
};

/// `asn1_ex_c2i` at `crypto/asn1/tasn_dec.c:900` (ASN1_R_NULL_IS_WRONG_LENGTH).
pub(crate) const TASN_DEC_900: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 900,
    func: c"asn1_ex_c2i",
    lib: 13,
    reason: 144,
    dynamic_reason: false,
};

/// `asn1_ex_c2i` at `crypto/asn1/tasn_dec.c:908` (ASN1_R_BOOLEAN_IS_WRONG_LENGTH).
pub(crate) const TASN_DEC_908: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 908,
    func: c"asn1_ex_c2i",
    lib: 13,
    reason: 106,
    dynamic_reason: false,
};

/// `asn1_ex_c2i` at `crypto/asn1/tasn_dec.c:950` (ASN1_R_TOO_LONG).
pub(crate) const TASN_DEC_950: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 950,
    func: c"asn1_ex_c2i",
    lib: 13,
    reason: 155,
    dynamic_reason: false,
};

/// `asn1_ex_c2i` at `crypto/asn1/tasn_dec.c:954` (ASN1_R_BMPSTRING_IS_WRONG_LENGTH).
pub(crate) const TASN_DEC_954: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 954,
    func: c"asn1_ex_c2i",
    lib: 13,
    reason: 214,
    dynamic_reason: false,
};

/// `asn1_ex_c2i` at `crypto/asn1/tasn_dec.c:958` (ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH).
pub(crate) const TASN_DEC_958: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 958,
    func: c"asn1_ex_c2i",
    lib: 13,
    reason: 215,
    dynamic_reason: false,
};

/// `asn1_ex_c2i` at `crypto/asn1/tasn_dec.c:962` (ASN1_R_GENERALIZEDTIME_IS_TOO_SHORT).
pub(crate) const TASN_DEC_962: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 962,
    func: c"asn1_ex_c2i",
    lib: 13,
    reason: 232,
    dynamic_reason: false,
};

/// `asn1_ex_c2i` at `crypto/asn1/tasn_dec.c:966` (ASN1_R_UTCTIME_IS_TOO_SHORT).
pub(crate) const TASN_DEC_966: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 966,
    func: c"asn1_ex_c2i",
    lib: 13,
    reason: 233,
    dynamic_reason: false,
};

/// `asn1_ex_c2i` at `crypto/asn1/tasn_dec.c:973` (ERR_R_ASN1_LIB).
pub(crate) const TASN_DEC_973: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 973,
    func: c"asn1_ex_c2i",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `asn1_ex_c2i` at `crypto/asn1/tasn_dec.c:987` (ERR_R_ASN1_LIB).
pub(crate) const TASN_DEC_987: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 987,
    func: c"asn1_ex_c2i",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `asn1_find_end` at `crypto/asn1/tasn_dec.c:1045` (ERR_R_NESTED_ASN1_ERROR).
pub(crate) const TASN_DEC_1045: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 1045,
    func: c"asn1_find_end",
    lib: 13,
    reason: 524554,
    dynamic_reason: false,
};

/// `asn1_find_end` at `crypto/asn1/tasn_dec.c:1050` (ERR_R_NESTED_ASN1_ERROR).
pub(crate) const TASN_DEC_1050: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 1050,
    func: c"asn1_find_end",
    lib: 13,
    reason: 524554,
    dynamic_reason: false,
};

/// `asn1_find_end` at `crypto/asn1/tasn_dec.c:1060` (ASN1_R_MISSING_EOC).
pub(crate) const TASN_DEC_1060: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 1060,
    func: c"asn1_find_end",
    lib: 13,
    reason: 137,
    dynamic_reason: false,
};

/// `asn1_collect` at `crypto/asn1/tasn_dec.c:1107` (ASN1_R_UNEXPECTED_EOC).
pub(crate) const TASN_DEC_1107: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 1107,
    func: c"asn1_collect",
    lib: 13,
    reason: 159,
    dynamic_reason: false,
};

/// `asn1_collect` at `crypto/asn1/tasn_dec.c:1116` (ERR_R_NESTED_ASN1_ERROR).
pub(crate) const TASN_DEC_1116: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 1116,
    func: c"asn1_collect",
    lib: 13,
    reason: 524554,
    dynamic_reason: false,
};

/// `asn1_collect` at `crypto/asn1/tasn_dec.c:1123` (ASN1_R_NESTED_ASN1_STRING).
pub(crate) const TASN_DEC_1123: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 1123,
    func: c"asn1_collect",
    lib: 13,
    reason: 197,
    dynamic_reason: false,
};

/// `asn1_collect` at `crypto/asn1/tasn_dec.c:1133` (ASN1_R_MISSING_EOC).
pub(crate) const TASN_DEC_1133: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 1133,
    func: c"asn1_collect",
    lib: 13,
    reason: 137,
    dynamic_reason: false,
};

/// `collect_data` at `crypto/asn1/tasn_dec.c:1147` (ASN1_R_LENGTH_TOO_LONG).
pub(crate) const TASN_DEC_1147: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 1147,
    func: c"collect_data",
    lib: 13,
    reason: 231,
    dynamic_reason: false,
};

/// `collect_data` at `crypto/asn1/tasn_dec.c:1151` (ERR_R_BUF_LIB).
pub(crate) const TASN_DEC_1151: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 1151,
    func: c"collect_data",
    lib: 13,
    reason: 524295,
    dynamic_reason: false,
};

/// `asn1_check_tlen` at `crypto/asn1/tasn_dec.c:1196` (ASN1_R_TOO_SMALL).
pub(crate) const TASN_DEC_1196: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 1196,
    func: c"asn1_check_tlen",
    lib: 13,
    reason: 224,
    dynamic_reason: false,
};

/// `asn1_check_tlen` at `crypto/asn1/tasn_dec.c:1219` (ASN1_R_TOO_LONG).
pub(crate) const TASN_DEC_1219: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 1219,
    func: c"asn1_check_tlen",
    lib: 13,
    reason: 155,
    dynamic_reason: false,
};

/// `asn1_check_tlen` at `crypto/asn1/tasn_dec.c:1226` (ASN1_R_BAD_OBJECT_HEADER).
pub(crate) const TASN_DEC_1226: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 1226,
    func: c"asn1_check_tlen",
    lib: 13,
    reason: 102,
    dynamic_reason: false,
};

/// `asn1_check_tlen` at `crypto/asn1/tasn_dec.c:1236` (ASN1_R_WRONG_TAG).
pub(crate) const TASN_DEC_1236: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_dec.c",
    line: 1236,
    func: c"asn1_check_tlen",
    lib: 13,
    reason: 168,
    dynamic_reason: false,
};

/// `ASN1_item_ex_i2d` at `crypto/asn1/tasn_enc.c:112` (ASN1_R_BAD_TEMPLATE).
pub(crate) const TASN_ENC_112: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_enc.c",
    line: 112,
    func: c"ASN1_item_ex_i2d",
    lib: 13,
    reason: 230,
    dynamic_reason: false,
};

/// `ASN1_item_ex_i2d` at `crypto/asn1/tasn_enc.c:123` (ASN1_R_BAD_TEMPLATE).
pub(crate) const TASN_ENC_123: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_enc.c",
    line: 123,
    func: c"ASN1_item_ex_i2d",
    lib: 13,
    reason: 230,
    dynamic_reason: false,
};

/// `asn1_template_ex_i2d` at `crypto/asn1/tasn_enc.c:309` (ASN1_R_ILLEGAL_ZERO_CONTENT).
pub(crate) const TASN_ENC_309: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_enc.c",
    line: 309,
    func: c"asn1_template_ex_i2d",
    lib: 13,
    reason: 222,
    dynamic_reason: false,
};

/// `asn1_template_ex_i2d` at `crypto/asn1/tasn_enc.c:350` (ASN1_R_ILLEGAL_ZERO_CONTENT).
pub(crate) const TASN_ENC_350: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_enc.c",
    line: 350,
    func: c"asn1_template_ex_i2d",
    lib: 13,
    reason: 222,
    dynamic_reason: false,
};

/// `asn1_template_ex_i2d` at `crypto/asn1/tasn_enc.c:371` (ASN1_R_ILLEGAL_ZERO_CONTENT).
pub(crate) const TASN_ENC_371: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_enc.c",
    line: 371,
    func: c"asn1_template_ex_i2d",
    lib: 13,
    reason: 222,
    dynamic_reason: false,
};

/// `asn1_item_embed_new` at `crypto/asn1/tasn_new.c:162` (ERR_R_ASN1_LIB).
pub(crate) const TASN_NEW_162: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_new.c",
    line: 162,
    func: c"asn1_item_embed_new",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `asn1_item_embed_new` at `crypto/asn1/tasn_new.c:168` (ASN1_R_AUX_ERROR).
pub(crate) const TASN_NEW_168: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_new.c",
    line: 168,
    func: c"asn1_item_embed_new",
    lib: 13,
    reason: 100,
    dynamic_reason: false,
};

/// `asn1_template_new` at `crypto/asn1/tasn_new.c:231` (ERR_R_CRYPTO_LIB).
pub(crate) const TASN_NEW_231: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_new.c",
    line: 231,
    func: c"asn1_template_new",
    lib: 13,
    reason: 524303,
    dynamic_reason: false,
};

/// `ossl_asn1_do_lock` at `crypto/asn1/tasn_utl.c:91` (ERR_R_CRYPTO_LIB).
pub(crate) const TASN_UTL_91: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_utl.c",
    line: 91,
    func: c"ossl_asn1_do_lock",
    lib: 13,
    reason: 524303,
    dynamic_reason: false,
};

/// `ossl_asn1_do_adb` at `crypto/asn1/tasn_utl.c:263` (ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE).
pub(crate) const TASN_UTL_263: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_utl.c",
    line: 263,
    func: c"ossl_asn1_do_adb",
    lib: 13,
    reason: 164,
    dynamic_reason: false,
};

/// `ossl_asn1_do_adb` at `crypto/asn1/tasn_utl.c:288` (ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE).
pub(crate) const TASN_UTL_288: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/tasn_utl.c",
    line: 288,
    func: c"ossl_asn1_do_adb",
    lib: 13,
    reason: 164,
    dynamic_reason: false,
};

/// `uint64_c2i` at `crypto/asn1/x_int64.c:95` (ASN1_R_ILLEGAL_NEGATIVE_VALUE).
pub(crate) const X_INT64_95: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/x_int64.c",
    line: 95,
    func: c"uint64_c2i",
    lib: 13,
    reason: 226,
    dynamic_reason: false,
};

/// `uint64_c2i` at `crypto/asn1/x_int64.c:100` (ASN1_R_TOO_LARGE).
pub(crate) const X_INT64_100: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/x_int64.c",
    line: 100,
    func: c"uint64_c2i",
    lib: 13,
    reason: 223,
    dynamic_reason: false,
};

/// `uint32_c2i` at `crypto/asn1/x_int64.c:196` (ASN1_R_ILLEGAL_NEGATIVE_VALUE).
pub(crate) const X_INT64_196: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/x_int64.c",
    line: 196,
    func: c"uint32_c2i",
    lib: 13,
    reason: 226,
    dynamic_reason: false,
};

/// `uint32_c2i` at `crypto/asn1/x_int64.c:201` (ASN1_R_TOO_SMALL).
pub(crate) const X_INT64_201: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/x_int64.c",
    line: 201,
    func: c"uint32_c2i",
    lib: 13,
    reason: 224,
    dynamic_reason: false,
};

/// `uint32_c2i` at `crypto/asn1/x_int64.c:208` (ASN1_R_TOO_LARGE).
pub(crate) const X_INT64_208: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/x_int64.c",
    line: 208,
    func: c"uint32_c2i",
    lib: 13,
    reason: 223,
    dynamic_reason: false,
};

/// `long_c2i` at `crypto/asn1/x_long.c:154` (ASN1_R_INTEGER_TOO_LARGE_FOR_LONG).
pub(crate) const X_LONG_154: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/x_long.c",
    line: 154,
    func: c"long_c2i",
    lib: 13,
    reason: 128,
    dynamic_reason: false,
};

/// `long_c2i` at `crypto/asn1/x_long.c:165` (ASN1_R_ILLEGAL_PADDING).
pub(crate) const X_LONG_165: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/x_long.c",
    line: 165,
    func: c"long_c2i",
    lib: 13,
    reason: 221,
    dynamic_reason: false,
};

/// `long_c2i` at `crypto/asn1/x_long.c:175` (ASN1_R_INTEGER_TOO_LARGE_FOR_LONG).
pub(crate) const X_LONG_175: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/x_long.c",
    line: 175,
    func: c"long_c2i",
    lib: 13,
    reason: 128,
    dynamic_reason: false,
};

/// `long_c2i` at `crypto/asn1/x_long.c:181` (ASN1_R_INTEGER_TOO_LARGE_FOR_LONG).
pub(crate) const X_LONG_181: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/x_long.c",
    line: 181,
    func: c"long_c2i",
    lib: 13,
    reason: 128,
    dynamic_reason: false,
};

/// `x509v3_add_len_value` at `crypto/x509/v3_utl.c:60` (ERR_R_CRYPTO_LIB).
pub(crate) const V3_UTL_60: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/x509/v3_utl.c",
    line: 60,
    func: c"x509v3_add_len_value",
    lib: 34,
    reason: 524303,
    dynamic_reason: false,
};

/// `i2s_ASN1_ENUMERATED` at `crypto/x509/v3_utl.c:174` (ERR_R_ASN1_LIB).
pub(crate) const V3_UTL_174: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/x509/v3_utl.c",
    line: 174,
    func: c"i2s_ASN1_ENUMERATED",
    lib: 34,
    reason: 524301,
    dynamic_reason: false,
};

/// `i2s_ASN1_ENUMERATED` at `crypto/x509/v3_utl.c:176` (ERR_R_X509V3_LIB).
pub(crate) const V3_UTL_176: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/x509/v3_utl.c",
    line: 176,
    func: c"i2s_ASN1_ENUMERATED",
    lib: 34,
    reason: 524322,
    dynamic_reason: false,
};

/// `i2s_ASN1_INTEGER` at `crypto/x509/v3_utl.c:189` (ERR_R_ASN1_LIB).
pub(crate) const V3_UTL_189: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/x509/v3_utl.c",
    line: 189,
    func: c"i2s_ASN1_INTEGER",
    lib: 34,
    reason: 524301,
    dynamic_reason: false,
};

/// `i2s_ASN1_INTEGER` at `crypto/x509/v3_utl.c:191` (ERR_R_X509V3_LIB).
pub(crate) const V3_UTL_191: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/x509/v3_utl.c",
    line: 191,
    func: c"i2s_ASN1_INTEGER",
    lib: 34,
    reason: 524322,
    dynamic_reason: false,
};

/// `s2i_ASN1_INTEGER` at `crypto/x509/v3_utl.c:204` (X509V3_R_INVALID_NULL_VALUE).
pub(crate) const V3_UTL_204: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/x509/v3_utl.c",
    line: 204,
    func: c"s2i_ASN1_INTEGER",
    lib: 34,
    reason: 109,
    dynamic_reason: false,
};

/// `s2i_ASN1_INTEGER` at `crypto/x509/v3_utl.c:209` (ERR_R_BN_LIB).
pub(crate) const V3_UTL_209: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/x509/v3_utl.c",
    line: 209,
    func: c"s2i_ASN1_INTEGER",
    lib: 34,
    reason: 524291,
    dynamic_reason: false,
};

/// `s2i_ASN1_INTEGER` at `crypto/x509/v3_utl.c:233` (X509V3_R_BN_DEC2BN_ERROR).
pub(crate) const V3_UTL_233: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/x509/v3_utl.c",
    line: 233,
    func: c"s2i_ASN1_INTEGER",
    lib: 34,
    reason: 100,
    dynamic_reason: false,
};

/// `s2i_ASN1_INTEGER` at `crypto/x509/v3_utl.c:243` (X509V3_R_BN_TO_ASN1_INTEGER_ERROR).
pub(crate) const V3_UTL_243: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/x509/v3_utl.c",
    line: 243,
    func: c"s2i_ASN1_INTEGER",
    lib: 34,
    reason: 101,
    dynamic_reason: false,
};

/// `X509V3_get_value_bool` at `crypto/x509/v3_utl.c:291` (X509V3_R_INVALID_BOOLEAN_STRING).
pub(crate) const V3_UTL_291: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/x509/v3_utl.c",
    line: 291,
    func: c"X509V3_get_value_bool",
    lib: 34,
    reason: 104,
    dynamic_reason: false,
};

/// `X509V3_parse_list` at `crypto/x509/v3_utl.c:340` (X509V3_R_INVALID_EMPTY_NAME).
pub(crate) const V3_UTL_340: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/x509/v3_utl.c",
    line: 340,
    func: c"X509V3_parse_list",
    lib: 34,
    reason: 108,
    dynamic_reason: false,
};

/// `X509V3_parse_list` at `crypto/x509/v3_utl.c:349` (X509V3_R_INVALID_EMPTY_NAME).
pub(crate) const V3_UTL_349: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/x509/v3_utl.c",
    line: 349,
    func: c"X509V3_parse_list",
    lib: 34,
    reason: 108,
    dynamic_reason: false,
};

/// `X509V3_parse_list` at `crypto/x509/v3_utl.c:364` (X509V3_R_INVALID_NULL_VALUE).
pub(crate) const V3_UTL_364: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/x509/v3_utl.c",
    line: 364,
    func: c"X509V3_parse_list",
    lib: 34,
    reason: 109,
    dynamic_reason: false,
};

/// `X509V3_parse_list` at `crypto/x509/v3_utl.c:379` (X509V3_R_INVALID_NULL_VALUE).
pub(crate) const V3_UTL_379: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/x509/v3_utl.c",
    line: 379,
    func: c"X509V3_parse_list",
    lib: 34,
    reason: 109,
    dynamic_reason: false,
};

/// `X509V3_parse_list` at `crypto/x509/v3_utl.c:388` (X509V3_R_INVALID_EMPTY_NAME).
pub(crate) const V3_UTL_388: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/x509/v3_utl.c",
    line: 388,
    func: c"X509V3_parse_list",
    lib: 34,
    reason: 108,
    dynamic_reason: false,
};

/// `i2d_ASN1_bio_stream` at `crypto/asn1/asn_mime.c:79` (ERR_R_BUF_LIB).
pub(crate) const ASN_MIME_79: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 79,
    func: c"i2d_ASN1_bio_stream",
    lib: 13,
    reason: 524295,
    dynamic_reason: false,
};

/// `B64_write_ASN1` at `crypto/asn1/asn_mime.c:112` (ERR_R_BIO_LIB).
pub(crate) const ASN_MIME_112: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 112,
    func: c"B64_write_ASN1",
    lib: 13,
    reason: 524320,
    dynamic_reason: false,
};

/// `b64_read_asn1` at `crypto/asn1/asn_mime.c:143` (ERR_R_BIO_LIB).
pub(crate) const ASN_MIME_143: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 143,
    func: c"b64_read_asn1",
    lib: 13,
    reason: 524320,
    dynamic_reason: false,
};

/// `b64_read_asn1` at `crypto/asn1/asn_mime.c:149` (ASN1_R_DECODE_ERROR).
pub(crate) const ASN_MIME_149: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 149,
    func: c"b64_read_asn1",
    lib: 13,
    reason: 110,
    dynamic_reason: false,
};

/// `asn1_output_data` at `crypto/asn1/asn_mime.c:394` (ASN1_R_STREAMING_NOT_SUPPORTED).
pub(crate) const ASN_MIME_394: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 394,
    func: c"asn1_output_data",
    lib: 13,
    reason: 202,
    dynamic_reason: false,
};

/// `SMIME_read_ASN1_ex` at `crypto/asn1/asn_mime.c:448` (ASN1_R_MIME_PARSE_ERROR).
pub(crate) const ASN_MIME_448: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 448,
    func: c"SMIME_read_ASN1_ex",
    lib: 13,
    reason: 207,
    dynamic_reason: false,
};

/// `SMIME_read_ASN1_ex` at `crypto/asn1/asn_mime.c:455` (ASN1_R_NO_CONTENT_TYPE).
pub(crate) const ASN_MIME_455: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 455,
    func: c"SMIME_read_ASN1_ex",
    lib: 13,
    reason: 209,
    dynamic_reason: false,
};

/// `SMIME_read_ASN1_ex` at `crypto/asn1/asn_mime.c:466` (ASN1_R_NO_MULTIPART_BOUNDARY).
pub(crate) const ASN_MIME_466: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 466,
    func: c"SMIME_read_ASN1_ex",
    lib: 13,
    reason: 211,
    dynamic_reason: false,
};

/// `SMIME_read_ASN1_ex` at `crypto/asn1/asn_mime.c:472` (ASN1_R_NO_MULTIPART_BODY_FAILURE).
pub(crate) const ASN_MIME_472: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 472,
    func: c"SMIME_read_ASN1_ex",
    lib: 13,
    reason: 210,
    dynamic_reason: false,
};

/// `SMIME_read_ASN1_ex` at `crypto/asn1/asn_mime.c:481` (ASN1_R_MIME_SIG_PARSE_ERROR).
pub(crate) const ASN_MIME_481: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 481,
    func: c"SMIME_read_ASN1_ex",
    lib: 13,
    reason: 208,
    dynamic_reason: false,
};

/// `SMIME_read_ASN1_ex` at `crypto/asn1/asn_mime.c:491` (ASN1_R_NO_SIG_CONTENT_TYPE).
pub(crate) const ASN_MIME_491: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 491,
    func: c"SMIME_read_ASN1_ex",
    lib: 13,
    reason: 212,
    dynamic_reason: false,
};

/// `SMIME_read_ASN1_ex` at `crypto/asn1/asn_mime.c:497` (ASN1_R_SIG_INVALID_MIME_TYPE).
pub(crate) const ASN_MIME_497: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 497,
    func: c"SMIME_read_ASN1_ex",
    lib: 13,
    reason: 213,
    dynamic_reason: false,
};

/// `SMIME_read_ASN1_ex` at `crypto/asn1/asn_mime.c:506` (ASN1_R_ASN1_SIG_PARSE_ERROR).
pub(crate) const ASN_MIME_506: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 506,
    func: c"SMIME_read_ASN1_ex",
    lib: 13,
    reason: 204,
    dynamic_reason: false,
};

/// `SMIME_read_ASN1_ex` at `crypto/asn1/asn_mime.c:524` (ASN1_R_INVALID_MIME_TYPE).
pub(crate) const ASN_MIME_524: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 524,
    func: c"SMIME_read_ASN1_ex",
    lib: 13,
    reason: 205,
    dynamic_reason: false,
};

/// `SMIME_read_ASN1_ex` at `crypto/asn1/asn_mime.c:533` (ASN1_R_ASN1_PARSE_ERROR).
pub(crate) const ASN_MIME_533: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 533,
    func: c"SMIME_read_ASN1_ex",
    lib: 13,
    reason: 203,
    dynamic_reason: false,
};

/// `SMIME_crlf_copy` at `crypto/asn1/asn_mime.c:554` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const ASN_MIME_554: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 554,
    func: c"SMIME_crlf_copy",
    lib: 13,
    reason: 786690,
    dynamic_reason: false,
};

/// `SMIME_crlf_copy` at `crypto/asn1/asn_mime.c:564` (ERR_R_BIO_LIB).
pub(crate) const ASN_MIME_564: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 564,
    func: c"SMIME_crlf_copy",
    lib: 13,
    reason: 524320,
    dynamic_reason: false,
};

/// `SMIME_text` at `crypto/asn1/asn_mime.c:620` (ASN1_R_MIME_PARSE_ERROR).
pub(crate) const ASN_MIME_620: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 620,
    func: c"SMIME_text",
    lib: 13,
    reason: 207,
    dynamic_reason: false,
};

/// `SMIME_text` at `crypto/asn1/asn_mime.c:625` (ASN1_R_MIME_NO_CONTENT_TYPE).
pub(crate) const ASN_MIME_625: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 625,
    func: c"SMIME_text",
    lib: 13,
    reason: 206,
    dynamic_reason: false,
};

/// `SMIME_text` at `crypto/asn1/asn_mime.c:630` (ASN1_R_INVALID_MIME_TYPE).
pub(crate) const ASN_MIME_630: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/asn_mime.c",
    line: 630,
    func: c"SMIME_text",
    lib: 13,
    reason: 205,
    dynamic_reason: false,
};

/// `copy_integer` at `crypto/params.c:138` (CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION).
pub(crate) const PARAMS_138: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 138,
    func: c"copy_integer",
    lib: 15,
    reason: 126,
    dynamic_reason: false,
};

/// `copy_integer` at `crypto/params.c:156` (CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION).
pub(crate) const PARAMS_156: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 156,
    func: c"copy_integer",
    lib: 15,
    reason: 126,
    dynamic_reason: false,
};

/// `unsigned_from_signed` at `crypto/params.c:185` (CRYPTO_R_PARAM_UNSIGNED_INTEGER_NEGATIVE_VALUE_UNSUPPORTED).
pub(crate) const PARAMS_185: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 185,
    func: c"unsigned_from_signed",
    lib: 15,
    reason: 125,
    dynamic_reason: false,
};

/// `general_get_int` at `crypto/params.c:202` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_202: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 202,
    func: c"general_get_int",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `general_get_int` at `crypto/params.c:209` (CRYPTO_R_PARAM_NOT_INTEGER_TYPE).
pub(crate) const PARAMS_209: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 209,
    func: c"general_get_int",
    lib: 15,
    reason: 124,
    dynamic_reason: false,
};

/// `general_set_int` at `crypto/params.c:227` (CRYPTO_R_PARAM_NOT_INTEGER_TYPE).
pub(crate) const PARAMS_227: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 227,
    func: c"general_set_int",
    lib: 15,
    reason: 124,
    dynamic_reason: false,
};

/// `general_get_uint` at `crypto/params.c:237` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_237: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 237,
    func: c"general_get_uint",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `general_get_uint` at `crypto/params.c:244` (CRYPTO_R_PARAM_NOT_INTEGER_TYPE).
pub(crate) const PARAMS_244: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 244,
    func: c"general_get_uint",
    lib: 15,
    reason: 124,
    dynamic_reason: false,
};

/// `general_set_uint` at `crypto/params.c:262` (CRYPTO_R_PARAM_NOT_INTEGER_TYPE).
pub(crate) const PARAMS_262: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 262,
    func: c"general_set_uint",
    lib: 15,
    reason: 124,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_int32` at `crypto/params.c:396` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_396: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 396,
    func: c"OSSL_PARAM_get_int32",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_int32` at `crypto/params.c:401` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_401: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 401,
    func: c"OSSL_PARAM_get_int32",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_int32` at `crypto/params.c:419` (CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION).
pub(crate) const PARAMS_419: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 419,
    func: c"OSSL_PARAM_get_int32",
    lib: 15,
    reason: 126,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_int32` at `crypto/params.c:437` (CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION).
pub(crate) const PARAMS_437: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 437,
    func: c"OSSL_PARAM_get_int32",
    lib: 15,
    reason: 126,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_int32` at `crypto/params.c:445` (CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION).
pub(crate) const PARAMS_445: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 445,
    func: c"OSSL_PARAM_get_int32",
    lib: 15,
    reason: 126,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_int32` at `crypto/params.c:462` (CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION).
pub(crate) const PARAMS_462: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 462,
    func: c"OSSL_PARAM_get_int32",
    lib: 15,
    reason: 126,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_int32` at `crypto/params.c:465` (CRYPTO_R_PARAM_UNSUPPORTED_FLOATING_POINT_FORMAT).
pub(crate) const PARAMS_465: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 465,
    func: c"OSSL_PARAM_get_int32",
    lib: 15,
    reason: 130,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_int32` at `crypto/params.c:469` (CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE).
pub(crate) const PARAMS_469: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 469,
    func: c"OSSL_PARAM_get_int32",
    lib: 15,
    reason: 129,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_int32` at `crypto/params.c:476` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_476: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 476,
    func: c"OSSL_PARAM_set_int32",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_int32` at `crypto/params.c:526` (CRYPTO_R_PARAM_CANNOT_BE_REPRESENTED_EXACTLY).
pub(crate) const PARAMS_526: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 526,
    func: c"OSSL_PARAM_set_int32",
    lib: 15,
    reason: 123,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_int32` at `crypto/params.c:533` (CRYPTO_R_PARAM_UNSUPPORTED_FLOATING_POINT_FORMAT).
pub(crate) const PARAMS_533: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 533,
    func: c"OSSL_PARAM_set_int32",
    lib: 15,
    reason: 130,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_int32` at `crypto/params.c:537` (CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE).
pub(crate) const PARAMS_537: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 537,
    func: c"OSSL_PARAM_set_int32",
    lib: 15,
    reason: 129,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_uint32` at `crypto/params.c:550` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_550: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 550,
    func: c"OSSL_PARAM_get_uint32",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_uint32` at `crypto/params.c:555` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_555: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 555,
    func: c"OSSL_PARAM_get_uint32",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_uint32` at `crypto/params.c:573` (CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION).
pub(crate) const PARAMS_573: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 573,
    func: c"OSSL_PARAM_get_uint32",
    lib: 15,
    reason: 126,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_uint32` at `crypto/params.c:590` (CRYPTO_R_PARAM_UNSIGNED_INTEGER_NEGATIVE_VALUE_UNSUPPORTED).
pub(crate) const PARAMS_590: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 590,
    func: c"OSSL_PARAM_get_uint32",
    lib: 15,
    reason: 125,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_uint32` at `crypto/params.c:599` (CRYPTO_R_PARAM_UNSIGNED_INTEGER_NEGATIVE_VALUE_UNSUPPORTED).
pub(crate) const PARAMS_599: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 599,
    func: c"OSSL_PARAM_get_uint32",
    lib: 15,
    reason: 125,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_uint32` at `crypto/params.c:601` (CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION).
pub(crate) const PARAMS_601: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 601,
    func: c"OSSL_PARAM_get_uint32",
    lib: 15,
    reason: 126,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_uint32` at `crypto/params.c:617` (CRYPTO_R_PARAM_CANNOT_BE_REPRESENTED_EXACTLY).
pub(crate) const PARAMS_617: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 617,
    func: c"OSSL_PARAM_get_uint32",
    lib: 15,
    reason: 123,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_uint32` at `crypto/params.c:620` (CRYPTO_R_PARAM_UNSUPPORTED_FLOATING_POINT_FORMAT).
pub(crate) const PARAMS_620: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 620,
    func: c"OSSL_PARAM_get_uint32",
    lib: 15,
    reason: 130,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_uint32` at `crypto/params.c:624` (CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE).
pub(crate) const PARAMS_624: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 624,
    func: c"OSSL_PARAM_get_uint32",
    lib: 15,
    reason: 129,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_uint32` at `crypto/params.c:631` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_631: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 631,
    func: c"OSSL_PARAM_set_uint32",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_uint32` at `crypto/params.c:663` (CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION).
pub(crate) const PARAMS_663: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 663,
    func: c"OSSL_PARAM_set_uint32",
    lib: 15,
    reason: 126,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_uint32` at `crypto/params.c:684` (CRYPTO_R_PARAM_CANNOT_BE_REPRESENTED_EXACTLY).
pub(crate) const PARAMS_684: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 684,
    func: c"OSSL_PARAM_set_uint32",
    lib: 15,
    reason: 123,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_uint32` at `crypto/params.c:691` (CRYPTO_R_PARAM_UNSUPPORTED_FLOATING_POINT_FORMAT).
pub(crate) const PARAMS_691: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 691,
    func: c"OSSL_PARAM_set_uint32",
    lib: 15,
    reason: 130,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_uint32` at `crypto/params.c:695` (CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE).
pub(crate) const PARAMS_695: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 695,
    func: c"OSSL_PARAM_set_uint32",
    lib: 15,
    reason: 129,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_int64` at `crypto/params.c:708` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_708: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 708,
    func: c"OSSL_PARAM_get_int64",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_int64` at `crypto/params.c:713` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_713: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 713,
    func: c"OSSL_PARAM_get_int64",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_int64` at `crypto/params.c:743` (CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION).
pub(crate) const PARAMS_743: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 743,
    func: c"OSSL_PARAM_get_int64",
    lib: 15,
    reason: 126,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_int64` at `crypto/params.c:766` (CRYPTO_R_PARAM_CANNOT_BE_REPRESENTED_EXACTLY).
pub(crate) const PARAMS_766: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 766,
    func: c"OSSL_PARAM_get_int64",
    lib: 15,
    reason: 123,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_int64` at `crypto/params.c:769` (CRYPTO_R_PARAM_UNSUPPORTED_FLOATING_POINT_FORMAT).
pub(crate) const PARAMS_769: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 769,
    func: c"OSSL_PARAM_get_int64",
    lib: 15,
    reason: 130,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_int64` at `crypto/params.c:773` (CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE).
pub(crate) const PARAMS_773: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 773,
    func: c"OSSL_PARAM_get_int64",
    lib: 15,
    reason: 129,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_int64` at `crypto/params.c:780` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_780: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 780,
    func: c"OSSL_PARAM_set_int64",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_int64` at `crypto/params.c:797` (CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION).
pub(crate) const PARAMS_797: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 797,
    func: c"OSSL_PARAM_set_int64",
    lib: 15,
    reason: 126,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_int64` at `crypto/params.c:819` (CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION).
pub(crate) const PARAMS_819: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 819,
    func: c"OSSL_PARAM_set_int64",
    lib: 15,
    reason: 126,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_int64` at `crypto/params.c:844` (CRYPTO_R_PARAM_CANNOT_BE_REPRESENTED_EXACTLY).
pub(crate) const PARAMS_844: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 844,
    func: c"OSSL_PARAM_set_int64",
    lib: 15,
    reason: 123,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_int64` at `crypto/params.c:847` (CRYPTO_R_PARAM_UNSUPPORTED_FLOATING_POINT_FORMAT).
pub(crate) const PARAMS_847: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 847,
    func: c"OSSL_PARAM_set_int64",
    lib: 15,
    reason: 130,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_int64` at `crypto/params.c:851` (CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE).
pub(crate) const PARAMS_851: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 851,
    func: c"OSSL_PARAM_set_int64",
    lib: 15,
    reason: 129,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_uint64` at `crypto/params.c:863` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_863: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 863,
    func: c"OSSL_PARAM_get_uint64",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_uint64` at `crypto/params.c:868` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_868: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 868,
    func: c"OSSL_PARAM_get_uint64",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_uint64` at `crypto/params.c:896` (CRYPTO_R_PARAM_UNSIGNED_INTEGER_NEGATIVE_VALUE_UNSUPPORTED).
pub(crate) const PARAMS_896: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 896,
    func: c"OSSL_PARAM_get_uint64",
    lib: 15,
    reason: 125,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_uint64` at `crypto/params.c:904` (CRYPTO_R_PARAM_UNSIGNED_INTEGER_NEGATIVE_VALUE_UNSUPPORTED).
pub(crate) const PARAMS_904: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 904,
    func: c"OSSL_PARAM_get_uint64",
    lib: 15,
    reason: 125,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_uint64` at `crypto/params.c:927` (CRYPTO_R_PARAM_CANNOT_BE_REPRESENTED_EXACTLY).
pub(crate) const PARAMS_927: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 927,
    func: c"OSSL_PARAM_get_uint64",
    lib: 15,
    reason: 123,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_uint64` at `crypto/params.c:930` (CRYPTO_R_PARAM_UNSUPPORTED_FLOATING_POINT_FORMAT).
pub(crate) const PARAMS_930: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 930,
    func: c"OSSL_PARAM_get_uint64",
    lib: 15,
    reason: 130,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_uint64` at `crypto/params.c:934` (CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE).
pub(crate) const PARAMS_934: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 934,
    func: c"OSSL_PARAM_get_uint64",
    lib: 15,
    reason: 129,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_uint64` at `crypto/params.c:941` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_941: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 941,
    func: c"OSSL_PARAM_set_uint64",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_uint64` at `crypto/params.c:959` (CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION).
pub(crate) const PARAMS_959: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 959,
    func: c"OSSL_PARAM_set_uint64",
    lib: 15,
    reason: 126,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_uint64` at `crypto/params.c:981` (CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION).
pub(crate) const PARAMS_981: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 981,
    func: c"OSSL_PARAM_set_uint64",
    lib: 15,
    reason: 126,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_uint64` at `crypto/params.c:989` (CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION).
pub(crate) const PARAMS_989: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 989,
    func: c"OSSL_PARAM_set_uint64",
    lib: 15,
    reason: 126,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_uint64` at `crypto/params.c:1003` (CRYPTO_R_PARAM_CANNOT_BE_REPRESENTED_EXACTLY).
pub(crate) const PARAMS_1003: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1003,
    func: c"OSSL_PARAM_set_uint64",
    lib: 15,
    reason: 123,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_uint64` at `crypto/params.c:1006` (CRYPTO_R_PARAM_UNSUPPORTED_FLOATING_POINT_FORMAT).
pub(crate) const PARAMS_1006: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1006,
    func: c"OSSL_PARAM_set_uint64",
    lib: 15,
    reason: 130,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_uint64` at `crypto/params.c:1010` (CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE).
pub(crate) const PARAMS_1010: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1010,
    func: c"OSSL_PARAM_set_uint64",
    lib: 15,
    reason: 129,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_BN` at `crypto/params.c:1088` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_1088: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1088,
    func: c"OSSL_PARAM_get_BN",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_BN` at `crypto/params.c:1100` (CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE).
pub(crate) const PARAMS_1100: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1100,
    func: c"OSSL_PARAM_get_BN",
    lib: 15,
    reason: 129,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_BN` at `crypto/params.c:1105` (ERR_R_BN_LIB).
pub(crate) const PARAMS_1105: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1105,
    func: c"OSSL_PARAM_get_BN",
    lib: 15,
    reason: 524291,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_BN` at `crypto/params.c:1118` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_1118: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1118,
    func: c"OSSL_PARAM_set_BN",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_BN` at `crypto/params.c:1123` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_1123: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1123,
    func: c"OSSL_PARAM_set_BN",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_BN` at `crypto/params.c:1127` (CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE).
pub(crate) const PARAMS_1127: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1127,
    func: c"OSSL_PARAM_set_BN",
    lib: 15,
    reason: 129,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_BN` at `crypto/params.c:1148` (CRYPTO_R_INTEGER_OVERFLOW).
pub(crate) const PARAMS_1148: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1148,
    func: c"OSSL_PARAM_set_BN",
    lib: 15,
    reason: 127,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_BN` at `crypto/params.c:1154` (CRYPTO_R_INTEGER_OVERFLOW).
pub(crate) const PARAMS_1154: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1154,
    func: c"OSSL_PARAM_set_BN",
    lib: 15,
    reason: 127,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_BN` at `crypto/params.c:1159` (CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE).
pub(crate) const PARAMS_1159: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1159,
    func: c"OSSL_PARAM_set_BN",
    lib: 15,
    reason: 129,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_BN` at `crypto/params.c:1166` (CRYPTO_R_TOO_SMALL_BUFFER).
pub(crate) const PARAMS_1166: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1166,
    func: c"OSSL_PARAM_set_BN",
    lib: 15,
    reason: 116,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_double` at `crypto/params.c:1184` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_1184: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1184,
    func: c"OSSL_PARAM_get_double",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_double` at `crypto/params.c:1194` (CRYPTO_R_PARAM_UNSUPPORTED_FLOATING_POINT_FORMAT).
pub(crate) const PARAMS_1194: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1194,
    func: c"OSSL_PARAM_get_double",
    lib: 15,
    reason: 130,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_double` at `crypto/params.c:1207` (CRYPTO_R_PARAM_CANNOT_BE_REPRESENTED_EXACTLY).
pub(crate) const PARAMS_1207: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1207,
    func: c"OSSL_PARAM_get_double",
    lib: 15,
    reason: 123,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_double` at `crypto/params.c:1222` (CRYPTO_R_PARAM_CANNOT_BE_REPRESENTED_EXACTLY).
pub(crate) const PARAMS_1222: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1222,
    func: c"OSSL_PARAM_get_double",
    lib: 15,
    reason: 123,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_double` at `crypto/params.c:1226` (CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE).
pub(crate) const PARAMS_1226: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1226,
    func: c"OSSL_PARAM_get_double",
    lib: 15,
    reason: 129,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_double` at `crypto/params.c:1239` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_1239: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1239,
    func: c"OSSL_PARAM_set_double",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_double` at `crypto/params.c:1255` (CRYPTO_R_PARAM_UNSUPPORTED_FLOATING_POINT_FORMAT).
pub(crate) const PARAMS_1255: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1255,
    func: c"OSSL_PARAM_set_double",
    lib: 15,
    reason: 130,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_double` at `crypto/params.c:1267` (CRYPTO_R_PARAM_CANNOT_BE_REPRESENTED_EXACTLY).
pub(crate) const PARAMS_1267: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1267,
    func: c"OSSL_PARAM_set_double",
    lib: 15,
    reason: 123,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_double` at `crypto/params.c:1277` (CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION).
pub(crate) const PARAMS_1277: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1277,
    func: c"OSSL_PARAM_set_double",
    lib: 15,
    reason: 126,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_double` at `crypto/params.c:1285` (CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION).
pub(crate) const PARAMS_1285: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1285,
    func: c"OSSL_PARAM_set_double",
    lib: 15,
    reason: 126,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_double` at `crypto/params.c:1298` (CRYPTO_R_PARAM_CANNOT_BE_REPRESENTED_EXACTLY).
pub(crate) const PARAMS_1298: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1298,
    func: c"OSSL_PARAM_set_double",
    lib: 15,
    reason: 123,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_double` at `crypto/params.c:1308` (CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION).
pub(crate) const PARAMS_1308: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1308,
    func: c"OSSL_PARAM_set_double",
    lib: 15,
    reason: 126,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_double` at `crypto/params.c:1316` (CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION).
pub(crate) const PARAMS_1316: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1316,
    func: c"OSSL_PARAM_set_double",
    lib: 15,
    reason: 126,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_double` at `crypto/params.c:1320` (CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE).
pub(crate) const PARAMS_1320: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1320,
    func: c"OSSL_PARAM_set_double",
    lib: 15,
    reason: 129,
    dynamic_reason: false,
};

/// `get_string_internal` at `crypto/params.c:1337` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_1337: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1337,
    func: c"get_string_internal",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `get_string_internal` at `crypto/params.c:1341` (CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE).
pub(crate) const PARAMS_1341: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1341,
    func: c"get_string_internal",
    lib: 15,
    reason: 129,
    dynamic_reason: false,
};

/// `get_string_internal` at `crypto/params.c:1356` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_1356: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1356,
    func: c"get_string_internal",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `get_string_internal` at `crypto/params.c:1373` (CRYPTO_R_TOO_SMALL_BUFFER).
pub(crate) const PARAMS_1373: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1373,
    func: c"get_string_internal",
    lib: 15,
    reason: 116,
    dynamic_reason: false,
};

/// `OSSL_PARAM_get_utf8_string` at `crypto/params.c:1403` (CRYPTO_R_NO_SPACE_FOR_TERMINATING_NULL).
pub(crate) const PARAMS_1403: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1403,
    func: c"OSSL_PARAM_get_utf8_string",
    lib: 15,
    reason: 128,
    dynamic_reason: false,
};

/// `set_string_internal` at `crypto/params.c:1422` (CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE).
pub(crate) const PARAMS_1422: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1422,
    func: c"set_string_internal",
    lib: 15,
    reason: 129,
    dynamic_reason: false,
};

/// `set_string_internal` at `crypto/params.c:1429` (CRYPTO_R_TOO_SMALL_BUFFER).
pub(crate) const PARAMS_1429: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1429,
    func: c"set_string_internal",
    lib: 15,
    reason: 116,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_utf8_string` at `crypto/params.c:1443` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_1443: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1443,
    func: c"OSSL_PARAM_set_utf8_string",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_octet_string` at `crypto/params.c:1454` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_1454: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1454,
    func: c"OSSL_PARAM_set_octet_string",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `get_ptr_internal` at `crypto/params.c:1488` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_1488: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1488,
    func: c"get_ptr_internal",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `get_ptr_internal` at `crypto/params.c:1492` (CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE).
pub(crate) const PARAMS_1492: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1492,
    func: c"get_ptr_internal",
    lib: 15,
    reason: 129,
    dynamic_reason: false,
};

/// `set_ptr_internal` at `crypto/params.c:1513` (CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE).
pub(crate) const PARAMS_1513: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1513,
    func: c"set_ptr_internal",
    lib: 15,
    reason: 129,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_utf8_ptr` at `crypto/params.c:1525` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_1525: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1525,
    func: c"OSSL_PARAM_set_utf8_ptr",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_octet_ptr` at `crypto/params.c:1537` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_1537: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1537,
    func: c"OSSL_PARAM_set_octet_ptr",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `get_string_ptr_internal` at `crypto/params.c:1676` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_1676: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1676,
    func: c"get_string_ptr_internal",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `get_string_ptr_internal` at `crypto/params.c:1684` (CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE).
pub(crate) const PARAMS_1684: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1684,
    func: c"get_string_ptr_internal",
    lib: 15,
    reason: 129,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_octet_string_or_ptr` at `crypto/params.c:1712` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_1712: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1712,
    func: c"OSSL_PARAM_set_octet_string_or_ptr",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_set_octet_string_or_ptr` at `crypto/params.c:1721` (CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE).
pub(crate) const PARAMS_1721: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params.c",
    line: 1721,
    func: c"OSSL_PARAM_set_octet_string_or_ptr",
    lib: 15,
    reason: 129,
    dynamic_reason: false,
};

/// `OSSL_PARAM_dup` at `crypto/params_dup.c:113` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_DUP_113: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params_dup.c",
    line: 113,
    func: c"OSSL_PARAM_dup",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_merge` at `crypto/params_dup.c:164` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAMS_DUP_164: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params_dup.c",
    line: 164,
    func: c"OSSL_PARAM_merge",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_merge` at `crypto/params_dup.c:182` (CRYPTO_R_NO_PARAMS_TO_MERGE).
pub(crate) const PARAMS_DUP_182: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params_dup.c",
    line: 182,
    func: c"OSSL_PARAM_merge",
    lib: 15,
    reason: 131,
    dynamic_reason: false,
};

/// `prepare_from_text` at `crypto/params_from_text.c:60` (CRYPTO_R_INVALID_NEGATIVE_VALUE).
pub(crate) const PARAMS_FROM_TEXT_60: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params_from_text.c",
    line: 60,
    func: c"prepare_from_text",
    lib: 15,
    reason: 122,
    dynamic_reason: false,
};

/// `prepare_from_text` at `crypto/params_from_text.c:102` (CRYPTO_R_TOO_SMALL_BUFFER).
pub(crate) const PARAMS_FROM_TEXT_102: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params_from_text.c",
    line: 102,
    func: c"prepare_from_text",
    lib: 15,
    reason: 116,
    dynamic_reason: false,
};

/// `prepare_from_text` at `crypto/params_from_text.c:112` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const PARAMS_FROM_TEXT_112: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params_from_text.c",
    line: 112,
    func: c"prepare_from_text",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `prepare_from_text` at `crypto/params_from_text.c:122` (CRYPTO_R_ODD_NUMBER_OF_DIGITS).
pub(crate) const PARAMS_FROM_TEXT_122: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/params_from_text.c",
    line: 122,
    func: c"prepare_from_text",
    lib: 15,
    reason: 103,
    dynamic_reason: false,
};

/// `param_push_num` at `crypto/param_build.c:80` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_80: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 80,
    func: c"param_push_num",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `param_push_num` at `crypto/param_build.c:84` (CRYPTO_R_TOO_MANY_BYTES).
pub(crate) const PARAM_BUILD_84: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 84,
    func: c"param_push_num",
    lib: 15,
    reason: 113,
    dynamic_reason: false,
};

/// `OSSL_PARAM_BLD_push_int` at `crypto/param_build.c:125` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_125: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 125,
    func: c"OSSL_PARAM_BLD_push_int",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_BLD_push_uint` at `crypto/param_build.c:136` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_136: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 136,
    func: c"OSSL_PARAM_BLD_push_uint",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_BLD_push_long` at `crypto/param_build.c:148` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_148: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 148,
    func: c"OSSL_PARAM_BLD_push_long",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_BLD_push_ulong` at `crypto/param_build.c:159` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_159: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 159,
    func: c"OSSL_PARAM_BLD_push_ulong",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_BLD_push_int32` at `crypto/param_build.c:171` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_171: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 171,
    func: c"OSSL_PARAM_BLD_push_int32",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_BLD_push_uint32` at `crypto/param_build.c:182` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_182: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 182,
    func: c"OSSL_PARAM_BLD_push_uint32",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_BLD_push_int64` at `crypto/param_build.c:194` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_194: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 194,
    func: c"OSSL_PARAM_BLD_push_int64",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_BLD_push_uint64` at `crypto/param_build.c:205` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_205: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 205,
    func: c"OSSL_PARAM_BLD_push_uint64",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_BLD_push_size_t` at `crypto/param_build.c:217` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_217: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 217,
    func: c"OSSL_PARAM_BLD_push_size_t",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_BLD_push_time_t` at `crypto/param_build.c:229` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_229: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 229,
    func: c"OSSL_PARAM_BLD_push_time_t",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_BLD_push_double` at `crypto/param_build.c:241` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_241: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 241,
    func: c"OSSL_PARAM_BLD_push_double",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `push_BN` at `crypto/param_build.c:255` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_255: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 255,
    func: c"push_BN",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `push_BN` at `crypto/param_build.c:265` (ERR_R_UNSUPPORTED).
pub(crate) const PARAM_BUILD_265: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 265,
    func: c"push_BN",
    lib: 15,
    reason: 524556,
    dynamic_reason: false,
};

/// `push_BN` at `crypto/param_build.c:272` (CRYPTO_R_ZERO_LENGTH_NUMBER).
pub(crate) const PARAM_BUILD_272: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 272,
    func: c"push_BN",
    lib: 15,
    reason: 115,
    dynamic_reason: false,
};

/// `push_BN` at `crypto/param_build.c:276` (CRYPTO_R_TOO_SMALL_BUFFER).
pub(crate) const PARAM_BUILD_276: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 276,
    func: c"push_BN",
    lib: 15,
    reason: 116,
    dynamic_reason: false,
};

/// `OSSL_PARAM_BLD_push_BN` at `crypto/param_build.c:297` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_297: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 297,
    func: c"OSSL_PARAM_BLD_push_BN",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_BLD_push_BN_pad` at `crypto/param_build.c:312` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_312: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 312,
    func: c"OSSL_PARAM_BLD_push_BN_pad",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_BLD_push_utf8_string` at `crypto/param_build.c:329` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_329: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 329,
    func: c"OSSL_PARAM_BLD_push_utf8_string",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_BLD_push_utf8_ptr` at `crypto/param_build.c:349` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_349: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 349,
    func: c"OSSL_PARAM_BLD_push_utf8_ptr",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_BLD_push_octet_string` at `crypto/param_build.c:369` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_369: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 369,
    func: c"OSSL_PARAM_BLD_push_octet_string",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_BLD_push_octet_ptr` at `crypto/param_build.c:387` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_387: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 387,
    func: c"OSSL_PARAM_BLD_push_octet_ptr",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_BLD_to_param` at `crypto/param_build.c:459` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PARAM_BUILD_459: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 459,
    func: c"OSSL_PARAM_BLD_to_param",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_PARAM_BLD_to_param` at `crypto/param_build.c:471` (CRYPTO_R_SECURE_MALLOC_FAILURE).
pub(crate) const PARAM_BUILD_471: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/param_build.c",
    line: 471,
    func: c"OSSL_PARAM_BLD_to_param",
    lib: 15,
    reason: 111,
    dynamic_reason: false,
};

/// `namemap_add_name` at `crypto/core_namemap.c:288` (ERR_raise dynamic reason).
pub(crate) const CORE_NAMEMAP_288: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/core_namemap.c",
    line: 288,
    func: c"namemap_add_name",
    lib: 15,
    reason: 0,
    dynamic_reason: true,
};

/// `ossl_namemap_add_names` at `crypto/core_namemap.c:321` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const CORE_NAMEMAP_321: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/core_namemap.c",
    line: 321,
    func: c"ossl_namemap_add_names",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `ossl_namemap_add_names` at `crypto/core_namemap.c:349` (CRYPTO_R_BAD_ALGORITHM_NAME).
pub(crate) const CORE_NAMEMAP_349: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/core_namemap.c",
    line: 349,
    func: c"ossl_namemap_add_names",
    lib: 15,
    reason: 117,
    dynamic_reason: false,
};

/// `ossl_namemap_add_names` at `crypto/core_namemap.c:359` (CRYPTO_R_CONFLICTING_NAMES).
pub(crate) const CORE_NAMEMAP_359: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/core_namemap.c",
    line: 359,
    func: c"ossl_namemap_add_names",
    lib: 15,
    reason: 118,
    dynamic_reason: false,
};

/// `ossl_namemap_add_names` at `crypto/core_namemap.c:378` (ERR_R_INTERNAL_ERROR).
pub(crate) const CORE_NAMEMAP_378: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/core_namemap.c",
    line: 378,
    func: c"ossl_namemap_add_names",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `ossl_property_string` at `crypto/property/property_string.c:158` (ERR_R_UNABLE_TO_GET_READ_LOCK).
pub(crate) const PROPERTY_STRING_158: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_string.c",
    line: 158,
    func: c"ossl_property_string",
    lib: 15,
    reason: 786703,
    dynamic_reason: false,
};

/// `ossl_property_string` at `crypto/property/property_string.c:165` (ERR_R_UNABLE_TO_GET_WRITE_LOCK).
pub(crate) const PROPERTY_STRING_165: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_string.c",
    line: 165,
    func: c"ossl_property_string",
    lib: 15,
    reason: 786704,
    dynamic_reason: false,
};

/// `ossl_property_str` at `crypto/property/property_string.c:228` (ERR_R_UNABLE_TO_GET_READ_LOCK).
pub(crate) const PROPERTY_STRING_228: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_string.c",
    line: 228,
    func: c"ossl_property_str",
    lib: 15,
    reason: 786703,
    dynamic_reason: false,
};

/// `parse_name` at `crypto/property/property_parse.c:67` (PROP_R_NOT_AN_IDENTIFIER).
pub(crate) const PROPERTY_PARSE_67: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 67,
    func: c"parse_name",
    lib: 55,
    reason: 103,
    dynamic_reason: false,
};

/// `parse_name` at `crypto/property/property_parse.c:88` (PROP_R_NAME_TOO_LONG).
pub(crate) const PROPERTY_PARSE_88: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 88,
    func: c"parse_name",
    lib: 55,
    reason: 100,
    dynamic_reason: false,
};

/// `parse_number` at `crypto/property/property_parse.c:103` (PROP_R_NOT_A_DECIMAL_DIGIT).
pub(crate) const PROPERTY_PARSE_103: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 103,
    func: c"parse_number",
    lib: 55,
    reason: 105,
    dynamic_reason: false,
};

/// `parse_number` at `crypto/property/property_parse.c:109` (PROP_R_PARSE_FAILED).
pub(crate) const PROPERTY_PARSE_109: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 109,
    func: c"parse_number",
    lib: 55,
    reason: 108,
    dynamic_reason: false,
};

/// `parse_number` at `crypto/property/property_parse.c:116` (PROP_R_NOT_A_DECIMAL_DIGIT).
pub(crate) const PROPERTY_PARSE_116: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 116,
    func: c"parse_number",
    lib: 55,
    reason: 105,
    dynamic_reason: false,
};

/// `parse_hex` at `crypto/property/property_parse.c:138` (PROP_R_NOT_AN_HEXADECIMAL_DIGIT).
pub(crate) const PROPERTY_PARSE_138: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 138,
    func: c"parse_hex",
    lib: 55,
    reason: 102,
    dynamic_reason: false,
};

/// `parse_hex` at `crypto/property/property_parse.c:144` (PROP_R_PARSE_FAILED).
pub(crate) const PROPERTY_PARSE_144: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 144,
    func: c"parse_hex",
    lib: 55,
    reason: 108,
    dynamic_reason: false,
};

/// `parse_hex` at `crypto/property/property_parse.c:153` (PROP_R_NOT_AN_HEXADECIMAL_DIGIT).
pub(crate) const PROPERTY_PARSE_153: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 153,
    func: c"parse_hex",
    lib: 55,
    reason: 102,
    dynamic_reason: false,
};

/// `parse_oct` at `crypto/property/property_parse.c:170` (PROP_R_NOT_AN_OCTAL_DIGIT).
pub(crate) const PROPERTY_PARSE_170: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 170,
    func: c"parse_oct",
    lib: 55,
    reason: 104,
    dynamic_reason: false,
};

/// `parse_oct` at `crypto/property/property_parse.c:175` (PROP_R_PARSE_FAILED).
pub(crate) const PROPERTY_PARSE_175: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 175,
    func: c"parse_oct",
    lib: 55,
    reason: 108,
    dynamic_reason: false,
};

/// `parse_oct` at `crypto/property/property_parse.c:183` (PROP_R_NOT_AN_OCTAL_DIGIT).
pub(crate) const PROPERTY_PARSE_183: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 183,
    func: c"parse_oct",
    lib: 55,
    reason: 104,
    dynamic_reason: false,
};

/// `parse_string` at `crypto/property/property_parse.c:209` (PROP_R_NO_MATCHING_STRING_DELIMITER).
pub(crate) const PROPERTY_PARSE_209: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 209,
    func: c"parse_string",
    lib: 55,
    reason: 106,
    dynamic_reason: false,
};

/// `parse_string` at `crypto/property/property_parse.c:215` (PROP_R_STRING_TOO_LONG).
pub(crate) const PROPERTY_PARSE_215: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 215,
    func: c"parse_string",
    lib: 55,
    reason: 109,
    dynamic_reason: false,
};

/// `parse_unquoted` at `crypto/property/property_parse.c:242` (PROP_R_NOT_AN_ASCII_CHARACTER).
pub(crate) const PROPERTY_PARSE_242: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 242,
    func: c"parse_unquoted",
    lib: 55,
    reason: 101,
    dynamic_reason: false,
};

/// `parse_unquoted` at `crypto/property/property_parse.c:248` (PROP_R_STRING_TOO_LONG).
pub(crate) const PROPERTY_PARSE_248: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 248,
    func: c"parse_unquoted",
    lib: 55,
    reason: 109,
    dynamic_reason: false,
};

/// `stack_to_property_list` at `crypto/property/property_parse.c:333` (PROP_R_PARSE_FAILED).
pub(crate) const PROPERTY_PARSE_333: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 333,
    func: c"stack_to_property_list",
    lib: 55,
    reason: 108,
    dynamic_reason: false,
};

/// `ossl_parse_property` at `crypto/property/property_parse.c:370` (PROP_R_PARSE_FAILED).
pub(crate) const PROPERTY_PARSE_370: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 370,
    func: c"ossl_parse_property",
    lib: 55,
    reason: 108,
    dynamic_reason: false,
};

/// `ossl_parse_property` at `crypto/property/property_parse.c:376` (PROP_R_NO_VALUE).
pub(crate) const PROPERTY_PARSE_376: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 376,
    func: c"ossl_parse_property",
    lib: 55,
    reason: 107,
    dynamic_reason: false,
};

/// `ossl_parse_property` at `crypto/property/property_parse.c:392` (PROP_R_TRAILING_CHARACTERS).
pub(crate) const PROPERTY_PARSE_392: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 392,
    func: c"ossl_parse_property",
    lib: 55,
    reason: 110,
    dynamic_reason: false,
};

/// `ossl_parse_query` at `crypto/property/property_parse.c:455` (PROP_R_TRAILING_CHARACTERS).
pub(crate) const PROPERTY_PARSE_455: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/property/property_parse.c",
    line: 455,
    func: c"ossl_parse_query",
    lib: 55,
    reason: 110,
    dynamic_reason: false,
};

/// `DSO_new_method` at `crypto/dso/dso_lib.c:23` (ERR_R_CRYPTO_LIB).
pub(crate) const DSO_LIB_23: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 23,
    func: c"DSO_new_method",
    lib: 37,
    reason: 524303,
    dynamic_reason: false,
};

/// `DSO_free` at `crypto/dso/dso_lib.c:64` (DSO_R_UNLOAD_FAILED).
pub(crate) const DSO_LIB_64: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 64,
    func: c"DSO_free",
    lib: 37,
    reason: 107,
    dynamic_reason: false,
};

/// `DSO_free` at `crypto/dso/dso_lib.c:70` (DSO_R_FINISH_FAILED).
pub(crate) const DSO_LIB_70: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 70,
    func: c"DSO_free",
    lib: 37,
    reason: 102,
    dynamic_reason: false,
};

/// `DSO_up_ref` at `crypto/dso/dso_lib.c:92` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const DSO_LIB_92: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 92,
    func: c"DSO_up_ref",
    lib: 37,
    reason: 786690,
    dynamic_reason: false,
};

/// `DSO_load` at `crypto/dso/dso_lib.c:112` (ERR_R_DSO_LIB).
pub(crate) const DSO_LIB_112: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 112,
    func: c"DSO_load",
    lib: 37,
    reason: 524325,
    dynamic_reason: false,
};

/// `DSO_load` at `crypto/dso/dso_lib.c:118` (DSO_R_CTRL_FAILED).
pub(crate) const DSO_LIB_118: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 118,
    func: c"DSO_load",
    lib: 37,
    reason: 100,
    dynamic_reason: false,
};

/// `DSO_load` at `crypto/dso/dso_lib.c:125` (DSO_R_DSO_ALREADY_LOADED).
pub(crate) const DSO_LIB_125: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 125,
    func: c"DSO_load",
    lib: 37,
    reason: 110,
    dynamic_reason: false,
};

/// `DSO_load` at `crypto/dso/dso_lib.c:134` (DSO_R_SET_FILENAME_FAILED).
pub(crate) const DSO_LIB_134: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 134,
    func: c"DSO_load",
    lib: 37,
    reason: 112,
    dynamic_reason: false,
};

/// `DSO_load` at `crypto/dso/dso_lib.c:139` (DSO_R_NO_FILENAME).
pub(crate) const DSO_LIB_139: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 139,
    func: c"DSO_load",
    lib: 37,
    reason: 111,
    dynamic_reason: false,
};

/// `DSO_load` at `crypto/dso/dso_lib.c:143` (DSO_R_UNSUPPORTED).
pub(crate) const DSO_LIB_143: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 143,
    func: c"DSO_load",
    lib: 37,
    reason: 108,
    dynamic_reason: false,
};

/// `DSO_load` at `crypto/dso/dso_lib.c:147` (DSO_R_LOAD_FAILED).
pub(crate) const DSO_LIB_147: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 147,
    func: c"DSO_load",
    lib: 37,
    reason: 103,
    dynamic_reason: false,
};

/// `DSO_bind_func` at `crypto/dso/dso_lib.c:163` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const DSO_LIB_163: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 163,
    func: c"DSO_bind_func",
    lib: 37,
    reason: 786690,
    dynamic_reason: false,
};

/// `DSO_bind_func` at `crypto/dso/dso_lib.c:167` (DSO_R_UNSUPPORTED).
pub(crate) const DSO_LIB_167: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 167,
    func: c"DSO_bind_func",
    lib: 37,
    reason: 108,
    dynamic_reason: false,
};

/// `DSO_bind_func` at `crypto/dso/dso_lib.c:171` (DSO_R_SYM_FAILURE).
pub(crate) const DSO_LIB_171: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 171,
    func: c"DSO_bind_func",
    lib: 37,
    reason: 106,
    dynamic_reason: false,
};

/// `DSO_ctrl` at `crypto/dso/dso_lib.c:190` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const DSO_LIB_190: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 190,
    func: c"DSO_ctrl",
    lib: 37,
    reason: 786690,
    dynamic_reason: false,
};

/// `DSO_ctrl` at `crypto/dso/dso_lib.c:210` (DSO_R_UNSUPPORTED).
pub(crate) const DSO_LIB_210: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 210,
    func: c"DSO_ctrl",
    lib: 37,
    reason: 108,
    dynamic_reason: false,
};

/// `DSO_get_filename` at `crypto/dso/dso_lib.c:219` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const DSO_LIB_219: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 219,
    func: c"DSO_get_filename",
    lib: 37,
    reason: 786690,
    dynamic_reason: false,
};

/// `DSO_set_filename` at `crypto/dso/dso_lib.c:230` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const DSO_LIB_230: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 230,
    func: c"DSO_set_filename",
    lib: 37,
    reason: 786690,
    dynamic_reason: false,
};

/// `DSO_set_filename` at `crypto/dso/dso_lib.c:234` (DSO_R_DSO_ALREADY_LOADED).
pub(crate) const DSO_LIB_234: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 234,
    func: c"DSO_set_filename",
    lib: 37,
    reason: 110,
    dynamic_reason: false,
};

/// `DSO_merge` at `crypto/dso/dso_lib.c:251` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const DSO_LIB_251: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 251,
    func: c"DSO_merge",
    lib: 37,
    reason: 786690,
    dynamic_reason: false,
};

/// `DSO_convert_filename` at `crypto/dso/dso_lib.c:268` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const DSO_LIB_268: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 268,
    func: c"DSO_convert_filename",
    lib: 37,
    reason: 786690,
    dynamic_reason: false,
};

/// `DSO_convert_filename` at `crypto/dso/dso_lib.c:274` (DSO_R_NO_FILENAME).
pub(crate) const DSO_LIB_274: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 274,
    func: c"DSO_convert_filename",
    lib: 37,
    reason: 111,
    dynamic_reason: false,
};

/// `DSO_pathbyaddr` at `crypto/dso/dso_lib.c:296` (DSO_R_UNSUPPORTED).
pub(crate) const DSO_LIB_296: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 296,
    func: c"DSO_pathbyaddr",
    lib: 37,
    reason: 108,
    dynamic_reason: false,
};

/// `DSO_global_lookup` at `crypto/dso/dso_lib.c:325` (DSO_R_UNSUPPORTED).
pub(crate) const DSO_LIB_325: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_lib.c",
    line: 325,
    func: c"DSO_global_lookup",
    lib: 37,
    reason: 108,
    dynamic_reason: false,
};

/// `dlfcn_load` at `crypto/dso/dso_dlfcn.c:102` (DSO_R_NO_FILENAME).
pub(crate) const DSO_DLFCN_102: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_dlfcn.c",
    line: 102,
    func: c"dlfcn_load",
    lib: 37,
    reason: 111,
    dynamic_reason: false,
};

/// `dlfcn_load` at `crypto/dso/dso_dlfcn.c:115` (DSO_R_LOAD_FAILED).
pub(crate) const DSO_DLFCN_115: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_dlfcn.c",
    line: 115,
    func: c"dlfcn_load",
    lib: 37,
    reason: 103,
    dynamic_reason: false,
};

/// `dlfcn_load` at `crypto/dso/dso_dlfcn.c:125` (DSO_R_STACK_ERROR).
pub(crate) const DSO_DLFCN_125: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_dlfcn.c",
    line: 125,
    func: c"dlfcn_load",
    lib: 37,
    reason: 105,
    dynamic_reason: false,
};

/// `dlfcn_unload` at `crypto/dso/dso_dlfcn.c:143` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const DSO_DLFCN_143: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_dlfcn.c",
    line: 143,
    func: c"dlfcn_unload",
    lib: 37,
    reason: 786690,
    dynamic_reason: false,
};

/// `dlfcn_unload` at `crypto/dso/dso_dlfcn.c:150` (DSO_R_NULL_HANDLE).
pub(crate) const DSO_DLFCN_150: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_dlfcn.c",
    line: 150,
    func: c"dlfcn_unload",
    lib: 37,
    reason: 104,
    dynamic_reason: false,
};

/// `dlfcn_bind_func` at `crypto/dso/dso_dlfcn.c:171` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const DSO_DLFCN_171: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_dlfcn.c",
    line: 171,
    func: c"dlfcn_bind_func",
    lib: 37,
    reason: 786690,
    dynamic_reason: false,
};

/// `dlfcn_bind_func` at `crypto/dso/dso_dlfcn.c:175` (DSO_R_STACK_ERROR).
pub(crate) const DSO_DLFCN_175: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_dlfcn.c",
    line: 175,
    func: c"dlfcn_bind_func",
    lib: 37,
    reason: 105,
    dynamic_reason: false,
};

/// `dlfcn_bind_func` at `crypto/dso/dso_dlfcn.c:180` (DSO_R_NULL_HANDLE).
pub(crate) const DSO_DLFCN_180: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_dlfcn.c",
    line: 180,
    func: c"dlfcn_bind_func",
    lib: 37,
    reason: 104,
    dynamic_reason: false,
};

/// `dlfcn_bind_func` at `crypto/dso/dso_dlfcn.c:185` (DSO_R_SYM_FAILURE).
pub(crate) const DSO_DLFCN_185: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_dlfcn.c",
    line: 185,
    func: c"dlfcn_bind_func",
    lib: 37,
    reason: 106,
    dynamic_reason: false,
};

/// `dlfcn_merger` at `crypto/dso/dso_dlfcn.c:198` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const DSO_DLFCN_198: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_dlfcn.c",
    line: 198,
    func: c"dlfcn_merger",
    lib: 37,
    reason: 786690,
    dynamic_reason: false,
};

/// `dlfcn_name_converter` at `crypto/dso/dso_dlfcn.c:260` (DSO_R_NAME_TRANSLATION_FAILED).
pub(crate) const DSO_DLFCN_260: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/dso/dso_dlfcn.c",
    line: 260,
    func: c"dlfcn_name_converter",
    lib: 37,
    reason: 109,
    dynamic_reason: false,
};

/// `OSSL_PROVIDER_add_builtin` at `crypto/provider.c:132` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PROVIDER_132: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider.c",
    line: 132,
    func: c"OSSL_PROVIDER_add_builtin",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `get_provider_store` at `crypto/provider_core.c:335` (ERR_R_INTERNAL_ERROR).
pub(crate) const PROVIDER_CORE_335: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider_core.c",
    line: 335,
    func: c"get_provider_store",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `ossl_provider_info_add_to_store` at `crypto/provider_core.c:362` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PROVIDER_CORE_362: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider_core.c",
    line: 362,
    func: c"ossl_provider_info_add_to_store",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `ossl_provider_info_add_to_store` at `crypto/provider_core.c:367` (ERR_R_INTERNAL_ERROR).
pub(crate) const PROVIDER_CORE_367: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider_core.c",
    line: 367,
    func: c"ossl_provider_info_add_to_store",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `provider_new` at `crypto/provider_core.c:455` (ERR_R_CRYPTO_LIB).
pub(crate) const PROVIDER_CORE_455: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider_core.c",
    line: 455,
    func: c"provider_new",
    lib: 15,
    reason: 524303,
    dynamic_reason: false,
};

/// `provider_new` at `crypto/provider_core.c:466` (ERR_R_CRYPTO_LIB).
pub(crate) const PROVIDER_CORE_466: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider_core.c",
    line: 466,
    func: c"provider_new",
    lib: 15,
    reason: 524303,
    dynamic_reason: false,
};

/// `ossl_provider_add_to_store` at `crypto/provider_core.c:694` (ERR_R_CRYPTO_LIB).
pub(crate) const PROVIDER_CORE_694: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider_core.c",
    line: 694,
    func: c"ossl_provider_add_to_store",
    lib: 15,
    reason: 524303,
    dynamic_reason: false,
};

/// `infopair_add` at `crypto/provider_core.c:816` (ERR_R_CRYPTO_LIB).
pub(crate) const PROVIDER_CORE_816: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider_core.c",
    line: 816,
    func: c"infopair_add",
    lib: 15,
    reason: 524303,
    dynamic_reason: false,
};

/// `provider_init` at `crypto/provider_core.c:959` (ERR_R_INTERNAL_ERROR).
pub(crate) const PROVIDER_CORE_959: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider_core.c",
    line: 959,
    func: c"provider_init",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `provider_init` at `crypto/provider_core.c:1026` (ERR_R_DSO_LIB).
pub(crate) const PROVIDER_CORE_1026: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider_core.c",
    line: 1026,
    func: c"provider_init",
    lib: 15,
    reason: 524325,
    dynamic_reason: false,
};

/// `provider_init` at `crypto/provider_core.c:1038` (ERR_R_UNSUPPORTED).
pub(crate) const PROVIDER_CORE_1038: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider_core.c",
    line: 1038,
    func: c"provider_init",
    lib: 15,
    reason: 524556,
    dynamic_reason: false,
};

/// `provider_init` at `crypto/provider_core.c:1054` (ERR_R_INIT_FAIL).
pub(crate) const PROVIDER_CORE_1054: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider_core.c",
    line: 1054,
    func: c"provider_init",
    lib: 15,
    reason: 786693,
    dynamic_reason: false,
};

/// `ossl_provider_test_operation_bit` at `crypto/provider_core.c:2059` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PROVIDER_CORE_2059: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider_core.c",
    line: 2059,
    func: c"ossl_provider_test_operation_bit",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `provider_conf_params_internal` at `crypto/provider_conf.c:100` (CONF_R_RECURSIVE_SECTION_REFERENCE).
pub(crate) const PROVIDER_CONF_100: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider_conf.c",
    line: 100,
    func: c"provider_conf_params_internal",
    lib: 14,
    reason: 126,
    dynamic_reason: false,
};

/// `provider_conf_activate` at `crypto/provider_conf.c:211` (ERR_R_INTERNAL_ERROR).
pub(crate) const PROVIDER_CONF_211: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider_conf.c",
    line: 211,
    func: c"provider_conf_activate",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `provider_conf_activate` at `crypto/provider_conf.c:224` (ERR_R_INTERNAL_ERROR).
pub(crate) const PROVIDER_CONF_224: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider_conf.c",
    line: 224,
    func: c"provider_conf_activate",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `provider_conf_parse_bool_setting` at `crypto/provider_conf.c:280` (CRYPTO_R_PROVIDER_SECTION_ERROR).
pub(crate) const PROVIDER_CONF_280: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider_conf.c",
    line: 280,
    func: c"provider_conf_parse_bool_setting",
    lib: 15,
    reason: 105,
    dynamic_reason: false,
};

/// `provider_conf_parse_bool_setting` at `crypto/provider_conf.c:302` (CRYPTO_R_PROVIDER_SECTION_ERROR).
pub(crate) const PROVIDER_CONF_302: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider_conf.c",
    line: 302,
    func: c"provider_conf_parse_bool_setting",
    lib: 15,
    reason: 105,
    dynamic_reason: false,
};

/// `provider_conf_load` at `crypto/provider_conf.c:328` (CRYPTO_R_PROVIDER_SECTION_ERROR).
pub(crate) const PROVIDER_CONF_328: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider_conf.c",
    line: 328,
    func: c"provider_conf_load",
    lib: 15,
    reason: 105,
    dynamic_reason: false,
};

/// `provider_conf_init` at `crypto/provider_conf.c:412` (CRYPTO_R_PROVIDER_SECTION_ERROR).
pub(crate) const PROVIDER_CONF_412: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/provider_conf.c",
    line: 412,
    func: c"provider_conf_init",
    lib: 15,
    reason: 105,
    dynamic_reason: false,
};

/// Every recorded raise site, in authority source order.
///
/// This is the complete inventory for the covered files, including the
/// allocation-failure arms that no runtime path in this crate can reach
/// (`sk_reserve`'s growth overflow and the two `ex_data.c` stack-growth
/// arms). It is kept so that coverage accounting, cross-checks and the
/// court's negative controls can enumerate the authority's sites rather
/// than a subset, which is also why it carries an `allow`: it is a
/// reference table, not a call site.
#[allow(dead_code)]
pub(crate) static ALL: &[ErrSite] = &[
    STACK_186,
    STACK_212,
    STACK_251,
    STACK_271,
    STACK_275,
    STACK_482,
    STACK_486,
    EX_DATA_37,
    EX_DATA_175,
    EX_DATA_191,
    EX_DATA_474,
    EX_DATA_481,
    EX_DATA_487,
    INIT_504,
    BIO_LIB_99,
    BIO_LIB_267,
    BIO_LIB_271,
    BIO_LIB_279,
    BIO_LIB_294,
    BIO_LIB_340,
    BIO_LIB_348,
    BIO_LIB_399,
    BIO_LIB_405,
    BIO_LIB_424,
    BIO_LIB_446,
    BIO_LIB_452,
    BIO_LIB_471,
    BIO_LIB_500,
    BIO_LIB_504,
    BIO_LIB_515,
    BIO_LIB_533,
    BIO_LIB_549,
    BIO_LIB_553,
    BIO_LIB_558,
    BIO_LIB_569,
    BIO_LIB_601,
    BIO_LIB_605,
    BIO_LIB_611,
    BIO_LIB_615,
    BIO_LIB_663,
    BIO_LIB_690,
    BIO_LIB_813,
    BIO_LIB_1002,
    BIO_LIB_1022,
    BIO_LIB_1064,
    BIO_LIB_1071,
    BIO_METH_27,
    BIO_ADDR_251,
    BIO_ADDR_256,
    BIO_ADDR_590,
    BIO_ADDR_593,
    BIO_ADDR_698,
    BIO_ADDR_707,
    BIO_ADDR_744,
    BIO_ADDR_746,
    BIO_ADDR_751,
    BIO_ADDR_767,
    BIO_ADDR_813,
    BIO_ADDR_833,
    BIO_ADDR_855,
    BIO_ADDR_858,
    BIO_ADDR_862,
    BIO_ADDR_909,
    BIO_ADDR_914,
    BIO_ADDR_956,
    BIO_PRINT_369,
    BIO_SOCK_57,
    BIO_SOCK_80,
    BIO_SOCK_89,
    BIO_SOCK_152,
    BIO_SOCK_154,
    BIO_SOCK_248,
    BIO_SOCK_301,
    BIO_SOCK_303,
    BIO_SOCK_314,
    BIO_SOCK_368,
    BIO_SOCK_387,
    BIO_SOCK_393,
    BIO_SOCK_410,
    BIO_SOCK_412,
    BIO_SOCK_416,
    BIO_SOCK_421,
    BIO_SOCK2_51,
    BIO_SOCK2_53,
    BIO_SOCK2_86,
    BIO_SOCK2_97,
    BIO_SOCK2_99,
    BIO_SOCK2_108,
    BIO_SOCK2_110,
    BIO_SOCK2_122,
    BIO_SOCK2_127,
    BIO_SOCK2_136,
    BIO_SOCK2_141,
    BIO_SOCK2_157,
    BIO_SOCK2_159,
    BIO_SOCK2_168,
    BIO_SOCK2_170,
    BIO_SOCK2_183,
    BIO_SOCK2_185,
    BIO_SOCK2_215,
    BIO_SOCK2_228,
    BIO_SOCK2_230,
    BIO_SOCK2_237,
    BIO_SOCK2_239,
    BIO_SOCK2_291,
    BIO_SOCK2_299,
    BIO_SOCK2_301,
    BIO_SOCK2_312,
    BIO_SOCK2_314,
    BIO_SOCK2_323,
    BIO_SOCK2_325,
    BIO_SOCK2_341,
    BIO_SOCK2_343,
    BIO_SOCK2_353,
    BIO_SOCK2_355,
    BIO_SOCK2_373,
    BIO_SOCK2_378,
    BIO_SOCK2_387,
    BIO_SOCK2_392,
    BIO_SOCK2_400,
    BIO_SOCK2_402,
    BIO_SOCK2_430,
    BIO_SOCK2_432,
    BSS_ACPT_157,
    BSS_ACPT_192,
    BSS_ACPT_203,
    BSS_ACPT_212,
    BSS_ACPT_233,
    BSS_ACPT_236,
    BSS_BIO_286,
    BSS_BIO_361,
    BSS_BIO_426,
    BSS_BIO_429,
    BSS_BIO_617,
    BSS_BIO_750,
    BSS_BIO_766,
    BSS_BIO_781,
    BSS_BIO_797,
    BSS_CONN_123,
    BSS_CONN_144,
    BSS_CONN_155,
    BSS_CONN_166,
    BSS_CONN_178,
    BSS_CONN_181,
    BSS_CONN_215,
    BSS_CONN_245,
    BSS_CONN_248,
    BSS_CONN_259,
    BSS_CONN_754,
    BSS_CONN_758,
    BSS_CONN_764,
    BSS_CONN_775,
    BSS_CONN_810,
    BSS_CONN_825,
    BSS_CONN_841,
    BSS_CONN_856,
    BSS_DGRAM_328,
    BSS_DGRAM_337,
    BSS_DGRAM_359,
    BSS_DGRAM_366,
    BSS_DGRAM_408,
    BSS_DGRAM_414,
    BSS_DGRAM_650,
    BSS_DGRAM_659,
    BSS_DGRAM_799,
    BSS_DGRAM_806,
    BSS_DGRAM_820,
    BSS_DGRAM_833,
    BSS_DGRAM_836,
    BSS_DGRAM_855,
    BSS_DGRAM_862,
    BSS_DGRAM_876,
    BSS_DGRAM_889,
    BSS_DGRAM_892,
    BSS_DGRAM_932,
    BSS_DGRAM_939,
    BSS_DGRAM_947,
    BSS_DGRAM_961,
    BSS_DGRAM_969,
    BSS_DGRAM_1231,
    BSS_DGRAM_1269,
    BSS_DGRAM_1301,
    BSS_DGRAM_1307,
    BSS_DGRAM_1402,
    BSS_DGRAM_1410,
    BSS_DGRAM_1420,
    BSS_DGRAM_1441,
    BSS_DGRAM_1447,
    BSS_DGRAM_1455,
    BSS_DGRAM_1473,
    BSS_DGRAM_1479,
    BSS_DGRAM_1487,
    BSS_DGRAM_1507,
    BSS_DGRAM_1522,
    BSS_DGRAM_1533,
    BSS_DGRAM_1604,
    BSS_DGRAM_1613,
    BSS_DGRAM_1653,
    BSS_DGRAM_1660,
    BSS_DGRAM_1704,
    BSS_DGRAM_1711,
    BSS_DGRAM_1751,
    BSS_DGRAM_1767,
    BSS_DGRAM_1778,
    BSS_DGRAM_1818,
    BSS_DGRAM_1827,
    BSS_DGRAM_1865,
    BSS_DGRAM_2181,
    BSS_DGRAM_PAIR_309,
    BSS_DGRAM_PAIR_345,
    BSS_DGRAM_PAIR_351,
    BSS_DGRAM_PAIR_360,
    BSS_DGRAM_PAIR_369,
    BSS_DGRAM_PAIR_376,
    BSS_DGRAM_PAIR_382,
    BSS_DGRAM_PAIR_388,
    BSS_DGRAM_PAIR_465,
    BSS_DGRAM_PAIR_1018,
    BSS_DGRAM_PAIR_1023,
    BSS_DGRAM_PAIR_1035,
    BSS_DGRAM_PAIR_1042,
    BSS_DGRAM_PAIR_1070,
    BSS_DGRAM_PAIR_1081,
    BSS_DGRAM_PAIR_1095,
    BSS_DGRAM_PAIR_1120,
    BSS_DGRAM_PAIR_1125,
    BSS_DGRAM_PAIR_1132,
    BSS_DGRAM_PAIR_1283,
    BSS_DGRAM_PAIR_1288,
    BSS_DGRAM_PAIR_1294,
    BSS_DGRAM_PAIR_1321,
    BSS_DGRAM_PAIR_1335,
    BSS_FILE_67,
    BSS_FILE_75,
    BSS_FILE_77,
    BSS_FILE_149,
    BSS_FILE_151,
    BSS_FILE_284,
    BSS_FILE_299,
    BSS_FILE_302,
    BSS_FILE_335,
    BSS_FILE_337,
    BSS_MEM_90,
    BSS_MEM_221,
    BSS_MEM_228,
    CONF_DEF_179,
    CONF_DEF_181,
    CONF_DEF_201,
    CONF_DEF_233,
    CONF_DEF_242,
    CONF_DEF_248,
    CONF_DEF_256,
    CONF_DEF_366,
    CONF_DEF_375,
    CONF_DEF_405,
    CONF_DEF_488,
    CONF_DEF_509,
    CONF_DEF_515,
    CONF_DEF_524,
    CONF_DEF_547,
    CONF_DEF_554,
    CONF_DEF_737,
    CONF_DEF_757,
    CONF_DEF_762,
    CONF_DEF_766,
    CONF_DEF_806,
    CONF_DEF_813,
    CONF_LIB_58,
    CONF_LIB_75,
    CONF_LIB_157,
    CONF_LIB_191,
    CONF_LIB_254,
    CONF_LIB_267,
    CONF_LIB_279,
    CONF_LIB_289,
    CONF_LIB_294,
    CONF_LIB_313,
    CONF_LIB_316,
    CONF_LIB_340,
    CONF_LIB_359,
    CONF_LIB_387,
    CONF_LIB_399,
    CONF_MOD_104,
    CONF_MOD_163,
    CONF_MOD_276,
    CONF_MOD_286,
    CONF_MOD_331,
    CONF_MOD_475,
    CONF_MOD_482,
    CONF_MOD_734,
    CONF_SSL_75,
    CONF_SSL_94,
    OBJ_DAT_270,
    OBJ_DAT_278,
    OBJ_DAT_329,
    OBJ_DAT_362,
    OBJ_DAT_573,
    OBJ_DAT_598,
    OBJ_DAT_706,
    OBJ_DAT_713,
    OBJ_DAT_726,
    OBJ_DAT_734,
    OBJ_DAT_806,
    OBJ_DAT_844,
    A_OBJECT_66,
    A_OBJECT_78,
    A_OBJECT_83,
    A_OBJECT_92,
    A_OBJECT_105,
    A_OBJECT_124,
    A_OBJECT_163,
    A_OBJECT_198,
    A_OBJECT_241,
    A_OBJECT_259,
    A_OBJECT_289,
    A_OBJECT_334,
    BUFFER_88,
    BUFFER_125,
    O_STR_229,
    O_STR_235,
    O_STR_241,
    O_STR_270,
    O_STR_303,
    O_STR_315,
    O_STR_352,
    BN_ADD_142,
    BN_BLIND_41,
    BN_BLIND_96,
    BN_BLIND_138,
    BN_BLIND_172,
    BN_BLIND_283,
    BN_CONV_151,
    BN_CTX_193,
    BN_CTX_231,
    BN_DIV_27,
    BN_DIV_217,
    BN_DIV_227,
    BN_EXP_57,
    BN_EXP_183,
    BN_EXP_327,
    BN_EXP_622,
    BN_EXP_1187,
    BN_EXP_1195,
    BN_EXP_1319,
    BN_EXP_1324,
    BN_EXP2_35,
    BN_GCD_525,
    BN_GCD_532,
    BN_GF2M_389,
    BN_GF2M_472,
    BN_GF2M_532,
    BN_GF2M_915,
    BN_GF2M_977,
    BN_GF2M_1065,
    BN_GF2M_1075,
    BN_GF2M_1111,
    BN_INTERN_41,
    BN_INTERN_53,
    BN_INTERN_97,
    BN_INTERN_109,
    BN_INTERN_120,
    BN_INTERN_126,
    BN_INTERN_187,
    BN_LIB_269,
    BN_LIB_273,
    BN_MOD_22,
    BN_MOD_194,
    BN_MOD_307,
    BN_MPI_49,
    BN_MPI_54,
    BN_PRIME_135,
    BN_PRIME_143,
    BN_RAND_98,
    BN_RAND_140,
    BN_RAND_145,
    BN_RAND_180,
    BN_RAND_193,
    BN_RAND_248,
    BN_RAND_253,
    BN_RAND_271,
    BN_RAND_332,
    BN_RAND_338,
    BN_RAND_385,
    BN_RECP_147,
    BN_RSA_FIPS186_4_391,
    BN_SHIFT_86,
    BN_SHIFT_155,
    BN_SQRT_43,
    BN_SQRT_203,
    BN_SQRT_214,
    BN_SQRT_229,
    BN_SQRT_321,
    BN_SQRT_352,
    A_BITSTR_139,
    A_D2I_FP_28,
    A_D2I_FP_92,
    A_D2I_FP_125,
    A_D2I_FP_138,
    A_D2I_FP_156,
    A_D2I_FP_161,
    A_D2I_FP_177,
    A_D2I_FP_188,
    A_D2I_FP_214,
    A_D2I_FP_244,
    A_D2I_FP_264,
    A_D2I_FP_278,
    A_D2I_FP_285,
    A_D2I_FP_300,
    A_D2I_FP_312,
    A_DUP_79,
    A_DUP_93,
    A_I2D_FP_24,
    A_I2D_FP_75,
    A_I2D_FP_92,
    A_I2D_FP_116,
    A_INT_160,
    A_INT_193,
    A_INT_213,
    A_INT_228,
    A_INT_284,
    A_INT_291,
    A_INT_320,
    A_INT_344,
    A_INT_348,
    A_INT_381,
    A_INT_385,
    A_INT_389,
    A_INT_468,
    A_INT_488,
    A_INT_501,
    A_INT_524,
    A_INT_530,
    A_INT_641,
    A_MBSTR_58,
    A_MBSTR_66,
    A_MBSTR_69,
    A_MBSTR_78,
    A_MBSTR_86,
    A_MBSTR_97,
    A_MBSTR_107,
    A_MBSTR_112,
    A_MBSTR_118,
    A_MBSTR_125,
    A_MBSTR_163,
    A_MBSTR_175,
    A_MBSTR_190,
    A_MBSTR_203,
    A_MBSTR_305,
    A_MBSTR_310,
    A_STRNID_133,
    A_STRNID_199,
    A_STRNID_205,
    A_STREX_150,
    A_STREX_156,
    A_TIME_336,
    ASN1_GEN_95,
    ASN1_GEN_275,
    ASN1_GEN_285,
    ASN1_GEN_296,
    ASN1_GEN_333,
    ASN1_GEN_345,
    ASN1_GEN_365,
    ASN1_GEN_394,
    ASN1_GEN_475,
    ASN1_GEN_480,
    ASN1_GEN_592,
    ASN1_GEN_603,
    ASN1_GEN_610,
    ASN1_GEN_617,
    ASN1_GEN_625,
    ASN1_GEN_631,
    ASN1_GEN_638,
    ASN1_GEN_642,
    ASN1_GEN_650,
    ASN1_GEN_654,
    ASN1_GEN_658,
    ASN1_GEN_663,
    ASN1_GEN_683,
    ASN1_GEN_690,
    ASN1_GEN_699,
    ASN1_GEN_705,
    ASN1_GEN_713,
    ASN1_GEN_719,
    ASN1_GEN_725,
    ASN1_GEN_735,
    ASN1_GEN_760,
    ASN1_GEN_764,
    ASN1_LIB_56,
    ASN1_LIB_95,
    ASN1_LIB_105,
    ASN1_LIB_305,
    ASN_MOID_32,
    ASN_MOID_38,
    ASN_MSTBL_29,
    ASN_MSTBL_35,
    ASN_MSTBL_102,
    ASN_MSTBL_107,
    ASN_MSTBL_113,
    ASN_PACK_22,
    ASN_PACK_32,
    ASN_PACK_36,
    ASN_PACK_59,
    ASN_PACK_73,
    BIO_ASN1_118,
    BIO_NDEF_67,
    EVP_ASN1_40,
    EVP_ASN1_141,
    EVP_ASN1_203,
    F_INT_100,
    F_INT_118,
    F_INT_135,
    F_STRING_92,
    F_STRING_110,
    F_STRING_129,
    TASN_DEC_140,
    TASN_DEC_208,
    TASN_DEC_212,
    TASN_DEC_222,
    TASN_DEC_236,
    TASN_DEC_252,
    TASN_DEC_261,
    TASN_DEC_270,
    TASN_DEC_279,
    TASN_DEC_298,
    TASN_DEC_314,
    TASN_DEC_338,
    TASN_DEC_350,
    TASN_DEC_375,
    TASN_DEC_387,
    TASN_DEC_393,
    TASN_DEC_427,
    TASN_DEC_466,
    TASN_DEC_471,
    TASN_DEC_491,
    TASN_DEC_507,
    TASN_DEC_551,
    TASN_DEC_556,
    TASN_DEC_563,
    TASN_DEC_571,
    TASN_DEC_579,
    TASN_DEC_639,
    TASN_DEC_658,
    TASN_DEC_669,
    TASN_DEC_681,
    TASN_DEC_688,
    TASN_DEC_694,
    TASN_DEC_703,
    TASN_DEC_712,
    TASN_DEC_739,
    TASN_DEC_753,
    TASN_DEC_757,
    TASN_DEC_764,
    TASN_DEC_779,
    TASN_DEC_796,
    TASN_DEC_814,
    TASN_DEC_832,
    TASN_DEC_873,
    TASN_DEC_900,
    TASN_DEC_908,
    TASN_DEC_950,
    TASN_DEC_954,
    TASN_DEC_958,
    TASN_DEC_962,
    TASN_DEC_966,
    TASN_DEC_973,
    TASN_DEC_987,
    TASN_DEC_1045,
    TASN_DEC_1050,
    TASN_DEC_1060,
    TASN_DEC_1107,
    TASN_DEC_1116,
    TASN_DEC_1123,
    TASN_DEC_1133,
    TASN_DEC_1147,
    TASN_DEC_1151,
    TASN_DEC_1196,
    TASN_DEC_1219,
    TASN_DEC_1226,
    TASN_DEC_1236,
    TASN_ENC_112,
    TASN_ENC_123,
    TASN_ENC_309,
    TASN_ENC_350,
    TASN_ENC_371,
    TASN_NEW_162,
    TASN_NEW_168,
    TASN_NEW_231,
    TASN_UTL_91,
    TASN_UTL_263,
    TASN_UTL_288,
    X_INT64_95,
    X_INT64_100,
    X_INT64_196,
    X_INT64_201,
    X_INT64_208,
    X_LONG_154,
    X_LONG_165,
    X_LONG_175,
    X_LONG_181,
    V3_UTL_60,
    V3_UTL_174,
    V3_UTL_176,
    V3_UTL_189,
    V3_UTL_191,
    V3_UTL_204,
    V3_UTL_209,
    V3_UTL_233,
    V3_UTL_243,
    V3_UTL_291,
    V3_UTL_340,
    V3_UTL_349,
    V3_UTL_364,
    V3_UTL_379,
    V3_UTL_388,
    ASN_MIME_79,
    ASN_MIME_112,
    ASN_MIME_143,
    ASN_MIME_149,
    ASN_MIME_394,
    ASN_MIME_448,
    ASN_MIME_455,
    ASN_MIME_466,
    ASN_MIME_472,
    ASN_MIME_481,
    ASN_MIME_491,
    ASN_MIME_497,
    ASN_MIME_506,
    ASN_MIME_524,
    ASN_MIME_533,
    ASN_MIME_554,
    ASN_MIME_564,
    ASN_MIME_620,
    ASN_MIME_625,
    ASN_MIME_630,
    PARAMS_138,
    PARAMS_156,
    PARAMS_185,
    PARAMS_202,
    PARAMS_209,
    PARAMS_227,
    PARAMS_237,
    PARAMS_244,
    PARAMS_262,
    PARAMS_396,
    PARAMS_401,
    PARAMS_419,
    PARAMS_437,
    PARAMS_445,
    PARAMS_462,
    PARAMS_465,
    PARAMS_469,
    PARAMS_476,
    PARAMS_526,
    PARAMS_533,
    PARAMS_537,
    PARAMS_550,
    PARAMS_555,
    PARAMS_573,
    PARAMS_590,
    PARAMS_599,
    PARAMS_601,
    PARAMS_617,
    PARAMS_620,
    PARAMS_624,
    PARAMS_631,
    PARAMS_663,
    PARAMS_684,
    PARAMS_691,
    PARAMS_695,
    PARAMS_708,
    PARAMS_713,
    PARAMS_743,
    PARAMS_766,
    PARAMS_769,
    PARAMS_773,
    PARAMS_780,
    PARAMS_797,
    PARAMS_819,
    PARAMS_844,
    PARAMS_847,
    PARAMS_851,
    PARAMS_863,
    PARAMS_868,
    PARAMS_896,
    PARAMS_904,
    PARAMS_927,
    PARAMS_930,
    PARAMS_934,
    PARAMS_941,
    PARAMS_959,
    PARAMS_981,
    PARAMS_989,
    PARAMS_1003,
    PARAMS_1006,
    PARAMS_1010,
    PARAMS_1088,
    PARAMS_1100,
    PARAMS_1105,
    PARAMS_1118,
    PARAMS_1123,
    PARAMS_1127,
    PARAMS_1148,
    PARAMS_1154,
    PARAMS_1159,
    PARAMS_1166,
    PARAMS_1184,
    PARAMS_1194,
    PARAMS_1207,
    PARAMS_1222,
    PARAMS_1226,
    PARAMS_1239,
    PARAMS_1255,
    PARAMS_1267,
    PARAMS_1277,
    PARAMS_1285,
    PARAMS_1298,
    PARAMS_1308,
    PARAMS_1316,
    PARAMS_1320,
    PARAMS_1337,
    PARAMS_1341,
    PARAMS_1356,
    PARAMS_1373,
    PARAMS_1403,
    PARAMS_1422,
    PARAMS_1429,
    PARAMS_1443,
    PARAMS_1454,
    PARAMS_1488,
    PARAMS_1492,
    PARAMS_1513,
    PARAMS_1525,
    PARAMS_1537,
    PARAMS_1676,
    PARAMS_1684,
    PARAMS_1712,
    PARAMS_1721,
    PARAMS_DUP_113,
    PARAMS_DUP_164,
    PARAMS_DUP_182,
    PARAMS_FROM_TEXT_60,
    PARAMS_FROM_TEXT_102,
    PARAMS_FROM_TEXT_112,
    PARAMS_FROM_TEXT_122,
    PARAM_BUILD_80,
    PARAM_BUILD_84,
    PARAM_BUILD_125,
    PARAM_BUILD_136,
    PARAM_BUILD_148,
    PARAM_BUILD_159,
    PARAM_BUILD_171,
    PARAM_BUILD_182,
    PARAM_BUILD_194,
    PARAM_BUILD_205,
    PARAM_BUILD_217,
    PARAM_BUILD_229,
    PARAM_BUILD_241,
    PARAM_BUILD_255,
    PARAM_BUILD_265,
    PARAM_BUILD_272,
    PARAM_BUILD_276,
    PARAM_BUILD_297,
    PARAM_BUILD_312,
    PARAM_BUILD_329,
    PARAM_BUILD_349,
    PARAM_BUILD_369,
    PARAM_BUILD_387,
    PARAM_BUILD_459,
    PARAM_BUILD_471,
    CORE_NAMEMAP_288,
    CORE_NAMEMAP_321,
    CORE_NAMEMAP_349,
    CORE_NAMEMAP_359,
    CORE_NAMEMAP_378,
    PROPERTY_STRING_158,
    PROPERTY_STRING_165,
    PROPERTY_STRING_228,
    PROPERTY_PARSE_67,
    PROPERTY_PARSE_88,
    PROPERTY_PARSE_103,
    PROPERTY_PARSE_109,
    PROPERTY_PARSE_116,
    PROPERTY_PARSE_138,
    PROPERTY_PARSE_144,
    PROPERTY_PARSE_153,
    PROPERTY_PARSE_170,
    PROPERTY_PARSE_175,
    PROPERTY_PARSE_183,
    PROPERTY_PARSE_209,
    PROPERTY_PARSE_215,
    PROPERTY_PARSE_242,
    PROPERTY_PARSE_248,
    PROPERTY_PARSE_333,
    PROPERTY_PARSE_370,
    PROPERTY_PARSE_376,
    PROPERTY_PARSE_392,
    PROPERTY_PARSE_455,
    DSO_LIB_23,
    DSO_LIB_64,
    DSO_LIB_70,
    DSO_LIB_92,
    DSO_LIB_112,
    DSO_LIB_118,
    DSO_LIB_125,
    DSO_LIB_134,
    DSO_LIB_139,
    DSO_LIB_143,
    DSO_LIB_147,
    DSO_LIB_163,
    DSO_LIB_167,
    DSO_LIB_171,
    DSO_LIB_190,
    DSO_LIB_210,
    DSO_LIB_219,
    DSO_LIB_230,
    DSO_LIB_234,
    DSO_LIB_251,
    DSO_LIB_268,
    DSO_LIB_274,
    DSO_LIB_296,
    DSO_LIB_325,
    DSO_DLFCN_102,
    DSO_DLFCN_115,
    DSO_DLFCN_125,
    DSO_DLFCN_143,
    DSO_DLFCN_150,
    DSO_DLFCN_171,
    DSO_DLFCN_175,
    DSO_DLFCN_180,
    DSO_DLFCN_185,
    DSO_DLFCN_198,
    DSO_DLFCN_260,
    PROVIDER_132,
    PROVIDER_CORE_335,
    PROVIDER_CORE_362,
    PROVIDER_CORE_367,
    PROVIDER_CORE_455,
    PROVIDER_CORE_466,
    PROVIDER_CORE_694,
    PROVIDER_CORE_816,
    PROVIDER_CORE_959,
    PROVIDER_CORE_1026,
    PROVIDER_CORE_1038,
    PROVIDER_CORE_1054,
    PROVIDER_CORE_2059,
    PROVIDER_CONF_100,
    PROVIDER_CONF_211,
    PROVIDER_CONF_224,
    PROVIDER_CONF_280,
    PROVIDER_CONF_302,
    PROVIDER_CONF_328,
    PROVIDER_CONF_412,
];
