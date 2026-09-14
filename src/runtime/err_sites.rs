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
];
