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
    /// `ERR_GET_LIB` of the raised code, which is the value of the site's
    /// library argument after `ERR_LIB_MASK`. The two differ only at the
    /// seven sites whose argument is a reason constant; see `LIB_CONST_RE`.
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

/// `ossl_method_construct_precondition` at `crypto/core_fetch.c:65` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const CORE_FETCH_65: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/core_fetch.c",
    line: 65,
    func: c"ossl_method_construct_precondition",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `ossl_method_construct_postcondition` at `crypto/core_fetch.c:92` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const CORE_FETCH_92: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/core_fetch.c",
    line: 92,
    func: c"ossl_method_construct_postcondition",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `evp_pkey_asym_cipher_init` at `crypto/evp/asymcipher.c:43` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const ASYMCIPHER_43: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 43,
    func: c"evp_pkey_asym_cipher_init",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `evp_pkey_asym_cipher_init` at `crypto/evp/asymcipher.c:57` (EVP_R_NO_KEY_SET).
pub(crate) const ASYMCIPHER_57: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 57,
    func: c"evp_pkey_asym_cipher_init",
    lib: 6,
    reason: 154,
    dynamic_reason: false,
};

/// `evp_pkey_asym_cipher_init` at `crypto/evp/asymcipher.c:67` (ERR_R_INTERNAL_ERROR).
pub(crate) const ASYMCIPHER_67: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 67,
    func: c"evp_pkey_asym_cipher_init",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `evp_pkey_asym_cipher_init` at `crypto/evp/asymcipher.c:75` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const ASYMCIPHER_75: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 75,
    func: c"evp_pkey_asym_cipher_init",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_pkey_asym_cipher_init` at `crypto/evp/asymcipher.c:160` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const ASYMCIPHER_160: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 160,
    func: c"evp_pkey_asym_cipher_init",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_pkey_asym_cipher_init` at `crypto/evp/asymcipher.c:168` (EVP_R_PROVIDER_ASYM_CIPHER_NOT_SUPPORTED).
pub(crate) const ASYMCIPHER_168: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 168,
    func: c"evp_pkey_asym_cipher_init",
    lib: 6,
    reason: 235,
    dynamic_reason: false,
};

/// `evp_pkey_asym_cipher_init` at `crypto/evp/asymcipher.c:177` (EVP_R_PROVIDER_ASYM_CIPHER_NOT_SUPPORTED).
pub(crate) const ASYMCIPHER_177: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 177,
    func: c"evp_pkey_asym_cipher_init",
    lib: 6,
    reason: 235,
    dynamic_reason: false,
};

/// `evp_pkey_asym_cipher_init` at `crypto/evp/asymcipher.c:185` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const ASYMCIPHER_185: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 185,
    func: c"evp_pkey_asym_cipher_init",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_pkey_asym_cipher_init` at `crypto/evp/asymcipher.c:204` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const ASYMCIPHER_204: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 204,
    func: c"evp_pkey_asym_cipher_init",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `evp_pkey_asym_cipher_init` at `crypto/evp/asymcipher.c:219` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const ASYMCIPHER_219: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 219,
    func: c"evp_pkey_asym_cipher_init",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `EVP_PKEY_encrypt` at `crypto/evp/asymcipher.c:251` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const ASYMCIPHER_251: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 251,
    func: c"EVP_PKEY_encrypt",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_encrypt` at `crypto/evp/asymcipher.c:256` (EVP_R_OPERATION_NOT_INITIALIZED).
pub(crate) const ASYMCIPHER_256: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 256,
    func: c"EVP_PKEY_encrypt",
    lib: 6,
    reason: 151,
    dynamic_reason: false,
};

/// `EVP_PKEY_encrypt` at `crypto/evp/asymcipher.c:268` (EVP_R_PROVIDER_ASYM_CIPHER_FAILURE).
pub(crate) const ASYMCIPHER_268: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 268,
    func: c"EVP_PKEY_encrypt",
    lib: 6,
    reason: 232,
    dynamic_reason: false,
};

/// `EVP_PKEY_encrypt` at `crypto/evp/asymcipher.c:275` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const ASYMCIPHER_275: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 275,
    func: c"EVP_PKEY_encrypt",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_decrypt` at `crypto/evp/asymcipher.c:300` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const ASYMCIPHER_300: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 300,
    func: c"EVP_PKEY_decrypt",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_decrypt` at `crypto/evp/asymcipher.c:305` (EVP_R_OPERATION_NOT_INITIALIZED).
pub(crate) const ASYMCIPHER_305: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 305,
    func: c"EVP_PKEY_decrypt",
    lib: 6,
    reason: 151,
    dynamic_reason: false,
};

/// `EVP_PKEY_decrypt` at `crypto/evp/asymcipher.c:317` (EVP_R_PROVIDER_ASYM_CIPHER_FAILURE).
pub(crate) const ASYMCIPHER_317: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 317,
    func: c"EVP_PKEY_decrypt",
    lib: 6,
    reason: 232,
    dynamic_reason: false,
};

/// `EVP_PKEY_decrypt` at `crypto/evp/asymcipher.c:325` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const ASYMCIPHER_325: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 325,
    func: c"EVP_PKEY_decrypt",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `evp_pkey_decrypt_alloc` at `crypto/evp/asymcipher.c:342` (ERR_R_EVP_LIB).
pub(crate) const ASYMCIPHER_342: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 342,
    func: c"evp_pkey_decrypt_alloc",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `evp_asym_cipher_from_algorithm` at `crypto/evp/asymcipher.c:378` (ERR_R_EVP_LIB).
pub(crate) const ASYMCIPHER_378: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 378,
    func: c"evp_asym_cipher_from_algorithm",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `evp_asym_cipher_from_algorithm` at `crypto/evp/asymcipher.c:475` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const ASYMCIPHER_475: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/asymcipher.c",
    line: 475,
    func: c"evp_asym_cipher_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `b64_read` at `crypto/evp/bio_b64.c:142` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_B64_142: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/bio_b64.c",
    line: 142,
    func: c"b64_read",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `b64_read` at `crypto/evp/bio_b64.c:149` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_B64_149: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/bio_b64.c",
    line: 149,
    func: c"b64_read",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `b64_write` at `crypto/evp/bio_b64.c:346` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_B64_346: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/bio_b64.c",
    line: 346,
    func: c"b64_write",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `b64_write` at `crypto/evp/bio_b64.c:350` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_B64_350: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/bio_b64.c",
    line: 350,
    func: c"b64_write",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `b64_write` at `crypto/evp/bio_b64.c:354` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_B64_354: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/bio_b64.c",
    line: 354,
    func: c"b64_write",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `b64_write` at `crypto/evp/bio_b64.c:366` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_B64_366: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/bio_b64.c",
    line: 366,
    func: c"b64_write",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `b64_write` at `crypto/evp/bio_b64.c:370` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_B64_370: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/bio_b64.c",
    line: 370,
    func: c"b64_write",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `b64_write` at `crypto/evp/bio_b64.c:388` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_B64_388: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/bio_b64.c",
    line: 388,
    func: c"b64_write",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `b64_write` at `crypto/evp/bio_b64.c:404` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_B64_404: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/bio_b64.c",
    line: 404,
    func: c"b64_write",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `b64_write` at `crypto/evp/bio_b64.c:408` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_B64_408: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/bio_b64.c",
    line: 408,
    func: c"b64_write",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `b64_write` at `crypto/evp/bio_b64.c:426` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_B64_426: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/bio_b64.c",
    line: 426,
    func: c"b64_write",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `b64_write` at `crypto/evp/bio_b64.c:430` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_B64_430: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/bio_b64.c",
    line: 430,
    func: c"b64_write",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `b64_write` at `crypto/evp/bio_b64.c:440` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_B64_440: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/bio_b64.c",
    line: 440,
    func: c"b64_write",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `b64_write` at `crypto/evp/bio_b64.c:444` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_B64_444: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/bio_b64.c",
    line: 444,
    func: c"b64_write",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `b64_write` at `crypto/evp/bio_b64.c:463` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_B64_463: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/bio_b64.c",
    line: 463,
    func: c"b64_write",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `b64_write` at `crypto/evp/bio_b64.c:467` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_B64_467: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/bio_b64.c",
    line: 467,
    func: c"b64_write",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `b64_ctrl` at `crypto/evp/bio_b64.c:504` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_B64_504: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/bio_b64.c",
    line: 504,
    func: c"b64_ctrl",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `b64_ctrl` at `crypto/evp/bio_b64.c:516` (ERR_R_INTERNAL_ERROR).
pub(crate) const BIO_B64_516: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/bio_b64.c",
    line: 516,
    func: c"b64_ctrl",
    lib: 32,
    reason: 786691,
    dynamic_reason: false,
};

/// `default_check` at `crypto/evp/ctrl_params_translate.c:306` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const CTRL_PARAMS_TRANSLATE_306: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 306,
    func: c"default_check",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `default_check` at `crypto/evp/ctrl_params_translate.c:311` (ERR_R_INTERNAL_ERROR).
pub(crate) const CTRL_PARAMS_TRANSLATE_311: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 311,
    func: c"default_check",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `default_check` at `crypto/evp/ctrl_params_translate.c:324` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const CTRL_PARAMS_TRANSLATE_324: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 324,
    func: c"default_check",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `default_check` at `crypto/evp/ctrl_params_translate.c:329` (ERR_R_INTERNAL_ERROR).
pub(crate) const CTRL_PARAMS_TRANSLATE_329: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 329,
    func: c"default_check",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `default_check` at `crypto/evp/ctrl_params_translate.c:337` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const CTRL_PARAMS_TRANSLATE_337: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 337,
    func: c"default_check",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `default_check` at `crypto/evp/ctrl_params_translate.c:342` (ERR_R_INTERNAL_ERROR).
pub(crate) const CTRL_PARAMS_TRANSLATE_342: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 342,
    func: c"default_check",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `default_fixup_args` at `crypto/evp/ctrl_params_translate.c:407` (ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
pub(crate) const CTRL_PARAMS_TRANSLATE_407: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 407,
    func: c"default_fixup_args",
    lib: 6,
    reason: 786689,
    dynamic_reason: false,
};

/// `default_fixup_args` at `crypto/evp/ctrl_params_translate.c:424` (ERR_R_UNSUPPORTED).
pub(crate) const CTRL_PARAMS_TRANSLATE_424: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 424,
    func: c"default_fixup_args",
    lib: 6,
    reason: 524556,
    dynamic_reason: false,
};

/// `default_fixup_args` at `crypto/evp/ctrl_params_translate.c:446` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const CTRL_PARAMS_TRANSLATE_446: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 446,
    func: c"default_fixup_args",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `default_fixup_args` at `crypto/evp/ctrl_params_translate.c:492` (ERR_R_UNSUPPORTED).
pub(crate) const CTRL_PARAMS_TRANSLATE_492: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 492,
    func: c"default_fixup_args",
    lib: 6,
    reason: 524556,
    dynamic_reason: false,
};

/// `default_fixup_args` at `crypto/evp/ctrl_params_translate.c:555` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const CTRL_PARAMS_TRANSLATE_555: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 555,
    func: c"default_fixup_args",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `default_fixup_args` at `crypto/evp/ctrl_params_translate.c:573` (ERR_R_INTERNAL_ERROR).
pub(crate) const CTRL_PARAMS_TRANSLATE_573: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 573,
    func: c"default_fixup_args",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `default_fixup_args` at `crypto/evp/ctrl_params_translate.c:586` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const CTRL_PARAMS_TRANSLATE_586: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 586,
    func: c"default_fixup_args",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `default_fixup_args` at `crypto/evp/ctrl_params_translate.c:649` (ERR_R_UNSUPPORTED).
pub(crate) const CTRL_PARAMS_TRANSLATE_649: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 649,
    func: c"default_fixup_args",
    lib: 6,
    reason: 524556,
    dynamic_reason: false,
};

/// `default_fixup_args` at `crypto/evp/ctrl_params_translate.c:667` (ERR_R_INTERNAL_ERROR).
pub(crate) const CTRL_PARAMS_TRANSLATE_667: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 667,
    func: c"default_fixup_args",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `default_fixup_args` at `crypto/evp/ctrl_params_translate.c:695` (ERR_R_UNSUPPORTED).
pub(crate) const CTRL_PARAMS_TRANSLATE_695: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 695,
    func: c"default_fixup_args",
    lib: 6,
    reason: 524556,
    dynamic_reason: false,
};

/// `fix_dh_nid` at `crypto/evp/ctrl_params_translate.c:1013` (EVP_R_INVALID_VALUE).
pub(crate) const CTRL_PARAMS_TRANSLATE_1013: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 1013,
    func: c"fix_dh_nid",
    lib: 6,
    reason: 222,
    dynamic_reason: false,
};

/// `fix_dh_nid5114` at `crypto/evp/ctrl_params_translate.c:1039` (EVP_R_INVALID_VALUE).
pub(crate) const CTRL_PARAMS_TRANSLATE_1039: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 1039,
    func: c"fix_dh_nid5114",
    lib: 6,
    reason: 222,
    dynamic_reason: false,
};

/// `fix_dh_nid5114` at `crypto/evp/ctrl_params_translate.c:1050` (EVP_R_INVALID_VALUE).
pub(crate) const CTRL_PARAMS_TRANSLATE_1050: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 1050,
    func: c"fix_dh_nid5114",
    lib: 6,
    reason: 222,
    dynamic_reason: false,
};

/// `fix_dh_paramgen_type` at `crypto/evp/ctrl_params_translate.c:1081` (EVP_R_INVALID_VALUE).
pub(crate) const CTRL_PARAMS_TRANSLATE_1081: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 1081,
    func: c"fix_dh_paramgen_type",
    lib: 6,
    reason: 222,
    dynamic_reason: false,
};

/// `fix_ec_param_enc` at `crypto/evp/ctrl_params_translate.c:1134` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const CTRL_PARAMS_TRANSLATE_1134: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 1134,
    func: c"fix_ec_param_enc",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `fix_rsa_padding_mode` at `crypto/evp/ctrl_params_translate.c:1327` (RSA_R_UNKNOWN_PADDING_TYPE).
pub(crate) const CTRL_PARAMS_TRANSLATE_1327: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 1327,
    func: c"fix_rsa_padding_mode",
    lib: 4,
    reason: 118,
    dynamic_reason: false,
};

/// `fix_rsa_padding_mode` at `crypto/evp/ctrl_params_translate.c:1337` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const CTRL_PARAMS_TRANSLATE_1337: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 1337,
    func: c"fix_rsa_padding_mode",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `fix_rsa_padding_mode` at `crypto/evp/ctrl_params_translate.c:1357` (RSA_R_UNKNOWN_PADDING_TYPE).
pub(crate) const CTRL_PARAMS_TRANSLATE_1357: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 1357,
    func: c"fix_rsa_padding_mode",
    lib: 4,
    reason: 118,
    dynamic_reason: false,
};

/// `get_payload_group_name` at `crypto/evp/ctrl_params_translate.c:1547` (EVP_R_UNSUPPORTED_KEY_TYPE).
pub(crate) const CTRL_PARAMS_TRANSLATE_1547: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 1547,
    func: c"get_payload_group_name",
    lib: 6,
    reason: 224,
    dynamic_reason: false,
};

/// `get_payload_private_key` at `crypto/evp/ctrl_params_translate.c:1588` (EVP_R_UNSUPPORTED_KEY_TYPE).
pub(crate) const CTRL_PARAMS_TRANSLATE_1588: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 1588,
    func: c"get_payload_private_key",
    lib: 6,
    reason: 224,
    dynamic_reason: false,
};

/// `get_payload_public_key` at `crypto/evp/ctrl_params_translate.c:1649` (EVP_R_UNSUPPORTED_KEY_TYPE).
pub(crate) const CTRL_PARAMS_TRANSLATE_1649: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 1649,
    func: c"get_payload_public_key",
    lib: 6,
    reason: 224,
    dynamic_reason: false,
};

/// `get_payload_public_key_ec` at `crypto/evp/ctrl_params_translate.c:1675` (EVP_R_UNSUPPORTED_KEY_TYPE).
pub(crate) const CTRL_PARAMS_TRANSLATE_1675: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 1675,
    func: c"get_payload_public_key_ec",
    lib: 6,
    reason: 224,
    dynamic_reason: false,
};

/// `get_payload_public_key_ec` at `crypto/evp/ctrl_params_translate.c:1711` (EVP_R_UNSUPPORTED_KEY_TYPE).
pub(crate) const CTRL_PARAMS_TRANSLATE_1711: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 1711,
    func: c"get_payload_public_key_ec",
    lib: 6,
    reason: 224,
    dynamic_reason: false,
};

/// `get_dh_dsa_payload_p` at `crypto/evp/ctrl_params_translate.c:1748` (EVP_R_UNSUPPORTED_KEY_TYPE).
pub(crate) const CTRL_PARAMS_TRANSLATE_1748: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 1748,
    func: c"get_dh_dsa_payload_p",
    lib: 6,
    reason: 224,
    dynamic_reason: false,
};

/// `get_ec_decoded_from_explicit_params` at `crypto/evp/ctrl_params_translate.c:1823` (EVP_R_INVALID_KEY).
pub(crate) const CTRL_PARAMS_TRANSLATE_1823: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 1823,
    func: c"get_ec_decoded_from_explicit_params",
    lib: 6,
    reason: 163,
    dynamic_reason: false,
};

/// `get_ec_decoded_from_explicit_params` at `crypto/evp/ctrl_params_translate.c:1829` (EVP_R_UNSUPPORTED_KEY_TYPE).
pub(crate) const CTRL_PARAMS_TRANSLATE_1829: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 1829,
    func: c"get_ec_decoded_from_explicit_params",
    lib: 6,
    reason: 224,
    dynamic_reason: false,
};

/// `fix_group_ecx` at `crypto/evp/ctrl_params_translate.c:2041` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const CTRL_PARAMS_TRANSLATE_2041: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 2041,
    func: c"fix_group_ecx",
    lib: 6,
    reason: 524550,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_ctrl_to_param` at `crypto/evp/ctrl_params_translate.c:2717` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const CTRL_PARAMS_TRANSLATE_2717: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ctrl_params_translate.c",
    line: 2717,
    func: c"evp_pkey_ctx_ctrl_to_param",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `dh_paramgen_check` at `crypto/evp/dh_ctrl.c:22` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const DH_CTRL_22: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/dh_ctrl.c",
    line: 22,
    func: c"dh_paramgen_check",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `dh_param_derive_check` at `crypto/evp/dh_ctrl.c:37` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const DH_CTRL_37: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/dh_ctrl.c",
    line: 37,
    func: c"dh_param_derive_check",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_set_dh_pad` at `crypto/evp/dh_ctrl.c:166` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const DH_CTRL_166: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/dh_ctrl.c",
    line: 166,
    func: c"EVP_PKEY_CTX_set_dh_pad",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_set_dh_kdf_outlen` at `crypto/evp/dh_ctrl.c:261` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const DH_CTRL_261: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/dh_ctrl.c",
    line: 261,
    func: c"EVP_PKEY_CTX_set_dh_kdf_outlen",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_get_dh_kdf_outlen` at `crypto/evp/dh_ctrl.c:281` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const DH_CTRL_281: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/dh_ctrl.c",
    line: 281,
    func: c"EVP_PKEY_CTX_get_dh_kdf_outlen",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_set0_dh_kdf_ukm` at `crypto/evp/dh_ctrl.c:313` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const DH_CTRL_313: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/dh_ctrl.c",
    line: 313,
    func: c"EVP_PKEY_CTX_set0_dh_kdf_ukm",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_get0_dh_kdf_ukm` at `crypto/evp/dh_ctrl.c:336` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const DH_CTRL_336: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/dh_ctrl.c",
    line: 336,
    func: c"EVP_PKEY_CTX_get0_dh_kdf_ukm",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `evp_md_ctx_new_ex` at `crypto/evp/digest.c:112` (ERR_R_EVP_LIB).
pub(crate) const DIGEST_112: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 112,
    func: c"evp_md_ctx_new_ex",
    lib: 13,
    reason: 524294,
    dynamic_reason: false,
};

/// `evp_md_ctx_free_algctx` at `crypto/evp/digest.c:147` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const DIGEST_147: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 147,
    func: c"evp_md_ctx_free_algctx",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_md_init_internal` at `crypto/evp/digest.c:178` (EVP_R_UPDATE_ERROR).
pub(crate) const DIGEST_178: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 178,
    func: c"evp_md_init_internal",
    lib: 6,
    reason: 189,
    dynamic_reason: false,
};

/// `evp_md_init_internal` at `crypto/evp/digest.c:189` (EVP_R_NO_DIGEST_SET).
pub(crate) const DIGEST_189: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 189,
    func: c"evp_md_init_internal",
    lib: 6,
    reason: 139,
    dynamic_reason: false,
};

/// `evp_md_init_internal` at `crypto/evp/digest.c:250` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const DIGEST_250: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 250,
    func: c"evp_md_init_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_md_init_internal` at `crypto/evp/digest.c:261` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const DIGEST_261: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 261,
    func: c"evp_md_init_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_md_init_internal` at `crypto/evp/digest.c:271` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const DIGEST_271: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 271,
    func: c"evp_md_init_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_md_init_internal` at `crypto/evp/digest.c:282` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const DIGEST_282: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 282,
    func: c"evp_md_init_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_md_init_internal` at `crypto/evp/digest.c:292` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const DIGEST_292: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 292,
    func: c"evp_md_init_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_md_init_internal` at `crypto/evp/digest.c:298` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const DIGEST_298: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 298,
    func: c"evp_md_init_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_md_init_internal` at `crypto/evp/digest.c:311` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const DIGEST_311: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 311,
    func: c"evp_md_init_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_md_init_internal` at `crypto/evp/digest.c:323` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const DIGEST_323: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 323,
    func: c"evp_md_init_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `EVP_DigestUpdate` at `crypto/evp/digest.c:391` (EVP_R_UPDATE_ERROR).
pub(crate) const DIGEST_391: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 391,
    func: c"EVP_DigestUpdate",
    lib: 6,
    reason: 189,
    dynamic_reason: false,
};

/// `EVP_DigestUpdate` at `crypto/evp/digest.c:412` (EVP_R_UPDATE_ERROR).
pub(crate) const DIGEST_412: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 412,
    func: c"EVP_DigestUpdate",
    lib: 6,
    reason: 189,
    dynamic_reason: false,
};

/// `EVP_DigestUpdate` at `crypto/evp/digest.c:422` (EVP_R_UPDATE_ERROR).
pub(crate) const DIGEST_422: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 422,
    func: c"EVP_DigestUpdate",
    lib: 6,
    reason: 189,
    dynamic_reason: false,
};

/// `EVP_DigestFinal_ex` at `crypto/evp/digest.c:459` (EVP_R_FINAL_ERROR).
pub(crate) const DIGEST_459: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 459,
    func: c"EVP_DigestFinal_ex",
    lib: 6,
    reason: 188,
    dynamic_reason: false,
};

/// `EVP_DigestFinal_ex` at `crypto/evp/digest.c:464` (EVP_R_FINAL_ERROR).
pub(crate) const DIGEST_464: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 464,
    func: c"EVP_DigestFinal_ex",
    lib: 6,
    reason: 188,
    dynamic_reason: false,
};

/// `EVP_DigestFinal_ex` at `crypto/evp/digest.c:476` (EVP_R_FINAL_ERROR).
pub(crate) const DIGEST_476: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 476,
    func: c"EVP_DigestFinal_ex",
    lib: 6,
    reason: 188,
    dynamic_reason: false,
};

/// `EVP_DigestFinalXOF` at `crypto/evp/digest.c:505` (EVP_R_INVALID_NULL_ALGORITHM).
pub(crate) const DIGEST_505: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 505,
    func: c"EVP_DigestFinalXOF",
    lib: 6,
    reason: 218,
    dynamic_reason: false,
};

/// `EVP_DigestFinalXOF` at `crypto/evp/digest.c:513` (EVP_R_FINAL_ERROR).
pub(crate) const DIGEST_513: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 513,
    func: c"EVP_DigestFinalXOF",
    lib: 6,
    reason: 188,
    dynamic_reason: false,
};

/// `EVP_DigestFinalXOF` at `crypto/evp/digest.c:518` (EVP_R_FINAL_ERROR).
pub(crate) const DIGEST_518: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 518,
    func: c"EVP_DigestFinalXOF",
    lib: 6,
    reason: 188,
    dynamic_reason: false,
};

/// `EVP_DigestFinalXOF` at `crypto/evp/digest.c:548` (EVP_R_NOT_XOF_OR_INVALID_LENGTH).
pub(crate) const DIGEST_548: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 548,
    func: c"EVP_DigestFinalXOF",
    lib: 6,
    reason: 178,
    dynamic_reason: false,
};

/// `EVP_DigestSqueeze` at `crypto/evp/digest.c:558` (EVP_R_INVALID_NULL_ALGORITHM).
pub(crate) const DIGEST_558: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 558,
    func: c"EVP_DigestSqueeze",
    lib: 6,
    reason: 218,
    dynamic_reason: false,
};

/// `EVP_DigestSqueeze` at `crypto/evp/digest.c:563` (EVP_R_INVALID_OPERATION).
pub(crate) const DIGEST_563: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 563,
    func: c"EVP_DigestSqueeze",
    lib: 6,
    reason: 148,
    dynamic_reason: false,
};

/// `EVP_DigestSqueeze` at `crypto/evp/digest.c:568` (EVP_R_METHOD_NOT_SUPPORTED).
pub(crate) const DIGEST_568: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 568,
    func: c"EVP_DigestSqueeze",
    lib: 6,
    reason: 144,
    dynamic_reason: false,
};

/// `EVP_MD_CTX_copy_ex` at `crypto/evp/digest.c:598` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const DIGEST_598: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 598,
    func: c"EVP_MD_CTX_copy_ex",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_MD_CTX_copy_ex` at `crypto/evp/digest.c:616` (EVP_R_NOT_ABLE_TO_COPY_CTX).
pub(crate) const DIGEST_616: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 616,
    func: c"EVP_MD_CTX_copy_ex",
    lib: 6,
    reason: 190,
    dynamic_reason: false,
};

/// `EVP_MD_CTX_copy_ex` at `crypto/evp/digest.c:647` (EVP_R_NOT_ABLE_TO_COPY_CTX).
pub(crate) const DIGEST_647: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 647,
    func: c"EVP_MD_CTX_copy_ex",
    lib: 6,
    reason: 190,
    dynamic_reason: false,
};

/// `EVP_MD_CTX_copy_ex` at `crypto/evp/digest.c:660` (EVP_R_NOT_ABLE_TO_COPY_CTX).
pub(crate) const DIGEST_660: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 660,
    func: c"EVP_MD_CTX_copy_ex",
    lib: 6,
    reason: 190,
    dynamic_reason: false,
};

/// `EVP_MD_CTX_copy_ex` at `crypto/evp/digest.c:674` (ERR_R_ENGINE_LIB).
pub(crate) const DIGEST_674: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 674,
    func: c"EVP_MD_CTX_copy_ex",
    lib: 6,
    reason: 524326,
    dynamic_reason: false,
};

/// `EVP_MD_CTX_ctrl` at `crypto/evp/digest.c:897` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const DIGEST_897: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 897,
    func: c"EVP_MD_CTX_ctrl",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_MD_CTX_ctrl` at `crypto/evp/digest.c:931` (EVP_R_CTRL_NOT_IMPLEMENTED).
pub(crate) const DIGEST_931: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 931,
    func: c"EVP_MD_CTX_ctrl",
    lib: 6,
    reason: 132,
    dynamic_reason: false,
};

/// `evp_md_from_algorithm` at `crypto/evp/digest.c:1026` (ERR_R_EVP_LIB).
pub(crate) const DIGEST_1026: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 1026,
    func: c"evp_md_from_algorithm",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `evp_md_from_algorithm` at `crypto/evp/digest.c:1034` (ERR_R_INTERNAL_ERROR).
pub(crate) const DIGEST_1034: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 1034,
    func: c"evp_md_from_algorithm",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `evp_md_from_algorithm` at `crypto/evp/digest.c:1130` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const DIGEST_1130: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 1130,
    func: c"evp_md_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_md_from_algorithm` at `crypto/evp/digest.c:1139` (EVP_R_CACHE_CONSTANTS_FAILED).
pub(crate) const DIGEST_1139: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/digest.c",
    line: 1139,
    func: c"evp_md_from_algorithm",
    lib: 6,
    reason: 225,
    dynamic_reason: false,
};

/// `dsa_paramgen_check` at `crypto/evp/dsa_ctrl.c:20` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const DSA_CTRL_20: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/dsa_ctrl.c",
    line: 20,
    func: c"dsa_paramgen_check",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `aesni_init_key` at `crypto/evp/e_aes.c:151` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_151: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 151,
    func: c"aesni_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `aesni_init_key` at `crypto/evp/e_aes.c:172` (EVP_R_AES_KEY_SETUP_FAILED).
pub(crate) const E_AES_172: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 172,
    func: c"aesni_init_key",
    lib: 6,
    reason: 143,
    dynamic_reason: false,
};

/// `aesni_gcm_init_key` at `crypto/evp/e_aes.c:234` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_234: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 234,
    func: c"aesni_gcm_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `aesni_xts_init_key` at `crypto/evp/e_aes.c:281` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_281: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 281,
    func: c"aesni_xts_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `aesni_xts_init_key` at `crypto/evp/e_aes.c:292` (EVP_R_XTS_DUPLICATED_KEYS).
pub(crate) const E_AES_292: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 292,
    func: c"aesni_xts_init_key",
    lib: 6,
    reason: 192,
    dynamic_reason: false,
};

/// `aesni_ccm_init_key` at `crypto/evp/e_aes.c:337` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_337: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 337,
    func: c"aesni_ccm_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `aesni_ocb_init_key` at `crypto/evp/e_aes.c:370` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_370: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 370,
    func: c"aesni_ocb_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `aes_t4_init_key` at `crypto/evp/e_aes.c:486` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_486: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 486,
    func: c"aes_t4_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `aes_t4_init_key` at `crypto/evp/e_aes.c:542` (EVP_R_AES_KEY_SETUP_FAILED).
pub(crate) const E_AES_542: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 542,
    func: c"aes_t4_init_key",
    lib: 6,
    reason: 143,
    dynamic_reason: false,
};

/// `aes_t4_gcm_init_key` at `crypto/evp/e_aes.c:588` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_588: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 588,
    func: c"aes_t4_gcm_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `aes_t4_xts_init_key` at `crypto/evp/e_aes.c:648` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_648: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 648,
    func: c"aes_t4_xts_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `aes_t4_xts_init_key` at `crypto/evp/e_aes.c:659` (EVP_R_XTS_DUPLICATED_KEYS).
pub(crate) const E_AES_659: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 659,
    func: c"aes_t4_xts_init_key",
    lib: 6,
    reason: 192,
    dynamic_reason: false,
};

/// `aes_t4_ccm_init_key` at `crypto/evp/e_aes.c:723` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_723: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 723,
    func: c"aes_t4_ccm_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `aes_t4_ocb_init_key` at `crypto/evp/e_aes.c:756` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_756: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 756,
    func: c"aes_t4_ocb_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `s390x_aes_ecb_init_key` at `crypto/evp/e_aes.c:1035` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_1035: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 1035,
    func: c"s390x_aes_ecb_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `s390x_aes_ofb_init_key` at `crypto/evp/e_aes.c:1065` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_1065: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 1065,
    func: c"s390x_aes_ofb_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `s390x_aes_ofb_init_key` at `crypto/evp/e_aes.c:1069` (EVP_R_INVALID_IV_LENGTH).
pub(crate) const E_AES_1069: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 1069,
    func: c"s390x_aes_ofb_init_key",
    lib: 6,
    reason: 194,
    dynamic_reason: false,
};

/// `s390x_aes_cfb_init_key` at `crypto/evp/e_aes.c:1131` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_1131: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 1131,
    func: c"s390x_aes_cfb_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `s390x_aes_cfb_init_key` at `crypto/evp/e_aes.c:1135` (EVP_R_INVALID_IV_LENGTH).
pub(crate) const E_AES_1135: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 1135,
    func: c"s390x_aes_cfb_init_key",
    lib: 6,
    reason: 194,
    dynamic_reason: false,
};

/// `s390x_aes_cfb_cipher` at `crypto/evp/e_aes.c:1161` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_1161: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 1161,
    func: c"s390x_aes_cfb_cipher",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `s390x_aes_cfb_cipher` at `crypto/evp/e_aes.c:1165` (EVP_R_INVALID_IV_LENGTH).
pub(crate) const E_AES_1165: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 1165,
    func: c"s390x_aes_cfb_cipher",
    lib: 6,
    reason: 194,
    dynamic_reason: false,
};

/// `s390x_aes_cfb8_init_key` at `crypto/evp/e_aes.c:1216` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_1216: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 1216,
    func: c"s390x_aes_cfb8_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `s390x_aes_cfb8_init_key` at `crypto/evp/e_aes.c:1220` (EVP_R_INVALID_IV_LENGTH).
pub(crate) const E_AES_1220: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 1220,
    func: c"s390x_aes_cfb8_init_key",
    lib: 6,
    reason: 194,
    dynamic_reason: false,
};

/// `s390x_aes_gcm_init_key` at `crypto/evp/e_aes.c:1625` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_1625: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 1625,
    func: c"s390x_aes_gcm_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `s390x_aes_gcm_tls_cipher` at `crypto/evp/e_aes.c:1677` (EVP_R_TOO_MANY_RECORDS).
pub(crate) const E_AES_1677: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 1677,
    func: c"s390x_aes_gcm_tls_cipher",
    lib: 6,
    reason: 183,
    dynamic_reason: false,
};

/// `s390x_aes_ccm_init_key` at `crypto/evp/e_aes.c:2036` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_2036: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 2036,
    func: c"s390x_aes_ccm_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `aes_init_key` at `crypto/evp/e_aes.c:2423` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_2423: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 2423,
    func: c"aes_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `aes_init_key` at `crypto/evp/e_aes.c:2504` (EVP_R_AES_KEY_SETUP_FAILED).
pub(crate) const E_AES_2504: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 2504,
    func: c"aes_init_key",
    lib: 6,
    reason: 143,
    dynamic_reason: false,
};

/// `aes_gcm_init_key` at `crypto/evp/e_aes.c:2806` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_2806: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 2806,
    func: c"aes_gcm_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `aes_gcm_tls_cipher` at `crypto/evp/e_aes.c:2899` (EVP_R_TOO_MANY_RECORDS).
pub(crate) const E_AES_2899: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 2899,
    func: c"aes_gcm_tls_cipher",
    lib: 6,
    reason: 183,
    dynamic_reason: false,
};

/// `aes_xts_init_key` at `crypto/evp/e_aes.c:3240` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_3240: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 3240,
    func: c"aes_xts_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `aes_xts_init_key` at `crypto/evp/e_aes.c:3261` (EVP_R_XTS_DUPLICATED_KEYS).
pub(crate) const E_AES_3261: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 3261,
    func: c"aes_xts_init_key",
    lib: 6,
    reason: 192,
    dynamic_reason: false,
};

/// `aes_xts_cipher` at `crypto/evp/e_aes.c:3360` (EVP_R_XTS_DATA_UNIT_IS_TOO_LARGE).
pub(crate) const E_AES_3360: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 3360,
    func: c"aes_xts_cipher",
    lib: 6,
    reason: 191,
    dynamic_reason: false,
};

/// `aes_ccm_init_key` at `crypto/evp/e_aes.c:3493` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_3493: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 3493,
    func: c"aes_ccm_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `aes_wrap_init_key` at `crypto/evp/e_aes.c:3683` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_3683: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 3683,
    func: c"aes_wrap_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `aes_wrap_cipher` at `crypto/evp/e_aes.c:3722` (EVP_R_PARTIALLY_OVERLAPPING).
pub(crate) const E_AES_3722: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 3722,
    func: c"aes_wrap_cipher",
    lib: 6,
    reason: 162,
    dynamic_reason: false,
};

/// `aes_ocb_init_key` at `crypto/evp/e_aes.c:3924` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_3924: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 3924,
    func: c"aes_ocb_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `aes_ocb_cipher` at `crypto/evp/e_aes.c:4026` (EVP_R_PARTIALLY_OVERLAPPING).
pub(crate) const E_AES_4026: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes.c",
    line: 4026,
    func: c"aes_ocb_cipher",
    lib: 6,
    reason: 162,
    dynamic_reason: false,
};

/// `aesni_cbc_hmac_sha1_init_key` at `crypto/evp/e_aes_cbc_hmac_sha1.c:76` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_CBC_HMAC_SHA1_76: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes_cbc_hmac_sha1.c",
    line: 76,
    func: c"aesni_cbc_hmac_sha1_init_key",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `aesni_cbc_hmac_sha1_cipher` at `crypto/evp/e_aes_cbc_hmac_sha1.c:498` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const E_AES_CBC_HMAC_SHA1_498: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aes_cbc_hmac_sha1.c",
    line: 498,
    func: c"aesni_cbc_hmac_sha1_cipher",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `aria_init_key` at `crypto/evp/e_aria.c:76` (EVP_R_ARIA_KEY_SETUP_FAILED).
pub(crate) const E_ARIA_76: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aria.c",
    line: 76,
    func: c"aria_init_key",
    lib: 6,
    reason: 176,
    dynamic_reason: false,
};

/// `aria_gcm_init_key` at `crypto/evp/e_aria.c:233` (EVP_R_ARIA_KEY_SETUP_FAILED).
pub(crate) const E_ARIA_233: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aria.c",
    line: 233,
    func: c"aria_gcm_init_key",
    lib: 6,
    reason: 176,
    dynamic_reason: false,
};

/// `aria_ccm_init_key` at `crypto/evp/e_aria.c:525` (EVP_R_ARIA_KEY_SETUP_FAILED).
pub(crate) const E_ARIA_525: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_aria.c",
    line: 525,
    func: c"aria_ccm_init_key",
    lib: 6,
    reason: 176,
    dynamic_reason: false,
};

/// `cmll_t4_init_key` at `crypto/evp/e_camellia.c:104` (EVP_R_CAMELLIA_KEY_SETUP_FAILED).
pub(crate) const E_CAMELLIA_104: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_camellia.c",
    line: 104,
    func: c"cmll_t4_init_key",
    lib: 6,
    reason: 157,
    dynamic_reason: false,
};

/// `camellia_init_key` at `crypto/evp/e_camellia.c:205` (EVP_R_CAMELLIA_KEY_SETUP_FAILED).
pub(crate) const E_CAMELLIA_205: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_camellia.c",
    line: 205,
    func: c"camellia_init_key",
    lib: 6,
    reason: 157,
    dynamic_reason: false,
};

/// `chacha20_poly1305_ctrl` at `crypto/evp/e_chacha20_poly1305.c:508` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const E_CHACHA20_POLY1305_508: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_chacha20_poly1305.c",
    line: 508,
    func: c"chacha20_poly1305_ctrl",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `chacha20_poly1305_ctrl` at `crypto/evp/e_chacha20_poly1305.c:527` (EVP_R_COPY_ERROR).
pub(crate) const E_CHACHA20_POLY1305_527: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_chacha20_poly1305.c",
    line: 527,
    func: c"chacha20_poly1305_ctrl",
    lib: 6,
    reason: 173,
    dynamic_reason: false,
};

/// `des_ede3_wrap_cipher` at `crypto/evp/e_des3.c:398` (EVP_R_PARTIALLY_OVERLAPPING).
pub(crate) const E_DES3_398: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_des3.c",
    line: 398,
    func: c"des_ede3_wrap_cipher",
    lib: 6,
    reason: 162,
    dynamic_reason: false,
};

/// `rc2_magic_to_meth` at `crypto/evp/e_rc2.c:125` (EVP_R_UNSUPPORTED_KEY_SIZE).
pub(crate) const E_RC2_125: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_rc2.c",
    line: 125,
    func: c"rc2_magic_to_meth",
    lib: 6,
    reason: 108,
    dynamic_reason: false,
};

/// `rc5_ctrl` at `crypto/evp/e_rc5.c:63` (EVP_R_UNSUPPORTED_NUMBER_OF_ROUNDS).
pub(crate) const E_RC5_63: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_rc5.c",
    line: 63,
    func: c"rc5_ctrl",
    lib: 6,
    reason: 135,
    dynamic_reason: false,
};

/// `r_32_12_16_init_key` at `crypto/evp/e_rc5.c:78` (EVP_R_BAD_KEY_LENGTH).
pub(crate) const E_RC5_78: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/e_rc5.c",
    line: 78,
    func: c"r_32_12_16_init_key",
    lib: 6,
    reason: 195,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_getset_ecdh_param_checks` at `crypto/evp/ec_ctrl.c:26` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const EC_CTRL_26: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ec_ctrl.c",
    line: 26,
    func: c"evp_pkey_ctx_getset_ecdh_param_checks",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_set_ecdh_cofactor_mode` at `crypto/evp/ec_ctrl.c:65` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const EC_CTRL_65: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ec_ctrl.c",
    line: 65,
    func: c"EVP_PKEY_CTX_set_ecdh_cofactor_mode",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_get_ecdh_cofactor_mode` at `crypto/evp/ec_ctrl.c:86` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const EC_CTRL_86: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ec_ctrl.c",
    line: 86,
    func: c"EVP_PKEY_CTX_get_ecdh_cofactor_mode",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_set_ecdh_kdf_outlen` at `crypto/evp/ec_ctrl.c:171` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const EC_CTRL_171: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ec_ctrl.c",
    line: 171,
    func: c"EVP_PKEY_CTX_set_ecdh_kdf_outlen",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_get_ecdh_kdf_outlen` at `crypto/evp/ec_ctrl.c:193` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const EC_CTRL_193: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ec_ctrl.c",
    line: 193,
    func: c"EVP_PKEY_CTX_get_ecdh_kdf_outlen",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_set0_ecdh_kdf_ukm` at `crypto/evp/ec_ctrl.c:231` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const EC_CTRL_231: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ec_ctrl.c",
    line: 231,
    func: c"EVP_PKEY_CTX_set0_ecdh_kdf_ukm",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_get0_ecdh_kdf_ukm` at `crypto/evp/ec_ctrl.c:260` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const EC_CTRL_260: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/ec_ctrl.c",
    line: 260,
    func: c"EVP_PKEY_CTX_get0_ecdh_kdf_ukm",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `alg_module_init` at `crypto/evp/evp_cnf.c:33` (EVP_R_ERROR_LOADING_SECTION).
pub(crate) const EVP_CNF_33: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_cnf.c",
    line: 33,
    func: c"alg_module_init",
    lib: 6,
    reason: 165,
    dynamic_reason: false,
};

/// `alg_module_init` at `crypto/evp/evp_cnf.c:51` (EVP_R_SET_DEFAULT_PROPERTY_FAILURE).
pub(crate) const EVP_CNF_51: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_cnf.c",
    line: 51,
    func: c"alg_module_init",
    lib: 6,
    reason: 209,
    dynamic_reason: false,
};

/// `alg_module_init` at `crypto/evp/evp_cnf.c:57` (EVP_R_SET_DEFAULT_PROPERTY_FAILURE).
pub(crate) const EVP_CNF_57: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_cnf.c",
    line: 57,
    func: c"alg_module_init",
    lib: 6,
    reason: 209,
    dynamic_reason: false,
};

/// `alg_module_init` at `crypto/evp/evp_cnf.c:61` (EVP_R_UNKNOWN_OPTION).
pub(crate) const EVP_CNF_61: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_cnf.c",
    line: 61,
    func: c"alg_module_init",
    lib: 6,
    reason: 169,
    dynamic_reason: false,
};

/// `evp_cipher_init_internal` at `crypto/evp/evp_enc.c:118` (EVP_R_NO_CIPHER_SET).
pub(crate) const EVP_ENC_118: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 118,
    func: c"evp_cipher_init_internal",
    lib: 6,
    reason: 131,
    dynamic_reason: false,
};

/// `evp_cipher_init_internal` at `crypto/evp/evp_enc.c:189` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EVP_ENC_189: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 189,
    func: c"evp_cipher_init_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_cipher_init_internal` at `crypto/evp/evp_enc.c:206` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EVP_ENC_206: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 206,
    func: c"evp_cipher_init_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_cipher_init_internal` at `crypto/evp/evp_enc.c:212` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EVP_ENC_212: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 212,
    func: c"evp_cipher_init_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_cipher_init_internal` at `crypto/evp/evp_enc.c:223` (EVP_R_PIPELINE_NOT_SUPPORTED).
pub(crate) const EVP_ENC_223: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 223,
    func: c"evp_cipher_init_internal",
    lib: 6,
    reason: 230,
    dynamic_reason: false,
};

/// `evp_cipher_init_internal` at `crypto/evp/evp_enc.c:230` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EVP_ENC_230: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 230,
    func: c"evp_cipher_init_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_cipher_init_internal` at `crypto/evp/evp_enc.c:273` (EVP_R_INVALID_LENGTH).
pub(crate) const EVP_ENC_273: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 273,
    func: c"evp_cipher_init_internal",
    lib: 6,
    reason: 221,
    dynamic_reason: false,
};

/// `evp_cipher_init_internal` at `crypto/evp/evp_enc.c:296` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EVP_ENC_296: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 296,
    func: c"evp_cipher_init_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_cipher_init_internal` at `crypto/evp/evp_enc.c:322` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EVP_ENC_322: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 322,
    func: c"evp_cipher_init_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_cipher_init_internal` at `crypto/evp/evp_enc.c:354` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EVP_ENC_354: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 354,
    func: c"evp_cipher_init_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_cipher_init_internal` at `crypto/evp/evp_enc.c:370` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EVP_ENC_370: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 370,
    func: c"evp_cipher_init_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_cipher_init_internal` at `crypto/evp/evp_enc.c:401` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EVP_ENC_401: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 401,
    func: c"evp_cipher_init_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_cipher_init_internal` at `crypto/evp/evp_enc.c:419` (EVP_R_WRAP_MODE_NOT_ALLOWED).
pub(crate) const EVP_ENC_419: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 419,
    func: c"evp_cipher_init_internal",
    lib: 6,
    reason: 170,
    dynamic_reason: false,
};

/// `evp_cipher_init_internal` at `crypto/evp/evp_enc.c:441` (EVP_R_INVALID_IV_LENGTH).
pub(crate) const EVP_ENC_441: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 441,
    func: c"evp_cipher_init_internal",
    lib: 6,
    reason: 194,
    dynamic_reason: false,
};

/// `evp_cipher_init_internal` at `crypto/evp/evp_enc.c:455` (EVP_R_INVALID_IV_LENGTH).
pub(crate) const EVP_ENC_455: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 455,
    func: c"evp_cipher_init_internal",
    lib: 6,
    reason: 194,
    dynamic_reason: false,
};

/// `evp_cipher_init_skey_internal` at `crypto/evp/evp_enc.c:500` (EVP_R_NO_CIPHER_SET).
pub(crate) const EVP_ENC_500: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 500,
    func: c"evp_cipher_init_skey_internal",
    lib: 6,
    reason: 131,
    dynamic_reason: false,
};

/// `evp_cipher_init_skey_internal` at `crypto/evp/evp_enc.c:511` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EVP_ENC_511: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 511,
    func: c"evp_cipher_init_skey_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_cipher_init_skey_internal` at `crypto/evp/evp_enc.c:539` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EVP_ENC_539: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 539,
    func: c"evp_cipher_init_skey_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_cipher_init_skey_internal` at `crypto/evp/evp_enc.c:545` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EVP_ENC_545: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 545,
    func: c"evp_cipher_init_skey_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_cipher_init_skey_internal` at `crypto/evp/evp_enc.c:557` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EVP_ENC_557: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 557,
    func: c"evp_cipher_init_skey_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_cipher_init_skey_internal` at `crypto/evp/evp_enc.c:563` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EVP_ENC_563: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 563,
    func: c"evp_cipher_init_skey_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_cipher_init_skey_internal` at `crypto/evp/evp_enc.c:590` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EVP_ENC_590: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 590,
    func: c"evp_cipher_init_skey_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_cipher_init_skey_internal` at `crypto/evp/evp_enc.c:611` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EVP_ENC_611: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 611,
    func: c"evp_cipher_init_skey_internal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `EVP_CipherPipelineEncryptInit` at `crypto/evp/evp_enc.c:662` (EVP_R_TOO_MANY_PIPES).
pub(crate) const EVP_ENC_662: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 662,
    func: c"EVP_CipherPipelineEncryptInit",
    lib: 6,
    reason: 231,
    dynamic_reason: false,
};

/// `EVP_CipherPipelineEncryptInit` at `crypto/evp/evp_enc.c:673` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EVP_ENC_673: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 673,
    func: c"EVP_CipherPipelineEncryptInit",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `EVP_CipherPipelineDecryptInit` at `crypto/evp/evp_enc.c:692` (EVP_R_TOO_MANY_PIPES).
pub(crate) const EVP_ENC_692: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 692,
    func: c"EVP_CipherPipelineDecryptInit",
    lib: 6,
    reason: 231,
    dynamic_reason: false,
};

/// `EVP_CipherPipelineDecryptInit` at `crypto/evp/evp_enc.c:703` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EVP_ENC_703: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 703,
    func: c"EVP_CipherPipelineDecryptInit",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `EVP_CipherPipelineUpdate` at `crypto/evp/evp_enc.c:733` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const EVP_ENC_733: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 733,
    func: c"EVP_CipherPipelineUpdate",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_CipherPipelineUpdate` at `crypto/evp/evp_enc.c:738` (EVP_R_NO_CIPHER_SET).
pub(crate) const EVP_ENC_738: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 738,
    func: c"EVP_CipherPipelineUpdate",
    lib: 6,
    reason: 131,
    dynamic_reason: false,
};

/// `EVP_CipherPipelineUpdate` at `crypto/evp/evp_enc.c:743` (EVP_R_INVALID_OPERATION).
pub(crate) const EVP_ENC_743: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 743,
    func: c"EVP_CipherPipelineUpdate",
    lib: 6,
    reason: 148,
    dynamic_reason: false,
};

/// `EVP_CipherPipelineUpdate` at `crypto/evp/evp_enc.c:748` (EVP_R_UPDATE_ERROR).
pub(crate) const EVP_ENC_748: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 748,
    func: c"EVP_CipherPipelineUpdate",
    lib: 6,
    reason: 189,
    dynamic_reason: false,
};

/// `EVP_CipherPipelineFinal` at `crypto/evp/evp_enc.c:783` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const EVP_ENC_783: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 783,
    func: c"EVP_CipherPipelineFinal",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_CipherPipelineFinal` at `crypto/evp/evp_enc.c:788` (EVP_R_NO_CIPHER_SET).
pub(crate) const EVP_ENC_788: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 788,
    func: c"EVP_CipherPipelineFinal",
    lib: 6,
    reason: 131,
    dynamic_reason: false,
};

/// `EVP_CipherPipelineFinal` at `crypto/evp/evp_enc.c:793` (EVP_R_INVALID_OPERATION).
pub(crate) const EVP_ENC_793: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 793,
    func: c"EVP_CipherPipelineFinal",
    lib: 6,
    reason: 148,
    dynamic_reason: false,
};

/// `EVP_CipherPipelineFinal` at `crypto/evp/evp_enc.c:798` (EVP_R_FINAL_ERROR).
pub(crate) const EVP_ENC_798: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 798,
    func: c"EVP_CipherPipelineFinal",
    lib: 6,
    reason: 188,
    dynamic_reason: false,
};

/// `evp_EncryptDecryptUpdate` at `crypto/evp/evp_enc.c:899` (EVP_R_PARTIALLY_OVERLAPPING).
pub(crate) const EVP_ENC_899: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 899,
    func: c"evp_EncryptDecryptUpdate",
    lib: 6,
    reason: 162,
    dynamic_reason: false,
};

/// `evp_EncryptDecryptUpdate` at `crypto/evp/evp_enc.c:916` (EVP_R_PARTIALLY_OVERLAPPING).
pub(crate) const EVP_ENC_916: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 916,
    func: c"evp_EncryptDecryptUpdate",
    lib: 6,
    reason: 162,
    dynamic_reason: false,
};

/// `evp_EncryptDecryptUpdate` at `crypto/evp/evp_enc.c:948` (EVP_R_OUTPUT_WOULD_OVERFLOW).
pub(crate) const EVP_ENC_948: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 948,
    func: c"evp_EncryptDecryptUpdate",
    lib: 6,
    reason: 202,
    dynamic_reason: false,
};

/// `EVP_EncryptUpdate` at `crypto/evp/evp_enc.c:983` (EVP_R_INVALID_LENGTH).
pub(crate) const EVP_ENC_983: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 983,
    func: c"EVP_EncryptUpdate",
    lib: 6,
    reason: 221,
    dynamic_reason: false,
};

/// `EVP_EncryptUpdate` at `crypto/evp/evp_enc.c:990` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const EVP_ENC_990: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 990,
    func: c"EVP_EncryptUpdate",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_EncryptUpdate` at `crypto/evp/evp_enc.c:996` (EVP_R_INVALID_OPERATION).
pub(crate) const EVP_ENC_996: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 996,
    func: c"EVP_EncryptUpdate",
    lib: 6,
    reason: 148,
    dynamic_reason: false,
};

/// `EVP_EncryptUpdate` at `crypto/evp/evp_enc.c:1001` (EVP_R_NO_CIPHER_SET).
pub(crate) const EVP_ENC_1001: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1001,
    func: c"EVP_EncryptUpdate",
    lib: 6,
    reason: 131,
    dynamic_reason: false,
};

/// `EVP_EncryptUpdate` at `crypto/evp/evp_enc.c:1011` (EVP_R_UPDATE_ERROR).
pub(crate) const EVP_ENC_1011: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1011,
    func: c"EVP_EncryptUpdate",
    lib: 6,
    reason: 189,
    dynamic_reason: false,
};

/// `EVP_EncryptUpdate` at `crypto/evp/evp_enc.c:1021` (EVP_R_UPDATE_ERROR).
pub(crate) const EVP_ENC_1021: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1021,
    func: c"EVP_EncryptUpdate",
    lib: 6,
    reason: 189,
    dynamic_reason: false,
};

/// `EVP_EncryptFinal_ex` at `crypto/evp/evp_enc.c:1052` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const EVP_ENC_1052: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1052,
    func: c"EVP_EncryptFinal_ex",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_EncryptFinal_ex` at `crypto/evp/evp_enc.c:1058` (EVP_R_INVALID_OPERATION).
pub(crate) const EVP_ENC_1058: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1058,
    func: c"EVP_EncryptFinal_ex",
    lib: 6,
    reason: 148,
    dynamic_reason: false,
};

/// `EVP_EncryptFinal_ex` at `crypto/evp/evp_enc.c:1063` (EVP_R_NO_CIPHER_SET).
pub(crate) const EVP_ENC_1063: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1063,
    func: c"EVP_EncryptFinal_ex",
    lib: 6,
    reason: 131,
    dynamic_reason: false,
};

/// `EVP_EncryptFinal_ex` at `crypto/evp/evp_enc.c:1072` (EVP_R_FINAL_ERROR).
pub(crate) const EVP_ENC_1072: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1072,
    func: c"EVP_EncryptFinal_ex",
    lib: 6,
    reason: 188,
    dynamic_reason: false,
};

/// `EVP_EncryptFinal_ex` at `crypto/evp/evp_enc.c:1081` (EVP_R_FINAL_ERROR).
pub(crate) const EVP_ENC_1081: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1081,
    func: c"EVP_EncryptFinal_ex",
    lib: 6,
    reason: 188,
    dynamic_reason: false,
};

/// `EVP_EncryptFinal_ex` at `crypto/evp/evp_enc.c:1110` (EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH).
pub(crate) const EVP_ENC_1110: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1110,
    func: c"EVP_EncryptFinal_ex",
    lib: 6,
    reason: 138,
    dynamic_reason: false,
};

/// `EVP_DecryptUpdate` at `crypto/evp/evp_enc.c:1137` (EVP_R_INVALID_LENGTH).
pub(crate) const EVP_ENC_1137: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1137,
    func: c"EVP_DecryptUpdate",
    lib: 6,
    reason: 221,
    dynamic_reason: false,
};

/// `EVP_DecryptUpdate` at `crypto/evp/evp_enc.c:1144` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const EVP_ENC_1144: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1144,
    func: c"EVP_DecryptUpdate",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_DecryptUpdate` at `crypto/evp/evp_enc.c:1150` (EVP_R_INVALID_OPERATION).
pub(crate) const EVP_ENC_1150: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1150,
    func: c"EVP_DecryptUpdate",
    lib: 6,
    reason: 148,
    dynamic_reason: false,
};

/// `EVP_DecryptUpdate` at `crypto/evp/evp_enc.c:1155` (EVP_R_NO_CIPHER_SET).
pub(crate) const EVP_ENC_1155: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1155,
    func: c"EVP_DecryptUpdate",
    lib: 6,
    reason: 131,
    dynamic_reason: false,
};

/// `EVP_DecryptUpdate` at `crypto/evp/evp_enc.c:1164` (EVP_R_UPDATE_ERROR).
pub(crate) const EVP_ENC_1164: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1164,
    func: c"EVP_DecryptUpdate",
    lib: 6,
    reason: 189,
    dynamic_reason: false,
};

/// `EVP_DecryptUpdate` at `crypto/evp/evp_enc.c:1173` (EVP_R_UPDATE_ERROR).
pub(crate) const EVP_ENC_1173: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1173,
    func: c"EVP_DecryptUpdate",
    lib: 6,
    reason: 189,
    dynamic_reason: false,
};

/// `EVP_DecryptUpdate` at `crypto/evp/evp_enc.c:1191` (EVP_R_PARTIALLY_OVERLAPPING).
pub(crate) const EVP_ENC_1191: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1191,
    func: c"EVP_DecryptUpdate",
    lib: 6,
    reason: 162,
    dynamic_reason: false,
};

/// `EVP_DecryptUpdate` at `crypto/evp/evp_enc.c:1218` (EVP_R_PARTIALLY_OVERLAPPING).
pub(crate) const EVP_ENC_1218: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1218,
    func: c"EVP_DecryptUpdate",
    lib: 6,
    reason: 162,
    dynamic_reason: false,
};

/// `EVP_DecryptUpdate` at `crypto/evp/evp_enc.c:1231` (EVP_R_OUTPUT_WOULD_OVERFLOW).
pub(crate) const EVP_ENC_1231: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1231,
    func: c"EVP_DecryptUpdate",
    lib: 6,
    reason: 202,
    dynamic_reason: false,
};

/// `EVP_DecryptFinal_ex` at `crypto/evp/evp_enc.c:1278` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const EVP_ENC_1278: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1278,
    func: c"EVP_DecryptFinal_ex",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_DecryptFinal_ex` at `crypto/evp/evp_enc.c:1284` (EVP_R_INVALID_OPERATION).
pub(crate) const EVP_ENC_1284: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1284,
    func: c"EVP_DecryptFinal_ex",
    lib: 6,
    reason: 148,
    dynamic_reason: false,
};

/// `EVP_DecryptFinal_ex` at `crypto/evp/evp_enc.c:1289` (EVP_R_NO_CIPHER_SET).
pub(crate) const EVP_ENC_1289: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1289,
    func: c"EVP_DecryptFinal_ex",
    lib: 6,
    reason: 131,
    dynamic_reason: false,
};

/// `EVP_DecryptFinal_ex` at `crypto/evp/evp_enc.c:1299` (EVP_R_FINAL_ERROR).
pub(crate) const EVP_ENC_1299: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1299,
    func: c"EVP_DecryptFinal_ex",
    lib: 6,
    reason: 188,
    dynamic_reason: false,
};

/// `EVP_DecryptFinal_ex` at `crypto/evp/evp_enc.c:1308` (EVP_R_FINAL_ERROR).
pub(crate) const EVP_ENC_1308: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1308,
    func: c"EVP_DecryptFinal_ex",
    lib: 6,
    reason: 188,
    dynamic_reason: false,
};

/// `EVP_DecryptFinal_ex` at `crypto/evp/evp_enc.c:1332` (EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH).
pub(crate) const EVP_ENC_1332: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1332,
    func: c"EVP_DecryptFinal_ex",
    lib: 6,
    reason: 138,
    dynamic_reason: false,
};

/// `EVP_DecryptFinal_ex` at `crypto/evp/evp_enc.c:1340` (EVP_R_WRONG_FINAL_BLOCK_LENGTH).
pub(crate) const EVP_ENC_1340: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1340,
    func: c"EVP_DecryptFinal_ex",
    lib: 6,
    reason: 109,
    dynamic_reason: false,
};

/// `EVP_DecryptFinal_ex` at `crypto/evp/evp_enc.c:1351` (EVP_R_BAD_DECRYPT).
pub(crate) const EVP_ENC_1351: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1351,
    func: c"EVP_DecryptFinal_ex",
    lib: 6,
    reason: 100,
    dynamic_reason: false,
};

/// `EVP_DecryptFinal_ex` at `crypto/evp/evp_enc.c:1356` (EVP_R_BAD_DECRYPT).
pub(crate) const EVP_ENC_1356: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1356,
    func: c"EVP_DecryptFinal_ex",
    lib: 6,
    reason: 100,
    dynamic_reason: false,
};

/// `EVP_CIPHER_CTX_set_key_length` at `crypto/evp/evp_enc.c:1382` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const EVP_ENC_1382: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1382,
    func: c"EVP_CIPHER_CTX_set_key_length",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `EVP_CIPHER_CTX_set_key_length` at `crypto/evp/evp_enc.c:1410` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const EVP_ENC_1410: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1410,
    func: c"EVP_CIPHER_CTX_set_key_length",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `EVP_CIPHER_CTX_ctrl` at `crypto/evp/evp_enc.c:1444` (EVP_R_NO_CIPHER_SET).
pub(crate) const EVP_ENC_1444: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1444,
    func: c"EVP_CIPHER_CTX_ctrl",
    lib: 6,
    reason: 131,
    dynamic_reason: false,
};

/// `EVP_CIPHER_CTX_ctrl` at `crypto/evp/evp_enc.c:1632` (EVP_R_CTRL_NOT_IMPLEMENTED).
pub(crate) const EVP_ENC_1632: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1632,
    func: c"EVP_CIPHER_CTX_ctrl",
    lib: 6,
    reason: 132,
    dynamic_reason: false,
};

/// `EVP_CIPHER_CTX_ctrl` at `crypto/evp/evp_enc.c:1640` (EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED).
pub(crate) const EVP_ENC_1640: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1640,
    func: c"EVP_CIPHER_CTX_ctrl",
    lib: 6,
    reason: 133,
    dynamic_reason: false,
};

/// `EVP_CIPHER_CTX_copy` at `crypto/evp/evp_enc.c:1785` (EVP_R_INPUT_NOT_INITIALIZED).
pub(crate) const EVP_ENC_1785: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1785,
    func: c"EVP_CIPHER_CTX_copy",
    lib: 6,
    reason: 111,
    dynamic_reason: false,
};

/// `EVP_CIPHER_CTX_copy` at `crypto/evp/evp_enc.c:1793` (EVP_R_NOT_ABLE_TO_COPY_CTX).
pub(crate) const EVP_ENC_1793: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1793,
    func: c"EVP_CIPHER_CTX_copy",
    lib: 6,
    reason: 190,
    dynamic_reason: false,
};

/// `EVP_CIPHER_CTX_copy` at `crypto/evp/evp_enc.c:1809` (EVP_R_NOT_ABLE_TO_COPY_CTX).
pub(crate) const EVP_ENC_1809: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1809,
    func: c"EVP_CIPHER_CTX_copy",
    lib: 6,
    reason: 190,
    dynamic_reason: false,
};

/// `EVP_CIPHER_CTX_copy` at `crypto/evp/evp_enc.c:1821` (ERR_R_ENGINE_LIB).
pub(crate) const EVP_ENC_1821: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1821,
    func: c"EVP_CIPHER_CTX_copy",
    lib: 6,
    reason: 524326,
    dynamic_reason: false,
};

/// `EVP_CIPHER_CTX_copy` at `crypto/evp/evp_enc.c:1841` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EVP_ENC_1841: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1841,
    func: c"EVP_CIPHER_CTX_copy",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_cipher_from_algorithm` at `crypto/evp/evp_enc.c:1898` (ERR_R_EVP_LIB).
pub(crate) const EVP_ENC_1898: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1898,
    func: c"evp_cipher_from_algorithm",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `evp_cipher_from_algorithm` at `crypto/evp/evp_enc.c:1906` (ERR_R_INTERNAL_ERROR).
pub(crate) const EVP_ENC_1906: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 1906,
    func: c"evp_cipher_from_algorithm",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `evp_cipher_from_algorithm` at `crypto/evp/evp_enc.c:2044` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const EVP_ENC_2044: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 2044,
    func: c"evp_cipher_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_cipher_from_algorithm` at `crypto/evp/evp_enc.c:2053` (EVP_R_CACHE_CONSTANTS_FAILED).
pub(crate) const EVP_ENC_2053: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_enc.c",
    line: 2053,
    func: c"evp_cipher_from_algorithm",
    lib: 6,
    reason: 225,
    dynamic_reason: false,
};

/// `inner_evp_generic_fetch` at `crypto/evp/evp_fetch.c:278` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const EVP_FETCH_278: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_fetch.c",
    line: 278,
    func: c"inner_evp_generic_fetch",
    lib: 6,
    reason: 524550,
    dynamic_reason: false,
};

/// `inner_evp_generic_fetch` at `crypto/evp/evp_fetch.c:287` (ERR_R_INTERNAL_ERROR).
pub(crate) const EVP_FETCH_287: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_fetch.c",
    line: 287,
    func: c"inner_evp_generic_fetch",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `inner_evp_generic_fetch` at `crypto/evp/evp_fetch.c:303` (ERR_R_INTERNAL_ERROR).
pub(crate) const EVP_FETCH_303: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_fetch.c",
    line: 303,
    func: c"inner_evp_generic_fetch",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `inner_evp_generic_fetch` at `crypto/evp/evp_fetch.c:352` (ERR_R_FETCH_FAILED).
pub(crate) const EVP_FETCH_352: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_fetch.c",
    line: 352,
    func: c"inner_evp_generic_fetch",
    lib: 6,
    reason: 524557,
    dynamic_reason: false,
};

/// `inner_evp_generic_fetch` at `crypto/evp/evp_fetch.c:376` (ERR_raise_data dynamic reason).
pub(crate) const EVP_FETCH_376: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_fetch.c",
    line: 376,
    func: c"inner_evp_generic_fetch",
    lib: 6,
    reason: 0,
    dynamic_reason: true,
};

/// `evp_set_parsed_default_properties` at `crypto/evp/evp_fetch.c:485` (ERR_R_INTERNAL_ERROR).
pub(crate) const EVP_FETCH_485: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_fetch.c",
    line: 485,
    func: c"evp_set_parsed_default_properties",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `evp_set_parsed_default_properties` at `crypto/evp/evp_fetch.c:492` (ERR_R_INTERNAL_ERROR).
pub(crate) const EVP_FETCH_492: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_fetch.c",
    line: 492,
    func: c"evp_set_parsed_default_properties",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `evp_set_parsed_default_properties` at `crypto/evp/evp_fetch.c:507` (ERR_R_INTERNAL_ERROR).
pub(crate) const EVP_FETCH_507: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_fetch.c",
    line: 507,
    func: c"evp_set_parsed_default_properties",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `evp_set_default_properties_int` at `crypto/evp/evp_fetch.c:517` (EVP_R_DEFAULT_QUERY_PARSE_ERROR).
pub(crate) const EVP_FETCH_517: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_fetch.c",
    line: 517,
    func: c"evp_set_default_properties_int",
    lib: 6,
    reason: 210,
    dynamic_reason: false,
};

/// `evp_default_properties_merge` at `crypto/evp/evp_fetch.c:543` (EVP_R_DEFAULT_QUERY_PARSE_ERROR).
pub(crate) const EVP_FETCH_543: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_fetch.c",
    line: 543,
    func: c"evp_default_properties_merge",
    lib: 6,
    reason: 210,
    dynamic_reason: false,
};

/// `evp_default_properties_merge` at `crypto/evp/evp_fetch.c:549` (ERR_R_CRYPTO_LIB).
pub(crate) const EVP_FETCH_549: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_fetch.c",
    line: 549,
    func: c"evp_default_properties_merge",
    lib: 6,
    reason: 524303,
    dynamic_reason: false,
};

/// `evp_get_global_properties_str` at `crypto/evp/evp_fetch.c:596` (ERR_R_INTERNAL_ERROR).
pub(crate) const EVP_FETCH_596: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_fetch.c",
    line: 596,
    func: c"evp_get_global_properties_str",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `evp_get_global_properties_str` at `crypto/evp/evp_fetch.c:604` (ERR_R_INTERNAL_ERROR).
pub(crate) const EVP_FETCH_604: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_fetch.c",
    line: 604,
    func: c"evp_get_global_properties_str",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `evp_cipher_param_to_asn1_ex` at `crypto/evp/evp_lib.c:144` (EVP_R_UNSUPPORTED_CIPHER).
pub(crate) const EVP_LIB_144: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_lib.c",
    line: 144,
    func: c"evp_cipher_param_to_asn1_ex",
    lib: 6,
    reason: 107,
    dynamic_reason: false,
};

/// `evp_cipher_param_to_asn1_ex` at `crypto/evp/evp_lib.c:146` (EVP_R_CIPHER_PARAMETER_ERROR).
pub(crate) const EVP_LIB_146: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_lib.c",
    line: 146,
    func: c"evp_cipher_param_to_asn1_ex",
    lib: 6,
    reason: 122,
    dynamic_reason: false,
};

/// `evp_cipher_asn1_to_param_ex` at `crypto/evp/evp_lib.c:213` (EVP_R_UNSUPPORTED_CIPHER).
pub(crate) const EVP_LIB_213: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_lib.c",
    line: 213,
    func: c"evp_cipher_asn1_to_param_ex",
    lib: 6,
    reason: 107,
    dynamic_reason: false,
};

/// `evp_cipher_asn1_to_param_ex` at `crypto/evp/evp_lib.c:215` (EVP_R_CIPHER_PARAMETER_ERROR).
pub(crate) const EVP_LIB_215: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_lib.c",
    line: 215,
    func: c"evp_cipher_asn1_to_param_ex",
    lib: 6,
    reason: 122,
    dynamic_reason: false,
};

/// `EVP_MD_get_block_size` at `crypto/evp/evp_lib.c:803` (EVP_R_MESSAGE_DIGEST_IS_NULL).
pub(crate) const EVP_LIB_803: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_lib.c",
    line: 803,
    func: c"EVP_MD_get_block_size",
    lib: 6,
    reason: 159,
    dynamic_reason: false,
};

/// `EVP_MD_get_size` at `crypto/evp/evp_lib.c:812` (EVP_R_MESSAGE_DIGEST_IS_NULL).
pub(crate) const EVP_LIB_812: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_lib.c",
    line: 812,
    func: c"EVP_MD_get_size",
    lib: 6,
    reason: 159,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_set_group_name` at `crypto/evp/evp_lib.c:1159` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const EVP_LIB_1159: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_lib.c",
    line: 1159,
    func: c"EVP_PKEY_CTX_set_group_name",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_get_group_name` at `crypto/evp/evp_lib.c:1179` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const EVP_LIB_1179: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_lib.c",
    line: 1179,
    func: c"EVP_PKEY_CTX_get_group_name",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `EVP_CIPHER_CTX_get_algor` at `crypto/evp/evp_lib.c:1353` (EVP_R_GETTING_ALGORITHMIDENTIFIER_NOT_SUPPORTED).
pub(crate) const EVP_LIB_1353: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_lib.c",
    line: 1353,
    func: c"EVP_CIPHER_CTX_get_algor",
    lib: 6,
    reason: 229,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_get_algor` at `crypto/evp/evp_lib.c:1471` (EVP_R_GETTING_ALGORITHMIDENTIFIER_NOT_SUPPORTED).
pub(crate) const EVP_LIB_1471: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_lib.c",
    line: 1471,
    func: c"EVP_PKEY_CTX_get_algor",
    lib: 6,
    reason: 229,
    dynamic_reason: false,
};

/// `EVP_PBE_CipherInit_ex` at `crypto/evp/evp_pbe.c:116` (EVP_R_UNKNOWN_PBE_ALGORITHM).
pub(crate) const EVP_PBE_116: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_pbe.c",
    line: 116,
    func: c"EVP_PBE_CipherInit_ex",
    lib: 6,
    reason: 121,
    dynamic_reason: false,
};

/// `EVP_PBE_CipherInit_ex` at `crypto/evp/evp_pbe.c:134` (EVP_R_UNKNOWN_CIPHER).
pub(crate) const EVP_PBE_134: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_pbe.c",
    line: 134,
    func: c"EVP_PBE_CipherInit_ex",
    lib: 6,
    reason: 160,
    dynamic_reason: false,
};

/// `EVP_PBE_CipherInit_ex` at `crypto/evp/evp_pbe.c:150` (EVP_R_UNKNOWN_DIGEST).
pub(crate) const EVP_PBE_150: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_pbe.c",
    line: 150,
    func: c"EVP_PBE_CipherInit_ex",
    lib: 6,
    reason: 161,
    dynamic_reason: false,
};

/// `EVP_PBE_alg_add_type` at `crypto/evp/evp_pbe.c:207` (ERR_R_CRYPTO_LIB).
pub(crate) const EVP_PBE_207: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_pbe.c",
    line: 207,
    func: c"EVP_PBE_alg_add_type",
    lib: 6,
    reason: 524303,
    dynamic_reason: false,
};

/// `EVP_PBE_alg_add_type` at `crypto/evp/evp_pbe.c:222` (ERR_R_CRYPTO_LIB).
pub(crate) const EVP_PBE_222: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_pbe.c",
    line: 222,
    func: c"EVP_PBE_alg_add_type",
    lib: 6,
    reason: 524303,
    dynamic_reason: false,
};

/// `evp_pkcs82pkey_legacy` at `crypto/evp/evp_pkey.c:41` (ERR_R_EVP_LIB).
pub(crate) const EVP_PKEY_41: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_pkey.c",
    line: 41,
    func: c"evp_pkcs82pkey_legacy",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `evp_pkcs82pkey_legacy` at `crypto/evp/evp_pkey.c:47` (EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM).
pub(crate) const EVP_PKEY_47: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_pkey.c",
    line: 47,
    func: c"evp_pkcs82pkey_legacy",
    lib: 6,
    reason: 118,
    dynamic_reason: false,
};

/// `evp_pkcs82pkey_legacy` at `crypto/evp/evp_pkey.c:57` (EVP_R_PRIVATE_KEY_DECODE_ERROR).
pub(crate) const EVP_PKEY_57: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_pkey.c",
    line: 57,
    func: c"evp_pkcs82pkey_legacy",
    lib: 6,
    reason: 145,
    dynamic_reason: false,
};

/// `evp_pkcs82pkey_legacy` at `crypto/evp/evp_pkey.c:61` (EVP_R_METHOD_NOT_SUPPORTED).
pub(crate) const EVP_PKEY_61: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_pkey.c",
    line: 61,
    func: c"evp_pkcs82pkey_legacy",
    lib: 6,
    reason: 144,
    dynamic_reason: false,
};

/// `EVP_PKEY2PKCS8` at `crypto/evp/evp_pkey.c:160` (ERR_R_ASN1_LIB).
pub(crate) const EVP_PKEY_160: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_pkey.c",
    line: 160,
    func: c"EVP_PKEY2PKCS8",
    lib: 6,
    reason: 524301,
    dynamic_reason: false,
};

/// `EVP_PKEY2PKCS8` at `crypto/evp/evp_pkey.c:167` (EVP_R_PRIVATE_KEY_ENCODE_ERROR).
pub(crate) const EVP_PKEY_167: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_pkey.c",
    line: 167,
    func: c"EVP_PKEY2PKCS8",
    lib: 6,
    reason: 146,
    dynamic_reason: false,
};

/// `EVP_PKEY2PKCS8` at `crypto/evp/evp_pkey.c:171` (EVP_R_METHOD_NOT_SUPPORTED).
pub(crate) const EVP_PKEY_171: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_pkey.c",
    line: 171,
    func: c"EVP_PKEY2PKCS8",
    lib: 6,
    reason: 144,
    dynamic_reason: false,
};

/// `EVP_PKEY2PKCS8` at `crypto/evp/evp_pkey.c:175` (EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM).
pub(crate) const EVP_PKEY_175: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_pkey.c",
    line: 175,
    func: c"EVP_PKEY2PKCS8",
    lib: 6,
    reason: 118,
    dynamic_reason: false,
};

/// `EVP_RAND_enable_locking` at `crypto/evp/evp_rand.c:98` (EVP_R_LOCKING_NOT_SUPPORTED).
pub(crate) const EVP_RAND_98: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_rand.c",
    line: 98,
    func: c"EVP_RAND_enable_locking",
    lib: 6,
    reason: 213,
    dynamic_reason: false,
};

/// `evp_rand_from_algorithm` at `crypto/evp/evp_rand.c:129` (ERR_R_EVP_LIB).
pub(crate) const EVP_RAND_129: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_rand.c",
    line: 129,
    func: c"evp_rand_from_algorithm",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `evp_rand_from_algorithm` at `crypto/evp/evp_rand.c:268` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const EVP_RAND_268: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_rand.c",
    line: 268,
    func: c"evp_rand_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_rand_from_algorithm` at `crypto/evp/evp_rand.c:274` (ERR_R_INTERNAL_ERROR).
pub(crate) const EVP_RAND_274: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_rand.c",
    line: 274,
    func: c"evp_rand_from_algorithm",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `EVP_RAND_CTX_new` at `crypto/evp/evp_rand.c:346` (EVP_R_INVALID_NULL_ALGORITHM).
pub(crate) const EVP_RAND_346: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_rand.c",
    line: 346,
    func: c"EVP_RAND_CTX_new",
    lib: 6,
    reason: 218,
    dynamic_reason: false,
};

/// `EVP_RAND_CTX_new` at `crypto/evp/evp_rand.c:359` (ERR_R_INTERNAL_ERROR).
pub(crate) const EVP_RAND_359: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_rand.c",
    line: 359,
    func: c"EVP_RAND_CTX_new",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `EVP_RAND_CTX_new` at `crypto/evp/evp_rand.c:371` (ERR_R_EVP_LIB).
pub(crate) const EVP_RAND_371: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_rand.c",
    line: 371,
    func: c"EVP_RAND_CTX_new",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `evp_rand_generate_locked` at `crypto/evp/evp_rand.c:562` (EVP_R_UNABLE_TO_GET_MAXIMUM_REQUEST_SIZE).
pub(crate) const EVP_RAND_562: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_rand.c",
    line: 562,
    func: c"evp_rand_generate_locked",
    lib: 6,
    reason: 215,
    dynamic_reason: false,
};

/// `evp_rand_generate_locked` at `crypto/evp/evp_rand.c:569` (EVP_R_GENERATE_ERROR).
pub(crate) const EVP_RAND_569: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_rand.c",
    line: 569,
    func: c"evp_rand_generate_locked",
    lib: 6,
    reason: 214,
    dynamic_reason: false,
};

/// `EVP_RAND_nonce` at `crypto/evp/evp_rand.c:656` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const EVP_RAND_656: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_rand.c",
    line: 656,
    func: c"EVP_RAND_nonce",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `geterr` at `crypto/evp/evp_utils.c:65` (EVP_R_CANNOT_GET_PARAMETERS).
pub(crate) const EVP_UTILS_65: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_utils.c",
    line: 65,
    func: c"geterr",
    lib: 6,
    reason: 197,
    dynamic_reason: false,
};

/// `seterr` at `crypto/evp/evp_utils.c:70` (EVP_R_CANNOT_SET_PARAMETERS).
pub(crate) const EVP_UTILS_70: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/evp_utils.c",
    line: 70,
    func: c"seterr",
    lib: 6,
    reason: 198,
    dynamic_reason: false,
};

/// `evp_keyexch_from_algorithm` at `crypto/evp/exchange.c:59` (ERR_R_EVP_LIB).
pub(crate) const EXCHANGE_59: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 59,
    func: c"evp_keyexch_from_algorithm",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `evp_keyexch_from_algorithm` at `crypto/evp/exchange.c:150` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const EXCHANGE_150: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 150,
    func: c"evp_keyexch_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_init_ex` at `crypto/evp/exchange.c:225` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const EXCHANGE_225: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 225,
    func: c"EVP_PKEY_derive_init_ex",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_init_ex` at `crypto/evp/exchange.c:249` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EXCHANGE_249: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 249,
    func: c"EVP_PKEY_derive_init_ex",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_init_ex` at `crypto/evp/exchange.c:261` (ERR_R_INTERNAL_ERROR).
pub(crate) const EXCHANGE_261: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 261,
    func: c"EVP_PKEY_derive_init_ex",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_init_ex` at `crypto/evp/exchange.c:268` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EXCHANGE_268: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 268,
    func: c"EVP_PKEY_derive_init_ex",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_init_ex` at `crypto/evp/exchange.c:355` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const EXCHANGE_355: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 355,
    func: c"EVP_PKEY_derive_init_ex",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_init_ex` at `crypto/evp/exchange.c:379` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const EXCHANGE_379: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 379,
    func: c"EVP_PKEY_derive_init_ex",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_set_peer_ex` at `crypto/evp/exchange.c:402` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const EXCHANGE_402: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 402,
    func: c"EVP_PKEY_derive_set_peer_ex",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_set_peer_ex` at `crypto/evp/exchange.c:410` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const EXCHANGE_410: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 410,
    func: c"EVP_PKEY_derive_set_peer_ex",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_set_peer_ex` at `crypto/evp/exchange.c:464` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const EXCHANGE_464: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 464,
    func: c"EVP_PKEY_derive_set_peer_ex",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_set_peer_ex` at `crypto/evp/exchange.c:470` (EVP_R_OPERATION_NOT_INITIALIZED).
pub(crate) const EXCHANGE_470: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 470,
    func: c"EVP_PKEY_derive_set_peer_ex",
    lib: 6,
    reason: 151,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_set_peer_ex` at `crypto/evp/exchange.c:483` (EVP_R_NO_KEY_SET).
pub(crate) const EXCHANGE_483: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 483,
    func: c"EVP_PKEY_derive_set_peer_ex",
    lib: 6,
    reason: 154,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_set_peer_ex` at `crypto/evp/exchange.c:488` (EVP_R_DIFFERENT_KEY_TYPES).
pub(crate) const EXCHANGE_488: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 488,
    func: c"EVP_PKEY_derive_set_peer_ex",
    lib: 6,
    reason: 101,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_set_peer_ex` at `crypto/evp/exchange.c:500` (EVP_R_DIFFERENT_PARAMETERS).
pub(crate) const EXCHANGE_500: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 500,
    func: c"EVP_PKEY_derive_set_peer_ex",
    lib: 6,
    reason: 153,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive` at `crypto/evp/exchange.c:529` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const EXCHANGE_529: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 529,
    func: c"EVP_PKEY_derive",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive` at `crypto/evp/exchange.c:534` (EVP_R_OPERATION_NOT_INITIALIZED).
pub(crate) const EXCHANGE_534: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 534,
    func: c"EVP_PKEY_derive",
    lib: 6,
    reason: 151,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive` at `crypto/evp/exchange.c:547` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const EXCHANGE_547: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 547,
    func: c"EVP_PKEY_derive",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_SKEY` at `crypto/evp/exchange.c:562` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const EXCHANGE_562: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 562,
    func: c"EVP_PKEY_derive_SKEY",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_SKEY` at `crypto/evp/exchange.c:567` (EVP_R_OPERATION_NOT_INITIALIZED).
pub(crate) const EXCHANGE_567: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 567,
    func: c"EVP_PKEY_derive_SKEY",
    lib: 6,
    reason: 151,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_SKEY` at `crypto/evp/exchange.c:572` (ERR_R_UNSUPPORTED).
pub(crate) const EXCHANGE_572: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 572,
    func: c"EVP_PKEY_derive_SKEY",
    lib: 524294,
    reason: 524556,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_SKEY` at `crypto/evp/exchange.c:589` (ERR_R_FETCH_FAILED).
pub(crate) const EXCHANGE_589: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 589,
    func: c"EVP_PKEY_derive_SKEY",
    lib: 6,
    reason: 524557,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_SKEY` at `crypto/evp/exchange.c:601` (ERR_R_UNSUPPORTED).
pub(crate) const EXCHANGE_601: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 601,
    func: c"EVP_PKEY_derive_SKEY",
    lib: 524294,
    reason: 524556,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_SKEY` at `crypto/evp/exchange.c:607` (ERR_R_CRYPTO_LIB).
pub(crate) const EXCHANGE_607: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 607,
    func: c"EVP_PKEY_derive_SKEY",
    lib: 524294,
    reason: 524303,
    dynamic_reason: false,
};

/// `EVP_PKEY_derive_SKEY` at `crypto/evp/exchange.c:619` (ERR_R_INTERNAL_ERROR).
pub(crate) const EXCHANGE_619: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/exchange.c",
    line: 619,
    func: c"EVP_PKEY_derive_SKEY",
    lib: 524294,
    reason: 786691,
    dynamic_reason: false,
};

/// `EVP_KDF_CTX_new` at `crypto/evp/kdf_lib.c:35` (ERR_R_EVP_LIB).
pub(crate) const KDF_LIB_35: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kdf_lib.c",
    line: 35,
    func: c"EVP_KDF_CTX_new",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `EVP_KDF_CTX_dup` at `crypto/evp/kdf_lib.c:69` (ERR_R_EVP_LIB).
pub(crate) const KDF_LIB_69: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kdf_lib.c",
    line: 69,
    func: c"EVP_KDF_CTX_dup",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `EVP_KDF_derive_SKEY` at `crypto/evp/kdf_lib.c:211` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const KDF_LIB_211: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kdf_lib.c",
    line: 211,
    func: c"EVP_KDF_derive_SKEY",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_KDF_derive_SKEY` at `crypto/evp/kdf_lib.c:230` (ERR_R_FETCH_FAILED).
pub(crate) const KDF_LIB_230: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kdf_lib.c",
    line: 230,
    func: c"EVP_KDF_derive_SKEY",
    lib: 6,
    reason: 524557,
    dynamic_reason: false,
};

/// `EVP_KDF_derive_SKEY` at `crypto/evp/kdf_lib.c:241` (ERR_R_UNSUPPORTED).
pub(crate) const KDF_LIB_241: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kdf_lib.c",
    line: 241,
    func: c"EVP_KDF_derive_SKEY",
    lib: 524294,
    reason: 524556,
    dynamic_reason: false,
};

/// `evp_kdf_from_algorithm` at `crypto/evp/kdf_meth.c:67` (ERR_R_EVP_LIB).
pub(crate) const KDF_METH_67: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kdf_meth.c",
    line: 67,
    func: c"evp_kdf_from_algorithm",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `evp_kdf_from_algorithm` at `crypto/evp/kdf_meth.c:154` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const KDF_METH_154: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kdf_meth.c",
    line: 154,
    func: c"evp_kdf_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_kem_init` at `crypto/evp/kem.c:42` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const KEM_42: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kem.c",
    line: 42,
    func: c"evp_kem_init",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_kem_init` at `crypto/evp/kem.c:50` (EVP_R_NO_KEY_SET).
pub(crate) const KEM_50: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kem.c",
    line: 50,
    func: c"evp_kem_init",
    lib: 6,
    reason: 154,
    dynamic_reason: false,
};

/// `evp_kem_init` at `crypto/evp/kem.c:54` (EVP_R_DIFFERENT_KEY_TYPES).
pub(crate) const KEM_54: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kem.c",
    line: 54,
    func: c"evp_kem_init",
    lib: 6,
    reason: 101,
    dynamic_reason: false,
};

/// `evp_kem_init` at `crypto/evp/kem.c:62` (ERR_R_INTERNAL_ERROR).
pub(crate) const KEM_62: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kem.c",
    line: 62,
    func: c"evp_kem_init",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `evp_kem_init` at `crypto/evp/kem.c:68` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const KEM_68: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kem.c",
    line: 68,
    func: c"evp_kem_init",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_kem_init` at `crypto/evp/kem.c:116` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const KEM_116: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kem.c",
    line: 116,
    func: c"evp_kem_init",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `evp_kem_init` at `crypto/evp/kem.c:146` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const KEM_146: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kem.c",
    line: 146,
    func: c"evp_kem_init",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_kem_init` at `crypto/evp/kem.c:157` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const KEM_157: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kem.c",
    line: 157,
    func: c"evp_kem_init",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_kem_init` at `crypto/evp/kem.c:165` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const KEM_165: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kem.c",
    line: 165,
    func: c"evp_kem_init",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_kem_init` at `crypto/evp/kem.c:177` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const KEM_177: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kem.c",
    line: 177,
    func: c"evp_kem_init",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `evp_kem_init` at `crypto/evp/kem.c:189` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const KEM_189: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kem.c",
    line: 189,
    func: c"evp_kem_init",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `evp_kem_init` at `crypto/evp/kem.c:195` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const KEM_195: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kem.c",
    line: 195,
    func: c"evp_kem_init",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `EVP_PKEY_encapsulate` at `crypto/evp/kem.c:234` (EVP_R_OPERATION_NOT_INITIALIZED).
pub(crate) const KEM_234: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kem.c",
    line: 234,
    func: c"EVP_PKEY_encapsulate",
    lib: 6,
    reason: 151,
    dynamic_reason: false,
};

/// `EVP_PKEY_encapsulate` at `crypto/evp/kem.c:239` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const KEM_239: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kem.c",
    line: 239,
    func: c"EVP_PKEY_encapsulate",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_decapsulate` at `crypto/evp/kem.c:273` (EVP_R_OPERATION_NOT_INITIALIZED).
pub(crate) const KEM_273: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kem.c",
    line: 273,
    func: c"EVP_PKEY_decapsulate",
    lib: 6,
    reason: 151,
    dynamic_reason: false,
};

/// `EVP_PKEY_decapsulate` at `crypto/evp/kem.c:278` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const KEM_278: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kem.c",
    line: 278,
    func: c"EVP_PKEY_decapsulate",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `evp_kem_from_algorithm` at `crypto/evp/kem.c:312` (ERR_R_EVP_LIB).
pub(crate) const KEM_312: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kem.c",
    line: 312,
    func: c"evp_kem_from_algorithm",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `evp_kem_from_algorithm` at `crypto/evp/kem.c:423` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const KEM_423: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/kem.c",
    line: 423,
    func: c"evp_kem_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_keymgmt_util_try_import` at `crypto/evp/keymgmt_lib.c:37` (ERR_R_EVP_LIB).
pub(crate) const KEYMGMT_LIB_37: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/keymgmt_lib.c",
    line: 37,
    func: c"evp_keymgmt_util_try_import",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `evp_keymgmt_util_assign_pkey` at `crypto/evp/keymgmt_lib.c:65` (ERR_R_INTERNAL_ERROR).
pub(crate) const KEYMGMT_LIB_65: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/keymgmt_lib.c",
    line: 65,
    func: c"evp_keymgmt_util_assign_pkey",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `evp_keymgmt_util_match` at `crypto/evp/keymgmt_lib.c:388` (EVP_R_DIFFERENT_KEY_TYPES).
pub(crate) const KEYMGMT_LIB_388: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/keymgmt_lib.c",
    line: 388,
    func: c"evp_keymgmt_util_match",
    lib: 6,
    reason: 101,
    dynamic_reason: false,
};

/// `evp_keymgmt_util_copy` at `crypto/evp/keymgmt_lib.c:491` (EVP_R_DIFFERENT_KEY_TYPES).
pub(crate) const KEYMGMT_LIB_491: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/keymgmt_lib.c",
    line: 491,
    func: c"evp_keymgmt_util_copy",
    lib: 6,
    reason: 101,
    dynamic_reason: false,
};

/// `keymgmt_from_algorithm` at `crypto/evp/keymgmt_meth.c:252` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const KEYMGMT_METH_252: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/keymgmt_meth.c",
    line: 252,
    func: c"keymgmt_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_keymgmt_gen` at `crypto/evp/keymgmt_meth.c:450` (EVP_R_PROVIDER_KEYMGMT_NOT_SUPPORTED).
pub(crate) const KEYMGMT_METH_450: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/keymgmt_meth.c",
    line: 450,
    func: c"evp_keymgmt_gen",
    lib: 6,
    reason: 236,
    dynamic_reason: false,
};

/// `evp_keymgmt_gen` at `crypto/evp/keymgmt_meth.c:458` (EVP_R_PROVIDER_KEYMGMT_FAILURE).
pub(crate) const KEYMGMT_METH_458: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/keymgmt_meth.c",
    line: 458,
    func: c"evp_keymgmt_gen",
    lib: 6,
    reason: 233,
    dynamic_reason: false,
};

/// `update` at `crypto/evp/m_sigver.c:21` (EVP_R_ONLY_ONESHOT_SUPPORTED).
pub(crate) const M_SIGVER_21: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 21,
    func: c"update",
    lib: 6,
    reason: 177,
    dynamic_reason: false,
};

/// `do_sigver_init` at `crypto/evp/m_sigver.c:87` (EVP_R_NO_KEY_SET).
pub(crate) const M_SIGVER_87: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 87,
    func: c"do_sigver_init",
    lib: 6,
    reason: 154,
    dynamic_reason: false,
};

/// `do_sigver_init` at `crypto/evp/m_sigver.c:105` (ERR_R_INTERNAL_ERROR).
pub(crate) const M_SIGVER_105: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 105,
    func: c"do_sigver_init",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `do_sigver_init` at `crypto/evp/m_sigver.c:112` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const M_SIGVER_112: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 112,
    func: c"do_sigver_init",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `do_sigver_init` at `crypto/evp/m_sigver.c:187` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const M_SIGVER_187: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 187,
    func: c"do_sigver_init",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `do_sigver_init` at `crypto/evp/m_sigver.c:201` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const M_SIGVER_201: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 201,
    func: c"do_sigver_init",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `do_sigver_init` at `crypto/evp/m_sigver.c:247` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const M_SIGVER_247: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 247,
    func: c"do_sigver_init",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `do_sigver_init` at `crypto/evp/m_sigver.c:258` (EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED).
pub(crate) const M_SIGVER_258: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 258,
    func: c"do_sigver_init",
    lib: 6,
    reason: 237,
    dynamic_reason: false,
};

/// `do_sigver_init` at `crypto/evp/m_sigver.c:266` (EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED).
pub(crate) const M_SIGVER_266: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 266,
    func: c"do_sigver_init",
    lib: 6,
    reason: 237,
    dynamic_reason: false,
};

/// `do_sigver_init` at `crypto/evp/m_sigver.c:281` (EVP_R_NO_DEFAULT_DIGEST).
pub(crate) const M_SIGVER_281: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 281,
    func: c"do_sigver_init",
    lib: 6,
    reason: 158,
    dynamic_reason: false,
};

/// `do_sigver_init` at `crypto/evp/m_sigver.c:282` (EVP_R_PROVIDER_SIGNATURE_FAILURE).
pub(crate) const M_SIGVER_282: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 282,
    func: c"do_sigver_init",
    lib: 6,
    reason: 234,
    dynamic_reason: false,
};

/// `do_sigver_init` at `crypto/evp/m_sigver.c:305` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const M_SIGVER_305: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 305,
    func: c"do_sigver_init",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `do_sigver_init` at `crypto/evp/m_sigver.c:318` (EVP_R_NO_DEFAULT_DIGEST).
pub(crate) const M_SIGVER_318: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 318,
    func: c"do_sigver_init",
    lib: 6,
    reason: 158,
    dynamic_reason: false,
};

/// `EVP_DigestSignUpdate` at `crypto/evp/m_sigver.c:411` (EVP_R_UPDATE_ERROR).
pub(crate) const M_SIGVER_411: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 411,
    func: c"EVP_DigestSignUpdate",
    lib: 6,
    reason: 189,
    dynamic_reason: false,
};

/// `EVP_DigestSignUpdate` at `crypto/evp/m_sigver.c:424` (EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED).
pub(crate) const M_SIGVER_424: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 424,
    func: c"EVP_DigestSignUpdate",
    lib: 6,
    reason: 237,
    dynamic_reason: false,
};

/// `EVP_DigestSignUpdate` at `crypto/evp/m_sigver.c:432` (EVP_R_PROVIDER_SIGNATURE_FAILURE).
pub(crate) const M_SIGVER_432: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 432,
    func: c"EVP_DigestSignUpdate",
    lib: 6,
    reason: 234,
    dynamic_reason: false,
};

/// `EVP_DigestSignUpdate` at `crypto/evp/m_sigver.c:440` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const M_SIGVER_440: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 440,
    func: c"EVP_DigestSignUpdate",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `EVP_DigestVerifyUpdate` at `crypto/evp/m_sigver.c:461` (EVP_R_UPDATE_ERROR).
pub(crate) const M_SIGVER_461: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 461,
    func: c"EVP_DigestVerifyUpdate",
    lib: 6,
    reason: 189,
    dynamic_reason: false,
};

/// `EVP_DigestVerifyUpdate` at `crypto/evp/m_sigver.c:474` (EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED).
pub(crate) const M_SIGVER_474: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 474,
    func: c"EVP_DigestVerifyUpdate",
    lib: 6,
    reason: 237,
    dynamic_reason: false,
};

/// `EVP_DigestVerifyUpdate` at `crypto/evp/m_sigver.c:482` (EVP_R_PROVIDER_SIGNATURE_FAILURE).
pub(crate) const M_SIGVER_482: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 482,
    func: c"EVP_DigestVerifyUpdate",
    lib: 6,
    reason: 234,
    dynamic_reason: false,
};

/// `EVP_DigestSignFinal` at `crypto/evp/m_sigver.c:509` (EVP_R_FINAL_ERROR).
pub(crate) const M_SIGVER_509: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 509,
    func: c"EVP_DigestSignFinal",
    lib: 6,
    reason: 188,
    dynamic_reason: false,
};

/// `EVP_DigestSignFinal` at `crypto/evp/m_sigver.c:522` (EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED).
pub(crate) const M_SIGVER_522: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 522,
    func: c"EVP_DigestSignFinal",
    lib: 6,
    reason: 237,
    dynamic_reason: false,
};

/// `EVP_DigestSignFinal` at `crypto/evp/m_sigver.c:538` (EVP_R_PROVIDER_SIGNATURE_FAILURE).
pub(crate) const M_SIGVER_538: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 538,
    func: c"EVP_DigestSignFinal",
    lib: 6,
    reason: 234,
    dynamic_reason: false,
};

/// `EVP_DigestSignFinal` at `crypto/evp/m_sigver.c:549` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const M_SIGVER_549: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 549,
    func: c"EVP_DigestSignFinal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `EVP_DigestSign` at `crypto/evp/m_sigver.c:628` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const M_SIGVER_628: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 628,
    func: c"EVP_DigestSign",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `EVP_DigestSign` at `crypto/evp/m_sigver.c:633` (EVP_R_FINAL_ERROR).
pub(crate) const M_SIGVER_633: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 633,
    func: c"EVP_DigestSign",
    lib: 6,
    reason: 188,
    dynamic_reason: false,
};

/// `EVP_DigestSign` at `crypto/evp/m_sigver.c:651` (EVP_R_PROVIDER_SIGNATURE_FAILURE).
pub(crate) const M_SIGVER_651: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 651,
    func: c"EVP_DigestSign",
    lib: 6,
    reason: 234,
    dynamic_reason: false,
};

/// `EVP_DigestVerifyFinal` at `crypto/evp/m_sigver.c:679` (EVP_R_FINAL_ERROR).
pub(crate) const M_SIGVER_679: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 679,
    func: c"EVP_DigestVerifyFinal",
    lib: 6,
    reason: 188,
    dynamic_reason: false,
};

/// `EVP_DigestVerifyFinal` at `crypto/evp/m_sigver.c:692` (EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED).
pub(crate) const M_SIGVER_692: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 692,
    func: c"EVP_DigestVerifyFinal",
    lib: 6,
    reason: 237,
    dynamic_reason: false,
};

/// `EVP_DigestVerifyFinal` at `crypto/evp/m_sigver.c:707` (EVP_R_PROVIDER_SIGNATURE_FAILURE).
pub(crate) const M_SIGVER_707: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 707,
    func: c"EVP_DigestVerifyFinal",
    lib: 6,
    reason: 234,
    dynamic_reason: false,
};

/// `EVP_DigestVerifyFinal` at `crypto/evp/m_sigver.c:718` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const M_SIGVER_718: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 718,
    func: c"EVP_DigestVerifyFinal",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `EVP_DigestVerify` at `crypto/evp/m_sigver.c:764` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const M_SIGVER_764: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 764,
    func: c"EVP_DigestVerify",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `EVP_DigestVerify` at `crypto/evp/m_sigver.c:769` (EVP_R_FINAL_ERROR).
pub(crate) const M_SIGVER_769: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 769,
    func: c"EVP_DigestVerify",
    lib: 6,
    reason: 188,
    dynamic_reason: false,
};

/// `EVP_DigestVerify` at `crypto/evp/m_sigver.c:785` (EVP_R_PROVIDER_SIGNATURE_FAILURE).
pub(crate) const M_SIGVER_785: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/m_sigver.c",
    line: 785,
    func: c"EVP_DigestVerify",
    lib: 6,
    reason: 234,
    dynamic_reason: false,
};

/// `EVP_MAC_CTX_new` at `crypto/evp/mac_lib.c:31` (ERR_R_EVP_LIB).
pub(crate) const MAC_LIB_31: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/mac_lib.c",
    line: 31,
    func: c"EVP_MAC_CTX_new",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `EVP_MAC_CTX_dup` at `crypto/evp/mac_lib.c:63` (ERR_R_EVP_LIB).
pub(crate) const MAC_LIB_63: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/mac_lib.c",
    line: 63,
    func: c"EVP_MAC_CTX_dup",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `EVP_MAC_init` at `crypto/evp/mac_lib.c:119` (ERR_R_UNSUPPORTED).
pub(crate) const MAC_LIB_119: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/mac_lib.c",
    line: 119,
    func: c"EVP_MAC_init",
    lib: 524294,
    reason: 524556,
    dynamic_reason: false,
};

/// `EVP_MAC_init_SKEY` at `crypto/evp/mac_lib.c:130` (ERR_R_UNSUPPORTED).
pub(crate) const MAC_LIB_130: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/mac_lib.c",
    line: 130,
    func: c"EVP_MAC_init_SKEY",
    lib: 524294,
    reason: 524556,
    dynamic_reason: false,
};

/// `evp_mac_final` at `crypto/evp/mac_lib.c:150` (EVP_R_INVALID_NULL_ALGORITHM).
pub(crate) const MAC_LIB_150: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/mac_lib.c",
    line: 150,
    func: c"evp_mac_final",
    lib: 6,
    reason: 218,
    dynamic_reason: false,
};

/// `evp_mac_final` at `crypto/evp/mac_lib.c:154` (EVP_R_FINAL_ERROR).
pub(crate) const MAC_LIB_154: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/mac_lib.c",
    line: 154,
    func: c"evp_mac_final",
    lib: 6,
    reason: 188,
    dynamic_reason: false,
};

/// `evp_mac_final` at `crypto/evp/mac_lib.c:161` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const MAC_LIB_161: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/mac_lib.c",
    line: 161,
    func: c"evp_mac_final",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `evp_mac_final` at `crypto/evp/mac_lib.c:168` (EVP_R_BUFFER_TOO_SMALL).
pub(crate) const MAC_LIB_168: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/mac_lib.c",
    line: 168,
    func: c"evp_mac_final",
    lib: 6,
    reason: 155,
    dynamic_reason: false,
};

/// `evp_mac_final` at `crypto/evp/mac_lib.c:176` (EVP_R_SETTING_XOF_FAILED).
pub(crate) const MAC_LIB_176: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/mac_lib.c",
    line: 176,
    func: c"evp_mac_final",
    lib: 6,
    reason: 227,
    dynamic_reason: false,
};

/// `EVP_Q_mac` at `crypto/evp/mac_lib.c:283` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const MAC_LIB_283: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/mac_lib.c",
    line: 283,
    func: c"EVP_Q_mac",
    lib: 6,
    reason: 524550,
    dynamic_reason: false,
};

/// `evp_mac_from_algorithm` at `crypto/evp/mac_meth.c:66` (ERR_R_EVP_LIB).
pub(crate) const MAC_METH_66: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/mac_meth.c",
    line: 66,
    func: c"evp_mac_from_algorithm",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `evp_mac_from_algorithm` at `crypto/evp/mac_meth.c:159` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const MAC_METH_159: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/mac_meth.c",
    line: 159,
    func: c"evp_mac_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `PKCS5_PBE_keyivgen_ex` at `crypto/evp/p5_crpt.c:46` (EVP_R_DECODE_ERROR).
pub(crate) const P5_CRPT_46: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p5_crpt.c",
    line: 46,
    func: c"PKCS5_PBE_keyivgen_ex",
    lib: 6,
    reason: 114,
    dynamic_reason: false,
};

/// `PKCS5_PBE_keyivgen_ex` at `crypto/evp/p5_crpt.c:52` (EVP_R_DECODE_ERROR).
pub(crate) const P5_CRPT_52: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p5_crpt.c",
    line: 52,
    func: c"PKCS5_PBE_keyivgen_ex",
    lib: 6,
    reason: 114,
    dynamic_reason: false,
};

/// `PKCS5_PBE_keyivgen_ex` at `crypto/evp/p5_crpt.c:58` (EVP_R_INVALID_IV_LENGTH).
pub(crate) const P5_CRPT_58: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p5_crpt.c",
    line: 58,
    func: c"PKCS5_PBE_keyivgen_ex",
    lib: 6,
    reason: 194,
    dynamic_reason: false,
};

/// `PKCS5_PBE_keyivgen_ex` at `crypto/evp/p5_crpt.c:63` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const P5_CRPT_63: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p5_crpt.c",
    line: 63,
    func: c"PKCS5_PBE_keyivgen_ex",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `PKCS5_v2_PBE_keyivgen_ex` at `crypto/evp/p5_crpt2.c:128` (EVP_R_DECODE_ERROR).
pub(crate) const P5_CRPT2_128: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p5_crpt2.c",
    line: 128,
    func: c"PKCS5_v2_PBE_keyivgen_ex",
    lib: 6,
    reason: 114,
    dynamic_reason: false,
};

/// `PKCS5_v2_PBE_keyivgen_ex` at `crypto/evp/p5_crpt2.c:135` (EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION).
pub(crate) const P5_CRPT2_135: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p5_crpt2.c",
    line: 135,
    func: c"PKCS5_v2_PBE_keyivgen_ex",
    lib: 6,
    reason: 124,
    dynamic_reason: false,
};

/// `PKCS5_v2_PBE_keyivgen_ex` at `crypto/evp/p5_crpt2.c:143` (EVP_R_UNSUPPORTED_CIPHER).
pub(crate) const P5_CRPT2_143: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p5_crpt2.c",
    line: 143,
    func: c"PKCS5_v2_PBE_keyivgen_ex",
    lib: 6,
    reason: 107,
    dynamic_reason: false,
};

/// `PKCS5_v2_PBE_keyivgen_ex` at `crypto/evp/p5_crpt2.c:155` (EVP_R_UNSUPPORTED_CIPHER).
pub(crate) const P5_CRPT2_155: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p5_crpt2.c",
    line: 155,
    func: c"PKCS5_v2_PBE_keyivgen_ex",
    lib: 6,
    reason: 107,
    dynamic_reason: false,
};

/// `PKCS5_v2_PBE_keyivgen_ex` at `crypto/evp/p5_crpt2.c:164` (EVP_R_CIPHER_PARAMETER_ERROR).
pub(crate) const P5_CRPT2_164: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p5_crpt2.c",
    line: 164,
    func: c"PKCS5_v2_PBE_keyivgen_ex",
    lib: 6,
    reason: 122,
    dynamic_reason: false,
};

/// `PKCS5_v2_PBKDF2_keyivgen_ex` at `crypto/evp/p5_crpt2.c:196` (EVP_R_NO_CIPHER_SET).
pub(crate) const P5_CRPT2_196: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p5_crpt2.c",
    line: 196,
    func: c"PKCS5_v2_PBKDF2_keyivgen_ex",
    lib: 6,
    reason: 131,
    dynamic_reason: false,
};

/// `PKCS5_v2_PBKDF2_keyivgen_ex` at `crypto/evp/p5_crpt2.c:207` (EVP_R_DECODE_ERROR).
pub(crate) const P5_CRPT2_207: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p5_crpt2.c",
    line: 207,
    func: c"PKCS5_v2_PBKDF2_keyivgen_ex",
    lib: 6,
    reason: 114,
    dynamic_reason: false,
};

/// `PKCS5_v2_PBKDF2_keyivgen_ex` at `crypto/evp/p5_crpt2.c:213` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const P5_CRPT2_213: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p5_crpt2.c",
    line: 213,
    func: c"PKCS5_v2_PBKDF2_keyivgen_ex",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `PKCS5_v2_PBKDF2_keyivgen_ex` at `crypto/evp/p5_crpt2.c:221` (EVP_R_UNSUPPORTED_KEYLENGTH).
pub(crate) const P5_CRPT2_221: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p5_crpt2.c",
    line: 221,
    func: c"PKCS5_v2_PBKDF2_keyivgen_ex",
    lib: 6,
    reason: 123,
    dynamic_reason: false,
};

/// `PKCS5_v2_PBKDF2_keyivgen_ex` at `crypto/evp/p5_crpt2.c:231` (EVP_R_UNSUPPORTED_PRF).
pub(crate) const P5_CRPT2_231: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p5_crpt2.c",
    line: 231,
    func: c"PKCS5_v2_PBKDF2_keyivgen_ex",
    lib: 6,
    reason: 125,
    dynamic_reason: false,
};

/// `PKCS5_v2_PBKDF2_keyivgen_ex` at `crypto/evp/p5_crpt2.c:241` (EVP_R_UNSUPPORTED_PRF).
pub(crate) const P5_CRPT2_241: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p5_crpt2.c",
    line: 241,
    func: c"PKCS5_v2_PBKDF2_keyivgen_ex",
    lib: 6,
    reason: 125,
    dynamic_reason: false,
};

/// `PKCS5_v2_PBKDF2_keyivgen_ex` at `crypto/evp/p5_crpt2.c:247` (EVP_R_UNSUPPORTED_SALT_TYPE).
pub(crate) const P5_CRPT2_247: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p5_crpt2.c",
    line: 247,
    func: c"PKCS5_v2_PBKDF2_keyivgen_ex",
    lib: 6,
    reason: 126,
    dynamic_reason: false,
};

/// `EVP_PKEY_decrypt_old` at `crypto/evp/p_dec.c:28` (EVP_R_PUBLIC_KEY_NOT_RSA).
pub(crate) const P_DEC_28: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_dec.c",
    line: 28,
    func: c"EVP_PKEY_decrypt_old",
    lib: 6,
    reason: 106,
    dynamic_reason: false,
};

/// `EVP_PKEY_encrypt_old` at `crypto/evp/p_enc.c:28` (EVP_R_PUBLIC_KEY_NOT_RSA).
pub(crate) const P_ENC_28: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_enc.c",
    line: 28,
    func: c"EVP_PKEY_encrypt_old",
    lib: 6,
    reason: 106,
    dynamic_reason: false,
};

/// `evp_pkey_get0_RSA_int` at `crypto/evp/p_legacy.c:43` (EVP_R_EXPECTING_AN_RSA_KEY).
pub(crate) const P_LEGACY_43: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_legacy.c",
    line: 43,
    func: c"evp_pkey_get0_RSA_int",
    lib: 6,
    reason: 127,
    dynamic_reason: false,
};

/// `evp_pkey_get0_EC_KEY_int` at `crypto/evp/p_legacy.c:79` (EVP_R_EXPECTING_A_EC_KEY).
pub(crate) const P_LEGACY_79: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_legacy.c",
    line: 79,
    func: c"evp_pkey_get0_EC_KEY_int",
    lib: 6,
    reason: 142,
    dynamic_reason: false,
};

/// `EVP_PKEY_get_bits` at `crypto/evp/p_lib.c:71` (EVP_R_UNKNOWN_BITS).
pub(crate) const P_LIB_71: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 71,
    func: c"EVP_PKEY_get_bits",
    lib: 6,
    reason: 166,
    dynamic_reason: false,
};

/// `EVP_PKEY_get_security_bits` at `crypto/evp/p_lib.c:87` (EVP_R_UNKNOWN_SECURITY_BITS).
pub(crate) const P_LIB_87: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 87,
    func: c"EVP_PKEY_get_security_bits",
    lib: 6,
    reason: 168,
    dynamic_reason: false,
};

/// `EVP_PKEY_copy_parameters` at `crypto/evp/p_lib.c:180` (EVP_R_DIFFERENT_KEY_TYPES).
pub(crate) const P_LIB_180: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 180,
    func: c"EVP_PKEY_copy_parameters",
    lib: 6,
    reason: 101,
    dynamic_reason: false,
};

/// `EVP_PKEY_copy_parameters` at `crypto/evp/p_lib.c:187` (EVP_R_MISSING_PARAMETERS).
pub(crate) const P_LIB_187: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 187,
    func: c"EVP_PKEY_copy_parameters",
    lib: 6,
    reason: 103,
    dynamic_reason: false,
};

/// `EVP_PKEY_copy_parameters` at `crypto/evp/p_lib.c:195` (EVP_R_DIFFERENT_PARAMETERS).
pub(crate) const P_LIB_195: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 195,
    func: c"EVP_PKEY_copy_parameters",
    lib: 6,
    reason: 153,
    dynamic_reason: false,
};

/// `EVP_PKEY_copy_parameters` at `crypto/evp/p_lib.c:223` (EVP_R_DIFFERENT_KEY_TYPES).
pub(crate) const P_LIB_223: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 223,
    func: c"EVP_PKEY_copy_parameters",
    lib: 6,
    reason: 101,
    dynamic_reason: false,
};

/// `new_raw_key_int` at `crypto/evp/p_lib.c:471` (EVP_R_KEY_SETUP_FAILED).
pub(crate) const P_LIB_471: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 471,
    func: c"new_raw_key_int",
    lib: 6,
    reason: 180,
    dynamic_reason: false,
};

/// `new_raw_key_int` at `crypto/evp/p_lib.c:487` (ERR_R_EVP_LIB).
pub(crate) const P_LIB_487: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 487,
    func: c"new_raw_key_int",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `new_raw_key_int` at `crypto/evp/p_lib.c:501` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const P_LIB_501: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 501,
    func: c"new_raw_key_int",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `new_raw_key_int` at `crypto/evp/p_lib.c:506` (EVP_R_KEY_SETUP_FAILED).
pub(crate) const P_LIB_506: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 506,
    func: c"new_raw_key_int",
    lib: 6,
    reason: 180,
    dynamic_reason: false,
};

/// `new_raw_key_int` at `crypto/evp/p_lib.c:511` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const P_LIB_511: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 511,
    func: c"new_raw_key_int",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `new_raw_key_int` at `crypto/evp/p_lib.c:516` (EVP_R_KEY_SETUP_FAILED).
pub(crate) const P_LIB_516: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 516,
    func: c"new_raw_key_int",
    lib: 6,
    reason: 180,
    dynamic_reason: false,
};

/// `EVP_PKEY_get_raw_private_key` at `crypto/evp/p_lib.c:606` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const P_LIB_606: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 606,
    func: c"EVP_PKEY_get_raw_private_key",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_get_raw_private_key` at `crypto/evp/p_lib.c:611` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const P_LIB_611: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 611,
    func: c"EVP_PKEY_get_raw_private_key",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_get_raw_private_key` at `crypto/evp/p_lib.c:616` (EVP_R_GET_RAW_KEY_FAILED).
pub(crate) const P_LIB_616: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 616,
    func: c"EVP_PKEY_get_raw_private_key",
    lib: 6,
    reason: 182,
    dynamic_reason: false,
};

/// `EVP_PKEY_get_raw_public_key` at `crypto/evp/p_lib.c:638` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const P_LIB_638: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 638,
    func: c"EVP_PKEY_get_raw_public_key",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_get_raw_public_key` at `crypto/evp/p_lib.c:643` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const P_LIB_643: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 643,
    func: c"EVP_PKEY_get_raw_public_key",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_get_raw_public_key` at `crypto/evp/p_lib.c:648` (EVP_R_GET_RAW_KEY_FAILED).
pub(crate) const P_LIB_648: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 648,
    func: c"EVP_PKEY_get_raw_public_key",
    lib: 6,
    reason: 182,
    dynamic_reason: false,
};

/// `new_cmac_key_int` at `crypto/evp/p_lib.c:673` (EVP_R_KEY_SETUP_FAILED).
pub(crate) const P_LIB_673: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 673,
    func: c"new_cmac_key_int",
    lib: 6,
    reason: 180,
    dynamic_reason: false,
};

/// `new_cmac_key_int` at `crypto/evp/p_lib.c:682` (EVP_R_KEY_SETUP_FAILED).
pub(crate) const P_LIB_682: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 682,
    func: c"new_cmac_key_int",
    lib: 6,
    reason: 180,
    dynamic_reason: false,
};

/// `new_cmac_key_int` at `crypto/evp/p_lib.c:701` (EVP_R_KEY_SETUP_FAILED).
pub(crate) const P_LIB_701: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 701,
    func: c"new_cmac_key_int",
    lib: 6,
    reason: 180,
    dynamic_reason: false,
};

/// `new_cmac_key_int` at `crypto/evp/p_lib.c:710` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const P_LIB_710: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 710,
    func: c"new_cmac_key_int",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_set1_engine` at `crypto/evp/p_lib.c:736` (ERR_R_ENGINE_LIB).
pub(crate) const P_LIB_736: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 736,
    func: c"EVP_PKEY_set1_engine",
    lib: 6,
    reason: 524326,
    dynamic_reason: false,
};

/// `EVP_PKEY_set1_engine` at `crypto/evp/p_lib.c:741` (EVP_R_UNSUPPORTED_ALGORITHM).
pub(crate) const P_LIB_741: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 741,
    func: c"EVP_PKEY_set1_engine",
    lib: 6,
    reason: 156,
    dynamic_reason: false,
};

/// `EVP_PKEY_get0_hmac` at `crypto/evp/p_lib.c:840` (EVP_R_EXPECTING_AN_HMAC_KEY).
pub(crate) const P_LIB_840: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 840,
    func: c"EVP_PKEY_get0_hmac",
    lib: 6,
    reason: 174,
    dynamic_reason: false,
};

/// `EVP_PKEY_get0_poly1305` at `crypto/evp/p_lib.c:856` (EVP_R_EXPECTING_A_POLY1305_KEY).
pub(crate) const P_LIB_856: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 856,
    func: c"EVP_PKEY_get0_poly1305",
    lib: 6,
    reason: 164,
    dynamic_reason: false,
};

/// `EVP_PKEY_get0_siphash` at `crypto/evp/p_lib.c:874` (EVP_R_EXPECTING_A_SIPHASH_KEY).
pub(crate) const P_LIB_874: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 874,
    func: c"EVP_PKEY_get0_siphash",
    lib: 6,
    reason: 175,
    dynamic_reason: false,
};

/// `evp_pkey_get0_DSA_int` at `crypto/evp/p_lib.c:890` (EVP_R_EXPECTING_A_DSA_KEY).
pub(crate) const P_LIB_890: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 890,
    func: c"evp_pkey_get0_DSA_int",
    lib: 6,
    reason: 129,
    dynamic_reason: false,
};

/// `evp_pkey_get0_ECX_KEY` at `crypto/evp/p_lib.c:930` (EVP_R_EXPECTING_A_ECX_KEY).
pub(crate) const P_LIB_930: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 930,
    func: c"evp_pkey_get0_ECX_KEY",
    lib: 6,
    reason: 219,
    dynamic_reason: false,
};

/// `evp_pkey_get0_DH_int` at `crypto/evp/p_lib.c:1001` (EVP_R_EXPECTING_A_DH_KEY).
pub(crate) const P_LIB_1001: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 1001,
    func: c"evp_pkey_get0_DH_int",
    lib: 6,
    reason: 128,
    dynamic_reason: false,
};

/// `EVP_PKEY_new` at `crypto/evp/p_lib.c:1504` (ERR_R_CRYPTO_LIB).
pub(crate) const P_LIB_1504: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 1504,
    func: c"EVP_PKEY_new",
    lib: 6,
    reason: 524303,
    dynamic_reason: false,
};

/// `EVP_PKEY_new` at `crypto/evp/p_lib.c:1511` (ERR_R_CRYPTO_LIB).
pub(crate) const P_LIB_1511: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 1511,
    func: c"EVP_PKEY_new",
    lib: 6,
    reason: 524303,
    dynamic_reason: false,
};

/// `pkey_set_type` at `crypto/evp/p_lib.c:1551` (ERR_R_INTERNAL_ERROR).
pub(crate) const P_LIB_1551: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 1551,
    func: c"pkey_set_type",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `pkey_set_type` at `crypto/evp/p_lib.c:1601` (EVP_R_UNSUPPORTED_ALGORITHM).
pub(crate) const P_LIB_1601: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 1601,
    func: c"pkey_set_type",
    lib: 6,
    reason: 156,
    dynamic_reason: false,
};

/// `pkey_set_type` at `crypto/evp/p_lib.c:1607` (ERR_R_INTERNAL_ERROR).
pub(crate) const P_LIB_1607: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 1607,
    func: c"pkey_set_type",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `pkey_set_type` at `crypto/evp/p_lib.c:1641` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const P_LIB_1641: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 1641,
    func: c"pkey_set_type",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `EVP_PKEY_set_type_by_keymgmt` at `crypto/evp/p_lib.c:1688` (ERR_R_INTERNAL_ERROR).
pub(crate) const P_LIB_1688: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 1688,
    func: c"EVP_PKEY_set_type_by_keymgmt",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `EVP_PKEY_dup` at `crypto/evp/p_lib.c:1720` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const P_LIB_1720: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 1720,
    func: c"EVP_PKEY_dup",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_PKEY_dup` at `crypto/evp/p_lib.c:1748` (EVP_R_UNSUPPORTED_KEY_TYPE).
pub(crate) const P_LIB_1748: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 1748,
    func: c"EVP_PKEY_dup",
    lib: 6,
    reason: 224,
    dynamic_reason: false,
};

/// `EVP_PKEY_get_size` at `crypto/evp/p_lib.c:1866` (EVP_R_UNKNOWN_MAX_SIZE).
pub(crate) const P_LIB_1866: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 1866,
    func: c"EVP_PKEY_get_size",
    lib: 6,
    reason: 167,
    dynamic_reason: false,
};

/// `evp_pkey_copy_downgraded` at `crypto/evp/p_lib.c:2088` (ERR_R_INTERNAL_ERROR).
pub(crate) const P_LIB_2088: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 2088,
    func: c"evp_pkey_copy_downgraded",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `evp_pkey_copy_downgraded` at `crypto/evp/p_lib.c:2102` (ERR_R_EVP_LIB).
pub(crate) const P_LIB_2102: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 2102,
    func: c"evp_pkey_copy_downgraded",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `evp_pkey_copy_downgraded` at `crypto/evp/p_lib.c:2115` (EVP_R_NO_IMPORT_FUNCTION).
pub(crate) const P_LIB_2115: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 2115,
    func: c"evp_pkey_copy_downgraded",
    lib: 6,
    reason: 206,
    dynamic_reason: false,
};

/// `evp_pkey_copy_downgraded` at `crypto/evp/p_lib.c:2126` (ERR_R_EVP_LIB).
pub(crate) const P_LIB_2126: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 2126,
    func: c"evp_pkey_copy_downgraded",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `evp_pkey_copy_downgraded` at `crypto/evp/p_lib.c:2142` (EVP_R_KEYMGMT_EXPORT_FAILURE).
pub(crate) const P_LIB_2142: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 2142,
    func: c"evp_pkey_copy_downgraded",
    lib: 6,
    reason: 205,
    dynamic_reason: false,
};

/// `EVP_PKEY_set_params` at `crypto/evp/p_lib.c:2434` (EVP_R_INVALID_KEY).
pub(crate) const P_LIB_2434: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 2434,
    func: c"EVP_PKEY_set_params",
    lib: 6,
    reason: 163,
    dynamic_reason: false,
};

/// `EVP_PKEY_get_params` at `crypto/evp/p_lib.c:2455` (EVP_R_INVALID_KEY).
pub(crate) const P_LIB_2455: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_lib.c",
    line: 2455,
    func: c"EVP_PKEY_get_params",
    lib: 6,
    reason: 163,
    dynamic_reason: false,
};

/// `EVP_OpenInit` at `crypto/evp/p_open.c:37` (ERR_R_EVP_LIB).
pub(crate) const P_OPEN_37: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_open.c",
    line: 37,
    func: c"EVP_OpenInit",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `EVP_SealInit` at `crypto/evp/p_seal.c:62` (ERR_R_EVP_LIB).
pub(crate) const P_SEAL_62: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_seal.c",
    line: 62,
    func: c"EVP_SealInit",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `EVP_SignFinal_ex` at `crypto/evp/p_sign.c:36` (ERR_R_EVP_LIB).
pub(crate) const P_SIGN_36: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_sign.c",
    line: 36,
    func: c"EVP_SignFinal_ex",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `EVP_VerifyFinal_ex` at `crypto/evp/p_verify.c:34` (ERR_R_EVP_LIB).
pub(crate) const P_VERIFY_34: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/p_verify.c",
    line: 34,
    func: c"EVP_VerifyFinal_ex",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `EVP_PBE_scrypt_ex` at `crypto/evp/pbe_scrypt.c:50` (EVP_R_PARAMETER_TOO_LARGE).
pub(crate) const PBE_SCRYPT_50: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pbe_scrypt.c",
    line: 50,
    func: c"EVP_PBE_scrypt_ex",
    lib: 6,
    reason: 187,
    dynamic_reason: false,
};

/// `try_provided_check` at `crypto/evp/pmeth_check.c:40` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const PMETH_CHECK_40: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_check.c",
    line: 40,
    func: c"try_provided_check",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_pkey_public_check_combined` at `crypto/evp/pmeth_check.c:53` (EVP_R_NO_KEY_SET).
pub(crate) const PMETH_CHECK_53: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_check.c",
    line: 53,
    func: c"evp_pkey_public_check_combined",
    lib: 6,
    reason: 154,
    dynamic_reason: false,
};

/// `evp_pkey_public_check_combined` at `crypto/evp/pmeth_check.c:78` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const PMETH_CHECK_78: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_check.c",
    line: 78,
    func: c"evp_pkey_public_check_combined",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `evp_pkey_param_check_combined` at `crypto/evp/pmeth_check.c:98` (EVP_R_NO_KEY_SET).
pub(crate) const PMETH_CHECK_98: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_check.c",
    line: 98,
    func: c"evp_pkey_param_check_combined",
    lib: 6,
    reason: 154,
    dynamic_reason: false,
};

/// `evp_pkey_param_check_combined` at `crypto/evp/pmeth_check.c:124` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const PMETH_CHECK_124: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_check.c",
    line: 124,
    func: c"evp_pkey_param_check_combined",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_private_check` at `crypto/evp/pmeth_check.c:144` (EVP_R_NO_KEY_SET).
pub(crate) const PMETH_CHECK_144: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_check.c",
    line: 144,
    func: c"EVP_PKEY_private_check",
    lib: 6,
    reason: 154,
    dynamic_reason: false,
};

/// `EVP_PKEY_private_check` at `crypto/evp/pmeth_check.c:154` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const PMETH_CHECK_154: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_check.c",
    line: 154,
    func: c"EVP_PKEY_private_check",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_pairwise_check` at `crypto/evp/pmeth_check.c:169` (EVP_R_NO_KEY_SET).
pub(crate) const PMETH_CHECK_169: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_check.c",
    line: 169,
    func: c"EVP_PKEY_pairwise_check",
    lib: 6,
    reason: 154,
    dynamic_reason: false,
};

/// `EVP_PKEY_pairwise_check` at `crypto/evp/pmeth_check.c:194` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const PMETH_CHECK_194: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_check.c",
    line: 194,
    func: c"EVP_PKEY_pairwise_check",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `gen_init` at `crypto/evp/pmeth_gn.c:50` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const PMETH_GN_50: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_gn.c",
    line: 50,
    func: c"gen_init",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `gen_init` at `crypto/evp/pmeth_gn.c:87` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const PMETH_GN_87: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_gn.c",
    line: 87,
    func: c"gen_init",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_generate` at `crypto/evp/pmeth_gn.c:146` (ERR_R_EVP_LIB).
pub(crate) const PMETH_GN_146: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_gn.c",
    line: 146,
    func: c"EVP_PKEY_generate",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `EVP_PKEY_generate` at `crypto/evp/pmeth_gn.c:241` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const PMETH_GN_241: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_gn.c",
    line: 241,
    func: c"EVP_PKEY_generate",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_generate` at `crypto/evp/pmeth_gn.c:245` (EVP_R_OPERATION_NOT_INITIALIZED).
pub(crate) const PMETH_GN_245: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_gn.c",
    line: 245,
    func: c"EVP_PKEY_generate",
    lib: 6,
    reason: 151,
    dynamic_reason: false,
};

/// `EVP_PKEY_generate` at `crypto/evp/pmeth_gn.c:250` (EVP_R_INACCESSIBLE_DOMAIN_PARAMETERS).
pub(crate) const PMETH_GN_250: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_gn.c",
    line: 250,
    func: c"EVP_PKEY_generate",
    lib: 6,
    reason: 204,
    dynamic_reason: false,
};

/// `EVP_PKEY_paramgen` at `crypto/evp/pmeth_gn.c:259` (EVP_R_OPERATION_NOT_INITIALIZED).
pub(crate) const PMETH_GN_259: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_gn.c",
    line: 259,
    func: c"EVP_PKEY_paramgen",
    lib: 6,
    reason: 151,
    dynamic_reason: false,
};

/// `EVP_PKEY_keygen` at `crypto/evp/pmeth_gn.c:268` (EVP_R_OPERATION_NOT_INITIALIZED).
pub(crate) const PMETH_GN_268: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_gn.c",
    line: 268,
    func: c"EVP_PKEY_keygen",
    lib: 6,
    reason: 151,
    dynamic_reason: false,
};

/// `fromdata_init` at `crypto/evp/pmeth_gn.c:351` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const PMETH_GN_351: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_gn.c",
    line: 351,
    func: c"fromdata_init",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_fromdata` at `crypto/evp/pmeth_gn.c:367` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const PMETH_GN_367: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_gn.c",
    line: 367,
    func: c"EVP_PKEY_fromdata",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_fromdata` at `crypto/evp/pmeth_gn.c:378` (ERR_R_EVP_LIB).
pub(crate) const PMETH_GN_378: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_gn.c",
    line: 378,
    func: c"EVP_PKEY_fromdata",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `EVP_PKEY_export` at `crypto/evp/pmeth_gn.c:439` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PMETH_GN_439: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_gn.c",
    line: 439,
    func: c"EVP_PKEY_export",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `int_ctx_new` at `crypto/evp/pmeth_lib.c:192` (EVP_R_UNSUPPORTED_ALGORITHM).
pub(crate) const PMETH_LIB_192: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 192,
    func: c"int_ctx_new",
    lib: 6,
    reason: 156,
    dynamic_reason: false,
};

/// `int_ctx_new` at `crypto/evp/pmeth_lib.c:219` (ERR_R_ENGINE_LIB).
pub(crate) const PMETH_LIB_219: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 219,
    func: c"int_ctx_new",
    lib: 6,
    reason: 524326,
    dynamic_reason: false,
};

/// `int_ctx_new` at `crypto/evp/pmeth_lib.c:255` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const PMETH_LIB_255: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 255,
    func: c"int_ctx_new",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `int_ctx_new` at `crypto/evp/pmeth_lib.c:284` (ERR_R_INTERNAL_ERROR).
pub(crate) const PMETH_LIB_284: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 284,
    func: c"int_ctx_new",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `int_ctx_new` at `crypto/evp/pmeth_lib.c:295` (EVP_R_UNSUPPORTED_ALGORITHM).
pub(crate) const PMETH_LIB_295: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 295,
    func: c"int_ctx_new",
    lib: 6,
    reason: 156,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_dup` at `crypto/evp/pmeth_lib.c:459` (ERR_R_ENGINE_LIB).
pub(crate) const PMETH_LIB_459: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 459,
    func: c"EVP_PKEY_CTX_dup",
    lib: 6,
    reason: 524326,
    dynamic_reason: false,
};

/// `EVP_PKEY_meth_add0` at `crypto/evp/pmeth_lib.c:619` (ERR_R_CRYPTO_LIB).
pub(crate) const PMETH_LIB_619: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 619,
    func: c"EVP_PKEY_meth_add0",
    lib: 6,
    reason: 524303,
    dynamic_reason: false,
};

/// `EVP_PKEY_meth_add0` at `crypto/evp/pmeth_lib.c:624` (ERR_R_CRYPTO_LIB).
pub(crate) const PMETH_LIB_624: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 624,
    func: c"EVP_PKEY_meth_add0",
    lib: 6,
    reason: 524303,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_get_signature_md` at `crypto/evp/pmeth_lib.c:916` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const PMETH_LIB_916: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 916,
    func: c"EVP_PKEY_CTX_get_signature_md",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_set_md` at `crypto/evp/pmeth_lib.c:950` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const PMETH_LIB_950: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 950,
    func: c"evp_pkey_ctx_set_md",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_set1_octet_string` at `crypto/evp/pmeth_lib.c:997` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const PMETH_LIB_997: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 997,
    func: c"evp_pkey_ctx_set1_octet_string",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_set1_octet_string` at `crypto/evp/pmeth_lib.c:1008` (EVP_R_INVALID_LENGTH).
pub(crate) const PMETH_LIB_1008: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1008,
    func: c"evp_pkey_ctx_set1_octet_string",
    lib: 6,
    reason: 221,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_add1_octet_string` at `crypto/evp/pmeth_lib.c:1037` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const PMETH_LIB_1037: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1037,
    func: c"evp_pkey_ctx_add1_octet_string",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_add1_octet_string` at `crypto/evp/pmeth_lib.c:1048` (EVP_R_INVALID_LENGTH).
pub(crate) const PMETH_LIB_1048: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1048,
    func: c"evp_pkey_ctx_add1_octet_string",
    lib: 6,
    reason: 221,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_set_hkdf_mode` at `crypto/evp/pmeth_lib.c:1158` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const PMETH_LIB_1158: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1158,
    func: c"EVP_PKEY_CTX_set_hkdf_mode",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_set_hkdf_mode` at `crypto/evp/pmeth_lib.c:1170` (EVP_R_INVALID_VALUE).
pub(crate) const PMETH_LIB_1170: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1170,
    func: c"EVP_PKEY_CTX_set_hkdf_mode",
    lib: 6,
    reason: 222,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_set_uint64` at `crypto/evp/pmeth_lib.c:1206` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const PMETH_LIB_1206: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1206,
    func: c"evp_pkey_ctx_set_uint64",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_set_kem_op` at `crypto/evp/pmeth_lib.c:1267` (EVP_R_INVALID_VALUE).
pub(crate) const PMETH_LIB_1267: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1267,
    func: c"EVP_PKEY_CTX_set_kem_op",
    lib: 6,
    reason: 222,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_set_kem_op` at `crypto/evp/pmeth_lib.c:1271` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const PMETH_LIB_1271: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1271,
    func: c"EVP_PKEY_CTX_set_kem_op",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_ctrl_int` at `crypto/evp/pmeth_lib.c:1309` (EVP_R_NO_OPERATION_SET).
pub(crate) const PMETH_LIB_1309: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1309,
    func: c"evp_pkey_ctx_ctrl_int",
    lib: 6,
    reason: 149,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_ctrl_int` at `crypto/evp/pmeth_lib.c:1314` (EVP_R_INVALID_OPERATION).
pub(crate) const PMETH_LIB_1314: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1314,
    func: c"evp_pkey_ctx_ctrl_int",
    lib: 6,
    reason: 148,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_ctrl_int` at `crypto/evp/pmeth_lib.c:1325` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const PMETH_LIB_1325: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1325,
    func: c"evp_pkey_ctx_ctrl_int",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_ctrl_int` at `crypto/evp/pmeth_lib.c:1334` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const PMETH_LIB_1334: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1334,
    func: c"evp_pkey_ctx_ctrl_int",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_ctrl` at `crypto/evp/pmeth_lib.c:1346` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const PMETH_LIB_1346: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1346,
    func: c"EVP_PKEY_CTX_ctrl",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_ctrl_str_int` at `crypto/evp/pmeth_lib.c:1380` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const PMETH_LIB_1380: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1380,
    func: c"evp_pkey_ctx_ctrl_str_int",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_ctrl_str_int` at `crypto/evp/pmeth_lib.c:1390` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const PMETH_LIB_1390: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1390,
    func: c"evp_pkey_ctx_ctrl_str_int",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_store_cached_data` at `crypto/evp/pmeth_lib.c:1460` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const PMETH_LIB_1460: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1460,
    func: c"evp_pkey_ctx_store_cached_data",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_store_cached_data` at `crypto/evp/pmeth_lib.c:1468` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const PMETH_LIB_1468: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1468,
    func: c"evp_pkey_ctx_store_cached_data",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_store_cached_data` at `crypto/evp/pmeth_lib.c:1473` (EVP_R_INVALID_OPERATION).
pub(crate) const PMETH_LIB_1473: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1473,
    func: c"evp_pkey_ctx_store_cached_data",
    lib: 6,
    reason: 148,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_store_cached_data` at `crypto/evp/pmeth_lib.c:1480` (EVP_R_COMMAND_NOT_SUPPORTED).
pub(crate) const PMETH_LIB_1480: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1480,
    func: c"evp_pkey_ctx_store_cached_data",
    lib: 6,
    reason: 147,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_store_cached_data` at `crypto/evp/pmeth_lib.c:1484` (EVP_R_INVALID_OPERATION).
pub(crate) const PMETH_LIB_1484: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1484,
    func: c"evp_pkey_ctx_store_cached_data",
    lib: 6,
    reason: 148,
    dynamic_reason: false,
};

/// `evp_pkey_ctx_store_cached_data` at `crypto/evp/pmeth_lib.c:1491` (EVP_R_INVALID_OPERATION).
pub(crate) const PMETH_LIB_1491: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1491,
    func: c"evp_pkey_ctx_store_cached_data",
    lib: 6,
    reason: 148,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_md` at `crypto/evp/pmeth_lib.c:1619` (EVP_R_INVALID_DIGEST).
pub(crate) const PMETH_LIB_1619: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/pmeth_lib.c",
    line: 1619,
    func: c"EVP_PKEY_CTX_md",
    lib: 6,
    reason: 152,
    dynamic_reason: false,
};

/// `EVP_SKEY_export` at `crypto/evp/s_lib.c:25` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const S_LIB_25: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/s_lib.c",
    line: 25,
    func: c"EVP_SKEY_export",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `evp_skey_alloc` at `crypto/evp/s_lib.c:47` (ERR_R_CRYPTO_LIB).
pub(crate) const S_LIB_47: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/s_lib.c",
    line: 47,
    func: c"evp_skey_alloc",
    lib: 6,
    reason: 524303,
    dynamic_reason: false,
};

/// `evp_skey_alloc_fetch` at `crypto/evp/s_lib.c:79` (ERR_R_FETCH_FAILED).
pub(crate) const S_LIB_79: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/s_lib.c",
    line: 79,
    func: c"evp_skey_alloc_fetch",
    lib: 6,
    reason: 524557,
    dynamic_reason: false,
};

/// `EVP_SKEY_get0_raw_key` at `crypto/evp/s_lib.c:169` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const S_LIB_169: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/s_lib.c",
    line: 169,
    func: c"EVP_SKEY_get0_raw_key",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_SKEY_to_provider` at `crypto/evp/s_lib.c:285` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const S_LIB_285: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/s_lib.c",
    line: 285,
    func: c"EVP_SKEY_to_provider",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_SKEY_to_provider` at `crypto/evp/s_lib.c:305` (ERR_R_FETCH_FAILED).
pub(crate) const S_LIB_305: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/s_lib.c",
    line: 305,
    func: c"EVP_SKEY_to_provider",
    lib: 6,
    reason: 524557,
    dynamic_reason: false,
};

/// `evp_signature_from_algorithm` at `crypto/evp/signature.c:68` (ERR_R_EVP_LIB).
pub(crate) const SIGNATURE_68: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 68,
    func: c"evp_signature_from_algorithm",
    lib: 6,
    reason: 524294,
    dynamic_reason: false,
};

/// `evp_signature_from_algorithm` at `crypto/evp/signature.c:296` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const SIGNATURE_296: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 296,
    func: c"evp_signature_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_signature_from_algorithm` at `crypto/evp/signature.c:310` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const SIGNATURE_310: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 310,
    func: c"evp_signature_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_signature_from_algorithm` at `crypto/evp/signature.c:315` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const SIGNATURE_315: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 315,
    func: c"evp_signature_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_signature_from_algorithm` at `crypto/evp/signature.c:329` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const SIGNATURE_329: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 329,
    func: c"evp_signature_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_signature_from_algorithm` at `crypto/evp/signature.c:340` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const SIGNATURE_340: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 340,
    func: c"evp_signature_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_signature_from_algorithm` at `crypto/evp/signature.c:353` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const SIGNATURE_353: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 353,
    func: c"evp_signature_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_signature_from_algorithm` at `crypto/evp/signature.c:363` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const SIGNATURE_363: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 363,
    func: c"evp_signature_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_signature_from_algorithm` at `crypto/evp/signature.c:374` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const SIGNATURE_374: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 374,
    func: c"evp_signature_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_signature_from_algorithm` at `crypto/evp/signature.c:385` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const SIGNATURE_385: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 385,
    func: c"evp_signature_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_signature_from_algorithm` at `crypto/evp/signature.c:396` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const SIGNATURE_396: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 396,
    func: c"evp_signature_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_signature_from_algorithm` at `crypto/evp/signature.c:409` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const SIGNATURE_409: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 409,
    func: c"evp_signature_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_signature_from_algorithm` at `crypto/evp/signature.c:419` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const SIGNATURE_419: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 419,
    func: c"evp_signature_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_signature_from_algorithm` at `crypto/evp/signature.c:425` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const SIGNATURE_425: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 425,
    func: c"evp_signature_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_signature_from_algorithm` at `crypto/evp/signature.c:431` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const SIGNATURE_431: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 431,
    func: c"evp_signature_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_signature_from_algorithm` at `crypto/evp/signature.c:437` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const SIGNATURE_437: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 437,
    func: c"evp_signature_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_signature_from_algorithm` at `crypto/evp/signature.c:443` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const SIGNATURE_443: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 443,
    func: c"evp_signature_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `evp_pkey_signature_init` at `crypto/evp/signature.c:580` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const SIGNATURE_580: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 580,
    func: c"evp_pkey_signature_init",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `evp_pkey_signature_init` at `crypto/evp/signature.c:596` (EVP_R_NO_KEY_SET).
pub(crate) const SIGNATURE_596: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 596,
    func: c"evp_pkey_signature_init",
    lib: 6,
    reason: 154,
    dynamic_reason: false,
};

/// `evp_pkey_signature_init` at `crypto/evp/signature.c:637` (EVP_R_SIGNATURE_TYPE_AND_KEY_TYPE_INCOMPATIBLE).
pub(crate) const SIGNATURE_637: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 637,
    func: c"evp_pkey_signature_init",
    lib: 6,
    reason: 228,
    dynamic_reason: false,
};

/// `evp_pkey_signature_init` at `crypto/evp/signature.c:664` (EVP_R_SIGNATURE_TYPE_AND_KEY_TYPE_INCOMPATIBLE).
pub(crate) const SIGNATURE_664: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 664,
    func: c"evp_pkey_signature_init",
    lib: 6,
    reason: 228,
    dynamic_reason: false,
};

/// `evp_pkey_signature_init` at `crypto/evp/signature.c:681` (EVP_R_NO_KEY_SET).
pub(crate) const SIGNATURE_681: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 681,
    func: c"evp_pkey_signature_init",
    lib: 6,
    reason: 154,
    dynamic_reason: false,
};

/// `evp_pkey_signature_init` at `crypto/evp/signature.c:691` (ERR_R_INTERNAL_ERROR).
pub(crate) const SIGNATURE_691: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 691,
    func: c"evp_pkey_signature_init",
    lib: 6,
    reason: 786691,
    dynamic_reason: false,
};

/// `evp_pkey_signature_init` at `crypto/evp/signature.c:699` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const SIGNATURE_699: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 699,
    func: c"evp_pkey_signature_init",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_pkey_signature_init` at `crypto/evp/signature.c:786` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const SIGNATURE_786: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 786,
    func: c"evp_pkey_signature_init",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_pkey_signature_init` at `crypto/evp/signature.c:793` (EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED).
pub(crate) const SIGNATURE_793: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 793,
    func: c"evp_pkey_signature_init",
    lib: 6,
    reason: 237,
    dynamic_reason: false,
};

/// `evp_pkey_signature_init` at `crypto/evp/signature.c:802` (EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED).
pub(crate) const SIGNATURE_802: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 802,
    func: c"evp_pkey_signature_init",
    lib: 6,
    reason: 237,
    dynamic_reason: false,
};

/// `evp_pkey_signature_init` at `crypto/evp/signature.c:811` (EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED).
pub(crate) const SIGNATURE_811: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 811,
    func: c"evp_pkey_signature_init",
    lib: 6,
    reason: 237,
    dynamic_reason: false,
};

/// `evp_pkey_signature_init` at `crypto/evp/signature.c:820` (EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED).
pub(crate) const SIGNATURE_820: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 820,
    func: c"evp_pkey_signature_init",
    lib: 6,
    reason: 237,
    dynamic_reason: false,
};

/// `evp_pkey_signature_init` at `crypto/evp/signature.c:829` (EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED).
pub(crate) const SIGNATURE_829: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 829,
    func: c"evp_pkey_signature_init",
    lib: 6,
    reason: 237,
    dynamic_reason: false,
};

/// `evp_pkey_signature_init` at `crypto/evp/signature.c:837` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const SIGNATURE_837: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 837,
    func: c"evp_pkey_signature_init",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_pkey_signature_init` at `crypto/evp/signature.c:862` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const SIGNATURE_862: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 862,
    func: c"evp_pkey_signature_init",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `evp_pkey_signature_init` at `crypto/evp/signature.c:883` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const SIGNATURE_883: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 883,
    func: c"evp_pkey_signature_init",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `EVP_PKEY_sign_message_update` at `crypto/evp/signature.c:933` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const SIGNATURE_933: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 933,
    func: c"EVP_PKEY_sign_message_update",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_PKEY_sign_message_update` at `crypto/evp/signature.c:938` (EVP_R_OPERATION_NOT_INITIALIZED).
pub(crate) const SIGNATURE_938: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 938,
    func: c"EVP_PKEY_sign_message_update",
    lib: 6,
    reason: 151,
    dynamic_reason: false,
};

/// `EVP_PKEY_sign_message_update` at `crypto/evp/signature.c:945` (EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED).
pub(crate) const SIGNATURE_945: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 945,
    func: c"EVP_PKEY_sign_message_update",
    lib: 6,
    reason: 237,
    dynamic_reason: false,
};

/// `EVP_PKEY_sign_message_update` at `crypto/evp/signature.c:952` (EVP_R_PROVIDER_SIGNATURE_FAILURE).
pub(crate) const SIGNATURE_952: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 952,
    func: c"EVP_PKEY_sign_message_update",
    lib: 6,
    reason: 234,
    dynamic_reason: false,
};

/// `EVP_PKEY_sign_message_final` at `crypto/evp/signature.c:965` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const SIGNATURE_965: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 965,
    func: c"EVP_PKEY_sign_message_final",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_PKEY_sign_message_final` at `crypto/evp/signature.c:970` (EVP_R_OPERATION_NOT_INITIALIZED).
pub(crate) const SIGNATURE_970: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 970,
    func: c"EVP_PKEY_sign_message_final",
    lib: 6,
    reason: 151,
    dynamic_reason: false,
};

/// `EVP_PKEY_sign_message_final` at `crypto/evp/signature.c:977` (EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED).
pub(crate) const SIGNATURE_977: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 977,
    func: c"EVP_PKEY_sign_message_final",
    lib: 6,
    reason: 237,
    dynamic_reason: false,
};

/// `EVP_PKEY_sign_message_final` at `crypto/evp/signature.c:985` (EVP_R_PROVIDER_SIGNATURE_FAILURE).
pub(crate) const SIGNATURE_985: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 985,
    func: c"EVP_PKEY_sign_message_final",
    lib: 6,
    reason: 234,
    dynamic_reason: false,
};

/// `EVP_PKEY_sign` at `crypto/evp/signature.c:999` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const SIGNATURE_999: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 999,
    func: c"EVP_PKEY_sign",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_PKEY_sign` at `crypto/evp/signature.c:1005` (EVP_R_OPERATION_NOT_INITIALIZED).
pub(crate) const SIGNATURE_1005: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1005,
    func: c"EVP_PKEY_sign",
    lib: 6,
    reason: 151,
    dynamic_reason: false,
};

/// `EVP_PKEY_sign` at `crypto/evp/signature.c:1015` (EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED).
pub(crate) const SIGNATURE_1015: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1015,
    func: c"EVP_PKEY_sign",
    lib: 6,
    reason: 237,
    dynamic_reason: false,
};

/// `EVP_PKEY_sign` at `crypto/evp/signature.c:1023` (EVP_R_PROVIDER_SIGNATURE_FAILURE).
pub(crate) const SIGNATURE_1023: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1023,
    func: c"EVP_PKEY_sign",
    lib: 6,
    reason: 234,
    dynamic_reason: false,
};

/// `EVP_PKEY_sign` at `crypto/evp/signature.c:1029` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const SIGNATURE_1029: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1029,
    func: c"EVP_PKEY_sign",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_CTX_set_signature` at `crypto/evp/signature.c:1064` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const SIGNATURE_1064: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1064,
    func: c"EVP_PKEY_CTX_set_signature",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_PKEY_verify_message_update` at `crypto/evp/signature.c:1087` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const SIGNATURE_1087: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1087,
    func: c"EVP_PKEY_verify_message_update",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_PKEY_verify_message_update` at `crypto/evp/signature.c:1092` (EVP_R_OPERATION_NOT_INITIALIZED).
pub(crate) const SIGNATURE_1092: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1092,
    func: c"EVP_PKEY_verify_message_update",
    lib: 6,
    reason: 151,
    dynamic_reason: false,
};

/// `EVP_PKEY_verify_message_update` at `crypto/evp/signature.c:1099` (EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED).
pub(crate) const SIGNATURE_1099: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1099,
    func: c"EVP_PKEY_verify_message_update",
    lib: 6,
    reason: 237,
    dynamic_reason: false,
};

/// `EVP_PKEY_verify_message_update` at `crypto/evp/signature.c:1106` (EVP_R_PROVIDER_SIGNATURE_FAILURE).
pub(crate) const SIGNATURE_1106: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1106,
    func: c"EVP_PKEY_verify_message_update",
    lib: 6,
    reason: 234,
    dynamic_reason: false,
};

/// `EVP_PKEY_verify_message_final` at `crypto/evp/signature.c:1118` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const SIGNATURE_1118: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1118,
    func: c"EVP_PKEY_verify_message_final",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_PKEY_verify_message_final` at `crypto/evp/signature.c:1123` (EVP_R_OPERATION_NOT_INITIALIZED).
pub(crate) const SIGNATURE_1123: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1123,
    func: c"EVP_PKEY_verify_message_final",
    lib: 6,
    reason: 151,
    dynamic_reason: false,
};

/// `EVP_PKEY_verify_message_final` at `crypto/evp/signature.c:1130` (EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED).
pub(crate) const SIGNATURE_1130: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1130,
    func: c"EVP_PKEY_verify_message_final",
    lib: 6,
    reason: 237,
    dynamic_reason: false,
};

/// `EVP_PKEY_verify_message_final` at `crypto/evp/signature.c:1138` (EVP_R_PROVIDER_SIGNATURE_FAILURE).
pub(crate) const SIGNATURE_1138: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1138,
    func: c"EVP_PKEY_verify_message_final",
    lib: 6,
    reason: 234,
    dynamic_reason: false,
};

/// `EVP_PKEY_verify` at `crypto/evp/signature.c:1152` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const SIGNATURE_1152: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1152,
    func: c"EVP_PKEY_verify",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_PKEY_verify` at `crypto/evp/signature.c:1158` (EVP_R_OPERATION_NOT_INITIALIZED).
pub(crate) const SIGNATURE_1158: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1158,
    func: c"EVP_PKEY_verify",
    lib: 6,
    reason: 151,
    dynamic_reason: false,
};

/// `EVP_PKEY_verify` at `crypto/evp/signature.c:1168` (EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED).
pub(crate) const SIGNATURE_1168: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1168,
    func: c"EVP_PKEY_verify",
    lib: 6,
    reason: 237,
    dynamic_reason: false,
};

/// `EVP_PKEY_verify` at `crypto/evp/signature.c:1176` (EVP_R_PROVIDER_SIGNATURE_FAILURE).
pub(crate) const SIGNATURE_1176: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1176,
    func: c"EVP_PKEY_verify",
    lib: 6,
    reason: 234,
    dynamic_reason: false,
};

/// `EVP_PKEY_verify` at `crypto/evp/signature.c:1182` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const SIGNATURE_1182: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1182,
    func: c"EVP_PKEY_verify",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `EVP_PKEY_verify_recover` at `crypto/evp/signature.c:1215` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const SIGNATURE_1215: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1215,
    func: c"EVP_PKEY_verify_recover",
    lib: 6,
    reason: 786690,
    dynamic_reason: false,
};

/// `EVP_PKEY_verify_recover` at `crypto/evp/signature.c:1220` (EVP_R_OPERATION_NOT_INITIALIZED).
pub(crate) const SIGNATURE_1220: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1220,
    func: c"EVP_PKEY_verify_recover",
    lib: 6,
    reason: 151,
    dynamic_reason: false,
};

/// `EVP_PKEY_verify_recover` at `crypto/evp/signature.c:1230` (EVP_R_PROVIDER_SIGNATURE_NOT_SUPPORTED).
pub(crate) const SIGNATURE_1230: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1230,
    func: c"EVP_PKEY_verify_recover",
    lib: 6,
    reason: 237,
    dynamic_reason: false,
};

/// `EVP_PKEY_verify_recover` at `crypto/evp/signature.c:1238` (EVP_R_PROVIDER_SIGNATURE_FAILURE).
pub(crate) const SIGNATURE_1238: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1238,
    func: c"EVP_PKEY_verify_recover",
    lib: 6,
    reason: 234,
    dynamic_reason: false,
};

/// `EVP_PKEY_verify_recover` at `crypto/evp/signature.c:1243` (EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE).
pub(crate) const SIGNATURE_1243: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/signature.c",
    line: 1243,
    func: c"EVP_PKEY_verify_recover",
    lib: 6,
    reason: 150,
    dynamic_reason: false,
};

/// `skeymgmt_from_algorithm` at `crypto/evp/skeymgmt_meth.c:116` (EVP_R_INVALID_PROVIDER_FUNCTIONS).
pub(crate) const SKEYMGMT_METH_116: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/skeymgmt_meth.c",
    line: 116,
    func: c"skeymgmt_from_algorithm",
    lib: 6,
    reason: 193,
    dynamic_reason: false,
};

/// `skeymgmt_from_algorithm` at `crypto/evp/skeymgmt_meth.c:122` (EVP_R_INITIALIZATION_ERROR).
pub(crate) const SKEYMGMT_METH_122: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/evp/skeymgmt_meth.c",
    line: 122,
    func: c"skeymgmt_from_algorithm",
    lib: 6,
    reason: 134,
    dynamic_reason: false,
};

/// `evp_pkey_new_raw_nist_public_key` at `crypto/hpke/hpke.c:122` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_122: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 122,
    func: c"evp_pkey_new_raw_nist_public_key",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_aead_dec` at `crypto/hpke/hpke.c:154` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_154: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 154,
    func: c"hpke_aead_dec",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `hpke_aead_dec` at `crypto/hpke/hpke.c:162` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_162: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 162,
    func: c"hpke_aead_dec",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_aead_dec` at `crypto/hpke/hpke.c:168` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_168: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 168,
    func: c"hpke_aead_dec",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_aead_dec` at `crypto/hpke/hpke.c:173` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_173: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 173,
    func: c"hpke_aead_dec",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_aead_dec` at `crypto/hpke/hpke.c:179` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_179: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 179,
    func: c"hpke_aead_dec",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_aead_dec` at `crypto/hpke/hpke.c:184` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_184: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 184,
    func: c"hpke_aead_dec",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_aead_dec` at `crypto/hpke/hpke.c:190` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_190: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 190,
    func: c"hpke_aead_dec",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_aead_dec` at `crypto/hpke/hpke.c:195` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_195: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 195,
    func: c"hpke_aead_dec",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_aead_enc` at `crypto/hpke/hpke.c:233` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_233: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 233,
    func: c"hpke_aead_enc",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `hpke_aead_enc` at `crypto/hpke/hpke.c:237` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_237: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 237,
    func: c"hpke_aead_enc",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `hpke_aead_enc` at `crypto/hpke/hpke.c:245` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_245: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 245,
    func: c"hpke_aead_enc",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_aead_enc` at `crypto/hpke/hpke.c:251` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_251: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 251,
    func: c"hpke_aead_enc",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_aead_enc` at `crypto/hpke/hpke.c:256` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_256: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 256,
    func: c"hpke_aead_enc",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_aead_enc` at `crypto/hpke/hpke.c:262` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_262: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 262,
    func: c"hpke_aead_enc",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_aead_enc` at `crypto/hpke/hpke.c:267` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_267: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 267,
    func: c"hpke_aead_enc",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_aead_enc` at `crypto/hpke/hpke.c:273` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_273: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 273,
    func: c"hpke_aead_enc",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_aead_enc` at `crypto/hpke/hpke.c:279` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_279: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 279,
    func: c"hpke_aead_enc",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_expansion` at `crypto/hpke/hpke.c:403` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_403: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 403,
    func: c"hpke_expansion",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `hpke_expansion` at `crypto/hpke/hpke.c:407` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_407: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 407,
    func: c"hpke_expansion",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `hpke_encap` at `crypto/hpke/hpke.c:462` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_462: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 462,
    func: c"hpke_encap",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `hpke_encap` at `crypto/hpke/hpke.c:467` (ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
pub(crate) const HPKE_467: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 467,
    func: c"hpke_encap",
    lib: 15,
    reason: 786689,
    dynamic_reason: false,
};

/// `hpke_encap` at `crypto/hpke/hpke.c:472` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_472: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 472,
    func: c"hpke_encap",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_encap` at `crypto/hpke/hpke.c:485` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_485: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 485,
    func: c"hpke_encap",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_encap` at `crypto/hpke/hpke.c:490` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_490: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 490,
    func: c"hpke_encap",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_encap` at `crypto/hpke/hpke.c:506` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_506: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 506,
    func: c"hpke_encap",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_encap` at `crypto/hpke/hpke.c:511` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_511: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 511,
    func: c"hpke_encap",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_encap` at `crypto/hpke/hpke.c:517` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_517: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 517,
    func: c"hpke_encap",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_encap` at `crypto/hpke/hpke.c:521` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_521: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 521,
    func: c"hpke_encap",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `hpke_encap` at `crypto/hpke/hpke.c:534` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_534: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 534,
    func: c"hpke_encap",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_decap` at `crypto/hpke/hpke.c:564` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_564: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 564,
    func: c"hpke_decap",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `hpke_decap` at `crypto/hpke/hpke.c:569` (ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
pub(crate) const HPKE_569: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 569,
    func: c"hpke_decap",
    lib: 15,
    reason: 786689,
    dynamic_reason: false,
};

/// `hpke_decap` at `crypto/hpke/hpke.c:574` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_574: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 574,
    func: c"hpke_decap",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_decap` at `crypto/hpke/hpke.c:587` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_587: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 587,
    func: c"hpke_decap",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_decap` at `crypto/hpke/hpke.c:603` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_603: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 603,
    func: c"hpke_decap",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_decap` at `crypto/hpke/hpke.c:607` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_607: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 607,
    func: c"hpke_decap",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_decap` at `crypto/hpke/hpke.c:612` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_612: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 612,
    func: c"hpke_decap",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_decap` at `crypto/hpke/hpke.c:617` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_617: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 617,
    func: c"hpke_decap",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_decap` at `crypto/hpke/hpke.c:626` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_626: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 626,
    func: c"hpke_decap",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_do_middle` at `crypto/hpke/hpke.c:672` (ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
pub(crate) const HPKE_672: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 672,
    func: c"hpke_do_middle",
    lib: 15,
    reason: 786689,
    dynamic_reason: false,
};

/// `hpke_do_middle` at `crypto/hpke/hpke.c:676` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_676: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 676,
    func: c"hpke_do_middle",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_do_middle` at `crypto/hpke/hpke.c:681` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_681: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 681,
    func: c"hpke_do_middle",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_do_middle` at `crypto/hpke/hpke.c:686` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_686: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 686,
    func: c"hpke_do_middle",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_do_middle` at `crypto/hpke/hpke.c:696` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_696: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 696,
    func: c"hpke_do_middle",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_do_middle` at `crypto/hpke/hpke.c:703` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_703: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 703,
    func: c"hpke_do_middle",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `hpke_do_middle` at `crypto/hpke/hpke.c:709` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_709: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 709,
    func: c"hpke_do_middle",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_do_middle` at `crypto/hpke/hpke.c:727` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_727: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 727,
    func: c"hpke_do_middle",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_do_middle` at `crypto/hpke/hpke.c:736` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_736: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 736,
    func: c"hpke_do_middle",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_do_middle` at `crypto/hpke/hpke.c:742` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_742: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 742,
    func: c"hpke_do_middle",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_do_middle` at `crypto/hpke/hpke.c:752` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_752: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 752,
    func: c"hpke_do_middle",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_do_middle` at `crypto/hpke/hpke.c:767` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_767: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 767,
    func: c"hpke_do_middle",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_do_middle` at `crypto/hpke/hpke.c:780` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_780: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 780,
    func: c"hpke_do_middle",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `hpke_do_middle` at `crypto/hpke/hpke.c:794` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_794: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 794,
    func: c"hpke_do_middle",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_new` at `crypto/hpke/hpke.c:820` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_820: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 820,
    func: c"OSSL_HPKE_CTX_new",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_new` at `crypto/hpke/hpke.c:824` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_824: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 824,
    func: c"OSSL_HPKE_CTX_new",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_new` at `crypto/hpke/hpke.c:828` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_828: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 828,
    func: c"OSSL_HPKE_CTX_new",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_new` at `crypto/hpke/hpke.c:843` (ERR_R_FETCH_FAILED).
pub(crate) const HPKE_843: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 843,
    func: c"OSSL_HPKE_CTX_new",
    lib: 15,
    reason: 524557,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_set1_psk` at `crypto/hpke/hpke.c:887` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_887: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 887,
    func: c"OSSL_HPKE_CTX_set1_psk",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_set1_psk` at `crypto/hpke/hpke.c:891` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_891: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 891,
    func: c"OSSL_HPKE_CTX_set1_psk",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_set1_psk` at `crypto/hpke/hpke.c:895` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_895: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 895,
    func: c"OSSL_HPKE_CTX_set1_psk",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_set1_psk` at `crypto/hpke/hpke.c:899` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_899: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 899,
    func: c"OSSL_HPKE_CTX_set1_psk",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_set1_psk` at `crypto/hpke/hpke.c:903` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_903: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 903,
    func: c"OSSL_HPKE_CTX_set1_psk",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_set1_psk` at `crypto/hpke/hpke.c:908` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_908: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 908,
    func: c"OSSL_HPKE_CTX_set1_psk",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_set1_ikme` at `crypto/hpke/hpke.c:932` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const HPKE_932: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 932,
    func: c"OSSL_HPKE_CTX_set1_ikme",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_set1_ikme` at `crypto/hpke/hpke.c:936` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_936: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 936,
    func: c"OSSL_HPKE_CTX_set1_ikme",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_set1_ikme` at `crypto/hpke/hpke.c:940` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_940: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 940,
    func: c"OSSL_HPKE_CTX_set1_ikme",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_set1_authpriv` at `crypto/hpke/hpke.c:954` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const HPKE_954: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 954,
    func: c"OSSL_HPKE_CTX_set1_authpriv",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_set1_authpriv` at `crypto/hpke/hpke.c:959` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_959: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 959,
    func: c"OSSL_HPKE_CTX_set1_authpriv",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_set1_authpriv` at `crypto/hpke/hpke.c:963` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_963: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 963,
    func: c"OSSL_HPKE_CTX_set1_authpriv",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_set1_authpub` at `crypto/hpke/hpke.c:983` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const HPKE_983: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 983,
    func: c"OSSL_HPKE_CTX_set1_authpub",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_set1_authpub` at `crypto/hpke/hpke.c:988` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_988: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 988,
    func: c"OSSL_HPKE_CTX_set1_authpub",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_set1_authpub` at `crypto/hpke/hpke.c:992` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_992: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 992,
    func: c"OSSL_HPKE_CTX_set1_authpub",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_set1_authpub` at `crypto/hpke/hpke.c:1011` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1011: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1011,
    func: c"OSSL_HPKE_CTX_set1_authpub",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_set1_authpub` at `crypto/hpke/hpke.c:1026` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1026: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1026,
    func: c"OSSL_HPKE_CTX_set1_authpub",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_get_seq` at `crypto/hpke/hpke.c:1043` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const HPKE_1043: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1043,
    func: c"OSSL_HPKE_CTX_get_seq",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_set_seq` at `crypto/hpke/hpke.c:1053` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const HPKE_1053: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1053,
    func: c"OSSL_HPKE_CTX_set_seq",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `OSSL_HPKE_CTX_set_seq` at `crypto/hpke/hpke.c:1062` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1062: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1062,
    func: c"OSSL_HPKE_CTX_set_seq",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_encap` at `crypto/hpke/hpke.c:1079` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1079: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1079,
    func: c"OSSL_HPKE_encap",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_encap` at `crypto/hpke/hpke.c:1083` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1083: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1083,
    func: c"OSSL_HPKE_encap",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_encap` at `crypto/hpke/hpke.c:1087` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1087: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1087,
    func: c"OSSL_HPKE_encap",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_encap` at `crypto/hpke/hpke.c:1091` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1091: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1091,
    func: c"OSSL_HPKE_encap",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_encap` at `crypto/hpke/hpke.c:1096` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1096: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1096,
    func: c"OSSL_HPKE_encap",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_encap` at `crypto/hpke/hpke.c:1101` (ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
pub(crate) const HPKE_1101: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1101,
    func: c"OSSL_HPKE_encap",
    lib: 15,
    reason: 786689,
    dynamic_reason: false,
};

/// `OSSL_HPKE_encap` at `crypto/hpke/hpke.c:1105` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1105: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1105,
    func: c"OSSL_HPKE_encap",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_decap` at `crypto/hpke/hpke.c:1126` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1126: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1126,
    func: c"OSSL_HPKE_decap",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_decap` at `crypto/hpke/hpke.c:1130` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1130: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1130,
    func: c"OSSL_HPKE_decap",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_decap` at `crypto/hpke/hpke.c:1134` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1134: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1134,
    func: c"OSSL_HPKE_decap",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_decap` at `crypto/hpke/hpke.c:1138` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1138: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1138,
    func: c"OSSL_HPKE_decap",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_decap` at `crypto/hpke/hpke.c:1143` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1143: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1143,
    func: c"OSSL_HPKE_decap",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_decap` at `crypto/hpke/hpke.c:1148` (ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
pub(crate) const HPKE_1148: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1148,
    func: c"OSSL_HPKE_decap",
    lib: 15,
    reason: 786689,
    dynamic_reason: false,
};

/// `OSSL_HPKE_decap` at `crypto/hpke/hpke.c:1153` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1153: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1153,
    func: c"OSSL_HPKE_decap",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_seal` at `crypto/hpke/hpke.c:1175` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1175: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1175,
    func: c"OSSL_HPKE_seal",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_seal` at `crypto/hpke/hpke.c:1179` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1179: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1179,
    func: c"OSSL_HPKE_seal",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_seal` at `crypto/hpke/hpke.c:1183` (ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
pub(crate) const HPKE_1183: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1183,
    func: c"OSSL_HPKE_seal",
    lib: 15,
    reason: 786689,
    dynamic_reason: false,
};

/// `OSSL_HPKE_seal` at `crypto/hpke/hpke.c:1188` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1188: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1188,
    func: c"OSSL_HPKE_seal",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_seal` at `crypto/hpke/hpke.c:1193` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1193: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1193,
    func: c"OSSL_HPKE_seal",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_seal` at `crypto/hpke/hpke.c:1197` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1197: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1197,
    func: c"OSSL_HPKE_seal",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_open` at `crypto/hpke/hpke.c:1217` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1217: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1217,
    func: c"OSSL_HPKE_open",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_open` at `crypto/hpke/hpke.c:1221` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1221: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1221,
    func: c"OSSL_HPKE_open",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_open` at `crypto/hpke/hpke.c:1225` (ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
pub(crate) const HPKE_1225: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1225,
    func: c"OSSL_HPKE_open",
    lib: 15,
    reason: 786689,
    dynamic_reason: false,
};

/// `OSSL_HPKE_open` at `crypto/hpke/hpke.c:1230` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1230: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1230,
    func: c"OSSL_HPKE_open",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_open` at `crypto/hpke/hpke.c:1235` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1235: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1235,
    func: c"OSSL_HPKE_open",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_open` at `crypto/hpke/hpke.c:1239` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1239: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1239,
    func: c"OSSL_HPKE_open",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_export` at `crypto/hpke/hpke.c:1259` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1259: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1259,
    func: c"OSSL_HPKE_export",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_export` at `crypto/hpke/hpke.c:1263` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1263: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1263,
    func: c"OSSL_HPKE_export",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_export` at `crypto/hpke/hpke.c:1267` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1267: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1267,
    func: c"OSSL_HPKE_export",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_export` at `crypto/hpke/hpke.c:1271` (ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED).
pub(crate) const HPKE_1271: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1271,
    func: c"OSSL_HPKE_export",
    lib: 15,
    reason: 786689,
    dynamic_reason: false,
};

/// `OSSL_HPKE_export` at `crypto/hpke/hpke.c:1276` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1276: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1276,
    func: c"OSSL_HPKE_export",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_export` at `crypto/hpke/hpke.c:1282` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1282: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1282,
    func: c"OSSL_HPKE_export",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_export` at `crypto/hpke/hpke.c:1300` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1300: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1300,
    func: c"OSSL_HPKE_export",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_keygen` at `crypto/hpke/hpke.c:1316` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1316: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1316,
    func: c"OSSL_HPKE_keygen",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_keygen` at `crypto/hpke/hpke.c:1320` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1320: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1320,
    func: c"OSSL_HPKE_keygen",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_keygen` at `crypto/hpke/hpke.c:1326` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1326: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1326,
    func: c"OSSL_HPKE_keygen",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_keygen` at `crypto/hpke/hpke.c:1339` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1339: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1339,
    func: c"OSSL_HPKE_keygen",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_keygen` at `crypto/hpke/hpke.c:1347` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1347: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1347,
    func: c"OSSL_HPKE_keygen",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_keygen` at `crypto/hpke/hpke.c:1351` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1351: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1351,
    func: c"OSSL_HPKE_keygen",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_keygen` at `crypto/hpke/hpke.c:1359` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1359: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1359,
    func: c"OSSL_HPKE_keygen",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_get_grease_value` at `crypto/hpke/hpke.c:1391` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_1391: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1391,
    func: c"OSSL_HPKE_get_grease_value",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `OSSL_HPKE_get_grease_value` at `crypto/hpke/hpke.c:1397` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1397: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1397,
    func: c"OSSL_HPKE_get_grease_value",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_get_grease_value` at `crypto/hpke/hpke.c:1404` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1404: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1404,
    func: c"OSSL_HPKE_get_grease_value",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_get_grease_value` at `crypto/hpke/hpke.c:1410` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1410: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1410,
    func: c"OSSL_HPKE_get_grease_value",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_get_grease_value` at `crypto/hpke/hpke.c:1416` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1416: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1416,
    func: c"OSSL_HPKE_get_grease_value",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_get_grease_value` at `crypto/hpke/hpke.c:1429` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1429: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1429,
    func: c"OSSL_HPKE_get_grease_value",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `OSSL_HPKE_get_grease_value` at `crypto/hpke/hpke.c:1434` (ERR_R_INTERNAL_ERROR).
pub(crate) const HPKE_1434: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke.c",
    line: 1434,
    func: c"OSSL_HPKE_get_grease_value",
    lib: 15,
    reason: 786691,
    dynamic_reason: false,
};

/// `ossl_HPKE_KEM_INFO_find_curve` at `crypto/hpke/hpke_util.c:168` (PROV_R_INVALID_CURVE).
pub(crate) const HPKE_UTIL_168: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke_util.c",
    line: 168,
    func: c"ossl_HPKE_KEM_INFO_find_curve",
    lib: 57,
    reason: 176,
    dynamic_reason: false,
};

/// `ossl_HPKE_KEM_INFO_find_id` at `crypto/hpke/hpke_util.c:181` (PROV_R_INVALID_CURVE).
pub(crate) const HPKE_UTIL_181: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke_util.c",
    line: 181,
    func: c"ossl_HPKE_KEM_INFO_find_id",
    lib: 57,
    reason: 176,
    dynamic_reason: false,
};

/// `ossl_HPKE_KEM_INFO_find_id` at `crypto/hpke/hpke_util.c:188` (PROV_R_INVALID_CURVE).
pub(crate) const HPKE_UTIL_188: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke_util.c",
    line: 188,
    func: c"ossl_HPKE_KEM_INFO_find_id",
    lib: 57,
    reason: 176,
    dynamic_reason: false,
};

/// `ossl_HPKE_KDF_INFO_find_id` at `crypto/hpke/hpke_util.c:210` (PROV_R_INVALID_KDF).
pub(crate) const HPKE_UTIL_210: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke_util.c",
    line: 210,
    func: c"ossl_HPKE_KDF_INFO_find_id",
    lib: 57,
    reason: 232,
    dynamic_reason: false,
};

/// `ossl_HPKE_AEAD_INFO_find_id` at `crypto/hpke/hpke_util.c:232` (PROV_R_INVALID_AEAD).
pub(crate) const HPKE_UTIL_232: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke_util.c",
    line: 232,
    func: c"ossl_HPKE_AEAD_INFO_find_id",
    lib: 57,
    reason: 231,
    dynamic_reason: false,
};

/// `kdf_derive` at `crypto/hpke/hpke_util.c:269` (PROV_R_FAILED_DURING_DERIVATION).
pub(crate) const HPKE_UTIL_269: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke_util.c",
    line: 269,
    func: c"kdf_derive",
    lib: 57,
    reason: 164,
    dynamic_reason: false,
};

/// `ossl_hpke_labeled_extract` at `crypto/hpke/hpke_util.c:329` (PROV_R_OUTPUT_BUFFER_TOO_SMALL).
pub(crate) const HPKE_UTIL_329: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke_util.c",
    line: 329,
    func: c"ossl_hpke_labeled_extract",
    lib: 57,
    reason: 106,
    dynamic_reason: false,
};

/// `ossl_hpke_labeled_expand` at `crypto/hpke/hpke_util.c:380` (PROV_R_OUTPUT_BUFFER_TOO_SMALL).
pub(crate) const HPKE_UTIL_380: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke_util.c",
    line: 380,
    func: c"ossl_hpke_labeled_expand",
    lib: 57,
    reason: 106,
    dynamic_reason: false,
};

/// `ossl_kdf_ctx_create` at `crypto/hpke/hpke_util.c:401` (ERR_R_FETCH_FAILED).
pub(crate) const HPKE_UTIL_401: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke_util.c",
    line: 401,
    func: c"ossl_kdf_ctx_create",
    lib: 15,
    reason: 524557,
    dynamic_reason: false,
};

/// `ossl_hpke_str2suite` at `crypto/hpke/hpke_util.c:459` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const HPKE_UTIL_459: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke_util.c",
    line: 459,
    func: c"ossl_hpke_str2suite",
    lib: 15,
    reason: 786690,
    dynamic_reason: false,
};

/// `ossl_hpke_str2suite` at `crypto/hpke/hpke_util.c:464` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const HPKE_UTIL_464: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/hpke/hpke_util.c",
    line: 464,
    func: c"ossl_hpke_str2suite",
    lib: 15,
    reason: 524550,
    dynamic_reason: false,
};

/// `EVP_PKEY_asn1_add0` at `crypto/asn1/ameth_lib.c:162` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const AMETH_LIB_162: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/ameth_lib.c",
    line: 162,
    func: c"EVP_PKEY_asn1_add0",
    lib: 6,
    reason: 524550,
    dynamic_reason: false,
};

/// `EVP_PKEY_asn1_add0` at `crypto/asn1/ameth_lib.c:174` (EVP_R_PKEY_APPLICATION_ASN1_METHOD_ALREADY_REGISTERED).
pub(crate) const AMETH_LIB_174: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/ameth_lib.c",
    line: 174,
    func: c"EVP_PKEY_asn1_add0",
    lib: 6,
    reason: 179,
    dynamic_reason: false,
};

/// `PKCS5_pbe2_set_scrypt` at `crypto/asn1/p5_scrypt.c:54` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const P5_SCRYPT_54: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 54,
    func: c"PKCS5_pbe2_set_scrypt",
    lib: 13,
    reason: 786690,
    dynamic_reason: false,
};

/// `PKCS5_pbe2_set_scrypt` at `crypto/asn1/p5_scrypt.c:59` (ASN1_R_INVALID_SCRYPT_PARAMETERS).
pub(crate) const P5_SCRYPT_59: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 59,
    func: c"PKCS5_pbe2_set_scrypt",
    lib: 13,
    reason: 227,
    dynamic_reason: false,
};

/// `PKCS5_pbe2_set_scrypt` at `crypto/asn1/p5_scrypt.c:65` (ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER).
pub(crate) const P5_SCRYPT_65: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 65,
    func: c"PKCS5_pbe2_set_scrypt",
    lib: 13,
    reason: 108,
    dynamic_reason: false,
};

/// `PKCS5_pbe2_set_scrypt` at `crypto/asn1/p5_scrypt.c:71` (ERR_R_ASN1_LIB).
pub(crate) const P5_SCRYPT_71: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 71,
    func: c"PKCS5_pbe2_set_scrypt",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `PKCS5_pbe2_set_scrypt` at `crypto/asn1/p5_scrypt.c:81` (ERR_R_ASN1_LIB).
pub(crate) const P5_SCRYPT_81: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 81,
    func: c"PKCS5_pbe2_set_scrypt",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `PKCS5_pbe2_set_scrypt` at `crypto/asn1/p5_scrypt.c:96` (ERR_R_EVP_LIB).
pub(crate) const P5_SCRYPT_96: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 96,
    func: c"PKCS5_pbe2_set_scrypt",
    lib: 13,
    reason: 524294,
    dynamic_reason: false,
};

/// `PKCS5_pbe2_set_scrypt` at `crypto/asn1/p5_scrypt.c:104` (ASN1_R_ERROR_SETTING_CIPHER_PARAMS).
pub(crate) const P5_SCRYPT_104: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 104,
    func: c"PKCS5_pbe2_set_scrypt",
    lib: 13,
    reason: 114,
    dynamic_reason: false,
};

/// `PKCS5_pbe2_set_scrypt` at `crypto/asn1/p5_scrypt.c:122` (ERR_R_ASN1_LIB).
pub(crate) const P5_SCRYPT_122: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 122,
    func: c"PKCS5_pbe2_set_scrypt",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `PKCS5_pbe2_set_scrypt` at `crypto/asn1/p5_scrypt.c:130` (ERR_R_ASN1_LIB).
pub(crate) const P5_SCRYPT_130: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 130,
    func: c"PKCS5_pbe2_set_scrypt",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `PKCS5_pbe2_set_scrypt` at `crypto/asn1/p5_scrypt.c:141` (ERR_R_ASN1_LIB).
pub(crate) const P5_SCRYPT_141: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 141,
    func: c"PKCS5_pbe2_set_scrypt",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `pkcs5_scrypt_set` at `crypto/asn1/p5_scrypt.c:166` (ERR_R_ASN1_LIB).
pub(crate) const P5_SCRYPT_166: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 166,
    func: c"pkcs5_scrypt_set",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `pkcs5_scrypt_set` at `crypto/asn1/p5_scrypt.c:175` (ERR_R_ASN1_LIB).
pub(crate) const P5_SCRYPT_175: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 175,
    func: c"pkcs5_scrypt_set",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `pkcs5_scrypt_set` at `crypto/asn1/p5_scrypt.c:183` (ERR_R_ASN1_LIB).
pub(crate) const P5_SCRYPT_183: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 183,
    func: c"pkcs5_scrypt_set",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `pkcs5_scrypt_set` at `crypto/asn1/p5_scrypt.c:188` (ERR_R_ASN1_LIB).
pub(crate) const P5_SCRYPT_188: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 188,
    func: c"pkcs5_scrypt_set",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `pkcs5_scrypt_set` at `crypto/asn1/p5_scrypt.c:193` (ERR_R_ASN1_LIB).
pub(crate) const P5_SCRYPT_193: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 193,
    func: c"pkcs5_scrypt_set",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `pkcs5_scrypt_set` at `crypto/asn1/p5_scrypt.c:202` (ERR_R_ASN1_LIB).
pub(crate) const P5_SCRYPT_202: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 202,
    func: c"pkcs5_scrypt_set",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `pkcs5_scrypt_set` at `crypto/asn1/p5_scrypt.c:206` (ERR_R_ASN1_LIB).
pub(crate) const P5_SCRYPT_206: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 206,
    func: c"pkcs5_scrypt_set",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `pkcs5_scrypt_set` at `crypto/asn1/p5_scrypt.c:215` (ERR_R_ASN1_LIB).
pub(crate) const P5_SCRYPT_215: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 215,
    func: c"pkcs5_scrypt_set",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `pkcs5_scrypt_set` at `crypto/asn1/p5_scrypt.c:226` (ERR_R_ASN1_LIB).
pub(crate) const P5_SCRYPT_226: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 226,
    func: c"pkcs5_scrypt_set",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `PKCS5_v2_scrypt_keyivgen_ex` at `crypto/asn1/p5_scrypt.c:252` (EVP_R_NO_CIPHER_SET).
pub(crate) const P5_SCRYPT_252: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 252,
    func: c"PKCS5_v2_scrypt_keyivgen_ex",
    lib: 6,
    reason: 131,
    dynamic_reason: false,
};

/// `PKCS5_v2_scrypt_keyivgen_ex` at `crypto/asn1/p5_scrypt.c:261` (EVP_R_DECODE_ERROR).
pub(crate) const P5_SCRYPT_261: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 261,
    func: c"PKCS5_v2_scrypt_keyivgen_ex",
    lib: 6,
    reason: 114,
    dynamic_reason: false,
};

/// `PKCS5_v2_scrypt_keyivgen_ex` at `crypto/asn1/p5_scrypt.c:267` (EVP_R_INVALID_KEY_LENGTH).
pub(crate) const P5_SCRYPT_267: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 267,
    func: c"PKCS5_v2_scrypt_keyivgen_ex",
    lib: 6,
    reason: 130,
    dynamic_reason: false,
};

/// `PKCS5_v2_scrypt_keyivgen_ex` at `crypto/asn1/p5_scrypt.c:278` (EVP_R_UNSUPPORTED_KEYLENGTH).
pub(crate) const P5_SCRYPT_278: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 278,
    func: c"PKCS5_v2_scrypt_keyivgen_ex",
    lib: 6,
    reason: 123,
    dynamic_reason: false,
};

/// `PKCS5_v2_scrypt_keyivgen_ex` at `crypto/asn1/p5_scrypt.c:289` (EVP_R_ILLEGAL_SCRYPT_PARAMETERS).
pub(crate) const P5_SCRYPT_289: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/p5_scrypt.c",
    line: 289,
    func: c"PKCS5_v2_scrypt_keyivgen_ex",
    lib: 6,
    reason: 171,
    dynamic_reason: false,
};

/// `i2d_provided` at `crypto/asn1/i2d_evp.c:69` (ASN1_R_UNSUPPORTED_TYPE).
pub(crate) const I2D_EVP_69: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/i2d_evp.c",
    line: 69,
    func: c"i2d_provided",
    lib: 13,
    reason: 196,
    dynamic_reason: false,
};

/// `i2d_KeyParams` at `crypto/asn1/i2d_evp.c:87` (ASN1_R_UNSUPPORTED_TYPE).
pub(crate) const I2D_EVP_87: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/i2d_evp.c",
    line: 87,
    func: c"i2d_KeyParams",
    lib: 13,
    reason: 196,
    dynamic_reason: false,
};

/// `i2d_PrivateKey_impl` at `crypto/asn1/i2d_evp.c:127` (ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE).
pub(crate) const I2D_EVP_127: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/i2d_evp.c",
    line: 127,
    func: c"i2d_PrivateKey_impl",
    lib: 13,
    reason: 167,
    dynamic_reason: false,
};

/// `i2d_PublicKey` at `crypto/asn1/i2d_evp.c:166` (ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE).
pub(crate) const I2D_EVP_166: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/i2d_evp.c",
    line: 166,
    func: c"i2d_PublicKey",
    lib: 13,
    reason: 167,
    dynamic_reason: false,
};

/// `d2i_PrivateKey_decoder` at `crypto/asn1/d2i_pr.c:61` (ASN1_R_ASN1_PARSE_ERROR).
pub(crate) const D2I_PR_61: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/d2i_pr.c",
    line: 61,
    func: c"d2i_PrivateKey_decoder",
    lib: 13,
    reason: 203,
    dynamic_reason: false,
};

/// `ossl_d2i_PrivateKey_legacy` at `crypto/asn1/d2i_pr.c:110` (ERR_R_EVP_LIB).
pub(crate) const D2I_PR_110: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/d2i_pr.c",
    line: 110,
    func: c"ossl_d2i_PrivateKey_legacy",
    lib: 13,
    reason: 524294,
    dynamic_reason: false,
};

/// `ossl_d2i_PrivateKey_legacy` at `crypto/asn1/d2i_pr.c:122` (ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE).
pub(crate) const D2I_PR_122: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/d2i_pr.c",
    line: 122,
    func: c"ossl_d2i_PrivateKey_legacy",
    lib: 13,
    reason: 163,
    dynamic_reason: false,
};

/// `ossl_d2i_PrivateKey_legacy` at `crypto/asn1/d2i_pr.c:150` (ERR_R_ASN1_LIB).
pub(crate) const D2I_PR_150: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/d2i_pr.c",
    line: 150,
    func: c"ossl_d2i_PrivateKey_legacy",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `d2i_AutoPrivateKey_legacy` at `crypto/asn1/d2i_pr.c:218` (ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE).
pub(crate) const D2I_PR_218: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/d2i_pr.c",
    line: 218,
    func: c"d2i_AutoPrivateKey_legacy",
    lib: 13,
    reason: 167,
    dynamic_reason: false,
};

/// `d2i_KeyParams` at `crypto/asn1/d2i_param.c:33` (ASN1_R_UNSUPPORTED_TYPE).
pub(crate) const D2I_PARAM_33: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/d2i_param.c",
    line: 33,
    func: c"d2i_KeyParams",
    lib: 13,
    reason: 196,
    dynamic_reason: false,
};

/// `d2i_PublicKey` at `crypto/asn1/d2i_pu.c:36` (ERR_R_EVP_LIB).
pub(crate) const D2I_PU_36: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/d2i_pu.c",
    line: 36,
    func: c"d2i_PublicKey",
    lib: 13,
    reason: 524294,
    dynamic_reason: false,
};

/// `d2i_PublicKey` at `crypto/asn1/d2i_pu.c:53` (ERR_R_EVP_LIB).
pub(crate) const D2I_PU_53: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/d2i_pu.c",
    line: 53,
    func: c"d2i_PublicKey",
    lib: 13,
    reason: 524294,
    dynamic_reason: false,
};

/// `d2i_PublicKey` at `crypto/asn1/d2i_pu.c:60` (ERR_R_ASN1_LIB).
pub(crate) const D2I_PU_60: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/d2i_pu.c",
    line: 60,
    func: c"d2i_PublicKey",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `d2i_PublicKey` at `crypto/asn1/d2i_pu.c:67` (ERR_R_ASN1_LIB).
pub(crate) const D2I_PU_67: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/d2i_pu.c",
    line: 67,
    func: c"d2i_PublicKey",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `d2i_PublicKey` at `crypto/asn1/d2i_pu.c:80` (ERR_R_ASN1_LIB).
pub(crate) const D2I_PU_80: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/d2i_pu.c",
    line: 80,
    func: c"d2i_PublicKey",
    lib: 13,
    reason: 524301,
    dynamic_reason: false,
};

/// `d2i_PublicKey` at `crypto/asn1/d2i_pu.c:86` (ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE).
pub(crate) const D2I_PU_86: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/asn1/d2i_pu.c",
    line: 86,
    func: c"d2i_PublicKey",
    lib: 13,
    reason: 163,
    dynamic_reason: false,
};

/// `PEM_def_callback` at `crypto/pem/pem_lib.c:64` (PEM_R_PROBLEMS_GETTING_PASSWORD).
pub(crate) const PEM_LIB_64: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 64,
    func: c"PEM_def_callback",
    lib: 9,
    reason: 109,
    dynamic_reason: false,
};

/// `PEM_ASN1_read` at `crypto/pem/pem_lib.c:118` (ERR_R_BUF_LIB).
pub(crate) const PEM_LIB_118: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 118,
    func: c"PEM_ASN1_read",
    lib: 9,
    reason: 524295,
    dynamic_reason: false,
};

/// `PEM_ASN1_write` at `crypto/pem/pem_lib.c:312` (ERR_R_BUF_LIB).
pub(crate) const PEM_LIB_312: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 312,
    func: c"PEM_ASN1_write",
    lib: 9,
    reason: 524295,
    dynamic_reason: false,
};

/// `PEM_ASN1_write_bio_internal` at `crypto/pem/pem_lib.c:346` (PEM_R_UNSUPPORTED_CIPHER).
pub(crate) const PEM_LIB_346: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 346,
    func: c"PEM_ASN1_write_bio_internal",
    lib: 9,
    reason: 113,
    dynamic_reason: false,
};

/// `PEM_ASN1_write_bio_internal` at `crypto/pem/pem_lib.c:352` (CRYPTO_R_INVALID_NULL_ARGUMENT).
pub(crate) const PEM_LIB_352: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 352,
    func: c"PEM_ASN1_write_bio_internal",
    lib: 15,
    reason: 109,
    dynamic_reason: false,
};

/// `PEM_ASN1_write_bio_internal` at `crypto/pem/pem_lib.c:358` (ERR_R_ASN1_LIB).
pub(crate) const PEM_LIB_358: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 358,
    func: c"PEM_ASN1_write_bio_internal",
    lib: 9,
    reason: 524301,
    dynamic_reason: false,
};

/// `PEM_ASN1_write_bio_internal` at `crypto/pem/pem_lib.c:376` (PEM_R_READ_KEY).
pub(crate) const PEM_LIB_376: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 376,
    func: c"PEM_ASN1_write_bio_internal",
    lib: 9,
    reason: 111,
    dynamic_reason: false,
};

/// `PEM_do_header` at `crypto/pem/pem_lib.c:459` (PEM_R_HEADER_TOO_LONG).
pub(crate) const PEM_LIB_459: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 459,
    func: c"PEM_do_header",
    lib: 9,
    reason: 128,
    dynamic_reason: false,
};

/// `PEM_do_header` at `crypto/pem/pem_lib.c:471` (PEM_R_BAD_PASSWORD_READ).
pub(crate) const PEM_LIB_471: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 471,
    func: c"PEM_do_header",
    lib: 9,
    reason: 104,
    dynamic_reason: false,
};

/// `PEM_do_header` at `crypto/pem/pem_lib.c:498` (PEM_R_BAD_DECRYPT).
pub(crate) const PEM_LIB_498: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 498,
    func: c"PEM_do_header",
    lib: 9,
    reason: 101,
    dynamic_reason: false,
};

/// `PEM_get_EVP_CIPHER_INFO` at `crypto/pem/pem_lib.c:533` (PEM_R_NOT_PROC_TYPE).
pub(crate) const PEM_LIB_533: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 533,
    func: c"PEM_get_EVP_CIPHER_INFO",
    lib: 9,
    reason: 107,
    dynamic_reason: false,
};

/// `PEM_get_EVP_CIPHER_INFO` at `crypto/pem/pem_lib.c:544` (PEM_R_NOT_ENCRYPTED).
pub(crate) const PEM_LIB_544: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 544,
    func: c"PEM_get_EVP_CIPHER_INFO",
    lib: 9,
    reason: 106,
    dynamic_reason: false,
};

/// `PEM_get_EVP_CIPHER_INFO` at `crypto/pem/pem_lib.c:549` (PEM_R_SHORT_HEADER).
pub(crate) const PEM_LIB_549: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 549,
    func: c"PEM_get_EVP_CIPHER_INFO",
    lib: 9,
    reason: 112,
    dynamic_reason: false,
};

/// `PEM_get_EVP_CIPHER_INFO` at `crypto/pem/pem_lib.c:558` (PEM_R_NOT_DEK_INFO).
pub(crate) const PEM_LIB_558: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 558,
    func: c"PEM_get_EVP_CIPHER_INFO",
    lib: 9,
    reason: 105,
    dynamic_reason: false,
};

/// `PEM_get_EVP_CIPHER_INFO` at `crypto/pem/pem_lib.c:576` (PEM_R_UNSUPPORTED_ENCRYPTION).
pub(crate) const PEM_LIB_576: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 576,
    func: c"PEM_get_EVP_CIPHER_INFO",
    lib: 9,
    reason: 114,
    dynamic_reason: false,
};

/// `PEM_get_EVP_CIPHER_INFO` at `crypto/pem/pem_lib.c:581` (PEM_R_MISSING_DEK_IV).
pub(crate) const PEM_LIB_581: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 581,
    func: c"PEM_get_EVP_CIPHER_INFO",
    lib: 9,
    reason: 129,
    dynamic_reason: false,
};

/// `PEM_get_EVP_CIPHER_INFO` at `crypto/pem/pem_lib.c:584` (PEM_R_UNEXPECTED_DEK_IV).
pub(crate) const PEM_LIB_584: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 584,
    func: c"PEM_get_EVP_CIPHER_INFO",
    lib: 9,
    reason: 130,
    dynamic_reason: false,
};

/// `load_iv` at `crypto/pem/pem_lib.c:606` (PEM_R_BAD_IV_CHARS).
pub(crate) const PEM_LIB_606: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 606,
    func: c"load_iv",
    lib: 9,
    reason: 103,
    dynamic_reason: false,
};

/// `PEM_write` at `crypto/pem/pem_lib.c:625` (ERR_R_BUF_LIB).
pub(crate) const PEM_LIB_625: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 625,
    func: c"PEM_write",
    lib: 9,
    reason: 524295,
    dynamic_reason: false,
};

/// `PEM_write_bio` at `crypto/pem/pem_lib.c:697` (ERR_raise dynamic reason).
pub(crate) const PEM_LIB_697: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 697,
    func: c"PEM_write_bio",
    lib: 9,
    reason: 0,
    dynamic_reason: true,
};

/// `PEM_read` at `crypto/pem/pem_lib.c:711` (ERR_R_BUF_LIB).
pub(crate) const PEM_LIB_711: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 711,
    func: c"PEM_read",
    lib: 9,
    reason: 524295,
    dynamic_reason: false,
};

/// `get_name` at `crypto/pem/pem_lib.c:794` (PEM_R_NO_START_LINE).
pub(crate) const PEM_LIB_794: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 794,
    func: c"get_name",
    lib: 9,
    reason: 108,
    dynamic_reason: false,
};

/// `get_header_and_data` at `crypto/pem/pem_lib.c:858` (PEM_R_BAD_END_LINE).
pub(crate) const PEM_LIB_858: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 858,
    func: c"get_header_and_data",
    lib: 9,
    reason: 102,
    dynamic_reason: false,
};

/// `get_header_and_data` at `crypto/pem/pem_lib.c:887` (PEM_R_BAD_END_LINE).
pub(crate) const PEM_LIB_887: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 887,
    func: c"get_header_and_data",
    lib: 9,
    reason: 102,
    dynamic_reason: false,
};

/// `get_header_and_data` at `crypto/pem/pem_lib.c:901` (PEM_R_BAD_END_LINE).
pub(crate) const PEM_LIB_901: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 901,
    func: c"get_header_and_data",
    lib: 9,
    reason: 102,
    dynamic_reason: false,
};

/// `get_header_and_data` at `crypto/pem/pem_lib.c:911` (PEM_R_BAD_END_LINE).
pub(crate) const PEM_LIB_911: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 911,
    func: c"get_header_and_data",
    lib: 9,
    reason: 102,
    dynamic_reason: false,
};

/// `PEM_read_bio_ex` at `crypto/pem/pem_lib.c:959` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const PEM_LIB_959: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 959,
    func: c"PEM_read_bio_ex",
    lib: 9,
    reason: 524550,
    dynamic_reason: false,
};

/// `PEM_read_bio_ex` at `crypto/pem/pem_lib.c:967` (ERR_R_BIO_LIB).
pub(crate) const PEM_LIB_967: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 967,
    func: c"PEM_read_bio_ex",
    lib: 9,
    reason: 524320,
    dynamic_reason: false,
};

/// `PEM_read_bio_ex` at `crypto/pem/pem_lib.c:978` (PEM_R_BAD_BASE64_DECODE).
pub(crate) const PEM_LIB_978: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 978,
    func: c"PEM_read_bio_ex",
    lib: 9,
    reason: 100,
    dynamic_reason: false,
};

/// `PEM_read_bio_ex` at `crypto/pem/pem_lib.c:989` (ERR_R_EVP_LIB).
pub(crate) const PEM_LIB_989: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 989,
    func: c"PEM_read_bio_ex",
    lib: 9,
    reason: 524294,
    dynamic_reason: false,
};

/// `PEM_read_bio_ex` at `crypto/pem/pem_lib.c:1000` (PEM_R_BAD_BASE64_DECODE).
pub(crate) const PEM_LIB_1000: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_lib.c",
    line: 1000,
    func: c"PEM_read_bio_ex",
    lib: 9,
    reason: 100,
    dynamic_reason: false,
};

/// `PEM_ASN1_read_bio` at `crypto/pem/pem_oth.c:33` (ERR_R_ASN1_LIB).
pub(crate) const PEM_OTH_33: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_oth.c",
    line: 33,
    func: c"PEM_ASN1_read_bio",
    lib: 9,
    reason: 524301,
    dynamic_reason: false,
};

/// `pem_read_bio_key_decoder` at `crypto/pem/pem_pkey.c:87` (PEM_R_UNSUPPORTED_KEY_COMPONENTS).
pub(crate) const PEM_PKEY_87: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_pkey.c",
    line: 87,
    func: c"pem_read_bio_key_decoder",
    lib: 9,
    reason: 126,
    dynamic_reason: false,
};

/// `pem_read_bio_key_legacy` at `crypto/pem/pem_pkey.c:161` (PEM_R_BAD_PASSWORD_READ).
pub(crate) const PEM_PKEY_161: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_pkey.c",
    line: 161,
    func: c"pem_read_bio_key_legacy",
    lib: 9,
    reason: 104,
    dynamic_reason: false,
};

/// `pem_read_bio_key_legacy` at `crypto/pem/pem_pkey.c:209` (ERR_R_ASN1_LIB).
pub(crate) const PEM_PKEY_209: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_pkey.c",
    line: 209,
    func: c"pem_read_bio_key_legacy",
    lib: 9,
    reason: 524301,
    dynamic_reason: false,
};

/// `PEM_read_PUBKEY_ex` at `crypto/pem/pem_pkey.c:288` (ERR_R_BUF_LIB).
pub(crate) const PEM_PKEY_288: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_pkey.c",
    line: 288,
    func: c"PEM_read_PUBKEY_ex",
    lib: 9,
    reason: 524295,
    dynamic_reason: false,
};

/// `PEM_write_bio_PrivateKey_traditional` at `crypto/pem/pem_pkey.c:360` (PEM_R_UNSUPPORTED_PUBLIC_KEY_TYPE).
pub(crate) const PEM_PKEY_360: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_pkey.c",
    line: 360,
    func: c"PEM_write_bio_PrivateKey_traditional",
    lib: 9,
    reason: 110,
    dynamic_reason: false,
};

/// `PEM_read_PrivateKey_ex` at `crypto/pem/pem_pkey.c:418` (ERR_R_BUF_LIB).
pub(crate) const PEM_PKEY_418: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_pkey.c",
    line: 418,
    func: c"PEM_read_PrivateKey_ex",
    lib: 9,
    reason: 524295,
    dynamic_reason: false,
};

/// `PEM_write_cb_ex_fnsig` at `crypto/pem/pem_pkey.c:439` (ERR_R_BUF_LIB).
pub(crate) const PEM_PKEY_439: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_pkey.c",
    line: 439,
    func: c"PEM_write_cb_ex_fnsig",
    lib: 9,
    reason: 524295,
    dynamic_reason: false,
};

/// `do_pk8pkey` at `crypto/pem/pem_pk8.c:132` (PEM_R_ERROR_CONVERTING_PRIVATE_KEY).
pub(crate) const PEM_PK8_132: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_pk8.c",
    line: 132,
    func: c"do_pk8pkey",
    lib: 9,
    reason: 115,
    dynamic_reason: false,
};

/// `do_pk8pkey` at `crypto/pem/pem_pk8.c:139` (PEM_R_READ_KEY).
pub(crate) const PEM_PK8_139: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_pk8.c",
    line: 139,
    func: c"do_pk8pkey",
    lib: 9,
    reason: 111,
    dynamic_reason: false,
};

/// `d2i_PKCS8PrivateKey_bio` at `crypto/pem/pem_pk8.c:185` (PEM_R_BAD_PASSWORD_READ).
pub(crate) const PEM_PK8_185: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_pk8.c",
    line: 185,
    func: c"d2i_PKCS8PrivateKey_bio",
    lib: 9,
    reason: 104,
    dynamic_reason: false,
};

/// `do_pk8pkey_fp` at `crypto/pem/pem_pk8.c:243` (ERR_R_BUF_LIB).
pub(crate) const PEM_PK8_243: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_pk8.c",
    line: 243,
    func: c"do_pk8pkey_fp",
    lib: 9,
    reason: 524295,
    dynamic_reason: false,
};

/// `d2i_PKCS8PrivateKey_fp` at `crypto/pem/pem_pk8.c:258` (ERR_R_BUF_LIB).
pub(crate) const PEM_PK8_258: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/pem/pem_pk8.c",
    line: 258,
    func: c"d2i_PKCS8PrivateKey_fp",
    lib: 9,
    reason: 524295,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:80` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_80: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 80,
    func: c"ossl_cipher_generic_get_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:91` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_91: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 91,
    func: c"ossl_cipher_generic_get_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:106` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_106: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 106,
    func: c"ossl_cipher_generic_get_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:117` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_117: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 117,
    func: c"ossl_cipher_generic_get_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:129` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_129: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 129,
    func: c"ossl_cipher_generic_get_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:140` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_140: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 140,
    func: c"ossl_cipher_generic_get_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:151` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_151: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 151,
    func: c"ossl_cipher_generic_get_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:162` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_162: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 162,
    func: c"ossl_cipher_generic_get_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:173` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_173: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 173,
    func: c"ossl_cipher_generic_get_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:184` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_184: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 184,
    func: c"ossl_cipher_generic_get_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params` at `providers/implementations/ciphers/ciphercommon.c:212` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_212: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 212,
    func: c"ossl_cipher_generic_get_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params` at `providers/implementations/ciphers/ciphercommon.c:217` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_217: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 217,
    func: c"ossl_cipher_generic_get_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params` at `providers/implementations/ciphers/ciphercommon.c:222` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_222: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 222,
    func: c"ossl_cipher_generic_get_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params` at `providers/implementations/ciphers/ciphercommon.c:227` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_227: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 227,
    func: c"ossl_cipher_generic_get_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params` at `providers/implementations/ciphers/ciphercommon.c:232` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_232: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 232,
    func: c"ossl_cipher_generic_get_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params` at `providers/implementations/ciphers/ciphercommon.c:237` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_237: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 237,
    func: c"ossl_cipher_generic_get_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params` at `providers/implementations/ciphers/ciphercommon.c:242` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_242: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 242,
    func: c"ossl_cipher_generic_get_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params` at `providers/implementations/ciphers/ciphercommon.c:246` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_246: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 246,
    func: c"ossl_cipher_generic_get_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params` at `providers/implementations/ciphers/ciphercommon.c:250` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_250: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 250,
    func: c"ossl_cipher_generic_get_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_get_params` at `providers/implementations/ciphers/ciphercommon.c:254` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_254: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 254,
    func: c"ossl_cipher_generic_get_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `cipher_generic_get_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:313` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_313: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 313,
    func: c"cipher_generic_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cipher_generic_get_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:322` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_322: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 322,
    func: c"cipher_generic_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cipher_generic_get_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:334` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_334: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 334,
    func: c"cipher_generic_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cipher_generic_get_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:345` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_345: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 345,
    func: c"cipher_generic_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cipher_generic_get_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:356` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_356: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 356,
    func: c"cipher_generic_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cipher_generic_get_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:367` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_367: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 367,
    func: c"cipher_generic_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cipher_generic_get_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:378` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_378: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 378,
    func: c"cipher_generic_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cipher_generic_set_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:437` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_437: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 437,
    func: c"cipher_generic_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cipher_generic_set_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:448` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_448: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 448,
    func: c"cipher_generic_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cipher_generic_set_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:475` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_475: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 475,
    func: c"cipher_generic_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cipher_generic_set_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:486` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_486: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 486,
    func: c"cipher_generic_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cipher_generic_set_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:501` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_501: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 501,
    func: c"cipher_generic_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cipher_var_keylen_set_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:565` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_565: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 565,
    func: c"cipher_var_keylen_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cipher_var_keylen_set_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:576` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_576: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 576,
    func: c"cipher_var_keylen_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cipher_var_keylen_set_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:587` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_587: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 587,
    func: c"cipher_var_keylen_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cipher_var_keylen_set_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:614` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_614: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 614,
    func: c"cipher_var_keylen_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cipher_var_keylen_set_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:625` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_625: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 625,
    func: c"cipher_var_keylen_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cipher_var_keylen_set_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon.c:640` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_640: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 640,
    func: c"cipher_var_keylen_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_var_keylen_set_ctx_params` at `providers/implementations/ciphers/ciphercommon.c:672` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_672: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 672,
    func: c"ossl_cipher_var_keylen_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `cipher_generic_init_internal` at `providers/implementations/ciphers/ciphercommon.c:719` (PROV_R_INVALID_KEY_LENGTH).
pub(crate) const PROV_CIPHERCOMMON_719: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 719,
    func: c"cipher_generic_init_internal",
    lib: 57,
    reason: 105,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_update` at `providers/implementations/ciphers/ciphercommon.c:783` (PROV_R_NO_KEY_SET).
pub(crate) const PROV_CIPHERCOMMON_783: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 783,
    func: c"ossl_cipher_generic_block_update",
    lib: 57,
    reason: 114,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_update` at `providers/implementations/ciphers/ciphercommon.c:798` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHERCOMMON_798: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 798,
    func: c"ossl_cipher_generic_block_update",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_update` at `providers/implementations/ciphers/ciphercommon.c:811` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHERCOMMON_811: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 811,
    func: c"ossl_cipher_generic_block_update",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_update` at `providers/implementations/ciphers/ciphercommon.c:816` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHERCOMMON_816: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 816,
    func: c"ossl_cipher_generic_block_update",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_update` at `providers/implementations/ciphers/ciphercommon.c:833` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHERCOMMON_833: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 833,
    func: c"ossl_cipher_generic_block_update",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_update` at `providers/implementations/ciphers/ciphercommon.c:839` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHERCOMMON_839: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 839,
    func: c"ossl_cipher_generic_block_update",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_update` at `providers/implementations/ciphers/ciphercommon.c:856` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHERCOMMON_856: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 856,
    func: c"ossl_cipher_generic_block_update",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_update` at `providers/implementations/ciphers/ciphercommon.c:875` (PROV_R_OUTPUT_BUFFER_TOO_SMALL).
pub(crate) const PROV_CIPHERCOMMON_875: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 875,
    func: c"ossl_cipher_generic_block_update",
    lib: 57,
    reason: 106,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_update` at `providers/implementations/ciphers/ciphercommon.c:879` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHERCOMMON_879: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 879,
    func: c"ossl_cipher_generic_block_update",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_update` at `providers/implementations/ciphers/ciphercommon.c:889` (PROV_R_OUTPUT_BUFFER_TOO_SMALL).
pub(crate) const PROV_CIPHERCOMMON_889: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 889,
    func: c"ossl_cipher_generic_block_update",
    lib: 57,
    reason: 106,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_update` at `providers/implementations/ciphers/ciphercommon.c:896` (PROV_R_OUTPUT_BUFFER_TOO_SMALL).
pub(crate) const PROV_CIPHERCOMMON_896: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 896,
    func: c"ossl_cipher_generic_block_update",
    lib: 57,
    reason: 106,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_update` at `providers/implementations/ciphers/ciphercommon.c:902` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHERCOMMON_902: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 902,
    func: c"ossl_cipher_generic_block_update",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_final` at `providers/implementations/ciphers/ciphercommon.c:928` (PROV_R_NO_KEY_SET).
pub(crate) const PROV_CIPHERCOMMON_928: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 928,
    func: c"ossl_cipher_generic_block_final",
    lib: 57,
    reason: 114,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_final` at `providers/implementations/ciphers/ciphercommon.c:934` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHERCOMMON_934: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 934,
    func: c"ossl_cipher_generic_block_final",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_final` at `providers/implementations/ciphers/ciphercommon.c:945` (PROV_R_WRONG_FINAL_BLOCK_LENGTH).
pub(crate) const PROV_CIPHERCOMMON_945: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 945,
    func: c"ossl_cipher_generic_block_final",
    lib: 57,
    reason: 107,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_final` at `providers/implementations/ciphers/ciphercommon.c:950` (PROV_R_OUTPUT_BUFFER_TOO_SMALL).
pub(crate) const PROV_CIPHERCOMMON_950: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 950,
    func: c"ossl_cipher_generic_block_final",
    lib: 57,
    reason: 106,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_final` at `providers/implementations/ciphers/ciphercommon.c:954` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHERCOMMON_954: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 954,
    func: c"ossl_cipher_generic_block_final",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_final` at `providers/implementations/ciphers/ciphercommon.c:968` (PROV_R_WRONG_FINAL_BLOCK_LENGTH).
pub(crate) const PROV_CIPHERCOMMON_968: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 968,
    func: c"ossl_cipher_generic_block_final",
    lib: 57,
    reason: 107,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_final` at `providers/implementations/ciphers/ciphercommon.c:973` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHERCOMMON_973: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 973,
    func: c"ossl_cipher_generic_block_final",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_block_final` at `providers/implementations/ciphers/ciphercommon.c:983` (PROV_R_OUTPUT_BUFFER_TOO_SMALL).
pub(crate) const PROV_CIPHERCOMMON_983: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 983,
    func: c"ossl_cipher_generic_block_final",
    lib: 57,
    reason: 106,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_stream_update` at `providers/implementations/ciphers/ciphercommon.c:999` (PROV_R_NO_KEY_SET).
pub(crate) const PROV_CIPHERCOMMON_999: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 999,
    func: c"ossl_cipher_generic_stream_update",
    lib: 57,
    reason: 114,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_stream_update` at `providers/implementations/ciphers/ciphercommon.c:1009` (PROV_R_OUTPUT_BUFFER_TOO_SMALL).
pub(crate) const PROV_CIPHERCOMMON_1009: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1009,
    func: c"ossl_cipher_generic_stream_update",
    lib: 57,
    reason: 106,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_stream_update` at `providers/implementations/ciphers/ciphercommon.c:1014` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHERCOMMON_1014: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1014,
    func: c"ossl_cipher_generic_stream_update",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_stream_final` at `providers/implementations/ciphers/ciphercommon.c:1063` (PROV_R_NO_KEY_SET).
pub(crate) const PROV_CIPHERCOMMON_1063: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1063,
    func: c"ossl_cipher_generic_stream_final",
    lib: 57,
    reason: 114,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_cipher` at `providers/implementations/ciphers/ciphercommon.c:1081` (PROV_R_NO_KEY_SET).
pub(crate) const PROV_CIPHERCOMMON_1081: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1081,
    func: c"ossl_cipher_generic_cipher",
    lib: 57,
    reason: 114,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_cipher` at `providers/implementations/ciphers/ciphercommon.c:1086` (PROV_R_OUTPUT_BUFFER_TOO_SMALL).
pub(crate) const PROV_CIPHERCOMMON_1086: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1086,
    func: c"ossl_cipher_generic_cipher",
    lib: 57,
    reason: 106,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_cipher` at `providers/implementations/ciphers/ciphercommon.c:1091` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHERCOMMON_1091: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1091,
    func: c"ossl_cipher_generic_cipher",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `ossl_cipher_common_get_ctx_params` at `providers/implementations/ciphers/ciphercommon.c:1102` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_1102: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1102,
    func: c"ossl_cipher_common_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_cipher_common_get_ctx_params` at `providers/implementations/ciphers/ciphercommon.c:1107` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_1107: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1107,
    func: c"ossl_cipher_common_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_cipher_common_get_ctx_params` at `providers/implementations/ciphers/ciphercommon.c:1113` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_1113: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1113,
    func: c"ossl_cipher_common_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_cipher_common_get_ctx_params` at `providers/implementations/ciphers/ciphercommon.c:1119` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_1119: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1119,
    func: c"ossl_cipher_common_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_cipher_common_get_ctx_params` at `providers/implementations/ciphers/ciphercommon.c:1124` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_1124: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1124,
    func: c"ossl_cipher_common_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_cipher_common_get_ctx_params` at `providers/implementations/ciphers/ciphercommon.c:1129` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_1129: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1129,
    func: c"ossl_cipher_common_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_cipher_common_get_ctx_params` at `providers/implementations/ciphers/ciphercommon.c:1135` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_1135: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1135,
    func: c"ossl_cipher_common_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_cipher_common_set_ctx_params` at `providers/implementations/ciphers/ciphercommon.c:1157` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_1157: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1157,
    func: c"ossl_cipher_common_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `ossl_cipher_common_set_ctx_params` at `providers/implementations/ciphers/ciphercommon.c:1167` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_1167: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1167,
    func: c"ossl_cipher_common_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `ossl_cipher_common_set_ctx_params` at `providers/implementations/ciphers/ciphercommon.c:1175` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_1175: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1175,
    func: c"ossl_cipher_common_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `ossl_cipher_common_set_ctx_params` at `providers/implementations/ciphers/ciphercommon.c:1182` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_1182: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1182,
    func: c"ossl_cipher_common_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `ossl_cipher_common_set_ctx_params` at `providers/implementations/ciphers/ciphercommon.c:1191` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_1191: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1191,
    func: c"ossl_cipher_common_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `ossl_cipher_common_set_ctx_params` at `providers/implementations/ciphers/ciphercommon.c:1195` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_1195: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1195,
    func: c"ossl_cipher_common_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `ossl_cipher_generic_initiv` at `providers/implementations/ciphers/ciphercommon.c:1221` (PROV_R_INVALID_IV_LENGTH).
pub(crate) const PROV_CIPHERCOMMON_1221: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon.c",
    line: 1221,
    func: c"ossl_cipher_generic_initiv",
    lib: 57,
    reason: 109,
    dynamic_reason: false,
};

/// `ossl_cipher_trailingdata` at `providers/implementations/ciphers/ciphercommon_block.c:70` (ERR_R_INTERNAL_ERROR).
pub(crate) const PROV_CIPHERCOMMON_BLOCK_70: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/ciphercommon_block.c",
    line: 70,
    func: c"ossl_cipher_trailingdata",
    lib: 57,
    reason: 786691,
    dynamic_reason: false,
};

/// `ossl_cipher_unpadblock` at `providers/implementations/ciphers/ciphercommon_block.c:97` (ERR_R_INTERNAL_ERROR).
pub(crate) const PROV_CIPHERCOMMON_BLOCK_97: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/ciphercommon_block.c",
    line: 97,
    func: c"ossl_cipher_unpadblock",
    lib: 57,
    reason: 786691,
    dynamic_reason: false,
};

/// `ossl_cipher_unpadblock` at `providers/implementations/ciphers/ciphercommon_block.c:107` (PROV_R_BAD_DECRYPT).
pub(crate) const PROV_CIPHERCOMMON_BLOCK_107: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/ciphercommon_block.c",
    line: 107,
    func: c"ossl_cipher_unpadblock",
    lib: 57,
    reason: 100,
    dynamic_reason: false,
};

/// `ossl_cipher_unpadblock` at `providers/implementations/ciphers/ciphercommon_block.c:112` (PROV_R_BAD_DECRYPT).
pub(crate) const PROV_CIPHERCOMMON_BLOCK_112: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/ciphercommon_block.c",
    line: 112,
    func: c"ossl_cipher_unpadblock",
    lib: 57,
    reason: 100,
    dynamic_reason: false,
};

/// `cipher_hw_aes_initkey` at `providers/implementations/ciphers/cipher_aes_hw.c:121` (PROV_R_KEY_SETUP_FAILED).
pub(crate) const PROV_CIPHER_AES_HW_121: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_hw.c",
    line: 121,
    func: c"cipher_hw_aes_initkey",
    lib: 57,
    reason: 101,
    dynamic_reason: false,
};

/// `cipher_hw_camellia_initkey` at `providers/implementations/ciphers/cipher_camellia_hw.c:30` (PROV_R_KEY_SETUP_FAILED).
pub(crate) const PROV_CIPHER_CAMELLIA_HW_30: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_camellia_hw.c",
    line: 30,
    func: c"cipher_hw_camellia_initkey",
    lib: 57,
    reason: 101,
    dynamic_reason: false,
};

/// `tdes_init` at `providers/implementations/ciphers/cipher_tdes_common.c:101` (PROV_R_INVALID_KEY_LENGTH).
pub(crate) const PROV_CIPHER_TDES_COMMON_101: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_tdes_common.c",
    line: 101,
    func: c"tdes_init",
    lib: 57,
    reason: 105,
    dynamic_reason: false,
};

/// `ossl_tdes_get_ctx_params` at `providers/implementations/ciphers/cipher_tdes_common.c:162` (PROV_R_FAILED_TO_GENERATE_KEY).
pub(crate) const PROV_CIPHER_TDES_COMMON_162: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_tdes_common.c",
    line: 162,
    func: c"ossl_tdes_get_ctx_params",
    lib: 57,
    reason: 121,
    dynamic_reason: false,
};

/// `ossl_tdes_get_params` at `providers/implementations/ciphers/cipher_tdes_common.c:195` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_TDES_COMMON_195: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_tdes_common.c",
    line: 195,
    func: c"ossl_tdes_get_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `null_get_ctx_params` at `providers/implementations/ciphers/cipher_null.c:130` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_NULL_130: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_null.c",
    line: 130,
    func: c"null_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `null_get_ctx_params` at `providers/implementations/ciphers/cipher_null.c:135` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_NULL_135: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_null.c",
    line: 135,
    func: c"null_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `null_get_ctx_params` at `providers/implementations/ciphers/cipher_null.c:141` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_NULL_141: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_null.c",
    line: 141,
    func: c"null_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `null_set_ctx_params` at `providers/implementations/ciphers/cipher_null.c:168` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_NULL_168: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_null.c",
    line: 168,
    func: c"null_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `aes_ocb_init` at `providers/implementations/ciphers/cipher_aes_ocb.c:119` (PROV_R_INVALID_IV_LENGTH).
pub(crate) const PROV_CIPHER_AES_OCB_119: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 119,
    func: c"aes_ocb_init",
    lib: 57,
    reason: 109,
    dynamic_reason: false,
};

/// `aes_ocb_init` at `providers/implementations/ciphers/cipher_aes_ocb.c:130` (PROV_R_INVALID_KEY_LENGTH).
pub(crate) const PROV_CIPHER_AES_OCB_130: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 130,
    func: c"aes_ocb_init",
    lib: 57,
    reason: 105,
    dynamic_reason: false,
};

/// `aes_ocb_block_update_internal` at `providers/implementations/ciphers/cipher_aes_ocb.c:173` (PROV_R_OUTPUT_BUFFER_TOO_SMALL).
pub(crate) const PROV_CIPHER_AES_OCB_173: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 173,
    func: c"aes_ocb_block_update_internal",
    lib: 57,
    reason: 106,
    dynamic_reason: false,
};

/// `aes_ocb_block_update_internal` at `providers/implementations/ciphers/cipher_aes_ocb.c:177` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHER_AES_OCB_177: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 177,
    func: c"aes_ocb_block_update_internal",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `aes_ocb_block_update_internal` at `providers/implementations/ciphers/cipher_aes_ocb.c:188` (PROV_R_OUTPUT_BUFFER_TOO_SMALL).
pub(crate) const PROV_CIPHER_AES_OCB_188: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 188,
    func: c"aes_ocb_block_update_internal",
    lib: 57,
    reason: 106,
    dynamic_reason: false,
};

/// `aes_ocb_block_update_internal` at `providers/implementations/ciphers/cipher_aes_ocb.c:192` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHER_AES_OCB_192: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 192,
    func: c"aes_ocb_block_update_internal",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `aes_ocb_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_ocb.c:363` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_OCB_363: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 363,
    func: c"aes_ocb_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `aes_ocb_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_ocb.c:369` (PROV_R_INVALID_TAG_LENGTH).
pub(crate) const PROV_CIPHER_AES_OCB_369: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 369,
    func: c"aes_ocb_set_ctx_params",
    lib: 57,
    reason: 118,
    dynamic_reason: false,
};

/// `aes_ocb_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_ocb.c:375` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const PROV_CIPHER_AES_OCB_375: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 375,
    func: c"aes_ocb_set_ctx_params",
    lib: 57,
    reason: 524550,
    dynamic_reason: false,
};

/// `aes_ocb_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_ocb.c:379` (PROV_R_INVALID_TAG_LENGTH).
pub(crate) const PROV_CIPHER_AES_OCB_379: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 379,
    func: c"aes_ocb_set_ctx_params",
    lib: 57,
    reason: 118,
    dynamic_reason: false,
};

/// `aes_ocb_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_ocb.c:388` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_OCB_388: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 388,
    func: c"aes_ocb_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `aes_ocb_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_ocb.c:404` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_OCB_404: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 404,
    func: c"aes_ocb_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `aes_ocb_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_ocb.c:408` (PROV_R_INVALID_KEY_LENGTH).
pub(crate) const PROV_CIPHER_AES_OCB_408: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 408,
    func: c"aes_ocb_set_ctx_params",
    lib: 57,
    reason: 105,
    dynamic_reason: false,
};

/// `aes_ocb_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_ocb.c:422` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_OCB_422: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 422,
    func: c"aes_ocb_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `aes_ocb_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_ocb.c:427` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_OCB_427: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 427,
    func: c"aes_ocb_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `aes_ocb_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_ocb.c:433` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_OCB_433: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 433,
    func: c"aes_ocb_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `aes_ocb_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_ocb.c:441` (PROV_R_INVALID_IV_LENGTH).
pub(crate) const PROV_CIPHER_AES_OCB_441: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 441,
    func: c"aes_ocb_get_ctx_params",
    lib: 57,
    reason: 109,
    dynamic_reason: false,
};

/// `aes_ocb_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_ocb.c:445` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_OCB_445: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 445,
    func: c"aes_ocb_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `aes_ocb_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_ocb.c:452` (PROV_R_INVALID_IV_LENGTH).
pub(crate) const PROV_CIPHER_AES_OCB_452: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 452,
    func: c"aes_ocb_get_ctx_params",
    lib: 57,
    reason: 109,
    dynamic_reason: false,
};

/// `aes_ocb_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_ocb.c:456` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_OCB_456: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 456,
    func: c"aes_ocb_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `aes_ocb_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_ocb.c:463` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_OCB_463: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 463,
    func: c"aes_ocb_get_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `aes_ocb_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_ocb.c:467` (PROV_R_INVALID_TAG_LENGTH).
pub(crate) const PROV_CIPHER_AES_OCB_467: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 467,
    func: c"aes_ocb_get_ctx_params",
    lib: 57,
    reason: 118,
    dynamic_reason: false,
};

/// `aes_ocb_cipher` at `providers/implementations/ciphers/cipher_aes_ocb.c:515` (PROV_R_OUTPUT_BUFFER_TOO_SMALL).
pub(crate) const PROV_CIPHER_AES_OCB_515: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 515,
    func: c"aes_ocb_cipher",
    lib: 57,
    reason: 106,
    dynamic_reason: false,
};

/// `aes_ocb_cipher` at `providers/implementations/ciphers/cipher_aes_ocb.c:528` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHER_AES_OCB_528: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 528,
    func: c"aes_ocb_cipher",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `aes_ocb_cipher` at `providers/implementations/ciphers/cipher_aes_ocb.c:533` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHER_AES_OCB_533: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_ocb.c",
    line: 533,
    func: c"aes_ocb_cipher",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `aes_wrap_init` at `providers/implementations/ciphers/cipher_aes_wrp.c:123` (PROV_R_INVALID_KEY_LENGTH).
pub(crate) const PROV_CIPHER_AES_WRP_123: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_wrp.c",
    line: 123,
    func: c"aes_wrap_init",
    lib: 57,
    reason: 105,
    dynamic_reason: false,
};

/// `aes_wrap_cipher_internal` at `providers/implementations/ciphers/cipher_aes_wrp.c:178` (PROV_R_INVALID_INPUT_LENGTH).
pub(crate) const PROV_CIPHER_AES_WRP_178: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_wrp.c",
    line: 178,
    func: c"aes_wrap_cipher_internal",
    lib: 57,
    reason: 230,
    dynamic_reason: false,
};

/// `aes_wrap_cipher_internal` at `providers/implementations/ciphers/cipher_aes_wrp.c:184` (PROV_R_INVALID_INPUT_LENGTH).
pub(crate) const PROV_CIPHER_AES_WRP_184: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_wrp.c",
    line: 184,
    func: c"aes_wrap_cipher_internal",
    lib: 57,
    reason: 230,
    dynamic_reason: false,
};

/// `aes_wrap_cipher_internal` at `providers/implementations/ciphers/cipher_aes_wrp.c:190` (PROV_R_INVALID_INPUT_LENGTH).
pub(crate) const PROV_CIPHER_AES_WRP_190: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_wrp.c",
    line: 190,
    func: c"aes_wrap_cipher_internal",
    lib: 57,
    reason: 230,
    dynamic_reason: false,
};

/// `aes_wrap_cipher_internal` at `providers/implementations/ciphers/cipher_aes_wrp.c:214` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHER_AES_WRP_214: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_wrp.c",
    line: 214,
    func: c"aes_wrap_cipher_internal",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `aes_wrap_cipher_internal` at `providers/implementations/ciphers/cipher_aes_wrp.c:218` (PROV_R_INVALID_OUTPUT_LENGTH).
pub(crate) const PROV_CIPHER_AES_WRP_218: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_wrp.c",
    line: 218,
    func: c"aes_wrap_cipher_internal",
    lib: 57,
    reason: 217,
    dynamic_reason: false,
};

/// `aes_wrap_cipher` at `providers/implementations/ciphers/cipher_aes_wrp.c:250` (PROV_R_OUTPUT_BUFFER_TOO_SMALL).
pub(crate) const PROV_CIPHER_AES_WRP_250: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_wrp.c",
    line: 250,
    func: c"aes_wrap_cipher",
    lib: 57,
    reason: 106,
    dynamic_reason: false,
};

/// `aes_wrap_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_wrp.c:274` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_WRP_274: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_wrp.c",
    line: 274,
    func: c"aes_wrap_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `aes_wrap_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_wrp.c:278` (PROV_R_INVALID_KEY_LENGTH).
pub(crate) const PROV_CIPHER_AES_WRP_278: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_wrp.c",
    line: 278,
    func: c"aes_wrap_set_ctx_params",
    lib: 57,
    reason: 105,
    dynamic_reason: false,
};

/// `aes_xts_check_keys_differ` at `providers/implementations/ciphers/cipher_aes_xts.c:59` (PROV_R_XTS_DUPLICATED_KEYS).
pub(crate) const PROV_CIPHER_AES_XTS_59: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_xts.c",
    line: 59,
    func: c"aes_xts_check_keys_differ",
    lib: 57,
    reason: 149,
    dynamic_reason: false,
};

/// `aes_xts_init` at `providers/implementations/ciphers/cipher_aes_xts.c:90` (PROV_R_INVALID_KEY_LENGTH).
pub(crate) const PROV_CIPHER_AES_XTS_90: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_xts.c",
    line: 90,
    func: c"aes_xts_init",
    lib: 57,
    reason: 105,
    dynamic_reason: false,
};

/// `aes_xts_cipher` at `providers/implementations/ciphers/cipher_aes_xts.c:202` (PROV_R_XTS_DATA_UNIT_IS_TOO_LARGE).
pub(crate) const PROV_CIPHER_AES_XTS_202: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_xts.c",
    line: 202,
    func: c"aes_xts_cipher",
    lib: 57,
    reason: 148,
    dynamic_reason: false,
};

/// `aes_xts_stream_update` at `providers/implementations/ciphers/cipher_aes_xts.c:223` (PROV_R_OUTPUT_BUFFER_TOO_SMALL).
pub(crate) const PROV_CIPHER_AES_XTS_223: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_xts.c",
    line: 223,
    func: c"aes_xts_stream_update",
    lib: 57,
    reason: 106,
    dynamic_reason: false,
};

/// `aes_xts_stream_update` at `providers/implementations/ciphers/cipher_aes_xts.c:228` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHER_AES_XTS_228: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_xts.c",
    line: 228,
    func: c"aes_xts_stream_update",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `aes_xts_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_xts.c:268` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_XTS_268: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_xts.c",
    line: 268,
    func: c"aes_xts_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `ossl_cipher_ccm_set_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon_ccm.c:108` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_108: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 108,
    func: c"ossl_cipher_ccm_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_ccm_set_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon_ccm.c:123` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_123: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 123,
    func: c"ossl_cipher_ccm_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_ccm_set_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon_ccm.c:142` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_142: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 142,
    func: c"ossl_cipher_ccm_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_ccm_set_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon_ccm.c:153` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_153: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 153,
    func: c"ossl_cipher_ccm_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_ccm_set_ctx_params` at `providers/implementations/ciphers/ciphercommon_ccm.c:186` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_186: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 186,
    func: c"ossl_ccm_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `ossl_ccm_set_ctx_params` at `providers/implementations/ciphers/ciphercommon_ccm.c:190` (PROV_R_INVALID_TAG_LENGTH).
pub(crate) const PROV_CIPHERCOMMON_CCM_190: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 190,
    func: c"ossl_ccm_set_ctx_params",
    lib: 57,
    reason: 118,
    dynamic_reason: false,
};

/// `ossl_ccm_set_ctx_params` at `providers/implementations/ciphers/ciphercommon_ccm.c:196` (PROV_R_TAG_NOT_NEEDED).
pub(crate) const PROV_CIPHERCOMMON_CCM_196: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 196,
    func: c"ossl_ccm_set_ctx_params",
    lib: 57,
    reason: 120,
    dynamic_reason: false,
};

/// `ossl_ccm_set_ctx_params` at `providers/implementations/ciphers/ciphercommon_ccm.c:207` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_207: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 207,
    func: c"ossl_ccm_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `ossl_ccm_set_ctx_params` at `providers/implementations/ciphers/ciphercommon_ccm.c:212` (PROV_R_INVALID_IV_LENGTH).
pub(crate) const PROV_CIPHERCOMMON_CCM_212: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 212,
    func: c"ossl_ccm_set_ctx_params",
    lib: 57,
    reason: 109,
    dynamic_reason: false,
};

/// `ossl_ccm_set_ctx_params` at `providers/implementations/ciphers/ciphercommon_ccm.c:223` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_223: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 223,
    func: c"ossl_ccm_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `ossl_ccm_set_ctx_params` at `providers/implementations/ciphers/ciphercommon_ccm.c:228` (PROV_R_INVALID_DATA).
pub(crate) const PROV_CIPHERCOMMON_CCM_228: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 228,
    func: c"ossl_ccm_set_ctx_params",
    lib: 57,
    reason: 115,
    dynamic_reason: false,
};

/// `ossl_ccm_set_ctx_params` at `providers/implementations/ciphers/ciphercommon_ccm.c:236` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_236: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 236,
    func: c"ossl_ccm_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `ossl_ccm_set_ctx_params` at `providers/implementations/ciphers/ciphercommon_ccm.c:240` (PROV_R_INVALID_IV_LENGTH).
pub(crate) const PROV_CIPHERCOMMON_CCM_240: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 240,
    func: c"ossl_ccm_set_ctx_params",
    lib: 57,
    reason: 109,
    dynamic_reason: false,
};

/// `ossl_cipher_ccm_get_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon_ccm.c:298` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_298: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 298,
    func: c"ossl_cipher_ccm_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_ccm_get_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon_ccm.c:307` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_307: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 307,
    func: c"ossl_cipher_ccm_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_ccm_get_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon_ccm.c:319` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_319: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 319,
    func: c"ossl_cipher_ccm_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_ccm_get_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon_ccm.c:342` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_342: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 342,
    func: c"ossl_cipher_ccm_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_ccm_get_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon_ccm.c:351` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_351: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 351,
    func: c"ossl_cipher_ccm_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_ccm_get_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon_ccm.c:363` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_363: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 363,
    func: c"ossl_cipher_ccm_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_cipher_ccm_get_ctx_params_decoder` at `providers/implementations/ciphers/ciphercommon_ccm.c:375` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_375: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 375,
    func: c"ossl_cipher_ccm_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_ccm_get_ctx_params` at `providers/implementations/ciphers/ciphercommon_ccm.c:403` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_403: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 403,
    func: c"ossl_ccm_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_ccm_get_ctx_params` at `providers/implementations/ciphers/ciphercommon_ccm.c:408` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_408: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 408,
    func: c"ossl_ccm_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_ccm_get_ctx_params` at `providers/implementations/ciphers/ciphercommon_ccm.c:414` (PROV_R_INVALID_IV_LENGTH).
pub(crate) const PROV_CIPHERCOMMON_CCM_414: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 414,
    func: c"ossl_ccm_get_ctx_params",
    lib: 57,
    reason: 109,
    dynamic_reason: false,
};

/// `ossl_ccm_get_ctx_params` at `providers/implementations/ciphers/ciphercommon_ccm.c:418` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_418: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 418,
    func: c"ossl_ccm_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_ccm_get_ctx_params` at `providers/implementations/ciphers/ciphercommon_ccm.c:425` (PROV_R_INVALID_IV_LENGTH).
pub(crate) const PROV_CIPHERCOMMON_CCM_425: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 425,
    func: c"ossl_ccm_get_ctx_params",
    lib: 57,
    reason: 109,
    dynamic_reason: false,
};

/// `ossl_ccm_get_ctx_params` at `providers/implementations/ciphers/ciphercommon_ccm.c:429` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_429: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 429,
    func: c"ossl_ccm_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_ccm_get_ctx_params` at `providers/implementations/ciphers/ciphercommon_ccm.c:435` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_435: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 435,
    func: c"ossl_ccm_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_ccm_get_ctx_params` at `providers/implementations/ciphers/ciphercommon_ccm.c:440` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_440: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 440,
    func: c"ossl_ccm_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_ccm_get_ctx_params` at `providers/implementations/ciphers/ciphercommon_ccm.c:446` (PROV_R_TAG_NOT_SET).
pub(crate) const PROV_CIPHERCOMMON_CCM_446: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 446,
    func: c"ossl_ccm_get_ctx_params",
    lib: 57,
    reason: 119,
    dynamic_reason: false,
};

/// `ossl_ccm_get_ctx_params` at `providers/implementations/ciphers/ciphercommon_ccm.c:450` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHERCOMMON_CCM_450: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 450,
    func: c"ossl_ccm_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ccm_init` at `providers/implementations/ciphers/ciphercommon_ccm.c:476` (PROV_R_INVALID_IV_LENGTH).
pub(crate) const PROV_CIPHERCOMMON_CCM_476: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 476,
    func: c"ccm_init",
    lib: 57,
    reason: 109,
    dynamic_reason: false,
};

/// `ccm_init` at `providers/implementations/ciphers/ciphercommon_ccm.c:484` (PROV_R_INVALID_KEY_LENGTH).
pub(crate) const PROV_CIPHERCOMMON_CCM_484: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 484,
    func: c"ccm_init",
    lib: 57,
    reason: 105,
    dynamic_reason: false,
};

/// `ossl_ccm_stream_update` at `providers/implementations/ciphers/ciphercommon_ccm.c:514` (PROV_R_OUTPUT_BUFFER_TOO_SMALL).
pub(crate) const PROV_CIPHERCOMMON_CCM_514: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 514,
    func: c"ossl_ccm_stream_update",
    lib: 57,
    reason: 106,
    dynamic_reason: false,
};

/// `ossl_ccm_stream_update` at `providers/implementations/ciphers/ciphercommon_ccm.c:519` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHERCOMMON_CCM_519: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 519,
    func: c"ossl_ccm_stream_update",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `ossl_ccm_cipher` at `providers/implementations/ciphers/ciphercommon_ccm.c:560` (PROV_R_OUTPUT_BUFFER_TOO_SMALL).
pub(crate) const PROV_CIPHERCOMMON_CCM_560: ErrSite = ErrSite {
    file: c"providers/implementations/ciphers/ciphercommon_ccm.c",
    line: 560,
    func: c"ossl_ccm_cipher",
    lib: 57,
    reason: 106,
    dynamic_reason: false,
};

/// `siv_init` at `providers/implementations/ciphers/cipher_aes_siv.c:90` (PROV_R_INVALID_KEY_LENGTH).
pub(crate) const PROV_CIPHER_AES_SIV_90: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_siv.c",
    line: 90,
    func: c"siv_init",
    lib: 57,
    reason: 105,
    dynamic_reason: false,
};

/// `siv_cipher` at `providers/implementations/ciphers/cipher_aes_siv.c:122` (PROV_R_OUTPUT_BUFFER_TOO_SMALL).
pub(crate) const PROV_CIPHER_AES_SIV_122: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_siv.c",
    line: 122,
    func: c"siv_cipher",
    lib: 57,
    reason: 106,
    dynamic_reason: false,
};

/// `aes_siv_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_siv.c:161` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_SIV_161: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_siv.c",
    line: 161,
    func: c"aes_siv_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `aes_siv_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_siv.c:167` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_SIV_167: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_siv.c",
    line: 167,
    func: c"aes_siv_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `aes_siv_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_siv.c:172` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_SIV_172: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_siv.c",
    line: 172,
    func: c"aes_siv_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `aes_siv_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_siv.c:206` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_SIV_206: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_siv.c",
    line: 206,
    func: c"aes_siv_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `aes_siv_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_siv.c:213` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_SIV_213: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_siv.c",
    line: 213,
    func: c"aes_siv_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `aes_siv_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_siv.c:223` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_SIV_223: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_siv.c",
    line: 223,
    func: c"aes_siv_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `chacha20_get_ctx_params` at `providers/implementations/ciphers/cipher_chacha20.c:111` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_CHACHA20_111: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_chacha20.c",
    line: 111,
    func: c"chacha20_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `chacha20_get_ctx_params` at `providers/implementations/ciphers/cipher_chacha20.c:116` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_CHACHA20_116: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_chacha20.c",
    line: 116,
    func: c"chacha20_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `chacha20_get_ctx_params` at `providers/implementations/ciphers/cipher_chacha20.c:126` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_CHACHA20_126: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_chacha20.c",
    line: 126,
    func: c"chacha20_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `chacha20_set_ctx_params` at `providers/implementations/ciphers/cipher_chacha20.c:156` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_CHACHA20_156: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_chacha20.c",
    line: 156,
    func: c"chacha20_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `chacha20_set_ctx_params` at `providers/implementations/ciphers/cipher_chacha20.c:160` (PROV_R_INVALID_KEY_LENGTH).
pub(crate) const PROV_CIPHER_CHACHA20_160: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_chacha20.c",
    line: 160,
    func: c"chacha20_set_ctx_params",
    lib: 57,
    reason: 105,
    dynamic_reason: false,
};

/// `chacha20_set_ctx_params` at `providers/implementations/ciphers/cipher_chacha20.c:167` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_CHACHA20_167: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_chacha20.c",
    line: 167,
    func: c"chacha20_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `chacha20_set_ctx_params` at `providers/implementations/ciphers/cipher_chacha20.c:171` (PROV_R_INVALID_IV_LENGTH).
pub(crate) const PROV_CIPHER_CHACHA20_171: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_chacha20.c",
    line: 171,
    func: c"chacha20_set_ctx_params",
    lib: 57,
    reason: 109,
    dynamic_reason: false,
};

/// `cipher_hw_aria_initkey` at `providers/implementations/ciphers/cipher_aria_hw.c:25` (PROV_R_KEY_SETUP_FAILED).
pub(crate) const PROV_CIPHER_ARIA_HW_25: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aria_hw.c",
    line: 25,
    func: c"cipher_hw_aria_initkey",
    lib: 57,
    reason: 101,
    dynamic_reason: false,
};

/// `sm4_xts_init` at `providers/implementations/ciphers/cipher_sm4_xts.c:54` (PROV_R_INVALID_KEY_LENGTH).
pub(crate) const PROV_CIPHER_SM4_XTS_54: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_sm4_xts.c",
    line: 54,
    func: c"sm4_xts_init",
    lib: 57,
    reason: 105,
    dynamic_reason: false,
};

/// `sm4_xts_cipher` at `providers/implementations/ciphers/cipher_sm4_xts.c:142` (PROV_R_XTS_DATA_UNIT_IS_TOO_LARGE).
pub(crate) const PROV_CIPHER_SM4_XTS_142: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_sm4_xts.c",
    line: 142,
    func: c"sm4_xts_cipher",
    lib: 57,
    reason: 148,
    dynamic_reason: false,
};

/// `sm4_xts_stream_update` at `providers/implementations/ciphers/cipher_sm4_xts.c:171` (PROV_R_OUTPUT_BUFFER_TOO_SMALL).
pub(crate) const PROV_CIPHER_SM4_XTS_171: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_sm4_xts.c",
    line: 171,
    func: c"sm4_xts_stream_update",
    lib: 57,
    reason: 106,
    dynamic_reason: false,
};

/// `sm4_xts_stream_update` at `providers/implementations/ciphers/cipher_sm4_xts.c:176` (PROV_R_CIPHER_OPERATION_FAILED).
pub(crate) const PROV_CIPHER_SM4_XTS_176: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_sm4_xts.c",
    line: 176,
    func: c"sm4_xts_stream_update",
    lib: 57,
    reason: 102,
    dynamic_reason: false,
};

/// `sm4_xts_set_ctx_params` at `providers/implementations/ciphers/cipher_sm4_xts.c:227` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_SM4_XTS_227: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_sm4_xts.c",
    line: 227,
    func: c"sm4_xts_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `sm4_xts_set_ctx_params` at `providers/implementations/ciphers/cipher_sm4_xts.c:235` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_SM4_XTS_235: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_sm4_xts.c",
    line: 235,
    func: c"sm4_xts_set_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `aes_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c:102` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_CBC_HMAC_SHA_102: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c",
    line: 102,
    func: c"aes_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `aes_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c:113` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_CBC_HMAC_SHA_113: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c",
    line: 113,
    func: c"aes_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `aes_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c:132` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_CBC_HMAC_SHA_132: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c",
    line: 132,
    func: c"aes_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `aes_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c:162` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_CBC_HMAC_SHA_162: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c",
    line: 162,
    func: c"aes_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `aes_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c:176` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_CBC_HMAC_SHA_176: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c",
    line: 176,
    func: c"aes_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `aes_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c:188` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_CBC_HMAC_SHA_188: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c",
    line: 188,
    func: c"aes_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `aes_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c:192` (PROV_R_INVALID_KEY_LENGTH).
pub(crate) const PROV_CIPHER_AES_CBC_HMAC_SHA_192: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c",
    line: 192,
    func: c"aes_set_ctx_params",
    lib: 57,
    reason: 105,
    dynamic_reason: false,
};

/// `aes_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c:200` (PROV_R_FAILED_TO_GET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_CBC_HMAC_SHA_200: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c",
    line: 200,
    func: c"aes_set_ctx_params",
    lib: 57,
    reason: 103,
    dynamic_reason: false,
};

/// `aes_set_ctx_params` at `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c:206` (ERR_R_INTERNAL_ERROR).
pub(crate) const PROV_CIPHER_AES_CBC_HMAC_SHA_206: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c",
    line: 206,
    func: c"aes_set_ctx_params",
    lib: 57,
    reason: 786691,
    dynamic_reason: false,
};

/// `aes_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c:231` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_CBC_HMAC_SHA_231: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c",
    line: 231,
    func: c"aes_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `aes_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c:238` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_CBC_HMAC_SHA_238: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c",
    line: 238,
    func: c"aes_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `aes_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c:244` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_CBC_HMAC_SHA_244: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c",
    line: 244,
    func: c"aes_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `aes_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c:250` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_CBC_HMAC_SHA_250: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c",
    line: 250,
    func: c"aes_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `aes_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c:257` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_CBC_HMAC_SHA_257: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c",
    line: 257,
    func: c"aes_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `aes_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c:262` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_CBC_HMAC_SHA_262: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c",
    line: 262,
    func: c"aes_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `aes_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c:267` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_CBC_HMAC_SHA_267: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c",
    line: 267,
    func: c"aes_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `aes_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c:273` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_CBC_HMAC_SHA_273: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c",
    line: 273,
    func: c"aes_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `aes_get_ctx_params` at `providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c:279` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_CIPHER_AES_CBC_HMAC_SHA_279: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/ciphers/cipher_aes_cbc_hmac_sha.c",
    line: 279,
    func: c"aes_get_ctx_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `cmac_get_ctx_params_decoder` at `providers/implementations/macs/cmac_prov.c:245` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CMAC_PROV_245: ErrSite = ErrSite {
    file: c"providers/implementations/macs/cmac_prov.c",
    line: 245,
    func: c"cmac_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cmac_get_ctx_params_decoder` at `providers/implementations/macs/cmac_prov.c:257` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CMAC_PROV_257: ErrSite = ErrSite {
    file: c"providers/implementations/macs/cmac_prov.c",
    line: 257,
    func: c"cmac_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cmac_get_ctx_params_decoder` at `providers/implementations/macs/cmac_prov.c:269` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CMAC_PROV_269: ErrSite = ErrSite {
    file: c"providers/implementations/macs/cmac_prov.c",
    line: 269,
    func: c"cmac_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cmac_set_ctx_params_decoder` at `providers/implementations/macs/cmac_prov.c:350` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CMAC_PROV_350: ErrSite = ErrSite {
    file: c"providers/implementations/macs/cmac_prov.c",
    line: 350,
    func: c"cmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cmac_set_ctx_params_decoder` at `providers/implementations/macs/cmac_prov.c:370` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CMAC_PROV_370: ErrSite = ErrSite {
    file: c"providers/implementations/macs/cmac_prov.c",
    line: 370,
    func: c"cmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cmac_set_ctx_params_decoder` at `providers/implementations/macs/cmac_prov.c:382` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CMAC_PROV_382: ErrSite = ErrSite {
    file: c"providers/implementations/macs/cmac_prov.c",
    line: 382,
    func: c"cmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cmac_set_ctx_params_decoder` at `providers/implementations/macs/cmac_prov.c:395` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CMAC_PROV_395: ErrSite = ErrSite {
    file: c"providers/implementations/macs/cmac_prov.c",
    line: 395,
    func: c"cmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cmac_set_ctx_params_decoder` at `providers/implementations/macs/cmac_prov.c:406` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_CMAC_PROV_406: ErrSite = ErrSite {
    file: c"providers/implementations/macs/cmac_prov.c",
    line: 406,
    func: c"cmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `cmac_set_ctx_params` at `providers/implementations/macs/cmac_prov.c:449` (PROV_R_INVALID_MODE).
pub(crate) const PROV_CMAC_PROV_449: ErrSite = ErrSite {
    file: c"providers/implementations/macs/cmac_prov.c",
    line: 449,
    func: c"cmac_set_ctx_params",
    lib: 57,
    reason: 125,
    dynamic_reason: false,
};

/// `cmac_set_ctx_params` at `providers/implementations/macs/cmac_prov.c:460` (PROV_R_NOT_SUPPORTED).
pub(crate) const PROV_CMAC_PROV_460: ErrSite = ErrSite {
    file: c"providers/implementations/macs/cmac_prov.c",
    line: 460,
    func: c"cmac_set_ctx_params",
    lib: 57,
    reason: 136,
    dynamic_reason: false,
};

/// `gmac_setkey` at `providers/implementations/macs/gmac_prov.c:111` (PROV_R_INVALID_KEY_LENGTH).
pub(crate) const PROV_GMAC_PROV_111: ErrSite = ErrSite {
    file: c"providers/implementations/macs/gmac_prov.c",
    line: 111,
    func: c"gmac_setkey",
    lib: 57,
    reason: 105,
    dynamic_reason: false,
};

/// `gmac_get_params_decoder` at `providers/implementations/macs/gmac_prov.c:200` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_GMAC_PROV_200: ErrSite = ErrSite {
    file: c"providers/implementations/macs/gmac_prov.c",
    line: 200,
    func: c"gmac_get_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `gmac_set_ctx_params_decoder` at `providers/implementations/macs/gmac_prov.c:268` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_GMAC_PROV_268: ErrSite = ErrSite {
    file: c"providers/implementations/macs/gmac_prov.c",
    line: 268,
    func: c"gmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `gmac_set_ctx_params_decoder` at `providers/implementations/macs/gmac_prov.c:279` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_GMAC_PROV_279: ErrSite = ErrSite {
    file: c"providers/implementations/macs/gmac_prov.c",
    line: 279,
    func: c"gmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `gmac_set_ctx_params_decoder` at `providers/implementations/macs/gmac_prov.c:290` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_GMAC_PROV_290: ErrSite = ErrSite {
    file: c"providers/implementations/macs/gmac_prov.c",
    line: 290,
    func: c"gmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `gmac_set_ctx_params_decoder` at `providers/implementations/macs/gmac_prov.c:301` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_GMAC_PROV_301: ErrSite = ErrSite {
    file: c"providers/implementations/macs/gmac_prov.c",
    line: 301,
    func: c"gmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `gmac_set_ctx_params_decoder` at `providers/implementations/macs/gmac_prov.c:312` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_GMAC_PROV_312: ErrSite = ErrSite {
    file: c"providers/implementations/macs/gmac_prov.c",
    line: 312,
    func: c"gmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `gmac_set_ctx_params` at `providers/implementations/macs/gmac_prov.c:354` (PROV_R_INVALID_MODE).
pub(crate) const PROV_GMAC_PROV_354: ErrSite = ErrSite {
    file: c"providers/implementations/macs/gmac_prov.c",
    line: 354,
    func: c"gmac_set_ctx_params",
    lib: 57,
    reason: 125,
    dynamic_reason: false,
};

/// `hmac_setkey` at `providers/implementations/macs/hmac_prov.c:177` (PROV_R_INVALID_KEY_LENGTH).
pub(crate) const PROV_HMAC_PROV_177: ErrSite = ErrSite {
    file: c"providers/implementations/macs/hmac_prov.c",
    line: 177,
    func: c"hmac_setkey",
    lib: 57,
    reason: 105,
    dynamic_reason: false,
};

/// `hmac_get_ctx_params_decoder` at `providers/implementations/macs/hmac_prov.c:313` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_HMAC_PROV_313: ErrSite = ErrSite {
    file: c"providers/implementations/macs/hmac_prov.c",
    line: 313,
    func: c"hmac_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `hmac_get_ctx_params_decoder` at `providers/implementations/macs/hmac_prov.c:325` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_HMAC_PROV_325: ErrSite = ErrSite {
    file: c"providers/implementations/macs/hmac_prov.c",
    line: 325,
    func: c"hmac_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `hmac_get_ctx_params_decoder` at `providers/implementations/macs/hmac_prov.c:337` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_HMAC_PROV_337: ErrSite = ErrSite {
    file: c"providers/implementations/macs/hmac_prov.c",
    line: 337,
    func: c"hmac_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `hmac_set_ctx_params_decoder` at `providers/implementations/macs/hmac_prov.c:427` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_HMAC_PROV_427: ErrSite = ErrSite {
    file: c"providers/implementations/macs/hmac_prov.c",
    line: 427,
    func: c"hmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `hmac_set_ctx_params_decoder` at `providers/implementations/macs/hmac_prov.c:438` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_HMAC_PROV_438: ErrSite = ErrSite {
    file: c"providers/implementations/macs/hmac_prov.c",
    line: 438,
    func: c"hmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `hmac_set_ctx_params_decoder` at `providers/implementations/macs/hmac_prov.c:462` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_HMAC_PROV_462: ErrSite = ErrSite {
    file: c"providers/implementations/macs/hmac_prov.c",
    line: 462,
    func: c"hmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `hmac_set_ctx_params_decoder` at `providers/implementations/macs/hmac_prov.c:472` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_HMAC_PROV_472: ErrSite = ErrSite {
    file: c"providers/implementations/macs/hmac_prov.c",
    line: 472,
    func: c"hmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `hmac_set_ctx_params_decoder` at `providers/implementations/macs/hmac_prov.c:485` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_HMAC_PROV_485: ErrSite = ErrSite {
    file: c"providers/implementations/macs/hmac_prov.c",
    line: 485,
    func: c"hmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `hmac_set_ctx_params_decoder` at `providers/implementations/macs/hmac_prov.c:496` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_HMAC_PROV_496: ErrSite = ErrSite {
    file: c"providers/implementations/macs/hmac_prov.c",
    line: 496,
    func: c"hmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `blake2_get_ctx_decoder` at `providers/implementations/include/prov/blake2_params.inc:46` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_BLAKE2_PARAMS_46: ErrSite = ErrSite {
    file: c"providers/implementations/include/prov/blake2_params.inc",
    line: 46,
    func: c"blake2_get_ctx_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `blake2_get_ctx_decoder` at `providers/implementations/include/prov/blake2_params.inc:57` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_BLAKE2_PARAMS_57: ErrSite = ErrSite {
    file: c"providers/implementations/include/prov/blake2_params.inc",
    line: 57,
    func: c"blake2_get_ctx_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `blake2_mac_set_ctx_decoder` at `providers/implementations/include/prov/blake2_params.inc:105` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_BLAKE2_PARAMS_105: ErrSite = ErrSite {
    file: c"providers/implementations/include/prov/blake2_params.inc",
    line: 105,
    func: c"blake2_mac_set_ctx_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `blake2_mac_set_ctx_decoder` at `providers/implementations/include/prov/blake2_params.inc:116` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_BLAKE2_PARAMS_116: ErrSite = ErrSite {
    file: c"providers/implementations/include/prov/blake2_params.inc",
    line: 116,
    func: c"blake2_mac_set_ctx_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `blake2_mac_set_ctx_decoder` at `providers/implementations/include/prov/blake2_params.inc:131` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_BLAKE2_PARAMS_131: ErrSite = ErrSite {
    file: c"providers/implementations/include/prov/blake2_params.inc",
    line: 131,
    func: c"blake2_mac_set_ctx_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `blake2_mac_set_ctx_decoder` at `providers/implementations/include/prov/blake2_params.inc:142` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_BLAKE2_PARAMS_142: ErrSite = ErrSite {
    file: c"providers/implementations/include/prov/blake2_params.inc",
    line: 142,
    func: c"blake2_mac_set_ctx_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `blake2_setkey` at `providers/implementations/macs/blake2_mac_impl.c:96` (PROV_R_INVALID_KEY_LENGTH).
pub(crate) const PROV_BLAKE2_MAC_IMPL_96: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/macs/blake2_mac_impl.c",
    line: 96,
    func: c"blake2_setkey",
    lib: 57,
    reason: 105,
    dynamic_reason: false,
};

/// `blake2_mac_init` at `providers/implementations/macs/blake2_mac_impl.c:119` (PROV_R_NO_KEY_SET).
pub(crate) const PROV_BLAKE2_MAC_IMPL_119: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/macs/blake2_mac_impl.c",
    line: 119,
    func: c"blake2_mac_init",
    lib: 57,
    reason: 114,
    dynamic_reason: false,
};

/// `blake2_mac_set_ctx_params` at `providers/implementations/macs/blake2_mac_impl.c:197` (PROV_R_NOT_XOF_OR_INVALID_LENGTH).
pub(crate) const PROV_BLAKE2_MAC_IMPL_197: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/macs/blake2_mac_impl.c",
    line: 197,
    func: c"blake2_mac_set_ctx_params",
    lib: 57,
    reason: 113,
    dynamic_reason: false,
};

/// `blake2_mac_set_ctx_params` at `providers/implementations/macs/blake2_mac_impl.c:216` (PROV_R_INVALID_CUSTOM_LENGTH).
pub(crate) const PROV_BLAKE2_MAC_IMPL_216: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/macs/blake2_mac_impl.c",
    line: 216,
    func: c"blake2_mac_set_ctx_params",
    lib: 57,
    reason: 111,
    dynamic_reason: false,
};

/// `blake2_mac_set_ctx_params` at `providers/implementations/macs/blake2_mac_impl.c:231` (PROV_R_INVALID_SALT_LENGTH).
pub(crate) const PROV_BLAKE2_MAC_IMPL_231: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/providers/implementations/macs/blake2_mac_impl.c",
    line: 231,
    func: c"blake2_mac_set_ctx_params",
    lib: 57,
    reason: 112,
    dynamic_reason: false,
};

/// `poly1305_setkey` at `providers/implementations/macs/poly1305_prov.c:92` (PROV_R_INVALID_KEY_LENGTH).
pub(crate) const PROV_POLY1305_PROV_92: ErrSite = ErrSite {
    file: c"providers/implementations/macs/poly1305_prov.c",
    line: 92,
    func: c"poly1305_setkey",
    lib: 57,
    reason: 105,
    dynamic_reason: false,
};

/// `poly1305_update` at `providers/implementations/macs/poly1305_prov.c:121` (PROV_R_NO_KEY_SET).
pub(crate) const PROV_POLY1305_PROV_121: ErrSite = ErrSite {
    file: c"providers/implementations/macs/poly1305_prov.c",
    line: 121,
    func: c"poly1305_update",
    lib: 57,
    reason: 114,
    dynamic_reason: false,
};

/// `poly1305_final` at `providers/implementations/macs/poly1305_prov.c:141` (PROV_R_NO_KEY_SET).
pub(crate) const PROV_POLY1305_PROV_141: ErrSite = ErrSite {
    file: c"providers/implementations/macs/poly1305_prov.c",
    line: 141,
    func: c"poly1305_final",
    lib: 57,
    reason: 114,
    dynamic_reason: false,
};

/// `poly1305_get_params_decoder` at `providers/implementations/macs/poly1305_prov.c:177` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_POLY1305_PROV_177: ErrSite = ErrSite {
    file: c"providers/implementations/macs/poly1305_prov.c",
    line: 177,
    func: c"poly1305_get_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `poly1305_set_ctx_params_decoder` at `providers/implementations/macs/poly1305_prov.c:234` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_POLY1305_PROV_234: ErrSite = ErrSite {
    file: c"providers/implementations/macs/poly1305_prov.c",
    line: 234,
    func: c"poly1305_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `siphash_get_ctx_params_decoder` at `providers/implementations/macs/siphash_prov.c:190` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_SIPHASH_PROV_190: ErrSite = ErrSite {
    file: c"providers/implementations/macs/siphash_prov.c",
    line: 190,
    func: c"siphash_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `siphash_get_ctx_params_decoder` at `providers/implementations/macs/siphash_prov.c:201` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_SIPHASH_PROV_201: ErrSite = ErrSite {
    file: c"providers/implementations/macs/siphash_prov.c",
    line: 201,
    func: c"siphash_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `siphash_get_ctx_params_decoder` at `providers/implementations/macs/siphash_prov.c:212` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_SIPHASH_PROV_212: ErrSite = ErrSite {
    file: c"providers/implementations/macs/siphash_prov.c",
    line: 212,
    func: c"siphash_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `siphash_set_params_decoder` at `providers/implementations/macs/siphash_prov.c:285` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_SIPHASH_PROV_285: ErrSite = ErrSite {
    file: c"providers/implementations/macs/siphash_prov.c",
    line: 285,
    func: c"siphash_set_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `siphash_set_params_decoder` at `providers/implementations/macs/siphash_prov.c:296` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_SIPHASH_PROV_296: ErrSite = ErrSite {
    file: c"providers/implementations/macs/siphash_prov.c",
    line: 296,
    func: c"siphash_set_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `siphash_set_params_decoder` at `providers/implementations/macs/siphash_prov.c:307` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_SIPHASH_PROV_307: ErrSite = ErrSite {
    file: c"providers/implementations/macs/siphash_prov.c",
    line: 307,
    func: c"siphash_set_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `siphash_set_params_decoder` at `providers/implementations/macs/siphash_prov.c:318` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_SIPHASH_PROV_318: ErrSite = ErrSite {
    file: c"providers/implementations/macs/siphash_prov.c",
    line: 318,
    func: c"siphash_set_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `kmac_setkey` at `providers/implementations/macs/kmac_prov.c:272` (PROV_R_INVALID_KEY_LENGTH).
pub(crate) const PROV_KMAC_PROV_272: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 272,
    func: c"kmac_setkey",
    lib: 57,
    reason: 105,
    dynamic_reason: false,
};

/// `kmac_setkey` at `providers/implementations/macs/kmac_prov.c:288` (PROV_R_INVALID_KEY_LENGTH).
pub(crate) const PROV_KMAC_PROV_288: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 288,
    func: c"kmac_setkey",
    lib: 57,
    reason: 105,
    dynamic_reason: false,
};

/// `kmac_setkey` at `providers/implementations/macs/kmac_prov.c:295` (PROV_R_INVALID_DIGEST_LENGTH).
pub(crate) const PROV_KMAC_PROV_295: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 295,
    func: c"kmac_setkey",
    lib: 57,
    reason: 166,
    dynamic_reason: false,
};

/// `kmac_init` at `providers/implementations/macs/kmac_prov.c:326` (PROV_R_NO_KEY_SET).
pub(crate) const PROV_KMAC_PROV_326: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 326,
    func: c"kmac_init",
    lib: 57,
    reason: 114,
    dynamic_reason: false,
};

/// `kmac_init` at `providers/implementations/macs/kmac_prov.c:335` (PROV_R_INVALID_DIGEST_LENGTH).
pub(crate) const PROV_KMAC_PROV_335: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 335,
    func: c"kmac_init",
    lib: 57,
    reason: 166,
    dynamic_reason: false,
};

/// `kmac_init` at `providers/implementations/macs/kmac_prov.c:351` (ERR_R_INTERNAL_ERROR).
pub(crate) const PROV_KMAC_PROV_351: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 351,
    func: c"kmac_init",
    lib: 57,
    reason: 786691,
    dynamic_reason: false,
};

/// `kmac_get_ctx_params_decoder` at `providers/implementations/macs/kmac_prov.c:434` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_KMAC_PROV_434: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 434,
    func: c"kmac_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `kmac_get_ctx_params_decoder` at `providers/implementations/macs/kmac_prov.c:446` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_KMAC_PROV_446: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 446,
    func: c"kmac_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `kmac_get_ctx_params_decoder` at `providers/implementations/macs/kmac_prov.c:458` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_KMAC_PROV_458: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 458,
    func: c"kmac_get_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `kmac_set_ctx_params_decoder` at `providers/implementations/macs/kmac_prov.c:550` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_KMAC_PROV_550: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 550,
    func: c"kmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `kmac_set_ctx_params_decoder` at `providers/implementations/macs/kmac_prov.c:574` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_KMAC_PROV_574: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 574,
    func: c"kmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `kmac_set_ctx_params_decoder` at `providers/implementations/macs/kmac_prov.c:584` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_KMAC_PROV_584: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 584,
    func: c"kmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `kmac_set_ctx_params_decoder` at `providers/implementations/macs/kmac_prov.c:598` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_KMAC_PROV_598: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 598,
    func: c"kmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `kmac_set_ctx_params_decoder` at `providers/implementations/macs/kmac_prov.c:610` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_KMAC_PROV_610: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 610,
    func: c"kmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `kmac_set_ctx_params_decoder` at `providers/implementations/macs/kmac_prov.c:621` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_KMAC_PROV_621: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 621,
    func: c"kmac_set_ctx_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `kmac_set_ctx_params` at `providers/implementations/macs/kmac_prov.c:672` (PROV_R_INVALID_OUTPUT_LENGTH).
pub(crate) const PROV_KMAC_PROV_672: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 672,
    func: c"kmac_set_ctx_params",
    lib: 57,
    reason: 217,
    dynamic_reason: false,
};

/// `kmac_set_ctx_params` at `providers/implementations/macs/kmac_prov.c:682` (PROV_R_INVALID_OUTPUT_LENGTH).
pub(crate) const PROV_KMAC_PROV_682: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 682,
    func: c"kmac_set_ctx_params",
    lib: 57,
    reason: 217,
    dynamic_reason: false,
};

/// `kmac_set_ctx_params` at `providers/implementations/macs/kmac_prov.c:699` (PROV_R_INVALID_CUSTOM_LENGTH).
pub(crate) const PROV_KMAC_PROV_699: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 699,
    func: c"kmac_set_ctx_params",
    lib: 57,
    reason: 111,
    dynamic_reason: false,
};

/// `right_encode` at `providers/implementations/macs/kmac_prov.c:741` (PROV_R_LENGTH_TOO_LARGE).
pub(crate) const PROV_KMAC_PROV_741: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 741,
    func: c"right_encode",
    lib: 57,
    reason: 202,
    dynamic_reason: false,
};

/// `encode_string` at `providers/implementations/macs/kmac_prov.c:778` (PROV_R_LENGTH_TOO_LARGE).
pub(crate) const PROV_KMAC_PROV_778: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 778,
    func: c"encode_string",
    lib: 57,
    reason: 202,
    dynamic_reason: false,
};

/// `bytepad` at `providers/implementations/macs/kmac_prov.c:811` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const PROV_KMAC_PROV_811: ErrSite = ErrSite {
    file: c"providers/implementations/macs/kmac_prov.c",
    line: 811,
    func: c"bytepad",
    lib: 57,
    reason: 786690,
    dynamic_reason: false,
};

/// `digest_default_get_params_decoder` at `providers/implementations/digests/digestcommon.c:56` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_DIGESTCOMMON_56: ErrSite = ErrSite {
    file: c"providers/implementations/digests/digestcommon.c",
    line: 56,
    func: c"digest_default_get_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `digest_default_get_params_decoder` at `providers/implementations/digests/digestcommon.c:67` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_DIGESTCOMMON_67: ErrSite = ErrSite {
    file: c"providers/implementations/digests/digestcommon.c",
    line: 67,
    func: c"digest_default_get_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `digest_default_get_params_decoder` at `providers/implementations/digests/digestcommon.c:78` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_DIGESTCOMMON_78: ErrSite = ErrSite {
    file: c"providers/implementations/digests/digestcommon.c",
    line: 78,
    func: c"digest_default_get_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `digest_default_get_params_decoder` at `providers/implementations/digests/digestcommon.c:89` (PROV_R_REPEATED_PARAMETER).
pub(crate) const PROV_DIGESTCOMMON_89: ErrSite = ErrSite {
    file: c"providers/implementations/digests/digestcommon.c",
    line: 89,
    func: c"digest_default_get_params_decoder",
    lib: 57,
    reason: 252,
    dynamic_reason: false,
};

/// `ossl_digest_default_get_params` at `providers/implementations/digests/digestcommon.c:111` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_DIGESTCOMMON_111: ErrSite = ErrSite {
    file: c"providers/implementations/digests/digestcommon.c",
    line: 111,
    func: c"ossl_digest_default_get_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_digest_default_get_params` at `providers/implementations/digests/digestcommon.c:115` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_DIGESTCOMMON_115: ErrSite = ErrSite {
    file: c"providers/implementations/digests/digestcommon.c",
    line: 115,
    func: c"ossl_digest_default_get_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_digest_default_get_params` at `providers/implementations/digests/digestcommon.c:120` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_DIGESTCOMMON_120: ErrSite = ErrSite {
    file: c"providers/implementations/digests/digestcommon.c",
    line: 120,
    func: c"ossl_digest_default_get_params",
    lib: 57,
    reason: 104,
    dynamic_reason: false,
};

/// `ossl_digest_default_get_params` at `providers/implementations/digests/digestcommon.c:125` (PROV_R_FAILED_TO_SET_PARAMETER).
pub(crate) const PROV_DIGESTCOMMON_125: ErrSite = ErrSite {
    file: c"providers/implementations/digests/digestcommon.c",
    line: 125,
    func: c"ossl_digest_default_get_params",
    lib: 57,
    reason: 104,
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
    CORE_FETCH_65,
    CORE_FETCH_92,
    ASYMCIPHER_43,
    ASYMCIPHER_57,
    ASYMCIPHER_67,
    ASYMCIPHER_75,
    ASYMCIPHER_160,
    ASYMCIPHER_168,
    ASYMCIPHER_177,
    ASYMCIPHER_185,
    ASYMCIPHER_204,
    ASYMCIPHER_219,
    ASYMCIPHER_251,
    ASYMCIPHER_256,
    ASYMCIPHER_268,
    ASYMCIPHER_275,
    ASYMCIPHER_300,
    ASYMCIPHER_305,
    ASYMCIPHER_317,
    ASYMCIPHER_325,
    ASYMCIPHER_342,
    ASYMCIPHER_378,
    ASYMCIPHER_475,
    BIO_B64_142,
    BIO_B64_149,
    BIO_B64_346,
    BIO_B64_350,
    BIO_B64_354,
    BIO_B64_366,
    BIO_B64_370,
    BIO_B64_388,
    BIO_B64_404,
    BIO_B64_408,
    BIO_B64_426,
    BIO_B64_430,
    BIO_B64_440,
    BIO_B64_444,
    BIO_B64_463,
    BIO_B64_467,
    BIO_B64_504,
    BIO_B64_516,
    CTRL_PARAMS_TRANSLATE_306,
    CTRL_PARAMS_TRANSLATE_311,
    CTRL_PARAMS_TRANSLATE_324,
    CTRL_PARAMS_TRANSLATE_329,
    CTRL_PARAMS_TRANSLATE_337,
    CTRL_PARAMS_TRANSLATE_342,
    CTRL_PARAMS_TRANSLATE_407,
    CTRL_PARAMS_TRANSLATE_424,
    CTRL_PARAMS_TRANSLATE_446,
    CTRL_PARAMS_TRANSLATE_492,
    CTRL_PARAMS_TRANSLATE_555,
    CTRL_PARAMS_TRANSLATE_573,
    CTRL_PARAMS_TRANSLATE_586,
    CTRL_PARAMS_TRANSLATE_649,
    CTRL_PARAMS_TRANSLATE_667,
    CTRL_PARAMS_TRANSLATE_695,
    CTRL_PARAMS_TRANSLATE_1013,
    CTRL_PARAMS_TRANSLATE_1039,
    CTRL_PARAMS_TRANSLATE_1050,
    CTRL_PARAMS_TRANSLATE_1081,
    CTRL_PARAMS_TRANSLATE_1134,
    CTRL_PARAMS_TRANSLATE_1327,
    CTRL_PARAMS_TRANSLATE_1337,
    CTRL_PARAMS_TRANSLATE_1357,
    CTRL_PARAMS_TRANSLATE_1547,
    CTRL_PARAMS_TRANSLATE_1588,
    CTRL_PARAMS_TRANSLATE_1649,
    CTRL_PARAMS_TRANSLATE_1675,
    CTRL_PARAMS_TRANSLATE_1711,
    CTRL_PARAMS_TRANSLATE_1748,
    CTRL_PARAMS_TRANSLATE_1823,
    CTRL_PARAMS_TRANSLATE_1829,
    CTRL_PARAMS_TRANSLATE_2041,
    CTRL_PARAMS_TRANSLATE_2717,
    DH_CTRL_22,
    DH_CTRL_37,
    DH_CTRL_166,
    DH_CTRL_261,
    DH_CTRL_281,
    DH_CTRL_313,
    DH_CTRL_336,
    DIGEST_112,
    DIGEST_147,
    DIGEST_178,
    DIGEST_189,
    DIGEST_250,
    DIGEST_261,
    DIGEST_271,
    DIGEST_282,
    DIGEST_292,
    DIGEST_298,
    DIGEST_311,
    DIGEST_323,
    DIGEST_391,
    DIGEST_412,
    DIGEST_422,
    DIGEST_459,
    DIGEST_464,
    DIGEST_476,
    DIGEST_505,
    DIGEST_513,
    DIGEST_518,
    DIGEST_548,
    DIGEST_558,
    DIGEST_563,
    DIGEST_568,
    DIGEST_598,
    DIGEST_616,
    DIGEST_647,
    DIGEST_660,
    DIGEST_674,
    DIGEST_897,
    DIGEST_931,
    DIGEST_1026,
    DIGEST_1034,
    DIGEST_1130,
    DIGEST_1139,
    DSA_CTRL_20,
    E_AES_151,
    E_AES_172,
    E_AES_234,
    E_AES_281,
    E_AES_292,
    E_AES_337,
    E_AES_370,
    E_AES_486,
    E_AES_542,
    E_AES_588,
    E_AES_648,
    E_AES_659,
    E_AES_723,
    E_AES_756,
    E_AES_1035,
    E_AES_1065,
    E_AES_1069,
    E_AES_1131,
    E_AES_1135,
    E_AES_1161,
    E_AES_1165,
    E_AES_1216,
    E_AES_1220,
    E_AES_1625,
    E_AES_1677,
    E_AES_2036,
    E_AES_2423,
    E_AES_2504,
    E_AES_2806,
    E_AES_2899,
    E_AES_3240,
    E_AES_3261,
    E_AES_3360,
    E_AES_3493,
    E_AES_3683,
    E_AES_3722,
    E_AES_3924,
    E_AES_4026,
    E_AES_CBC_HMAC_SHA1_76,
    E_AES_CBC_HMAC_SHA1_498,
    E_ARIA_76,
    E_ARIA_233,
    E_ARIA_525,
    E_CAMELLIA_104,
    E_CAMELLIA_205,
    E_CHACHA20_POLY1305_508,
    E_CHACHA20_POLY1305_527,
    E_DES3_398,
    E_RC2_125,
    E_RC5_63,
    E_RC5_78,
    EC_CTRL_26,
    EC_CTRL_65,
    EC_CTRL_86,
    EC_CTRL_171,
    EC_CTRL_193,
    EC_CTRL_231,
    EC_CTRL_260,
    EVP_CNF_33,
    EVP_CNF_51,
    EVP_CNF_57,
    EVP_CNF_61,
    EVP_ENC_118,
    EVP_ENC_189,
    EVP_ENC_206,
    EVP_ENC_212,
    EVP_ENC_223,
    EVP_ENC_230,
    EVP_ENC_273,
    EVP_ENC_296,
    EVP_ENC_322,
    EVP_ENC_354,
    EVP_ENC_370,
    EVP_ENC_401,
    EVP_ENC_419,
    EVP_ENC_441,
    EVP_ENC_455,
    EVP_ENC_500,
    EVP_ENC_511,
    EVP_ENC_539,
    EVP_ENC_545,
    EVP_ENC_557,
    EVP_ENC_563,
    EVP_ENC_590,
    EVP_ENC_611,
    EVP_ENC_662,
    EVP_ENC_673,
    EVP_ENC_692,
    EVP_ENC_703,
    EVP_ENC_733,
    EVP_ENC_738,
    EVP_ENC_743,
    EVP_ENC_748,
    EVP_ENC_783,
    EVP_ENC_788,
    EVP_ENC_793,
    EVP_ENC_798,
    EVP_ENC_899,
    EVP_ENC_916,
    EVP_ENC_948,
    EVP_ENC_983,
    EVP_ENC_990,
    EVP_ENC_996,
    EVP_ENC_1001,
    EVP_ENC_1011,
    EVP_ENC_1021,
    EVP_ENC_1052,
    EVP_ENC_1058,
    EVP_ENC_1063,
    EVP_ENC_1072,
    EVP_ENC_1081,
    EVP_ENC_1110,
    EVP_ENC_1137,
    EVP_ENC_1144,
    EVP_ENC_1150,
    EVP_ENC_1155,
    EVP_ENC_1164,
    EVP_ENC_1173,
    EVP_ENC_1191,
    EVP_ENC_1218,
    EVP_ENC_1231,
    EVP_ENC_1278,
    EVP_ENC_1284,
    EVP_ENC_1289,
    EVP_ENC_1299,
    EVP_ENC_1308,
    EVP_ENC_1332,
    EVP_ENC_1340,
    EVP_ENC_1351,
    EVP_ENC_1356,
    EVP_ENC_1382,
    EVP_ENC_1410,
    EVP_ENC_1444,
    EVP_ENC_1632,
    EVP_ENC_1640,
    EVP_ENC_1785,
    EVP_ENC_1793,
    EVP_ENC_1809,
    EVP_ENC_1821,
    EVP_ENC_1841,
    EVP_ENC_1898,
    EVP_ENC_1906,
    EVP_ENC_2044,
    EVP_ENC_2053,
    EVP_FETCH_278,
    EVP_FETCH_287,
    EVP_FETCH_303,
    EVP_FETCH_352,
    EVP_FETCH_376,
    EVP_FETCH_485,
    EVP_FETCH_492,
    EVP_FETCH_507,
    EVP_FETCH_517,
    EVP_FETCH_543,
    EVP_FETCH_549,
    EVP_FETCH_596,
    EVP_FETCH_604,
    EVP_LIB_144,
    EVP_LIB_146,
    EVP_LIB_213,
    EVP_LIB_215,
    EVP_LIB_803,
    EVP_LIB_812,
    EVP_LIB_1159,
    EVP_LIB_1179,
    EVP_LIB_1353,
    EVP_LIB_1471,
    EVP_PBE_116,
    EVP_PBE_134,
    EVP_PBE_150,
    EVP_PBE_207,
    EVP_PBE_222,
    EVP_PKEY_41,
    EVP_PKEY_47,
    EVP_PKEY_57,
    EVP_PKEY_61,
    EVP_PKEY_160,
    EVP_PKEY_167,
    EVP_PKEY_171,
    EVP_PKEY_175,
    EVP_RAND_98,
    EVP_RAND_129,
    EVP_RAND_268,
    EVP_RAND_274,
    EVP_RAND_346,
    EVP_RAND_359,
    EVP_RAND_371,
    EVP_RAND_562,
    EVP_RAND_569,
    EVP_RAND_656,
    EVP_UTILS_65,
    EVP_UTILS_70,
    EXCHANGE_59,
    EXCHANGE_150,
    EXCHANGE_225,
    EXCHANGE_249,
    EXCHANGE_261,
    EXCHANGE_268,
    EXCHANGE_355,
    EXCHANGE_379,
    EXCHANGE_402,
    EXCHANGE_410,
    EXCHANGE_464,
    EXCHANGE_470,
    EXCHANGE_483,
    EXCHANGE_488,
    EXCHANGE_500,
    EXCHANGE_529,
    EXCHANGE_534,
    EXCHANGE_547,
    EXCHANGE_562,
    EXCHANGE_567,
    EXCHANGE_572,
    EXCHANGE_589,
    EXCHANGE_601,
    EXCHANGE_607,
    EXCHANGE_619,
    KDF_LIB_35,
    KDF_LIB_69,
    KDF_LIB_211,
    KDF_LIB_230,
    KDF_LIB_241,
    KDF_METH_67,
    KDF_METH_154,
    KEM_42,
    KEM_50,
    KEM_54,
    KEM_62,
    KEM_68,
    KEM_116,
    KEM_146,
    KEM_157,
    KEM_165,
    KEM_177,
    KEM_189,
    KEM_195,
    KEM_234,
    KEM_239,
    KEM_273,
    KEM_278,
    KEM_312,
    KEM_423,
    KEYMGMT_LIB_37,
    KEYMGMT_LIB_65,
    KEYMGMT_LIB_388,
    KEYMGMT_LIB_491,
    KEYMGMT_METH_252,
    KEYMGMT_METH_450,
    KEYMGMT_METH_458,
    M_SIGVER_21,
    M_SIGVER_87,
    M_SIGVER_105,
    M_SIGVER_112,
    M_SIGVER_187,
    M_SIGVER_201,
    M_SIGVER_247,
    M_SIGVER_258,
    M_SIGVER_266,
    M_SIGVER_281,
    M_SIGVER_282,
    M_SIGVER_305,
    M_SIGVER_318,
    M_SIGVER_411,
    M_SIGVER_424,
    M_SIGVER_432,
    M_SIGVER_440,
    M_SIGVER_461,
    M_SIGVER_474,
    M_SIGVER_482,
    M_SIGVER_509,
    M_SIGVER_522,
    M_SIGVER_538,
    M_SIGVER_549,
    M_SIGVER_628,
    M_SIGVER_633,
    M_SIGVER_651,
    M_SIGVER_679,
    M_SIGVER_692,
    M_SIGVER_707,
    M_SIGVER_718,
    M_SIGVER_764,
    M_SIGVER_769,
    M_SIGVER_785,
    MAC_LIB_31,
    MAC_LIB_63,
    MAC_LIB_119,
    MAC_LIB_130,
    MAC_LIB_150,
    MAC_LIB_154,
    MAC_LIB_161,
    MAC_LIB_168,
    MAC_LIB_176,
    MAC_LIB_283,
    MAC_METH_66,
    MAC_METH_159,
    P5_CRPT_46,
    P5_CRPT_52,
    P5_CRPT_58,
    P5_CRPT_63,
    P5_CRPT2_128,
    P5_CRPT2_135,
    P5_CRPT2_143,
    P5_CRPT2_155,
    P5_CRPT2_164,
    P5_CRPT2_196,
    P5_CRPT2_207,
    P5_CRPT2_213,
    P5_CRPT2_221,
    P5_CRPT2_231,
    P5_CRPT2_241,
    P5_CRPT2_247,
    P_DEC_28,
    P_ENC_28,
    P_LEGACY_43,
    P_LEGACY_79,
    P_LIB_71,
    P_LIB_87,
    P_LIB_180,
    P_LIB_187,
    P_LIB_195,
    P_LIB_223,
    P_LIB_471,
    P_LIB_487,
    P_LIB_501,
    P_LIB_506,
    P_LIB_511,
    P_LIB_516,
    P_LIB_606,
    P_LIB_611,
    P_LIB_616,
    P_LIB_638,
    P_LIB_643,
    P_LIB_648,
    P_LIB_673,
    P_LIB_682,
    P_LIB_701,
    P_LIB_710,
    P_LIB_736,
    P_LIB_741,
    P_LIB_840,
    P_LIB_856,
    P_LIB_874,
    P_LIB_890,
    P_LIB_930,
    P_LIB_1001,
    P_LIB_1504,
    P_LIB_1511,
    P_LIB_1551,
    P_LIB_1601,
    P_LIB_1607,
    P_LIB_1641,
    P_LIB_1688,
    P_LIB_1720,
    P_LIB_1748,
    P_LIB_1866,
    P_LIB_2088,
    P_LIB_2102,
    P_LIB_2115,
    P_LIB_2126,
    P_LIB_2142,
    P_LIB_2434,
    P_LIB_2455,
    P_OPEN_37,
    P_SEAL_62,
    P_SIGN_36,
    P_VERIFY_34,
    PBE_SCRYPT_50,
    PMETH_CHECK_40,
    PMETH_CHECK_53,
    PMETH_CHECK_78,
    PMETH_CHECK_98,
    PMETH_CHECK_124,
    PMETH_CHECK_144,
    PMETH_CHECK_154,
    PMETH_CHECK_169,
    PMETH_CHECK_194,
    PMETH_GN_50,
    PMETH_GN_87,
    PMETH_GN_146,
    PMETH_GN_241,
    PMETH_GN_245,
    PMETH_GN_250,
    PMETH_GN_259,
    PMETH_GN_268,
    PMETH_GN_351,
    PMETH_GN_367,
    PMETH_GN_378,
    PMETH_GN_439,
    PMETH_LIB_192,
    PMETH_LIB_219,
    PMETH_LIB_255,
    PMETH_LIB_284,
    PMETH_LIB_295,
    PMETH_LIB_459,
    PMETH_LIB_619,
    PMETH_LIB_624,
    PMETH_LIB_916,
    PMETH_LIB_950,
    PMETH_LIB_997,
    PMETH_LIB_1008,
    PMETH_LIB_1037,
    PMETH_LIB_1048,
    PMETH_LIB_1158,
    PMETH_LIB_1170,
    PMETH_LIB_1206,
    PMETH_LIB_1267,
    PMETH_LIB_1271,
    PMETH_LIB_1309,
    PMETH_LIB_1314,
    PMETH_LIB_1325,
    PMETH_LIB_1334,
    PMETH_LIB_1346,
    PMETH_LIB_1380,
    PMETH_LIB_1390,
    PMETH_LIB_1460,
    PMETH_LIB_1468,
    PMETH_LIB_1473,
    PMETH_LIB_1480,
    PMETH_LIB_1484,
    PMETH_LIB_1491,
    PMETH_LIB_1619,
    S_LIB_25,
    S_LIB_47,
    S_LIB_79,
    S_LIB_169,
    S_LIB_285,
    S_LIB_305,
    SIGNATURE_68,
    SIGNATURE_296,
    SIGNATURE_310,
    SIGNATURE_315,
    SIGNATURE_329,
    SIGNATURE_340,
    SIGNATURE_353,
    SIGNATURE_363,
    SIGNATURE_374,
    SIGNATURE_385,
    SIGNATURE_396,
    SIGNATURE_409,
    SIGNATURE_419,
    SIGNATURE_425,
    SIGNATURE_431,
    SIGNATURE_437,
    SIGNATURE_443,
    SIGNATURE_580,
    SIGNATURE_596,
    SIGNATURE_637,
    SIGNATURE_664,
    SIGNATURE_681,
    SIGNATURE_691,
    SIGNATURE_699,
    SIGNATURE_786,
    SIGNATURE_793,
    SIGNATURE_802,
    SIGNATURE_811,
    SIGNATURE_820,
    SIGNATURE_829,
    SIGNATURE_837,
    SIGNATURE_862,
    SIGNATURE_883,
    SIGNATURE_933,
    SIGNATURE_938,
    SIGNATURE_945,
    SIGNATURE_952,
    SIGNATURE_965,
    SIGNATURE_970,
    SIGNATURE_977,
    SIGNATURE_985,
    SIGNATURE_999,
    SIGNATURE_1005,
    SIGNATURE_1015,
    SIGNATURE_1023,
    SIGNATURE_1029,
    SIGNATURE_1064,
    SIGNATURE_1087,
    SIGNATURE_1092,
    SIGNATURE_1099,
    SIGNATURE_1106,
    SIGNATURE_1118,
    SIGNATURE_1123,
    SIGNATURE_1130,
    SIGNATURE_1138,
    SIGNATURE_1152,
    SIGNATURE_1158,
    SIGNATURE_1168,
    SIGNATURE_1176,
    SIGNATURE_1182,
    SIGNATURE_1215,
    SIGNATURE_1220,
    SIGNATURE_1230,
    SIGNATURE_1238,
    SIGNATURE_1243,
    SKEYMGMT_METH_116,
    SKEYMGMT_METH_122,
    HPKE_122,
    HPKE_154,
    HPKE_162,
    HPKE_168,
    HPKE_173,
    HPKE_179,
    HPKE_184,
    HPKE_190,
    HPKE_195,
    HPKE_233,
    HPKE_237,
    HPKE_245,
    HPKE_251,
    HPKE_256,
    HPKE_262,
    HPKE_267,
    HPKE_273,
    HPKE_279,
    HPKE_403,
    HPKE_407,
    HPKE_462,
    HPKE_467,
    HPKE_472,
    HPKE_485,
    HPKE_490,
    HPKE_506,
    HPKE_511,
    HPKE_517,
    HPKE_521,
    HPKE_534,
    HPKE_564,
    HPKE_569,
    HPKE_574,
    HPKE_587,
    HPKE_603,
    HPKE_607,
    HPKE_612,
    HPKE_617,
    HPKE_626,
    HPKE_672,
    HPKE_676,
    HPKE_681,
    HPKE_686,
    HPKE_696,
    HPKE_703,
    HPKE_709,
    HPKE_727,
    HPKE_736,
    HPKE_742,
    HPKE_752,
    HPKE_767,
    HPKE_780,
    HPKE_794,
    HPKE_820,
    HPKE_824,
    HPKE_828,
    HPKE_843,
    HPKE_887,
    HPKE_891,
    HPKE_895,
    HPKE_899,
    HPKE_903,
    HPKE_908,
    HPKE_932,
    HPKE_936,
    HPKE_940,
    HPKE_954,
    HPKE_959,
    HPKE_963,
    HPKE_983,
    HPKE_988,
    HPKE_992,
    HPKE_1011,
    HPKE_1026,
    HPKE_1043,
    HPKE_1053,
    HPKE_1062,
    HPKE_1079,
    HPKE_1083,
    HPKE_1087,
    HPKE_1091,
    HPKE_1096,
    HPKE_1101,
    HPKE_1105,
    HPKE_1126,
    HPKE_1130,
    HPKE_1134,
    HPKE_1138,
    HPKE_1143,
    HPKE_1148,
    HPKE_1153,
    HPKE_1175,
    HPKE_1179,
    HPKE_1183,
    HPKE_1188,
    HPKE_1193,
    HPKE_1197,
    HPKE_1217,
    HPKE_1221,
    HPKE_1225,
    HPKE_1230,
    HPKE_1235,
    HPKE_1239,
    HPKE_1259,
    HPKE_1263,
    HPKE_1267,
    HPKE_1271,
    HPKE_1276,
    HPKE_1282,
    HPKE_1300,
    HPKE_1316,
    HPKE_1320,
    HPKE_1326,
    HPKE_1339,
    HPKE_1347,
    HPKE_1351,
    HPKE_1359,
    HPKE_1391,
    HPKE_1397,
    HPKE_1404,
    HPKE_1410,
    HPKE_1416,
    HPKE_1429,
    HPKE_1434,
    HPKE_UTIL_168,
    HPKE_UTIL_181,
    HPKE_UTIL_188,
    HPKE_UTIL_210,
    HPKE_UTIL_232,
    HPKE_UTIL_269,
    HPKE_UTIL_329,
    HPKE_UTIL_380,
    HPKE_UTIL_401,
    HPKE_UTIL_459,
    HPKE_UTIL_464,
    AMETH_LIB_162,
    AMETH_LIB_174,
    P5_SCRYPT_54,
    P5_SCRYPT_59,
    P5_SCRYPT_65,
    P5_SCRYPT_71,
    P5_SCRYPT_81,
    P5_SCRYPT_96,
    P5_SCRYPT_104,
    P5_SCRYPT_122,
    P5_SCRYPT_130,
    P5_SCRYPT_141,
    P5_SCRYPT_166,
    P5_SCRYPT_175,
    P5_SCRYPT_183,
    P5_SCRYPT_188,
    P5_SCRYPT_193,
    P5_SCRYPT_202,
    P5_SCRYPT_206,
    P5_SCRYPT_215,
    P5_SCRYPT_226,
    P5_SCRYPT_252,
    P5_SCRYPT_261,
    P5_SCRYPT_267,
    P5_SCRYPT_278,
    P5_SCRYPT_289,
    I2D_EVP_69,
    I2D_EVP_87,
    I2D_EVP_127,
    I2D_EVP_166,
    D2I_PR_61,
    D2I_PR_110,
    D2I_PR_122,
    D2I_PR_150,
    D2I_PR_218,
    D2I_PARAM_33,
    D2I_PU_36,
    D2I_PU_53,
    D2I_PU_60,
    D2I_PU_67,
    D2I_PU_80,
    D2I_PU_86,
    PEM_LIB_64,
    PEM_LIB_118,
    PEM_LIB_312,
    PEM_LIB_346,
    PEM_LIB_352,
    PEM_LIB_358,
    PEM_LIB_376,
    PEM_LIB_459,
    PEM_LIB_471,
    PEM_LIB_498,
    PEM_LIB_533,
    PEM_LIB_544,
    PEM_LIB_549,
    PEM_LIB_558,
    PEM_LIB_576,
    PEM_LIB_581,
    PEM_LIB_584,
    PEM_LIB_606,
    PEM_LIB_625,
    PEM_LIB_697,
    PEM_LIB_711,
    PEM_LIB_794,
    PEM_LIB_858,
    PEM_LIB_887,
    PEM_LIB_901,
    PEM_LIB_911,
    PEM_LIB_959,
    PEM_LIB_967,
    PEM_LIB_978,
    PEM_LIB_989,
    PEM_LIB_1000,
    PEM_OTH_33,
    PEM_PKEY_87,
    PEM_PKEY_161,
    PEM_PKEY_209,
    PEM_PKEY_288,
    PEM_PKEY_360,
    PEM_PKEY_418,
    PEM_PKEY_439,
    PEM_PK8_132,
    PEM_PK8_139,
    PEM_PK8_185,
    PEM_PK8_243,
    PEM_PK8_258,
    PROV_CIPHERCOMMON_80,
    PROV_CIPHERCOMMON_91,
    PROV_CIPHERCOMMON_106,
    PROV_CIPHERCOMMON_117,
    PROV_CIPHERCOMMON_129,
    PROV_CIPHERCOMMON_140,
    PROV_CIPHERCOMMON_151,
    PROV_CIPHERCOMMON_162,
    PROV_CIPHERCOMMON_173,
    PROV_CIPHERCOMMON_184,
    PROV_CIPHERCOMMON_212,
    PROV_CIPHERCOMMON_217,
    PROV_CIPHERCOMMON_222,
    PROV_CIPHERCOMMON_227,
    PROV_CIPHERCOMMON_232,
    PROV_CIPHERCOMMON_237,
    PROV_CIPHERCOMMON_242,
    PROV_CIPHERCOMMON_246,
    PROV_CIPHERCOMMON_250,
    PROV_CIPHERCOMMON_254,
    PROV_CIPHERCOMMON_313,
    PROV_CIPHERCOMMON_322,
    PROV_CIPHERCOMMON_334,
    PROV_CIPHERCOMMON_345,
    PROV_CIPHERCOMMON_356,
    PROV_CIPHERCOMMON_367,
    PROV_CIPHERCOMMON_378,
    PROV_CIPHERCOMMON_437,
    PROV_CIPHERCOMMON_448,
    PROV_CIPHERCOMMON_475,
    PROV_CIPHERCOMMON_486,
    PROV_CIPHERCOMMON_501,
    PROV_CIPHERCOMMON_565,
    PROV_CIPHERCOMMON_576,
    PROV_CIPHERCOMMON_587,
    PROV_CIPHERCOMMON_614,
    PROV_CIPHERCOMMON_625,
    PROV_CIPHERCOMMON_640,
    PROV_CIPHERCOMMON_672,
    PROV_CIPHERCOMMON_719,
    PROV_CIPHERCOMMON_783,
    PROV_CIPHERCOMMON_798,
    PROV_CIPHERCOMMON_811,
    PROV_CIPHERCOMMON_816,
    PROV_CIPHERCOMMON_833,
    PROV_CIPHERCOMMON_839,
    PROV_CIPHERCOMMON_856,
    PROV_CIPHERCOMMON_875,
    PROV_CIPHERCOMMON_879,
    PROV_CIPHERCOMMON_889,
    PROV_CIPHERCOMMON_896,
    PROV_CIPHERCOMMON_902,
    PROV_CIPHERCOMMON_928,
    PROV_CIPHERCOMMON_934,
    PROV_CIPHERCOMMON_945,
    PROV_CIPHERCOMMON_950,
    PROV_CIPHERCOMMON_954,
    PROV_CIPHERCOMMON_968,
    PROV_CIPHERCOMMON_973,
    PROV_CIPHERCOMMON_983,
    PROV_CIPHERCOMMON_999,
    PROV_CIPHERCOMMON_1009,
    PROV_CIPHERCOMMON_1014,
    PROV_CIPHERCOMMON_1063,
    PROV_CIPHERCOMMON_1081,
    PROV_CIPHERCOMMON_1086,
    PROV_CIPHERCOMMON_1091,
    PROV_CIPHERCOMMON_1102,
    PROV_CIPHERCOMMON_1107,
    PROV_CIPHERCOMMON_1113,
    PROV_CIPHERCOMMON_1119,
    PROV_CIPHERCOMMON_1124,
    PROV_CIPHERCOMMON_1129,
    PROV_CIPHERCOMMON_1135,
    PROV_CIPHERCOMMON_1157,
    PROV_CIPHERCOMMON_1167,
    PROV_CIPHERCOMMON_1175,
    PROV_CIPHERCOMMON_1182,
    PROV_CIPHERCOMMON_1191,
    PROV_CIPHERCOMMON_1195,
    PROV_CIPHERCOMMON_1221,
    PROV_CIPHERCOMMON_BLOCK_70,
    PROV_CIPHERCOMMON_BLOCK_97,
    PROV_CIPHERCOMMON_BLOCK_107,
    PROV_CIPHERCOMMON_BLOCK_112,
    PROV_CIPHER_AES_HW_121,
    PROV_CIPHER_CAMELLIA_HW_30,
    PROV_CIPHER_TDES_COMMON_101,
    PROV_CIPHER_TDES_COMMON_162,
    PROV_CIPHER_TDES_COMMON_195,
    PROV_CIPHER_NULL_130,
    PROV_CIPHER_NULL_135,
    PROV_CIPHER_NULL_141,
    PROV_CIPHER_NULL_168,
    PROV_CIPHER_AES_OCB_119,
    PROV_CIPHER_AES_OCB_130,
    PROV_CIPHER_AES_OCB_173,
    PROV_CIPHER_AES_OCB_177,
    PROV_CIPHER_AES_OCB_188,
    PROV_CIPHER_AES_OCB_192,
    PROV_CIPHER_AES_OCB_363,
    PROV_CIPHER_AES_OCB_369,
    PROV_CIPHER_AES_OCB_375,
    PROV_CIPHER_AES_OCB_379,
    PROV_CIPHER_AES_OCB_388,
    PROV_CIPHER_AES_OCB_404,
    PROV_CIPHER_AES_OCB_408,
    PROV_CIPHER_AES_OCB_422,
    PROV_CIPHER_AES_OCB_427,
    PROV_CIPHER_AES_OCB_433,
    PROV_CIPHER_AES_OCB_441,
    PROV_CIPHER_AES_OCB_445,
    PROV_CIPHER_AES_OCB_452,
    PROV_CIPHER_AES_OCB_456,
    PROV_CIPHER_AES_OCB_463,
    PROV_CIPHER_AES_OCB_467,
    PROV_CIPHER_AES_OCB_515,
    PROV_CIPHER_AES_OCB_528,
    PROV_CIPHER_AES_OCB_533,
    PROV_CIPHER_AES_WRP_123,
    PROV_CIPHER_AES_WRP_178,
    PROV_CIPHER_AES_WRP_184,
    PROV_CIPHER_AES_WRP_190,
    PROV_CIPHER_AES_WRP_214,
    PROV_CIPHER_AES_WRP_218,
    PROV_CIPHER_AES_WRP_250,
    PROV_CIPHER_AES_WRP_274,
    PROV_CIPHER_AES_WRP_278,
    PROV_CIPHER_AES_XTS_59,
    PROV_CIPHER_AES_XTS_90,
    PROV_CIPHER_AES_XTS_202,
    PROV_CIPHER_AES_XTS_223,
    PROV_CIPHER_AES_XTS_228,
    PROV_CIPHER_AES_XTS_268,
    PROV_CIPHERCOMMON_CCM_108,
    PROV_CIPHERCOMMON_CCM_123,
    PROV_CIPHERCOMMON_CCM_142,
    PROV_CIPHERCOMMON_CCM_153,
    PROV_CIPHERCOMMON_CCM_186,
    PROV_CIPHERCOMMON_CCM_190,
    PROV_CIPHERCOMMON_CCM_196,
    PROV_CIPHERCOMMON_CCM_207,
    PROV_CIPHERCOMMON_CCM_212,
    PROV_CIPHERCOMMON_CCM_223,
    PROV_CIPHERCOMMON_CCM_228,
    PROV_CIPHERCOMMON_CCM_236,
    PROV_CIPHERCOMMON_CCM_240,
    PROV_CIPHERCOMMON_CCM_298,
    PROV_CIPHERCOMMON_CCM_307,
    PROV_CIPHERCOMMON_CCM_319,
    PROV_CIPHERCOMMON_CCM_342,
    PROV_CIPHERCOMMON_CCM_351,
    PROV_CIPHERCOMMON_CCM_363,
    PROV_CIPHERCOMMON_CCM_375,
    PROV_CIPHERCOMMON_CCM_403,
    PROV_CIPHERCOMMON_CCM_408,
    PROV_CIPHERCOMMON_CCM_414,
    PROV_CIPHERCOMMON_CCM_418,
    PROV_CIPHERCOMMON_CCM_425,
    PROV_CIPHERCOMMON_CCM_429,
    PROV_CIPHERCOMMON_CCM_435,
    PROV_CIPHERCOMMON_CCM_440,
    PROV_CIPHERCOMMON_CCM_446,
    PROV_CIPHERCOMMON_CCM_450,
    PROV_CIPHERCOMMON_CCM_476,
    PROV_CIPHERCOMMON_CCM_484,
    PROV_CIPHERCOMMON_CCM_514,
    PROV_CIPHERCOMMON_CCM_519,
    PROV_CIPHERCOMMON_CCM_560,
    PROV_CIPHER_AES_SIV_90,
    PROV_CIPHER_AES_SIV_122,
    PROV_CIPHER_AES_SIV_161,
    PROV_CIPHER_AES_SIV_167,
    PROV_CIPHER_AES_SIV_172,
    PROV_CIPHER_AES_SIV_206,
    PROV_CIPHER_AES_SIV_213,
    PROV_CIPHER_AES_SIV_223,
    PROV_CIPHER_CHACHA20_111,
    PROV_CIPHER_CHACHA20_116,
    PROV_CIPHER_CHACHA20_126,
    PROV_CIPHER_CHACHA20_156,
    PROV_CIPHER_CHACHA20_160,
    PROV_CIPHER_CHACHA20_167,
    PROV_CIPHER_CHACHA20_171,
    PROV_CIPHER_ARIA_HW_25,
    PROV_CIPHER_SM4_XTS_54,
    PROV_CIPHER_SM4_XTS_142,
    PROV_CIPHER_SM4_XTS_171,
    PROV_CIPHER_SM4_XTS_176,
    PROV_CIPHER_SM4_XTS_227,
    PROV_CIPHER_SM4_XTS_235,
    PROV_CIPHER_AES_CBC_HMAC_SHA_102,
    PROV_CIPHER_AES_CBC_HMAC_SHA_113,
    PROV_CIPHER_AES_CBC_HMAC_SHA_132,
    PROV_CIPHER_AES_CBC_HMAC_SHA_162,
    PROV_CIPHER_AES_CBC_HMAC_SHA_176,
    PROV_CIPHER_AES_CBC_HMAC_SHA_188,
    PROV_CIPHER_AES_CBC_HMAC_SHA_192,
    PROV_CIPHER_AES_CBC_HMAC_SHA_200,
    PROV_CIPHER_AES_CBC_HMAC_SHA_206,
    PROV_CIPHER_AES_CBC_HMAC_SHA_231,
    PROV_CIPHER_AES_CBC_HMAC_SHA_238,
    PROV_CIPHER_AES_CBC_HMAC_SHA_244,
    PROV_CIPHER_AES_CBC_HMAC_SHA_250,
    PROV_CIPHER_AES_CBC_HMAC_SHA_257,
    PROV_CIPHER_AES_CBC_HMAC_SHA_262,
    PROV_CIPHER_AES_CBC_HMAC_SHA_267,
    PROV_CIPHER_AES_CBC_HMAC_SHA_273,
    PROV_CIPHER_AES_CBC_HMAC_SHA_279,
    PROV_CMAC_PROV_245,
    PROV_CMAC_PROV_257,
    PROV_CMAC_PROV_269,
    PROV_CMAC_PROV_350,
    PROV_CMAC_PROV_370,
    PROV_CMAC_PROV_382,
    PROV_CMAC_PROV_395,
    PROV_CMAC_PROV_406,
    PROV_CMAC_PROV_449,
    PROV_CMAC_PROV_460,
    PROV_GMAC_PROV_111,
    PROV_GMAC_PROV_200,
    PROV_GMAC_PROV_268,
    PROV_GMAC_PROV_279,
    PROV_GMAC_PROV_290,
    PROV_GMAC_PROV_301,
    PROV_GMAC_PROV_312,
    PROV_GMAC_PROV_354,
    PROV_HMAC_PROV_177,
    PROV_HMAC_PROV_313,
    PROV_HMAC_PROV_325,
    PROV_HMAC_PROV_337,
    PROV_HMAC_PROV_427,
    PROV_HMAC_PROV_438,
    PROV_HMAC_PROV_462,
    PROV_HMAC_PROV_472,
    PROV_HMAC_PROV_485,
    PROV_HMAC_PROV_496,
    PROV_BLAKE2_PARAMS_46,
    PROV_BLAKE2_PARAMS_57,
    PROV_BLAKE2_PARAMS_105,
    PROV_BLAKE2_PARAMS_116,
    PROV_BLAKE2_PARAMS_131,
    PROV_BLAKE2_PARAMS_142,
    PROV_BLAKE2_MAC_IMPL_96,
    PROV_BLAKE2_MAC_IMPL_119,
    PROV_BLAKE2_MAC_IMPL_197,
    PROV_BLAKE2_MAC_IMPL_216,
    PROV_BLAKE2_MAC_IMPL_231,
    PROV_POLY1305_PROV_92,
    PROV_POLY1305_PROV_121,
    PROV_POLY1305_PROV_141,
    PROV_POLY1305_PROV_177,
    PROV_POLY1305_PROV_234,
    PROV_SIPHASH_PROV_190,
    PROV_SIPHASH_PROV_201,
    PROV_SIPHASH_PROV_212,
    PROV_SIPHASH_PROV_285,
    PROV_SIPHASH_PROV_296,
    PROV_SIPHASH_PROV_307,
    PROV_SIPHASH_PROV_318,
    PROV_KMAC_PROV_272,
    PROV_KMAC_PROV_288,
    PROV_KMAC_PROV_295,
    PROV_KMAC_PROV_326,
    PROV_KMAC_PROV_335,
    PROV_KMAC_PROV_351,
    PROV_KMAC_PROV_434,
    PROV_KMAC_PROV_446,
    PROV_KMAC_PROV_458,
    PROV_KMAC_PROV_550,
    PROV_KMAC_PROV_574,
    PROV_KMAC_PROV_584,
    PROV_KMAC_PROV_598,
    PROV_KMAC_PROV_610,
    PROV_KMAC_PROV_621,
    PROV_KMAC_PROV_672,
    PROV_KMAC_PROV_682,
    PROV_KMAC_PROV_699,
    PROV_KMAC_PROV_741,
    PROV_KMAC_PROV_778,
    PROV_KMAC_PROV_811,
    PROV_DIGESTCOMMON_56,
    PROV_DIGESTCOMMON_67,
    PROV_DIGESTCOMMON_78,
    PROV_DIGESTCOMMON_89,
    PROV_DIGESTCOMMON_111,
    PROV_DIGESTCOMMON_115,
    PROV_DIGESTCOMMON_120,
    PROV_DIGESTCOMMON_125,
];
