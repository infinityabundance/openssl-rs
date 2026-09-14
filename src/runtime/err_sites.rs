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
}

/// `sk_reserve` at `crypto/stack/stack.c:186` (CRYPTO_R_TOO_MANY_RECORDS).
pub(crate) const STACK_186: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/stack/stack.c",
    line: 186,
    func: c"sk_reserve",
    lib: 15,
    reason: 114,
};

/// `sk_reserve` at `crypto/stack/stack.c:212` (CRYPTO_R_TOO_MANY_RECORDS).
pub(crate) const STACK_212: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/stack/stack.c",
    line: 212,
    func: c"sk_reserve",
    lib: 15,
    reason: 114,
};

/// `OPENSSL_sk_reserve` at `crypto/stack/stack.c:251` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const STACK_251: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/stack/stack.c",
    line: 251,
    func: c"OPENSSL_sk_reserve",
    lib: 15,
    reason: 786690,
};

/// `OPENSSL_sk_insert` at `crypto/stack/stack.c:271` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const STACK_271: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/stack/stack.c",
    line: 271,
    func: c"OPENSSL_sk_insert",
    lib: 15,
    reason: 786690,
};

/// `OPENSSL_sk_insert` at `crypto/stack/stack.c:275` (CRYPTO_R_TOO_MANY_RECORDS).
pub(crate) const STACK_275: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/stack/stack.c",
    line: 275,
    func: c"OPENSSL_sk_insert",
    lib: 15,
    reason: 114,
};

/// `OPENSSL_sk_set` at `crypto/stack/stack.c:482` (ERR_R_PASSED_NULL_PARAMETER).
pub(crate) const STACK_482: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/stack/stack.c",
    line: 482,
    func: c"OPENSSL_sk_set",
    lib: 15,
    reason: 786690,
};

/// `OPENSSL_sk_set` at `crypto/stack/stack.c:486` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const STACK_486: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/stack/stack.c",
    line: 486,
    func: c"OPENSSL_sk_set",
    lib: 15,
    reason: 524550,
};

/// `get_and_lock` at `crypto/ex_data.c:37` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const EX_DATA_37: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/ex_data.c",
    line: 37,
    func: c"get_and_lock",
    lib: 15,
    reason: 524550,
};

/// `ossl_crypto_get_ex_new_index_ex` at `crypto/ex_data.c:175` (ERR_R_CRYPTO_LIB).
pub(crate) const EX_DATA_175: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/ex_data.c",
    line: 175,
    func: c"ossl_crypto_get_ex_new_index_ex",
    lib: 15,
    reason: 524303,
};

/// `ossl_crypto_get_ex_new_index_ex` at `crypto/ex_data.c:191` (ERR_R_CRYPTO_LIB).
pub(crate) const EX_DATA_191: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/ex_data.c",
    line: 191,
    func: c"ossl_crypto_get_ex_new_index_ex",
    lib: 15,
    reason: 524303,
};

/// `CRYPTO_set_ex_data` at `crypto/ex_data.c:474` (ERR_R_CRYPTO_LIB).
pub(crate) const EX_DATA_474: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/ex_data.c",
    line: 474,
    func: c"CRYPTO_set_ex_data",
    lib: 15,
    reason: 524303,
};

/// `CRYPTO_set_ex_data` at `crypto/ex_data.c:481` (ERR_R_CRYPTO_LIB).
pub(crate) const EX_DATA_481: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/ex_data.c",
    line: 481,
    func: c"CRYPTO_set_ex_data",
    lib: 15,
    reason: 524303,
};

/// `CRYPTO_set_ex_data` at `crypto/ex_data.c:487` (ERR_R_PASSED_INVALID_ARGUMENT).
pub(crate) const EX_DATA_487: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/ex_data.c",
    line: 487,
    func: c"CRYPTO_set_ex_data",
    lib: 15,
    reason: 524550,
};

/// `OPENSSL_init_crypto` at `crypto/init.c:504` (ERR_R_INIT_FAIL).
pub(crate) const INIT_504: ErrSite = ErrSite {
    file: c"../../src/openssl-3.6.4/crypto/init.c",
    line: 504,
    func: c"OPENSSL_init_crypto",
    lib: 15,
    reason: 786693,
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
];
