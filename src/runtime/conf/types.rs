//! Phase 4 — CONF: the shared types of `crypto/conf`.
//!
//! `CONF` is opaque in the public headers, but two layouts still matter and are
//! therefore transcribed rather than invented:
//!
//! * `CONF_VALUE`, which **is** public (`openssl/conf.h`) and whose three fields
//!   are read and written by callers;
//! * `struct conf_st` and `struct conf_method_st` from
//!   `openssl/conftypes.h`, which the *classic* CONF API manipulates by value:
//!   `CONF_set_nconf(&ctmp, hash)` builds a `CONF` on the caller's stack and hands
//!   its address to the method table, so the field order decides what the method
//!   functions see.
//!
//! `struct conf_st`'s final member is `OSSL_LIB_CTX *libctx`. That type belongs
//! to Phase 6 and is not defined here; the field is carried as an opaque pointer
//! so that `NCONF_get0_libctx` can return exactly what `NCONF_new_ex` was given
//! and the layout stays correct for when the real context arrives.

use core::ffi::{c_char, c_int, c_long, c_void};

use crate::runtime::bio::Bio;
use crate::runtime::lhash::OpenSslLhash;

/// `CONF_VALUE` from `openssl/conf.h`.
///
/// `name == NULL` marks a *section*: its `value` is then a
/// `STACK_OF(CONF_VALUE)` holding the section's entries, and its `section` is the
/// section's own name. That overloading is the data model, not an accident, and
/// `conf_value_cmp` depends on it.
#[repr(C)]
pub struct ConfValue {
    /// The section this entry belongs to, or a section's own name.
    pub section: *mut c_char,
    /// The key, or NULL for a section entry.
    pub name: *mut c_char,
    /// The value, or (for a section entry) a `STACK_OF(CONF_VALUE)`.
    pub value: *mut c_char,
}

/// `CONF *(*)(CONF_METHOD *)` — `struct conf_method_st.create`.
pub type ConfCreateFn = unsafe extern "C" fn(*mut ConfMethod) -> *mut Conf;
/// `int (*)(CONF *)` — `init`.
pub type ConfInitFn = unsafe extern "C" fn(*mut Conf) -> c_int;
/// `int (*)(CONF *)` — `destroy`.
pub type ConfDestroyFn = unsafe extern "C" fn(*mut Conf) -> c_int;
/// `int (*)(CONF *)` — `destroy_data`.
pub type ConfDestroyDataFn = unsafe extern "C" fn(*mut Conf) -> c_int;
/// `int (*)(CONF *, BIO *, long *)` — `load_bio`.
pub type ConfLoadBioFn = unsafe extern "C" fn(*mut Conf, *mut Bio, *mut c_long) -> c_int;
/// `int (*)(const CONF *, BIO *)` — `dump`.
pub type ConfDumpFn = unsafe extern "C" fn(*const Conf, *mut Bio) -> c_int;
/// `int (*)(const CONF *, char)` — `is_number`.
pub type ConfIsNumberFn = unsafe extern "C" fn(*const Conf, c_char) -> c_int;
/// `int (*)(const CONF *, char)` — `to_int`.
pub type ConfToIntFn = unsafe extern "C" fn(*const Conf, c_char) -> c_int;
/// `int (*)(CONF *, const char *, long *)` — `load`.
pub type ConfLoadFn = unsafe extern "C" fn(*mut Conf, *const c_char, *mut c_long) -> c_int;

/// `struct conf_method_st` from `openssl/conftypes.h`.
///
/// Deprecated in the headers but load-bearing in the ABI: `NCONF_default()` and
/// `NCONF_WIN32()` both return a pointer to one of these, and a caller may build
/// its own and pass it to `NCONF_new_ex`.
#[repr(C)]
pub struct ConfMethod {
    /// The method's name, as `CONF_METHOD->name`.
    pub name: *const c_char,
    /// Allocates and initialises a `CONF`.
    pub create: Option<ConfCreateFn>,
    /// Initialises a caller-provided `CONF`.
    pub init: Option<ConfInitFn>,
    /// Frees the `CONF` and its data.
    pub destroy: Option<ConfDestroyFn>,
    /// Frees only the data.
    pub destroy_data: Option<ConfDestroyDataFn>,
    /// Parses from a BIO.
    pub load_bio: Option<ConfLoadBioFn>,
    /// Writes the model back out.
    pub dump: Option<ConfDumpFn>,
    /// Whether a byte counts as a digit for `NCONF_get_number_e`.
    pub is_number: Option<ConfIsNumberFn>,
    /// The digit's value, for `NCONF_get_number_e`.
    pub to_int: Option<ConfToIntFn>,
    /// Parses from a named file.
    pub load: Option<ConfLoadFn>,
}

/// `struct conf_st` from `openssl/conftypes.h`.
#[repr(C)]
pub struct Conf {
    /// The method table this configuration was created with.
    pub meth: *mut ConfMethod,
    /// The method's private data. For the default method this is the
    /// `CONF_type_default` character-class table, and `is_keytype` reads it.
    pub meth_data: *mut c_void,
    /// `LHASH_OF(CONF_VALUE) *` — the only place the model is stored.
    pub data: *mut OpenSslLhash,
    /// `.pragma dollarid` — when set, `$` is part of an identifier.
    pub flag_dollarid: c_int,
    /// `.pragma abspath` — when set, a relative `.include` is an error.
    pub flag_abspath: c_int,
    /// `includedir` from `.pragma includedir`.
    pub includedir: *mut c_char,
    /// The `OSSL_LIB_CTX` this configuration is bound to (Phase 6).
    pub libctx: *mut c_void,
}
