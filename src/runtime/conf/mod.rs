//! Phase 4 — CONF: the configuration data model, the parser and the module
//! registry.
//!
//! `libcrypto` carries a configuration reader that is a compatibility surface in
//! its own right: `openssl.cnf` is *input that applications and administrators
//! write*, so its grammar — sections, `name = value`, `$variable` expansion,
//! `$section::name` qualification, quoting and escaping, line continuation,
//! `.pragma` lines, `.include` of a file or a directory, the UTF-8 BOM — is
//! observable behaviour and not an implementation detail.
//!
//! ## The layers, and where this stratum stands
//!
//! * [`init_settings`] — the `OPENSSL_INIT_SETTINGS` object that carries a
//!   configuration filename, application name and flag word into
//!   `OPENSSL_init_crypto`. Present.
//! * [`types`] — `CONF`, `CONF_VALUE` and `CONF_METHOD`, transcribed from
//!   `openssl/conftypes.h` and `openssl/conf.h`.
//! * [`api`] — `conf_api.c`: the model, its hash and comparison functions, the
//!   lookups, and the two-phase free walk.
//! * [`def`] — `conf_def.c`: the parser, the dumper and the two character-class
//!   tables, plus `NCONF_default`/`NCONF_WIN32`.
//! * [`lib`] — `conf_lib.c`: the classic API's bridge onto `NCONF`, the `NCONF`
//!   accessors, and `NCONF_get_number_e`.
//! * [`modparse`] — `CONF_parse_list` and `CONF_get1_default_config_file`.
//! * the module registry (`CONF_modules_*`, `CONF_imodule_*`, `CONF_module_add`)
//!   and the automatic loader (`conf_sap.c`). **Structurally blocked**, not merely
//!   unstarted: `CONF_modules_load` begins with `conf_diagnostics`, which reads
//!   and writes the `OSSL_LIB_CTX` diagnostics flag, and `OSSL_LIB_CTX` is
//!   Phase 6. Those symbols are a recorded hand-off to Phase 6 in
//!   `forensics/phase4-obligations.json`; see [`modparse`] and
//!   `docs/DECISIONS.md` D50.
//!
//! The shell still aborts loudly on any deferred symbol; none of it is scaffolded
//! into looking present.
//!
//! ## Why `OPENSSL_INIT_*` lives in this module
//!
//! Those five symbols are `conf_lib.c` exports, and they were in **no phase's
//! family** until this module existed: Phase 3's `init.rs` family matches the
//! prefix `OPENSSL_init` (lower case), which does not match `OPENSSL_INIT_new`.
//! An export owned by no phase is invisible to every ledger, so it was silently
//! scaffolded. The family list in `forensics/tools/phase4_obligations.py` now
//! carries `OPENSSL_INIT_`, which puts them under this stratum's accounting.

pub mod api;
pub mod def;
pub mod init_settings;
pub mod lib;
pub mod modparse;
pub mod types;
