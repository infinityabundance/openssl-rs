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
//! * the data model (`conf_api.c`), the default method — parser, dumper, the two
//!   character-class tables (`conf_def.c`) — and the public accessor layer
//!   (`conf_lib.c`). **Not yet written.**
//! * the module registry (`CONF_modules_*`, `CONF_imodule_*`, `CONF_module_add`)
//!   and the automatic loader (`conf_sap.c`). **Not yet written**, and
//!   structurally blocked rather than merely unstarted: `CONF_modules_load`
//!   begins with `conf_diagnostics`, which reads and writes the `OSSL_LIB_CTX`
//!   diagnostics flag, and `OSSL_LIB_CTX` is Phase 6. The registry cannot be
//!   reconstructed faithfully before it exists.
//!
//! Every symbol in the stratum is therefore *unimplemented and recorded as such*
//! in `forensics/phase4-obligations.json`; none of it is scaffolded into looking
//! present, and the shell continues to abort loudly on any of them.
//!
//! ## Why `OPENSSL_INIT_*` lives in this module
//!
//! Those five symbols are `conf_lib.c` exports, and they were in **no phase's
//! family** until this module existed: Phase 3's `init.rs` family matches the
//! prefix `OPENSSL_init` (lower case), which does not match `OPENSSL_INIT_new`.
//! An export owned by no phase is invisible to every ledger, so it was silently
//! scaffolded. The family list in `forensics/tools/phase4_obligations.py` now
//! carries `OPENSSL_INIT_`, which puts them under this stratum's accounting.

pub mod init_settings;
