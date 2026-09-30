//! Phase 7.4 — `crypto/evp/evp_cnf.c`: the `alg_section` configuration module.
//!
//! `crypto/evp/evp_cnf.c` is 60 lines and publishes one export, `EVP_add_alg_module`, which
//! registers the process's configuration handler `alg_module_init` under the `alg_section`
//! name. It was one of Phase 7's reasoned deferrals: `alg_module_init`'s `fips_mode` arm reads
//! the section value through `X509V3_get_value_bool` (`crypto/x509/v3_utl.c:266`), which was
//! `x509v3.h`'s and Phase 11's until the 10.14.3 slice landed it. With that name built the
//! pair's closure is complete, so the deferred pair is transcribed rather than withheld a third
//! time (D451's rule): the `forensics/tools/phase7_obligations.py` blocked-handoff row and the
//! `forensics/prerequisites.json` unit record are **retired rather than left stale**, the rule
//! D453 and D454 used for `ASN1_item_sign_ex` and `ASN1_item_verify_ex`.
//!
//! ## The three option arms, and the two `ERR_raise`s each of them shares
//!
//! The handler walks the section's `CONF_VALUE` pairs. `fips_mode` reads a boolean through the
//! just-landed `X509V3_get_value_bool` and enables FIPS properties with `loadconfig = 0`;
//! `default_properties` sets a property string with `loadconfig = 0, mirrored = 0`; and anything
//! else is `ERR_raise_data(EVP_R_UNKNOWN_OPTION, "name=%s, value=%s", …)`. Both of the first
//! two arms raise `EVP_R_SET_DEFAULT_PROPERTY_FAILURE` when their setter answers zero, and a
//! section that does not resolve at all is `EVP_R_ERROR_LOADING_SECTION`. Every coordinate is
//! the generated `EVP_CNF_*` constant (`crypto/evp/evp_cnf.c` has been in
//! `gen_err_raise_sites.py`'s covered set since Phase 7).
//!
//! ## The two `OSSL_TRACE` calls
//!
//! `OSSL_TRACE2(CONF, …)` (`:27`) and `OSSL_TRACE(CONF, …)` (`:67`) are compiled out of the
//! admitted build, which configures `no-trace`; they are omitted here with this sentence as
//! their record, the convention `src/evp/fetch.rs`, `src/runtime/confmod/mod.rs` and the rest
//! of the crate use (`src/runtime/trace.rs` is the runtime surface they would call).
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int};

use crate::evp::fetch::{evp_default_properties_enable_fips_int, evp_set_default_properties_int};
use crate::runtime::bio::sys::strcmp;
use crate::runtime::conf::lib::{NCONF_get0_libctx, NCONF_get_section};
use crate::runtime::conf::types::{Conf, ConfValue};
use crate::runtime::confmod::{CONF_imodule_get_value, CONF_module_add, ConfImodule};
use crate::runtime::err::{err_sites, raise_site, raise_site_data};
use crate::runtime::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::v3_utl::X509V3_get_value_bool;

/// `static int alg_module_init(CONF_IMODULE *md, const CONF *cnf)` —
/// `crypto/evp/evp_cnf.c:24-64`.
///
/// # Safety
///
/// `md` must be a live module initialisation and `cnf` the live configuration it belongs to.
unsafe extern "C" fn alg_module_init(md: *mut ConfImodule, cnf: *const Conf) -> c_int {
    // SAFETY: `md` is live per the contract.
    let oid_section = unsafe { CONF_imodule_get_value(md) };
    // SAFETY: `cnf` is live and `oid_section` is NUL-terminated or NULL.
    let sktmp = unsafe { NCONF_get_section(cnf, oid_section) };
    if sktmp.is_null() {
        // SAFETY: the site is a compile-time constant.
        unsafe { raise_site(&err_sites::EVP_CNF_33) };
        return 0;
    }
    // SAFETY: `sktmp` is a live stack of `CONF_VALUE` pointers per the contract.
    let n = unsafe { OPENSSL_sk_num(sktmp) };
    let mut i = 0;
    while i < n {
        // SAFETY: `0 <= i < n` and every element is a `CONF_VALUE`.
        let oval = unsafe { OPENSSL_sk_value(sktmp, i) }.cast::<ConfValue>();
        // SAFETY: `oval` is a live `CONF_VALUE`; a section entry's `name` is NUL-terminated
        // (only a section itself has a NULL `name`, and sections are not elements of a
        // section's value stack).
        let name = unsafe { (*oval).name };
        // SAFETY: `name` is NUL-terminated per the note above; the literal is static.
        if unsafe { strcmp(name, c"fips_mode".as_ptr()) } == 0 {
            let mut m: c_int = 0;
            // SAFETY: `oval` is live and `m` is a writable slot.
            if unsafe { X509V3_get_value_bool(oval, &mut m) } == 0 {
                return 0;
            }
            // SAFETY: `cnf` is live per the contract.
            let libctx = unsafe { NCONF_get0_libctx(cnf) };
            // SAFETY: `libctx` is NULL or live; the two ints are the authority's literals.
            if unsafe { evp_default_properties_enable_fips_int(libctx, c_int::from(m > 0), 0) } == 0
            {
                // SAFETY: the site is a compile-time constant.
                unsafe { raise_site(&err_sites::EVP_CNF_51) };
                return 0;
            }
        } else {
            // SAFETY: `name` is NUL-terminated per the note above; the literal is static.
            if unsafe { strcmp(name, c"default_properties".as_ptr()) } == 0 {
                // SAFETY: `cnf` is live per the contract.
                let libctx = unsafe { NCONF_get0_libctx(cnf) };
                // SAFETY: `oval` is live; `libctx` is NULL or live; `(*oval).value` is
                // NUL-terminated or NULL, and the two trailing ints are the authority's
                // literals.
                if unsafe { evp_set_default_properties_int(libctx, (*oval).value, 0, 0) } == 0 {
                    // SAFETY: the site is a compile-time constant.
                    unsafe { raise_site(&err_sites::EVP_CNF_57) };
                    return 0;
                }
            } else {
                // `ERR_raise_data(EVP_R_UNKNOWN_OPTION, "name=%s, value=%s", …)`, formatted by
                // `BIO_vsnprintf` (D53), whose `%s` of NULL is the literal `<NULL>`.
                let mut buf: Vec<u8> = b"name=".to_vec();
                // SAFETY: `oval` is a live `CONF_VALUE`.
                unsafe { push_cstr_or_null(&mut buf, (*oval).name) };
                buf.extend_from_slice(b", value=");
                // SAFETY: as above.
                unsafe { push_cstr_or_null(&mut buf, (*oval).value) };
                buf.push(0);
                // SAFETY: the site is a compile-time constant and `buf` is NUL-terminated.
                unsafe { raise_site_data(&err_sites::EVP_CNF_61, buf.as_ptr().cast::<c_char>()) };
                return 0;
            }
        }
        i += 1;
    }
    1
}

/// Appends `p`'s bytes, or the literal `<NULL>` when `p` is NULL — `crypto/err/err.c:855-856`,
/// the same convention `v3_utl.c`'s `X509V3_conf_add_error_name_value` uses.
///
/// # Safety
///
/// `p` must be NULL or NUL-terminated.
unsafe fn push_cstr_or_null(buf: &mut Vec<u8>, p: *const c_char) {
    if p.is_null() {
        buf.extend_from_slice(b"<NULL>");
    } else {
        // SAFETY: `p` is NUL-terminated per the contract.
        buf.extend_from_slice(unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes());
    }
}

/// `void EVP_add_alg_module(void)` — `crypto/evp/evp_cnf.c:66-70`.
///
/// Registers `alg_module_init` under `alg_section`; the return value is discarded by the
/// authority and by this transcription (the authority's own body discards it too).
///
/// # Safety
///
/// The caller must accept that this writes the process-global configuration-module list; the
/// authority's own callers take the module lock's equivalent by construction (it runs during
/// `OPENSSL_init_crypto`).
#[no_mangle]
pub unsafe extern "C" fn EVP_add_alg_module() {
    // SAFETY: `alg_module_add`'s contract is `alg_module_init`'s; the module is static (no DSO).
    unsafe { CONF_module_add(c"alg_section".as_ptr(), Some(alg_module_init), None) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pair's closure is now complete, so the export can be reached. The registration is a
    /// process-global write, so the arm takes the global-state lock and unregisters nothing —
    /// `CONF_module_add` is idempotent for a repeated name (`links` is bumped).
    #[test]
    fn the_alg_module_registers_under_its_own_name() {
        let _guard = crate::test_support::lock_global_state();
        // SAFETY: the pair's contract is the authority's; the module list is process-global, so
        // the lock above is the one the authority's own comment asks for.
        unsafe { EVP_add_alg_module() };
    }
}
