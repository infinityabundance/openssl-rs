//! Phase 10.1 — `providers/implementations/encode_decode/encode_key2blob.c`: the provider's
//! **EC point "blob" encoders**, one `OSSL_OP_ENCODER` table per key type whose public point has an
//! X9.62-style octet encoding, published by both the `default` and the `base` provider.
//!
//! This is one of the eleven row-publishing units of `docs/PHASE-10-SUBPHASES.md` §1a (`2 tables`,
//! `4 rows`), and the second to land after `encode_key2text.c`. Its closure is the one that unit
//! could not supply: `i2o_ECPublicKey` (`src/ec/asn1.rs`, landed with Phase 8.7) is the only
//! dependency, together with the two keymgmt pilfers `endecoder_common.rs` already carries.
//!
//! ## The row is a table over one shared engine
//!
//! Every table's dispatch is the authority's `MAKE_BLOB_ENCODER` expansion (`:121-172`): `newctx`
//! and `freectx` are the unit's two, shared by both; `does_selection` runs the unit's
//! `key2blob_check_selection` against `EVP_PKEY_PUBLIC_KEY`; `import_object`/`free_object` pilfer
//! the key type's own `ossl_*_keymgmt_functions`; and `encode` calls the shared `key2blob_encode`,
//! which writes `i2o_ECPublicKey`'s octets straight to the core BIO.
//!
//! ## The bytes are the contract
//!
//! `RT-CODEC` drives these rows through `OSSL_ENCODER_CTX_new_for_pkey(pkey, PUBLIC_KEY, "blob", …)`
//! and compares the transcript byte for byte against the authority's: the X9.62 uncompressed point
//! (`0x04 || X || Y`) that `i2o_ECPublicKey` produces. A transcription that round-trips the
//! keymgmt's own import is not this (`docs/PHASE-10-SUBPHASES.md` §3.1).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_int, c_uchar, c_void};
use core::ptr;

use crate::context::dispatch::{OsslDispatch, OSSL_DISPATCH_END};
use crate::ec::EcKey;
use crate::encoder_meth::{
    OSSL_FUNC_ENCODER_DOES_SELECTION, OSSL_FUNC_ENCODER_ENCODE, OSSL_FUNC_ENCODER_FREECTX,
    OSSL_FUNC_ENCODER_FREE_OBJECT, OSSL_FUNC_ENCODER_IMPORT_OBJECT, OSSL_FUNC_ENCODER_NEWCTX,
};
use crate::evp::pkey::{
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
};
use crate::params::OsslParam;
use crate::passphrase::OsslPassphraseCallback;
use crate::provider::endecoder_common::{ossl_prov_free_key, ossl_prov_import_key};
use crate::runtime::bio::core_bio::ossl_bio_new_from_core_bio;
use crate::runtime::bio::{BIO_free, BIO_write};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::mem::CRYPTO_free;

/// `OSSL_KEYMGMT_SELECT_ALL_PARAMETERS` — `include/openssl/evp.h:105`, the domain-or-other pair.
/// The crate keeps no shared constant for it, so it is spelled here from the two halves, as
/// `src/x509/x_pubkey.rs` does for the same three-way selection.
const OSSL_KEYMGMT_SELECT_ALL_PARAMETERS: c_int =
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;

/// `EVP_PKEY_PUBLIC_KEY` — `include/openssl/evp.h:110`, `KEY_PARAMETERS | SELECT_PUBLIC_KEY`. The
/// blob encoder's `does_selection` passes this as its `selection_mask`; `src/evp/pkey.rs` keeps its
/// copy module-private, so it is spelled here from the same three halves.
const EVP_PKEY_PUBLIC_KEY: c_int =
    OSSL_KEYMGMT_SELECT_ALL_PARAMETERS | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

/// `static int write_blob(void *provctx, OSSL_CORE_BIO *cout, void *data, int len)` —
/// `encode_key2blob.c:29-41`.
///
/// # Safety
/// `provctx` must be a live provider context; `cout` a live core BIO; `data` readable for `len`.
unsafe fn write_blob(
    _provctx: *mut c_void,
    cout: *mut c_void,
    data: *const c_void,
    len: c_int,
) -> c_int {
    // SAFETY: `cout` is the core BIO this encode owns.
    let out = unsafe { ossl_bio_new_from_core_bio(cout.cast()) };
    if out.is_null() {
        return 0;
    }
    // SAFETY: `out` is live and `data` is readable for `len`.
    let ret = unsafe { BIO_write(out, data, len) };
    // SAFETY: `out` is live and this call owns the reference the bridge took.
    unsafe { BIO_free(out) };
    ret
}

/// `static void *key2blob_newctx(void *provctx)` — `encode_key2blob.c:46-49`.
///
/// The authority returns `provctx` itself and allocates nothing, so `freectx` has nothing to free
/// and `encode` receives the provider context as `vctx`, which is what `write_blob` reads.
///
/// # Safety
/// The encoder `newctx` dispatch contract.
unsafe extern "C" fn key2blob_newctx(provctx: *mut c_void) -> *mut c_void {
    provctx
}

/// `static void key2blob_freectx(void *vctx)` — `encode_key2blob.c:51-53`. Empty, as the
/// authority's is.
///
/// # Safety
/// The encoder `freectx` dispatch contract.
unsafe extern "C" fn key2blob_freectx(_vctx: *mut c_void) {}

/// `static int key2blob_check_selection(int selection, int selection_mask)` —
/// `encode_key2blob.c:55-86`.
///
/// The selections are levels: the first of the three the caller asks for is answered by whether the
/// row's mask carries it, and an empty selection is accepted so the caller may guess.
fn key2blob_check_selection(selection: c_int, selection_mask: c_int) -> c_int {
    let checks = [
        OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
        OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
    ];

    if selection == 0 {
        return 1;
    }
    for check in checks {
        let check1 = (selection & check) != 0;
        let check2 = (selection_mask & check) != 0;
        if check1 {
            return c_int::from(check2);
        }
    }
    0
}

/// `static int key2blob_encode(void *vctx, const void *key, int selection, OSSL_CORE_BIO *cout)` —
/// `encode_key2blob.c:88-99`.
///
/// # Safety
/// `vctx` the provider context; `key` a live `EC_KEY *` from the `EC`/`SM2` keymgmt; `cout` the
/// core BIO the framework wrapped around the caller's output.
unsafe fn key2blob_encode(vctx: *mut c_void, key: *const c_void, cout: *mut c_void) -> c_int {
    let mut ok = 0;
    let mut pubkey: *mut c_uchar = ptr::null_mut();

    // SAFETY: `key` is the EC/SM2 keymgmt's own object and `pubkey` is this frame's out-parameter.
    let pubkey_len = unsafe { crate::ec::asn1::i2o_ECPublicKey(key.cast::<EcKey>(), &mut pubkey) };
    if pubkey_len > 0 && !pubkey.is_null() {
        // SAFETY: `pubkey` is a live buffer of `pubkey_len` bytes this call owns.
        ok = unsafe { write_blob(vctx, cout, pubkey.cast::<c_void>(), pubkey_len) };
    }
    // SAFETY: `pubkey` is NULL or the allocation `i2o_ECPublicKey` made.
    unsafe { CRYPTO_free(pubkey.cast::<c_void>(), ptr::null(), 0) };
    ok
}

/// One `MAKE_BLOB_ENCODER(impl, type, selection_name)` expansion (`encode_key2blob.c:121-172`),
/// for the two key types whose public point this unit encodes. `$keymgmt` is the key type's own
/// `ossl_*_keymgmt_functions` and `$raise` the site the `key_abstract != NULL` refusal records,
/// which is the macro's *invocation* line — the same attribution `make_text_encoder!` uses.
///
/// The generated names follow the macro's own substitution (`impl##2blob_*`), and the table symbol
/// is `ossl_##impl##_to_blob_encoder_functions[]` in the authority spelled as a Rust `static`.
macro_rules! make_blob_encoder {
    ($encode:ident, $import:ident, $free:ident, $does:ident, $table:ident, $keymgmt:path, $raise:path) => {
        /// `import_object` — `ossl_prov_import_key(<keymgmt>, ctx, selection, params)`.
        ///
        /// # Safety
        /// The encoder `import_object` dispatch contract.
        unsafe extern "C" fn $import(
            ctx: *mut c_void,
            selection: c_int,
            params: *const OsslParam,
        ) -> *mut c_void {
            // SAFETY: the table is the key type's own and the arguments are the caller's.
            unsafe { ossl_prov_import_key($keymgmt.as_ptr(), ctx, selection, params) }
        }

        /// `free_object` — `ossl_prov_free_key(<keymgmt>, key)`.
        ///
        /// # Safety
        /// The encoder `free_object` dispatch contract.
        unsafe extern "C" fn $free(key: *mut c_void) {
            // SAFETY: the table is the key type's own and `key` is its object.
            unsafe { ossl_prov_free_key($keymgmt.as_ptr(), key) }
        }

        /// `does_selection` — the unit's `key2blob_check_selection` against `EVP_PKEY_PUBLIC_KEY`.
        ///
        /// # Safety
        /// The encoder `does_selection` dispatch contract.
        unsafe extern "C" fn $does(_ctx: *mut c_void, selection: c_int) -> c_int {
            key2blob_check_selection(selection, EVP_PKEY_PUBLIC_KEY)
        }

        /// `encode` — the macro's generated body: refuse an abstract object, else run the shared
        /// engine.
        ///
        /// # Safety
        /// The encoder `encode` dispatch contract.
        unsafe extern "C" fn $encode(
            vctx: *mut c_void,
            cout: *mut c_void,
            key: *const c_void,
            key_abstract: *const OsslParam,
            _selection: c_int,
            _cb: Option<OsslPassphraseCallback>,
            _cbarg: *mut c_void,
        ) -> c_int {
            if !key_abstract.is_null() {
                // SAFETY: a compile-time-constant site.
                unsafe { raise_site(&$raise) };
                return 0;
            }
            // SAFETY: the encoder contract is the caller's; the engine is this unit's own.
            unsafe { key2blob_encode(vctx, key, cout) }
        }

        pub(crate) static $table: [OsslDispatch; 7] = [
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_NEWCTX,
                function: key2blob_newctx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_FREECTX,
                function: key2blob_freectx as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_DOES_SELECTION,
                function: $does as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_IMPORT_OBJECT,
                function: $import as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_FREE_OBJECT,
                function: $free as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_FUNC_ENCODER_ENCODE,
                function: $encode as *mut c_void,
            },
            OsslDispatch {
                function_id: OSSL_DISPATCH_END,
                function: ptr::null_mut(),
            },
        ];
    };
}

// The two expansions, in the authority's order (`:175`, `:177`). `SM2` reuses `ec`'s keymgmt, as
// the authority's `MAKE_BLOB_ENCODER(sm2, ec, PUBLIC_KEY)` does.
make_blob_encoder!(
    ec2blob_encode,
    ec2blob_import_object,
    ec2blob_free_object,
    ec2blob_does_selection,
    EC_TO_BLOB_FUNCTIONS,
    crate::provider::ec_kmgmt::EC_KEYMGMT_FUNCTIONS,
    err_sites::PROV_ENCODE_KEY2BLOB_175
);
make_blob_encoder!(
    sm22blob_encode,
    sm22blob_import_object,
    sm22blob_free_object,
    sm22blob_does_selection,
    SM2_TO_BLOB_FUNCTIONS,
    crate::provider::ec_kmgmt::SM2_KEYMGMT_FUNCTIONS,
    err_sites::PROV_ENCODE_KEY2BLOB_177
);

#[cfg(test)]
mod tests {
    use super::*;

    /// Both tables are the authority's six-slot shape — `newctx`, `freectx`, `does_selection`,
    /// `import_object`, `free_object`, `encode` — and the terminator.
    #[test]
    fn each_blob_table_is_the_authoritys_six_slot_shape() {
        for fns in [&EC_TO_BLOB_FUNCTIONS[..], &SM2_TO_BLOB_FUNCTIONS[..]] {
            let mut i = 0;
            let mut seen = [false; 6];
            let mut unexpected = 0;
            // SAFETY: each table is terminated and each read is within it.
            unsafe {
                while (*fns.as_ptr().add(i)).function_id != OSSL_DISPATCH_END {
                    match (*fns.as_ptr().add(i)).function_id {
                        OSSL_FUNC_ENCODER_NEWCTX => seen[0] = true,
                        OSSL_FUNC_ENCODER_FREECTX => seen[1] = true,
                        OSSL_FUNC_ENCODER_DOES_SELECTION => seen[2] = true,
                        OSSL_FUNC_ENCODER_IMPORT_OBJECT => seen[3] = true,
                        OSSL_FUNC_ENCODER_FREE_OBJECT => seen[4] = true,
                        OSSL_FUNC_ENCODER_ENCODE => seen[5] = true,
                        _ => unexpected += 1,
                    }
                    i += 1;
                }
            }
            assert_eq!(unexpected, 0, "a blob table carries an unexpected slot");
            assert!(seen.iter().all(|&s| s), "a blob table is missing a slot");
            assert_eq!(i, 6);
        }
    }

    /// The selection rule is the authority's: an empty selection is accepted, and the first of the
    /// three levels the caller asks for is answered by the mask. `EVP_PKEY_PUBLIC_KEY`'s mask
    /// carries the public-key and both parameter bits but not the private-key bit.
    #[test]
    fn the_selection_rule_is_the_authoritys() {
        assert_eq!(key2blob_check_selection(0, EVP_PKEY_PUBLIC_KEY), 1);
        assert_eq!(
            key2blob_check_selection(OSSL_KEYMGMT_SELECT_PUBLIC_KEY, EVP_PKEY_PUBLIC_KEY),
            1
        );
        assert_eq!(
            key2blob_check_selection(OSSL_KEYMGMT_SELECT_PRIVATE_KEY, EVP_PKEY_PUBLIC_KEY),
            0
        );
        assert_eq!(
            key2blob_check_selection(OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, EVP_PKEY_PUBLIC_KEY),
            1
        );
        assert_eq!(EVP_PKEY_PUBLIC_KEY, 0x86);
    }
}
