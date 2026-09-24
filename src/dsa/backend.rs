//! `crypto/dsa/dsa_backend.c` — the DSA provider/legacy bridge, Phase 8.6.
//!
//! One hundred and ninety-three lines and **four internals** plus one file-local helper. The unit
//! is [`crate::dsa::ossl`]'s and [`crate::dsa::object`]'s counterpart on the provider side — the
//! same sentence every backend carries — and its four definitions split the same two ways:
//!
//! * the **key paths**: `ossl_dsa_key_fromdata` and `ossl_dsa_dup`;
//! * the **object paths**: `ossl_dsa_is_foreign` and `ossl_dsa_key_from_pkcs8`.
//!
//! ## The three things a reader should not tidy away
//!
//! * **`ossl_dsa_key_fromdata`'s "neither half" early return.** A `params[]` carrying no
//!   `priv`/`pub` at all is a **success** with nothing written — the authority's comment says so —
//!   which is what makes the function safe to call with only a subset present.
//! * **`ossl_dsa_dup`'s two `== 0` domain-parameter tests are the authority's**, identical in
//!   shape to `crypto/dh/dh_backend.c`'s: the key halves are copied only when the
//!   domain-parameters bit is *not* selected, so `OSSL_KEYMGMT_SELECT_ALL` skips both. The unit
//!   test records it rather than correcting it.
//! * **`ossl_dsa_key_from_pkcs8` computes the public key by modular exponentiation** rather than
//!   reading it, and it does so with the **`BN_CTX_new` of no context** — the authority's
//!   `BN_CTX_new()` rather than the `_ex` form the RSA and DH twins use, because there is no
//!   `libctx` plumbing on this path. It also checks `privkey->type` for a **negative** integer,
//!   which the DH twin does not.
//!
//! ## What is deliberately **not** here
//!
//! `ossl_dsa_key_from_pkcs8` is inside `#ifndef FIPS_MODULE` in the authority, which this profile
//! compiles, so it is transcribed. Nothing else in the file is guarded.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::asn1::prim::ASN1_INTEGER_to_BN;
use crate::asn1::string::ASN1_STRING_clear_free;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_get0};
use crate::bn::arith::BN_mod_exp;
use crate::bn::bignum::{
    BN_clear_free, BN_dup, BN_free, BN_new, BN_secure_new, BN_set_flags, BigNum, BN_FLG_CONSTTIME,
};
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new};
use crate::dsa::asn1::d2i_DSAparams;
use crate::dsa::object::{
    ossl_dsa_new, DSA_free, DSA_get0_g, DSA_get0_p, DSA_get_method, DSA_set0_key,
};
use crate::dsa::ossl::DSA_OpenSSL;
use crate::dsa::Dsa;
use crate::evp::pkey::{OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY};
use crate::ffc::params::ossl_ffc_params_copy;
use crate::params::{OSSL_PARAM_get_BN, OSSL_PARAM_locate_const, OsslParam};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::ex_data::{CRYPTO_dup_ex_data, CRYPTO_EX_INDEX_DSA};

// `OSSL_KEYMGMT_SELECT_*` — `include/openssl/core_dispatch.h:640-652`, restated per module as
// `src/ec/backend.rs`, `src/rsa/backend.rs` and `src/dh/backend.rs` restate them.
const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;
const OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS: c_int = 0x04;

/// `int ossl_dsa_key_fromdata(DSA *dsa, const OSSL_PARAM params[], int include_private)` —
/// `dsa_backend.c:30-62`. Internal, declared in `include/crypto/dsa.h`.
///
/// The provider's import path into a `DSA`, and it is the **simplest of the three** backends'
/// importers: no derivation, no multiprime, no extra scalars, because a DSA key *is* its four
/// numbers and the domain parameters come from the object's embedded `FFC_PARAMS` rather than
/// from this function.
///
/// Two early answers are worth naming. A `params[]` with neither half is a **success** ("It's ok
/// if neither half is present", the authority's comment), which is the arm that lets a caller
/// import only the domain parameters through `ossl_dsa_ffc_params_fromdata` and then call this for
/// nothing. And the private half is located **only when `include_private` is set**, so a public
/// import cannot overwrite a secret even if the caller passes one.
///
/// `#[allow(dead_code)]`'s reason: **the provider keymgmt's `import`/`import_from` are its
/// readers**; nothing in this crate calls it yet. The unit test drives it directly.
///
/// # Safety
/// `dsa` is NULL or a live object; `params` is a key-terminated descriptor array. On success the
/// converted values' ownership passes to `dsa`.
#[allow(dead_code)] // read by the provider keymgmt's `import`/`import_from`
pub(crate) unsafe fn ossl_dsa_key_fromdata(
    dsa: *mut Dsa,
    params: *const OsslParam,
    include_private: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if dsa.is_null() {
            return 0;
        }

        let mut priv_key: *mut BigNum = ptr::null_mut();
        let mut pub_key: *mut BigNum = ptr::null_mut();

        let mut param_priv_key: *const OsslParam = ptr::null();
        if include_private != 0 {
            param_priv_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        }
        let param_pub_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);

        /* It's ok if neither half is present */
        if param_priv_key.is_null() && param_pub_key.is_null() {
            return 1;
        }

        if !param_pub_key.is_null() && OSSL_PARAM_get_BN(param_pub_key, &mut pub_key) == 0 {
            return dsa_key_fromdata_err(priv_key, pub_key);
        }
        if !param_priv_key.is_null() && OSSL_PARAM_get_BN(param_priv_key, &mut priv_key) == 0 {
            return dsa_key_fromdata_err(priv_key, pub_key);
        }

        if DSA_set0_key(dsa, pub_key, priv_key) == 0 {
            return dsa_key_fromdata_err(priv_key, pub_key);
        }

        1
    }
}

/// The authority's `err:` label of [`ossl_dsa_key_fromdata`].
///
/// # Safety
/// Each pointer is NULL or a `BIGNUM` this call still owns.
unsafe fn dsa_key_fromdata_err(priv_key: *mut BigNum, pub_key: *mut BigNum) -> c_int {
    // SAFETY: each pointer is NULL or this call's own, per the contract.
    unsafe {
        BN_clear_free(priv_key);
        BN_free(pub_key);
    }
    0
}

/// `int ossl_dsa_is_foreign(const DSA *dsa)` — `dsa_backend.c:64-71`. Internal.
///
/// The DSA member of the `detect_foreign_key` trio, and the one whose cast is visible in the
/// authority: `DSA_get_method((DSA *)dsa)` discards the `const` because the accessor takes a
/// mutable pointer on both sides. That is transcribed rather than hidden.
///
/// `#[allow(dead_code)]`'s reason: **`crypto/evp/p_lib.c`'s static `detect_foreign_key` is its
/// reader**, in Phase 7's module.
///
/// # Safety
/// `dsa` is a live object.
#[allow(dead_code)] // read by crypto/evp/p_lib.c's `detect_foreign_key`
pub(crate) unsafe fn ossl_dsa_is_foreign(dsa: *const Dsa) -> c_int {
    // SAFETY: `dsa` is live per the contract; the cast only discards `const`, which is what the
    // authority's own `(DSA *)dsa` does.
    unsafe {
        if !(*dsa).engine.is_null() || !ptr::eq(DSA_get_method(dsa.cast_mut()), DSA_OpenSSL()) {
            return 1;
        }
    }
    0
}

/// `static ossl_inline int dsa_bn_dup_check(BIGNUM **out, const BIGNUM *f)` —
/// `dsa_backend.c:73-78`. The RSA and DH twins' shape: a NULL source is a success with nothing
/// written.
///
/// # Safety
/// `out` is writable; `f` is NULL or live.
unsafe fn dsa_bn_dup_check(out: *mut *mut BigNum, f: *const BigNum) -> c_int {
    if !f.is_null() {
        // SAFETY: `f` is live and `out` is the caller's writable slot.
        unsafe {
            *out = BN_dup(f);
            if (*out).is_null() {
                return 0;
            }
        }
    }
    1
}

/// `DSA *ossl_dsa_dup(const DSA *dsa, int selection)` — `dsa_backend.c:80-118`. Internal.
///
/// The copier the provider keymgmt's `dup` method reaches, and it is `ossl_dh_dup`'s twin down to
/// the two `== 0` tests: the public and private halves are copied only when their bit is selected
/// **and** the domain-parameters bit is *not* selected, so `OSSL_KEYMGMT_SELECT_ALL` skips both.
/// That is the authority's text in all three of `rsa_backend.c`'s siblings (RSA's is the odd one
/// out because it has no domain parameters to select).
///
/// `#[allow(dead_code)]`'s reason: **the provider keymgmt's `dup` is its reader**.
///
/// # Safety
/// `dsa` is a live object; on success the answer is a new object the caller owns.
#[allow(dead_code)] // read by the provider keymgmt's `dup`
pub(crate) unsafe fn ossl_dsa_dup(dsa: *const Dsa, selection: c_int) -> *mut Dsa {
    // SAFETY: the caller's contract; every pointer below is checked before use.
    unsafe {
        /* Do not try to duplicate foreign DSA keys */
        if ossl_dsa_is_foreign(dsa) != 0 {
            return ptr::null_mut();
        }

        let dupkey = ossl_dsa_new((*dsa).libctx);
        if dupkey.is_null() {
            return ptr::null_mut();
        }

        let ok = 'build: {
            if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0
                && ossl_ffc_params_copy(&mut (*dupkey).params, &(*dsa).params) == 0
            {
                break 'build false;
            }

            (*dupkey).flags = (*dsa).flags;

            if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
                && ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0
                    || dsa_bn_dup_check(&mut (*dupkey).pub_key, (*dsa).pub_key) == 0)
            {
                break 'build false;
            }

            if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
                && ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0
                    || dsa_bn_dup_check(&mut (*dupkey).priv_key, (*dsa).priv_key) == 0)
            {
                break 'build false;
            }

            if CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_DSA, &mut (*dupkey).ex_data, &(*dsa).ex_data) == 0
            {
                break 'build false;
            }

            true
        };

        if !ok {
            DSA_free(dupkey);
            return ptr::null_mut();
        }

        dupkey
    }
}

/// Which of the authority's three exit labels [`ossl_dsa_key_from_pkcs8`] took.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pkcs8Exit {
    /// `done:` — the object is the answer.
    Done,
    /// `decerr:` — raise `DSA_R_DECODE_ERROR`, then fall through to `dsaerr:`'s release.
    DecodeError,
    /// `dsaerr:` — release without a raise of its own, because each failure raised its reason at
    /// the site.
    KeyError,
}

/// `DSA *ossl_dsa_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf, OSSL_LIB_CTX *libctx, const char
/// *propq)` — `dsa_backend.c:120-192`. Internal, inside `#ifndef FIPS_MODULE`.
///
/// The PKCS#8 decoder's DSA half. Its container shape is the DH twin's — an `ASN1_INTEGER` in the
/// outer octet string, the domain parameters inside the identifier's parameters — with three
/// differences that are all authority-visible:
///
/// * **there is no NID switch.** `d2i_DSAparams` is the only template, because DSA has one
///   parameter spelling where DH has two;
/// * **the identifier's type and the integer's sign are checked together**: `privkey->type ==
///   V_ASN1_NEG_INTEGER || ptype != V_ASN1_SEQUENCE` is one `if`, so a negative private key is
///   refused exactly as an absent parameter sequence is;
/// * **the public key is `g^x mod p`**, computed with `BN_mod_exp` over a `BN_CTX_new()` and with
///   the private value marked `BN_FLG_CONSTTIME` first, which is the constant-time contract
///   `crypto/dsa/dsa_ossl.c`'s own `dsa_mod_exp` keeps.
///
/// The `dsaerr:` label releases the two `BIGNUM`s with `BN_free` — **not** `BN_clear_free`, even
/// for the private one — and then the object. That is the authority's text, and it is recorded
/// here because it reads like a mistake: the same file's `ossl_dsa_key_fromdata` uses
/// `BN_clear_free` for the secret.
///
/// `#[allow(dead_code)]`'s reason: **8.8's `dsa_ameth.c` `priv_decode` callback is its reader**.
///
/// # Safety
/// `p8inf` is a live `PKCS8_PRIV_KEY_INFO`; on success the answer is a new `DSA` the caller owns.
#[allow(dead_code)] // read by 8.8's dsa_ameth.c `priv_decode`
pub(crate) unsafe fn ossl_dsa_key_from_pkcs8(
    p8inf: *const crate::asn1::p8_pkey::Pkcs8PrivKeyInfo,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut Dsa {
    let _ = (libctx, propq);

    // SAFETY: the caller's contract.
    unsafe {
        let mut p: *const c_uchar = ptr::null();
        let mut pklen: c_int = 0;
        let mut ptype: c_int = 0;
        let mut pval: *const c_void = ptr::null();
        let mut palg: *const X509Algor = ptr::null();

        if crate::asn1::p8_pkey::PKCS8_pkey_get0(
            ptr::null_mut(),
            &mut p,
            &mut pklen,
            &mut palg,
            p8inf,
        ) == 0
        {
            return ptr::null_mut();
        }
        X509_ALGOR_get0(ptr::null_mut(), &mut ptype, &mut pval, palg);

        let (exit, dsa, dsa_pubkey, dsa_privkey, ctx, privkey) = 'body: {
            let privkey =
                crate::asn1::typ::d2i_ASN1_INTEGER(ptr::null_mut(), &mut p, pklen as c_long);
            if privkey.is_null() {
                break 'body (
                    Pkcs8Exit::DecodeError,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    privkey,
                );
            }
            if (*privkey).type_ == crate::asn1::layout::V_ASN1_NEG_INTEGER
                || ptype != crate::asn1::layout::V_ASN1_SEQUENCE
            {
                break 'body (
                    Pkcs8Exit::DecodeError,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    privkey,
                );
            }

            /* `pstr = pval`: the algorithm identifier's parameter read as a string. */
            let pstr = pval.cast::<Asn1String>();
            let mut pm: *const c_uchar = (*pstr).data.cast_const();
            let pmlen: c_int = (*pstr).length;
            let dsa = d2i_DSAparams(ptr::null_mut(), &mut pm, pmlen as c_long);
            if dsa.is_null() {
                break 'body (
                    Pkcs8Exit::DecodeError,
                    dsa,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    privkey,
                );
            }

            /* We have parameters now set private key */
            let dsa_privkey = BN_secure_new();
            if dsa_privkey.is_null() || ASN1_INTEGER_to_BN(privkey, dsa_privkey).is_null() {
                raise_site(&err_sites::DSA_BACKEND_154);
                break 'body (
                    Pkcs8Exit::KeyError,
                    dsa,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    privkey,
                );
            }
            /* Calculate public key */
            let dsa_pubkey = BN_new();
            if dsa_pubkey.is_null() {
                raise_site(&err_sites::DSA_BACKEND_159);
                break 'body (
                    Pkcs8Exit::KeyError,
                    dsa,
                    ptr::null_mut(),
                    dsa_privkey,
                    ptr::null_mut(),
                    privkey,
                );
            }
            let ctx = BN_CTX_new();
            if ctx.is_null() {
                raise_site(&err_sites::DSA_BACKEND_163);
                break 'body (
                    Pkcs8Exit::KeyError,
                    dsa,
                    dsa_pubkey,
                    dsa_privkey,
                    ptr::null_mut(),
                    privkey,
                );
            }

            let dsa_p = DSA_get0_p(dsa);
            let dsa_g = DSA_get0_g(dsa);
            BN_set_flags(dsa_privkey, BN_FLG_CONSTTIME);
            if BN_mod_exp(dsa_pubkey, dsa_g, dsa_privkey, dsa_p, ctx) == 0 {
                raise_site(&err_sites::DSA_BACKEND_171);
                break 'body (
                    Pkcs8Exit::KeyError,
                    dsa,
                    dsa_pubkey,
                    dsa_privkey,
                    ctx,
                    privkey,
                );
            }
            if DSA_set0_key(dsa, dsa_pubkey, dsa_privkey) == 0 {
                raise_site(&err_sites::DSA_BACKEND_175);
                break 'body (
                    Pkcs8Exit::KeyError,
                    dsa,
                    dsa_pubkey,
                    dsa_privkey,
                    ctx,
                    privkey,
                );
            }

            (Pkcs8Exit::Done, dsa, dsa_pubkey, dsa_privkey, ctx, privkey)
        };

        if exit == Pkcs8Exit::DecodeError {
            raise_site(&err_sites::DSA_BACKEND_182);
        }
        let dsa = if exit != Pkcs8Exit::Done {
            // The authority's `dsaerr:` label, shared by `decerr:`'s fall-through. Both releases
            // are `BN_free`, including the private value's -- see this function's own note.
            BN_free(dsa_privkey);
            BN_free(dsa_pubkey);
            DSA_free(dsa);
            ptr::null_mut()
        } else {
            dsa
        };

        // The authority's `done:` label, reached from every path.
        BN_CTX_free(ctx);
        ASN1_STRING_clear_free(privkey);
        dsa
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::bignum::{BN_num_bits, BN_set_word};
    use crate::dsa::object::{DSA_get0_key, DSA_new};
    use crate::params::{OSSL_PARAM_construct_BN, OSSL_PARAM_construct_end};

    /// A live `DSA`, freed on drop.
    struct OwnedDsa(*mut Dsa);

    impl OwnedDsa {
        fn new() -> Self {
            // SAFETY: `DSA_new` answers a fresh object or NULL; the assertion covers the second
            // case.
            let dsa = unsafe { DSA_new() };
            assert!(!dsa.is_null());
            OwnedDsa(dsa)
        }
    }

    impl Drop for OwnedDsa {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a live object this test owns.
            unsafe { DSA_free(self.0) };
        }
    }

    /// **The "neither half" early return is a success**, which is the one arm of this importer
    /// that is not a conversion: an empty descriptor array answers 1 with nothing written, so a
    /// caller can use the function to import only what is present.
    #[test]
    fn an_array_with_neither_half_imports_nothing_and_succeeds() {
        let params = [OSSL_PARAM_construct_end()];
        let dsa = OwnedDsa::new();
        // SAFETY: the object is live and the array is key-terminated.
        assert_eq!(
            // SAFETY: as above.
            unsafe { ossl_dsa_key_fromdata(dsa.0, params.as_ptr(), 1) },
            1
        );
        // SAFETY: the object is live.
        unsafe {
            let mut pub_: *const BigNum = ptr::null();
            let mut priv_: *const BigNum = ptr::null();
            DSA_get0_key(dsa.0, &mut pub_, &mut priv_);
            assert!(pub_.is_null() && priv_.is_null());
        }
    }

    /// Both halves import under `include_private`, and the private one is **not** read when the
    /// flag is clear — the arm that keeps a public re-import from overwriting a secret.
    #[test]
    fn the_private_half_travels_only_with_include_private() {
        let mut pub_buf = [5u8];
        let mut priv_buf = [7u8];
        // SAFETY: every buffer outlives the array.
        let params = unsafe {
            [
                OSSL_PARAM_construct_BN(
                    OSSL_PKEY_PARAM_PRIV_KEY,
                    priv_buf.as_mut_ptr(),
                    priv_buf.len(),
                ),
                OSSL_PARAM_construct_BN(
                    OSSL_PKEY_PARAM_PUB_KEY,
                    pub_buf.as_mut_ptr(),
                    pub_buf.len(),
                ),
                OSSL_PARAM_construct_end(),
            ]
        };

        let dsa = OwnedDsa::new();
        // SAFETY: the object is live and the array is key-terminated.
        assert_eq!(
            // SAFETY: as above.
            unsafe { ossl_dsa_key_fromdata(dsa.0, params.as_ptr(), 1) },
            1
        );
        // SAFETY: the object is live.
        unsafe {
            assert_eq!(BN_num_bits((*dsa.0).pub_key), 3);
            assert_eq!(BN_num_bits((*dsa.0).priv_key), 3);
        }

        /* A second object, with the flag clear: the public half lands, the private one does not. */
        let dsa = OwnedDsa::new();
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe { ossl_dsa_key_fromdata(dsa.0, params.as_ptr(), 0) },
            1
        );
        // SAFETY: the object is live.
        unsafe {
            assert!(!(*dsa.0).pub_key.is_null());
            assert!((*dsa.0).priv_key.is_null());
        }
    }

    /// `ossl_dsa_dup`'s two `== 0` domain-parameter tests, the same pair `dh::backend`'s own test
    /// records: `SELECT_ALL` copies the parameters and skips the halves; the halves without the
    /// domain-parameters bit are refused outright.
    #[test]
    fn the_duplicator_copies_the_halves_only_without_the_domain_parameter_bit() {
        let dsa = OwnedDsa::new();
        // SAFETY: the object is live; the two `BIGNUM`s are this test's own and their ownership
        // passes to the object on success.
        unsafe {
            let p = BN_new();
            let q = BN_new();
            let g = BN_new();
            assert!(!p.is_null() && !q.is_null() && !g.is_null());
            assert_eq!(BN_set_word(p, 23), 1);
            assert_eq!(BN_set_word(q, 11), 1);
            assert_eq!(BN_set_word(g, 2), 1);
            /* `DSA_set0_pqg` refuses when a slot is empty on both sides, so all three are set. */
            assert_eq!(crate::dsa::object::DSA_set0_pqg(dsa.0, p, q, g), 1);
            assert_eq!(ossl_dsa_is_foreign(dsa.0), 0);
        }

        // SAFETY: the object is live; the copy is this test's own.
        unsafe {
            let copy = ossl_dsa_dup(
                dsa.0,
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                    | OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                    | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
            );
            assert!(!copy.is_null());
            assert!((*copy).pub_key.is_null());
            assert!((*copy).priv_key.is_null());
            assert!(!(*copy).params.p.is_null());
            DSA_free(copy);
        }

        // SAFETY: as above.
        unsafe {
            let copy = ossl_dsa_dup(
                dsa.0,
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            );
            assert!(copy.is_null());
        }
    }
}
