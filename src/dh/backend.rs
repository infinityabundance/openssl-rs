//! `crypto/dh/dh_backend.c` — the DH provider/legacy bridge, Phase 8.5.
//!
//! Two hundred and forty-three lines and **seven internals** plus two file-local helpers. The
//! unit's header carries the same sentence every backend does — "the intention with the 'backend'
//! source file is to offer backend functions for legacy backends (`EVP_PKEY_ASN1_METHOD` and
//! `EVP_PKEY_METHOD`) and provider implementations alike" — and its seven definitions split the
//! same two ways `crypto/rsa/rsa_backend.c`'s do:
//!
//! * the **parameter and key paths**: `ossl_dh_params_fromdata`, `ossl_dh_params_todata`,
//!   `ossl_dh_key_fromdata` and `ossl_dh_key_todata`, and the file-local wrapper that sits on the
//!   FFC layer;
//! * the **object paths**: `ossl_dh_is_foreign`, `ossl_dh_dup` and `ossl_dh_key_from_pkcs8`.
//!
//! ## The four things a reader should not tidy away
//!
//! * **`dh_ffc_params_fromdata` bumps `dirty_cnt` indirectly.** It calls
//!   [`crate::dh::group_params::ossl_dh_cache_named_group`], whose own comment says so, rather
//!   than touching the counter itself.
//! * **`ossl_dh_key_fromdata` treats an absent private key as "leave it".** `DH_set0_key`'s
//!   contract is "each slot is replaced only when the argument is non-NULL", so a
//!   public-half-only import answers 1 with the object's private key untouched — which is the
//!   opposite of [`oll_ffc_params_fromdata`]'s unconditional `set0` tail, whose own module doc
//!   records it.
//! * **`ossl_dh_params_todata` writes `priv_len` only when it is positive.** A `length` of 0 is
//!   the object's "unset" and is omitted rather than written as a zero, which is what lets a
//!   recipient distinguish it from a caller that asked for a zero-length key.
//! * **`ossl_dh_dup`'s two `== 0` tests are the authority's, not a transcription slip.** The
//!   public and private halves are copied when their bit is selected **and** the domain-parameters
//!   bit is *not* selected. With `OSSL_KEYMGMT_SELECT_ALL` — what a provider `dup` method passes —
//!   the bit *is* selected and the `if` body is short-circuited before `dh_bn_dup_check` runs, so
//!   the halves are **not** copied at all. The unit test below records that as the authority's
//!   behaviour rather than "fixing" it.
//!
//! ## What is deliberately **not** here
//!
//! `ossl_dh_key_from_pkcs8` is inside `#ifndef FIPS_MODULE` in the authority, which this profile
//! compiles, so it is transcribed. Nothing else in the file is guarded.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use crate::asn1::layout::Asn1String;
use crate::asn1::prim::ASN1_INTEGER_to_BN;
use crate::asn1::string::ASN1_STRING_clear_free;
use crate::asn1::x_algor::{X509Algor, X509_ALGOR_get0};
use crate::bn::bignum::{BN_clear_free, BN_dup, BN_free, BN_secure_new, BigNum};
use crate::dh::asn1::{d2i_DHparams, d2i_DHxparams};
use crate::dh::group_params::ossl_dh_cache_named_group;
use crate::dh::key::{DH_OpenSSL, DH_generate_key};
use crate::dh::object::{
    ossl_dh_get0_params, ossl_dh_get_method, ossl_dh_new_ex, DH_free, DH_get0_key, DH_get_length,
    DH_set0_key, DH_set_length,
};
use crate::dh::Dh;
use crate::evp::pkey::{OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY};
use crate::evp::pkey_ctx::OSSL_PKEY_PARAM_DH_PRIV_LEN;
use crate::ffc::backend::ossl_ffc_params_fromdata;
use crate::ffc::params::{ossl_ffc_params_copy, ossl_ffc_params_todata};
use crate::param_build_set::{ossl_param_build_set_bn, ossl_param_build_set_long};
use crate::params::build::OSSL_PARAM_BLD;
use crate::params::{OSSL_PARAM_get_BN, OSSL_PARAM_get_long, OSSL_PARAM_locate_const, OsslParam};
use crate::runtime::err::{err_sites, raise_site};
use crate::runtime::ex_data::{CRYPTO_dup_ex_data, CRYPTO_EX_INDEX_DH};
use crate::runtime::obj::{NID_dhKeyAgreement, NID_dhpublicnumber, OBJ_obj2nid};

// `OSSL_KEYMGMT_SELECT_*` — `include/openssl/core_dispatch.h:640-652`, restated per module as
// `src/ec/backend.rs` and `src/rsa/backend.rs` restate them.
const OSSL_KEYMGMT_SELECT_PRIVATE_KEY: c_int = 0x01;
const OSSL_KEYMGMT_SELECT_PUBLIC_KEY: c_int = 0x02;
const OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS: c_int = 0x04;

/// `static int dh_ffc_params_fromdata(DH *dh, const OSSL_PARAM params[])` —
/// `dh_backend.c:31-40`.
///
/// The FFC layer's importer with the one DH-specific addition the authority's comment names: a
/// successful import **refreshes the named-group cache**, which increments `dh->dirty_cnt`. That
/// is why the counter bump is not here — it is
/// [`crate::dh::group_params::ossl_dh_cache_named_group`]'s, and writing it in both places would be
/// two bumps for one import.
///
/// # Safety
/// `dh` is a live object; `params` is a key-terminated descriptor array.
unsafe fn dh_ffc_params_fromdata(dh: *mut Dh, params: *const OsslParam) -> c_int {
    // SAFETY: `dh` is live per the contract; `ossl_dh_get0_params` answers the embedded params.
    unsafe {
        let ffc = ossl_dh_get0_params(dh);

        let ret = ossl_ffc_params_fromdata(ffc, params);
        if ret != 0 {
            ossl_dh_cache_named_group(dh); /* This increments dh->dirty_cnt */
        }
        ret
    }
}

/// `int ossl_dh_params_fromdata(DH *dh, const OSSL_PARAM params[])` — `dh_backend.c:42-57`.
/// Internal, declared in `include/crypto/dh.h`.
///
/// The parameter half of the provider import: the FFC parameters, then the one DH-only scalar.
/// **`priv_len` is read as a `long` and stored through `DH_set_length`**, which is why the
/// parameter goes through `OSSL_PARAM_get_long` here and `_get_int` for the gindex/pcounter/h
/// family on the FFC layer — those are `int` fields and this one is a four-byte member the
/// accessor widens.
///
/// The two refusals share one `if`: a `priv_len` that is present but not a number, and one that is
/// a number `DH_set_length` refuses, both answer 0 with the FFC import already applied — the
/// authority does not roll back, and neither does this.
///
/// `#[allow(dead_code)]`'s reason: **the provider keymgmt's `import`/`import_from` are its
/// readers**; nothing in this crate calls it yet. The unit test drives it directly.
///
/// # Safety
/// `dh` is a live object; `params` is a key-terminated descriptor array.
#[allow(dead_code)] // read by the provider keymgmt's `import`/`import_from`
pub(crate) unsafe fn ossl_dh_params_fromdata(dh: *mut Dh, params: *const OsslParam) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if dh_ffc_params_fromdata(dh, params) == 0 {
            return 0;
        }

        let param_priv_len = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DH_PRIV_LEN);
        if !param_priv_len.is_null() {
            let mut priv_len: c_long = 0;
            if OSSL_PARAM_get_long(param_priv_len, &mut priv_len) == 0
                || DH_set_length(dh, priv_len) == 0
            {
                return 0;
            }
        }

        1
    }
}

/// `int ossl_dh_key_fromdata(DH *dh, const OSSL_PARAM params[], int include_private)` —
/// `dh_backend.c:59-88`. Internal.
///
/// **The private half is read only when `include_private` is set**, and that is the whole of the
/// selection logic: with `include_private == 0` the local `priv_key` stays NULL and
/// `DH_set0_key`'s "replace only when non-NULL" contract leaves the object's own private key
/// alone. A caller that re-imports the public half of a key it already holds therefore does not
/// lose the private half.
///
/// The refusal's two releases differ — `BN_clear_free` for the secret and `BN_free` for the public
/// value — exactly as `src/dh/object.rs` releases them.
///
/// `#[allow(dead_code)]`'s reason: as [`ossl_dh_params_fromdata`].
///
/// # Safety
/// `dh` is NULL or a live object; `params` is a key-terminated descriptor array. On success the
/// converted values' ownership passes to `dh`.
#[allow(dead_code)] // read by the provider keymgmt's `import`
pub(crate) unsafe fn ossl_dh_key_fromdata(
    dh: *mut Dh,
    params: *const OsslParam,
    include_private: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if dh.is_null() {
            return 0;
        }

        let mut priv_key: *mut BigNum = ptr::null_mut();
        let mut pub_key: *mut BigNum = ptr::null_mut();

        let param_priv_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        let param_pub_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);

        if include_private != 0
            && !param_priv_key.is_null()
            && OSSL_PARAM_get_BN(param_priv_key, &mut priv_key) == 0
        {
            return dh_key_fromdata_err(priv_key, pub_key);
        }

        if !param_pub_key.is_null() && OSSL_PARAM_get_BN(param_pub_key, &mut pub_key) == 0 {
            return dh_key_fromdata_err(priv_key, pub_key);
        }

        if DH_set0_key(dh, pub_key, priv_key) == 0 {
            return dh_key_fromdata_err(priv_key, pub_key);
        }

        1
    }
}

/// The authority's `err:` label of [`ossl_dh_key_fromdata`]: the secret cleared, the public value
/// freed.
///
/// # Safety
/// Each pointer is NULL or a `BIGNUM` this call still owns.
unsafe fn dh_key_fromdata_err(priv_key: *mut BigNum, pub_key: *mut BigNum) -> c_int {
    // SAFETY: each pointer is NULL or this call's own, per the contract.
    unsafe {
        BN_clear_free(priv_key);
        BN_free(pub_key);
    }
    0
}

/// `int ossl_dh_params_todata(DH *dh, OSSL_PARAM_BLD *bld, OSSL_PARAM params[])` —
/// `dh_backend.c:90-100`. Internal.
///
/// Two writes and no selection at all: the FFC parameters through
/// [`crate::ffc::params::ossl_ffc_params_todata`] and `priv_len` when it is positive. The `l > 0`
/// test is the one thing a reader should not fold into the setter: a `length` of 0 is the object's
/// "unset" and must be **omitted**, not written as a zero the recipient would read as a request.
///
/// `#[allow(dead_code)]`'s reason: as [`ossl_dh_params_fromdata`].
///
/// # Safety
/// `dh` is a live object; `bld` is NULL or a live builder; `params` is NULL or a key-terminated
/// descriptor array.
#[allow(dead_code)] // read by the provider keymgmt's `export`
pub(crate) unsafe fn ossl_dh_params_todata(
    dh: *mut Dh,
    bld: *mut OSSL_PARAM_BLD,
    params: *mut OsslParam,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        let l = DH_get_length(dh);

        if ossl_ffc_params_todata(ossl_dh_get0_params(dh), bld, params) == 0 {
            return 0;
        }
        if l > 0 && ossl_param_build_set_long(bld, params, OSSL_PKEY_PARAM_DH_PRIV_LEN, l) == 0 {
            return 0;
        }
        1
    }
}

/// `int ossl_dh_key_todata(DH *dh, OSSL_PARAM_BLD *bld, OSSL_PARAM params[], int
/// include_private)` — `dh_backend.c:102-120`. Internal.
///
/// The mirror of [`ossl_dh_key_fromdata`], and this one guards each half on its own NULL: `priv`
/// is written only when it exists **and** the caller asked for the private half, and `pub` when it
/// exists. A NULL object is a 0, which is the only refusal in the function.
///
/// `#[allow(dead_code)]`'s reason: as [`ossl_dh_params_fromdata`].
///
/// # Safety
/// `dh` is NULL or a live object; `bld` is NULL or a live builder; `params` is NULL or a
/// key-terminated descriptor array.
#[allow(dead_code)] // read by the provider keymgmt's `export`
pub(crate) unsafe fn ossl_dh_key_todata(
    dh: *mut Dh,
    bld: *mut OSSL_PARAM_BLD,
    params: *mut OsslParam,
    include_private: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        if dh.is_null() {
            return 0;
        }

        let mut priv_borrow: *const BigNum = ptr::null();
        let mut pub_borrow: *const BigNum = ptr::null();

        DH_get0_key(dh, &mut pub_borrow, &mut priv_borrow);
        if !priv_borrow.is_null()
            && include_private != 0
            && ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_PRIV_KEY, priv_borrow) == 0
        {
            return 0;
        }
        if !pub_borrow.is_null()
            && ossl_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_PUB_KEY, pub_borrow) == 0
        {
            return 0;
        }

        1
    }
}

/// `int ossl_dh_is_foreign(const DH *dh)` — `dh_backend.c:122-129`. Internal.
///
/// The same test [`crate::rsa::backend::ossl_rsa_is_foreign`] makes: an `ENGINE` or a method other
/// than `DH_OpenSSL()` means the object's internals are another implementation's, so a provider
/// must not copy them. `crypto/evp/p_lib.c`'s static `detect_foreign_key` calls this, with its RSA
/// and DSA twins, whenever a legacy key is attached to an `EVP_PKEY`.
///
/// `#[allow(dead_code)]`'s reason: **`detect_foreign_key` is its reader**, in Phase 7's module.
/// The `forensics/prerequisites.json` deferral row that named this function is **retired** by this
/// commit: the name is built now, and its own reason said the row existed to give
/// `EVP_PKEY_assign` a resolvable blocker.
///
/// # Safety
/// `dh` is a live object.
#[allow(dead_code)] // read by crypto/evp/p_lib.c's `detect_foreign_key`
pub(crate) unsafe fn ossl_dh_is_foreign(dh: *const Dh) -> c_int {
    // SAFETY: `dh` is live per the contract.
    unsafe {
        if !(*dh).engine.is_null() || !ptr::eq(ossl_dh_get_method(dh), DH_OpenSSL()) {
            return 1;
        }
    }
    0
}

/// `static ossl_inline int dh_bn_dup_check(BIGNUM **out, const BIGNUM *f)` —
/// `dh_backend.c:131-136`. The RSA twin's shape: a NULL source is a success with nothing written.
///
/// # Safety
/// `out` is writable; `f` is NULL or live.
unsafe fn dh_bn_dup_check(out: *mut *mut BigNum, f: *const BigNum) -> c_int {
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

/// `DH *ossl_dh_dup(const DH *dh, int selection)` — `dh_backend.c:138-177`. Internal.
///
/// The copier the provider keymgmt's `dup` method reaches. Compared with
/// [`crate::rsa::backend::ossl_rsa_dup`] it has one extra member — `length`, copied
/// *unconditionally* rather than under a selection bit — and one structural difference that is the
/// authority's: the public and private halves are guarded by
/// `(selection & DOMAIN_PARAMETERS) == 0 || !dh_bn_dup_check(...)`, so a selection that has the
/// domain-parameters bit set **short-circuits the copy**. `OSSL_KEYMGMT_SELECT_ALL` — what a
/// provider's `dup` method passes — has that bit set, so the two `dh_bn_dup_check` calls are
/// skipped and the copy carries the parameters but neither key half. That is what the authority
/// writes; the unit test records it rather than "fixing" it.
///
/// The `err:` label releases the half-built object, whose every pointer is NULL or owned by it.
///
/// `#[allow(dead_code)]`'s reason: **the provider keymgmt's `dup` is its reader**, and the
/// `EVP_PKEY`-level path that would reach it is 8.8's.
///
/// # Safety
/// `dh` is a live object; on success the answer is a new object the caller owns.
#[allow(dead_code)] // read by the provider keymgmt's `dup`
pub(crate) unsafe fn ossl_dh_dup(dh: *const Dh, selection: c_int) -> *mut Dh {
    // SAFETY: the caller's contract; every pointer below is checked before use.
    unsafe {
        /* Do not try to duplicate foreign DH keys */
        if ossl_dh_is_foreign(dh) != 0 {
            return ptr::null_mut();
        }

        let dupkey = ossl_dh_new_ex((*dh).libctx);
        if dupkey.is_null() {
            return ptr::null_mut();
        }

        let ok = 'build: {
            // The authority assigns a `long` to an `int32_t` member, which truncates; the cast is that
            // truncation written out.
            (*dupkey).length = DH_get_length(dh) as i32;
            if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0
                && ossl_ffc_params_copy(&mut (*dupkey).params, &(*dh).params) == 0
            {
                break 'build false;
            }

            (*dupkey).flags = (*dh).flags;

            if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
                && ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0
                    || dh_bn_dup_check(&mut (*dupkey).pub_key, (*dh).pub_key) == 0)
            {
                break 'build false;
            }

            if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
                && ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0
                    || dh_bn_dup_check(&mut (*dupkey).priv_key, (*dh).priv_key) == 0)
            {
                break 'build false;
            }

            if CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_DH, &mut (*dupkey).ex_data, &(*dh).ex_data) == 0 {
                break 'build false;
            }

            true
        };

        if !ok {
            DH_free(dupkey);
            return ptr::null_mut();
        }

        dupkey
    }
}

/// Which of the authority's three exit labels [`ossl_dh_key_from_pkcs8`] took, modelled as a
/// value because Rust has no `goto`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pkcs8Exit {
    /// `done:` — the object is the answer.
    Done,
    /// `decerr:` — raise `DH_R_DECODE_ERROR`, then fall through to `dherr:`'s release.
    DecodeError,
    /// `dherr:` — release without raising, because the failure already raised its own reason.
    KeyError,
}

/// `DH *ossl_dh_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf, OSSL_LIB_CTX *libctx, const char
/// *propq)` — `dh_backend.c:180-242`. Internal, inside `#ifndef FIPS_MODULE`.
///
/// The PKCS#8 decoder's DH half, and its shape is **two nested containers**: the private key is an
/// `ASN1_INTEGER` in the outer octet string, the domain parameters are a `DHparams` or `DHxparams`
/// sequence inside the algorithm identifier's parameters, and the identifier's own NID chooses
/// which of the two templates decodes them (`dhKeyAgreement` against `dhpublicnumber`).
///
/// **The public key is computed, not decoded.** After `DH_set0_key(dh, NULL, privkey_bn)` the
/// authority calls `DH_generate_key`, whose own body is `g^x mod p` when only the private half is
/// present — so a PKCS#8 file that carries no public value still produces one, and `dirty_cnt`
/// moves twice (once in `set0_key`, once in the generator).
///
/// The two error labels have different reaches and are **not** interchangeable: `decerr` raises
/// `DH_R_DECODE_ERROR` and falls through into `dherr`, which releases the object; `dherr` alone
/// raises nothing, because the failure it wraps — the `BN` conversion — already raised
/// `DH_R_BN_ERROR` immediately above it. The `done:` label releases the `ASN1_INTEGER` on every
/// path, including the one that consumed it.
///
/// `libctx` and `propq` are accepted and unused on this path — the two template decoders fetch
/// nothing — and are kept because the header's signature carries them and the EC twin uses its
/// own.
///
/// `#[allow(dead_code)]`'s reason: **8.8's `dh_ameth.c` `priv_decode` callback is its reader**.
///
/// # Safety
/// `p8inf` is a live `PKCS8_PRIV_KEY_INFO`; on success the answer is a new `DH` the caller owns.
#[allow(dead_code)] // read by 8.8's dh_ameth.c `priv_decode`
pub(crate) unsafe fn ossl_dh_key_from_pkcs8(
    p8inf: *const crate::asn1::p8_pkey::Pkcs8PrivKeyInfo,
    libctx: *mut c_void,
    propq: *const c_char,
) -> *mut Dh {
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

        // The authority's three labels, and its `done:` label always runs, so the block carries
        // the `ASN1_INTEGER` out with the exit tag. Every other local lives inside the block
        // because nothing after it reads one.
        let (exit, dh, privkey) = 'decode: {
            if ptype != crate::asn1::layout::V_ASN1_SEQUENCE {
                break 'decode (Pkcs8Exit::DecodeError, ptr::null_mut(), ptr::null_mut());
            }
            let privkey =
                crate::asn1::typ::d2i_ASN1_INTEGER(ptr::null_mut(), &mut p, pklen as c_long);
            if privkey.is_null() {
                break 'decode (Pkcs8Exit::DecodeError, ptr::null_mut(), privkey);
            }

            /* `pstr = pval`: the algorithm identifier's parameter read as a string. */
            let pstr = pval.cast::<Asn1String>();
            let mut pm: *const c_uchar = (*pstr).data.cast_const();
            let pmlen: c_int = (*pstr).length;
            let nid = OBJ_obj2nid((*palg).algorithm);
            let dh = if nid == NID_dhKeyAgreement {
                d2i_DHparams(ptr::null_mut(), &mut pm, pmlen as c_long)
            } else if nid == NID_dhpublicnumber {
                d2i_DHxparams(ptr::null_mut(), &mut pm, pmlen as c_long)
            } else {
                break 'decode (Pkcs8Exit::DecodeError, ptr::null_mut(), privkey);
            };
            if dh.is_null() {
                break 'decode (Pkcs8Exit::DecodeError, dh, privkey);
            }

            /* We have parameters now set private key */
            let privkey_bn = BN_secure_new();
            if privkey_bn.is_null() || ASN1_INTEGER_to_BN(privkey, privkey_bn).is_null() {
                raise_site(&err_sites::DH_BACKEND_222);
                BN_clear_free(privkey_bn);
                break 'decode (Pkcs8Exit::KeyError, dh, privkey);
            }
            if DH_set0_key(dh, ptr::null_mut(), privkey_bn) == 0 {
                break 'decode (Pkcs8Exit::KeyError, dh, privkey);
            }
            /* Calculate public key, increments dirty_cnt */
            if DH_generate_key(dh) == 0 {
                break 'decode (Pkcs8Exit::KeyError, dh, privkey);
            }

            (Pkcs8Exit::Done, dh, privkey)
        };

        if exit == Pkcs8Exit::DecodeError {
            raise_site(&err_sites::DH_BACKEND_235);
        }
        let dh = if exit != Pkcs8Exit::Done {
            // The authority's `dherr:` label, shared by `decerr:`'s fall-through.
            DH_free(dh);
            ptr::null_mut()
        } else {
            dh
        };

        // The authority's `done:` label, reached from every path.
        ASN1_STRING_clear_free(privkey);
        dh
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn::bignum::{BN_new, BN_num_bits, BN_set_word};
    use crate::dh::object::{DH_get0_pqg, DH_new, DH_set0_pqg};
    use crate::params::build::{OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_to_param};
    use crate::params::dup::OSSL_PARAM_free;
    use crate::params::{
        OSSL_PARAM_construct_BN, OSSL_PARAM_construct_end, OSSL_PARAM_construct_long,
        OSSL_PARAM_get_long, OSSL_PARAM_locate,
    };

    /// A live `DH`, freed on drop.
    struct OwnedDh(*mut Dh);

    impl OwnedDh {
        fn new() -> Self {
            // SAFETY: `DH_new` answers a fresh object or NULL; the assertion below covers the
            // second case.
            let dh = unsafe { DH_new() };
            assert!(!dh.is_null());
            OwnedDh(dh)
        }
    }

    impl Drop for OwnedDh {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a live object this test owns.
            unsafe { DH_free(self.0) };
        }
    }

    /// A one-byte modulus (twenty-three), a one-byte order and a one-byte generator. One byte
    /// because `OSSL_PARAM_UNSIGNED_INTEGER` is native-endian, so a multi-byte value would make
    /// this test a statement about the host's byte order rather than about the import.
    const P_BYTES: [u8; 1] = [0x17];
    const Q_BYTES: [u8; 1] = [0x05];
    const G_BYTES: [u8; 1] = [0x02];

    /// The parameter half round-trips, and `priv_len` is the one scalar that is not an FFC
    /// parameter: it is imported as a `long`, stored in the object's four-byte `length`, and
    /// written back **only when it is positive**.
    #[test]
    fn the_parameter_half_imports_the_ffc_numbers_and_priv_len() {
        let mut p_bytes = P_BYTES;
        let mut q_bytes = Q_BYTES;
        let mut g_bytes = G_BYTES;
        let mut priv_len: c_long = 200;
        // SAFETY: every buffer outlives the array.
        let params = unsafe {
            [
                OSSL_PARAM_construct_BN(
                    crate::evp::pkey_ctx::OSSL_PKEY_PARAM_FFC_P,
                    p_bytes.as_mut_ptr(),
                    p_bytes.len(),
                ),
                OSSL_PARAM_construct_BN(
                    crate::evp::pkey_ctx::OSSL_PKEY_PARAM_FFC_Q,
                    q_bytes.as_mut_ptr(),
                    q_bytes.len(),
                ),
                OSSL_PARAM_construct_BN(
                    crate::evp::pkey_ctx::OSSL_PKEY_PARAM_FFC_G,
                    g_bytes.as_mut_ptr(),
                    g_bytes.len(),
                ),
                OSSL_PARAM_construct_long(OSSL_PKEY_PARAM_DH_PRIV_LEN, &mut priv_len),
                OSSL_PARAM_construct_end(),
            ]
        };

        let dh = OwnedDh::new();
        // SAFETY: the object is live and the array is key-terminated.
        assert_eq!(unsafe { ossl_dh_params_fromdata(dh.0, params.as_ptr()) }, 1);
        // SAFETY: the object is live.
        unsafe {
            assert_eq!(DH_get_length(dh.0), 200);
            let mut p: *const BigNum = ptr::null();
            let mut q: *const BigNum = ptr::null();
            let mut g: *const BigNum = ptr::null();
            DH_get0_pqg(dh.0, &mut p, &mut q, &mut g);
            assert!(!p.is_null() && !q.is_null() && !g.is_null());
            assert_eq!(BN_num_bits(p), 5);
        }

        /* The writer, read back through the builder. */
        let bld = OSSL_PARAM_BLD_new();
        assert!(!bld.is_null());
        // SAFETY: every object here is live.
        unsafe {
            assert_eq!(ossl_dh_params_todata(dh.0, bld, ptr::null_mut()), 1);
            let out = OSSL_PARAM_BLD_to_param(bld);
            assert!(!out.is_null());
            let mut l: c_long = 0;
            assert_eq!(
                OSSL_PARAM_get_long(OSSL_PARAM_locate(out, OSSL_PKEY_PARAM_DH_PRIV_LEN), &mut l),
                1
            );
            assert_eq!(l, 200);
            assert!(!OSSL_PARAM_locate(out, crate::evp::pkey_ctx::OSSL_PKEY_PARAM_FFC_P).is_null());
            OSSL_PARAM_free(out);
            OSSL_PARAM_BLD_free(bld);
        }
    }

    /// `priv_len` of zero is the object's "unset" and is **omitted**, which is the `l > 0` guard
    /// made observable: the key is absent from the writer's output rather than present as a zero.
    #[test]
    fn a_zero_priv_len_is_omitted_rather_than_written() {
        let dh = OwnedDh::new();
        let bld = OSSL_PARAM_BLD_new();
        assert!(!bld.is_null());
        // SAFETY: every object here is live.
        unsafe {
            assert_eq!(ossl_dh_params_todata(dh.0, bld, ptr::null_mut()), 1);
            let out = OSSL_PARAM_BLD_to_param(bld);
            assert!(!out.is_null());
            assert!(OSSL_PARAM_locate(out, OSSL_PKEY_PARAM_DH_PRIV_LEN).is_null());
            OSSL_PARAM_free(out);
            OSSL_PARAM_BLD_free(bld);
        }
    }

    /// The key half, both directions, and the two guards that decide what travels: the private
    /// value is imported only with `include_private`, and written back only when it exists *and*
    /// the caller asked for it.
    #[test]
    fn the_key_half_imports_and_exports_each_side_under_its_own_flag() {
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

        let dh = OwnedDh::new();
        // SAFETY: the object is live and the array is key-terminated.
        assert_eq!(unsafe { ossl_dh_key_fromdata(dh.0, params.as_ptr(), 1) }, 1);
        // SAFETY: the object is live.
        unsafe {
            let mut pub_: *const BigNum = ptr::null();
            let mut priv_: *const BigNum = ptr::null();
            DH_get0_key(dh.0, &mut pub_, &mut priv_);
            assert!(!pub_.is_null() && !priv_.is_null());
        }

        /* The writer with the private half asked for. */
        let bld = OSSL_PARAM_BLD_new();
        // SAFETY: every object here is live.
        unsafe {
            assert_eq!(ossl_dh_key_todata(dh.0, bld, ptr::null_mut(), 1), 1);
            let out = OSSL_PARAM_BLD_to_param(bld);
            assert!(!OSSL_PARAM_locate(out, OSSL_PKEY_PARAM_PRIV_KEY).is_null());
            assert!(!OSSL_PARAM_locate(out, OSSL_PKEY_PARAM_PUB_KEY).is_null());
            OSSL_PARAM_free(out);
            OSSL_PARAM_BLD_free(bld);
        }

        /* ... and without it: the public half remains, the private one is absent. */
        let bld = OSSL_PARAM_BLD_new();
        // SAFETY: as above.
        unsafe {
            assert_eq!(ossl_dh_key_todata(dh.0, bld, ptr::null_mut(), 0), 1);
            let out = OSSL_PARAM_BLD_to_param(bld);
            assert!(OSSL_PARAM_locate(out, OSSL_PKEY_PARAM_PRIV_KEY).is_null());
            assert!(!OSSL_PARAM_locate(out, OSSL_PKEY_PARAM_PUB_KEY).is_null());
            OSSL_PARAM_free(out);
            OSSL_PARAM_BLD_free(bld);
        }
    }

    /// **`ossl_dh_dup`'s `== 0` domain-parameter tests, made observable.** `SELECT_ALL` copies the
    /// parameters and *skips* the two key halves; a selection that names the halves without the
    /// domain-parameters bit refuses the whole duplication. Both are asserted here rather than
    /// described, so a later "fix" to the guard would fail this test.
    #[test]
    fn the_duplicator_copies_the_halves_only_without_the_domain_parameter_bit() {
        let dh = OwnedDh::new();
        // SAFETY: the object is live; the two `BIGNUM`s are this test's own and their ownership
        // passes to the object on success.
        unsafe {
            let p = BN_new();
            let g = BN_new();
            assert!(!p.is_null() && !g.is_null());
            assert_eq!(BN_set_word(p, 23), 1);
            assert_eq!(BN_set_word(g, 2), 1);
            assert_eq!(DH_set0_pqg(dh.0, p, ptr::null_mut(), g), 1);
            assert_eq!(ossl_dh_is_foreign(dh.0), 0);
        }

        /* SELECT_ALL: the parameters travel, the halves do not. */
        // SAFETY: the object is live; the copy is this test's own.
        unsafe {
            let copy = ossl_dh_dup(
                dh.0,
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                    | OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                    | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
            );
            assert!(!copy.is_null());
            assert!((*copy).pub_key.is_null());
            assert!((*copy).priv_key.is_null());
            assert!(!(*copy).params.p.is_null());
            DH_free(copy);
        }

        /* The halves without the domain-parameters bit: the authority refuses outright. */
        // SAFETY: as above.
        unsafe {
            let copy = ossl_dh_dup(
                dh.0,
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            );
            assert!(copy.is_null());
        }
    }
}
