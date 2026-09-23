//! Phase 8.10 — `providers/implementations/kem/ec_kem.c.in`: the `EC` DHKEM row's prerequisites.
//!
//! Seven hundred and sixty-odd source lines, and this module carries **one function of it**:
//! `ossl_ec_dhkem_derive_private` (`ec_kem.c.in:387-452`). The rest of the unit — the `PROV_EC_CTX`
//! object, the four init/encap/decap slots, the generated decoder and the
//! `ossl_ec_asym_kem_functions` table — is **not transcribed**, and the unit's one row
//! (`EC` under `OSSL_OP_KEM`) therefore stays `unimplemented`.
//!
//! ## Why the one function lands without its unit, and why that is not a partial transcription
//!
//! D327's whole-unit rule is about what a pass **claims**: a unit is transcribed whole or it is
//! withheld with a reason, and the census counts its rows accordingly. Here the claim is narrower
//! and is exactly what `ec_kmgmt.c` needs: `crypto/ec/ec_key.c`'s `ossl_ec_generate_key_dhkem`
//! (`:357-386`) — which `ec_kmgmt.c`'s `ec_gen` reaches whenever the caller sets
//! `OSSL_PKEY_PARAM_DHKEM_IKM` — is a one-line call to **this** function, declared in `prov/ecx.h`
//! and defined in the KEM unit. D387 landed `ossl_dh_gen_type_name2id` out of `crypto/evp/dh_support.c`
//! for the same shape of reason; the difference here is only that the defining file happens to be a
//! provider-row unit, so the row stays open and is named as such rather than the unit being claimed.
//!
//! The function is `#[no_mangle]` because the authority's definition is not `static` and both
//! `crypto/ec/ec_key.c` and this unit's own `derivekey` call it across translation units.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(unreachable_pub)]

use core::ffi::{c_char, c_int};

use crate::bn::arith::BN_cmp;
use crate::bn::bignum::{BN_bin2bn, BN_is_zero, BigNum};
use crate::ec::curve::EC_curve_nid2nist;
use crate::ec::key::{ossl_ec_key_get0_propq, ossl_ec_key_get_libctx, EC_KEY_get0_group};
use crate::ec::lib::{EC_GROUP_get0_order, EC_GROUP_get_curve_name};
use crate::ec::EcKey;
use crate::evp::kdf::{EVP_KDF_CTX_free, EvpKdfCtx};
use crate::hpke::ossl_HPKE_KEM_INFO_find_curve;
use crate::hpke::{hpke_labeled_expand, hpke_labeled_extract, kdf_ctx_create};
use crate::runtime::bio::print::BIO_snprintf;
use crate::runtime::err::err_sites;
use crate::runtime::err::raise_site;
use crate::runtime::err::raise_site_data;
use crate::runtime::mem::cleanse;

/// `LABEL_KEM` — `ec_kem.c.in:70`, `"KEM"`.
const LABEL_KEM: &[u8] = b"KEM";
/// `OSSL_DHKEM_LABEL_DKP_PRK` — `prov/ecx.h:21`, `"dkp_prk"`.
const OSSL_DHKEM_LABEL_DKP_PRK: &[u8] = b"dkp_prk";
/// `OSSL_DHKEM_LABEL_CANDIDATE` — `prov/ecx.h:23`, `"candidate"`.
const OSSL_DHKEM_LABEL_CANDIDATE: &[u8] = b"candidate";

/// `OSSL_HPKE_MAX_SECRET` — `include/internal/hpke_util.h:15`.
const OSSL_HPKE_MAX_SECRET: usize = 64;
/// `OSSL_HPKE_MAX_PRIVATE` — `include/internal/hpke_util.h:17`.
const OSSL_HPKE_MAX_PRIVATE: usize = 66;

/// `static const char *ec_curvename_get0(const EC_KEY *ec)` — `ec_kem.c.in:106-111`.
///
/// # Safety
/// `ec` is live.
unsafe fn ec_curvename_get0(ec: *const EcKey) -> *const c_char {
    // SAFETY: `ec` is live per the contract.
    let group = unsafe { EC_KEY_get0_group(ec) };
    // SAFETY: `group` is the key's own group, live whenever the key is.
    unsafe { EC_curve_nid2nist(EC_GROUP_get_curve_name(group)) }
}

/// `int ossl_ec_dhkem_derive_private(EC_KEY *ec, BIGNUM *priv, const unsigned char *ikm,
/// size_t ikmlen)` — `ec_kem.c.in:387-452`.
///
/// The `-2` return is the authority's "unsupported curve" answer, distinct from the `0` a failed
/// KDF context or a failed expansion gives, and `ossl_ec_generate_key_dhkem` propagates it as a
/// plain failure (`<= 0`).
///
/// # Safety
/// `ec` is live; `priv` is a live `BIGNUM` the caller owns; `ikm` is NULL or readable for `ikmlen`.
#[allow(unused_assignments)] // the authority initialises `kdfctx` to NULL and assigns it before its only read
#[no_mangle]
pub unsafe extern "C" fn ossl_ec_dhkem_derive_private(
    ec: *mut EcKey,
    priv_: *mut BigNum,
    ikm: *const u8,
    ikmlen: usize,
) -> c_int {
    let mut ret: c_int = 0;
    let mut suiteid: [u8; 2] = [0; 2];
    let mut prk: [u8; OSSL_HPKE_MAX_SECRET] = [0; OSSL_HPKE_MAX_SECRET];
    let mut privbuf: [u8; OSSL_HPKE_MAX_PRIVATE] = [0; OSSL_HPKE_MAX_PRIVATE];
    let mut counter: u8 = 0;
    let mut kdfctx: *mut EvpKdfCtx = core::ptr::null_mut();

    // SAFETY: `ec` is live per the contract.
    let curve = unsafe { ec_curvename_get0(ec) };
    if curve.is_null() {
        return -2;
    }

    // SAFETY: `curve` is NUL-terminated and the table's own contract holds.
    let info = unsafe { ossl_HPKE_KEM_INFO_find_curve(curve) };
    if info.is_null() {
        return -2;
    }

    // SAFETY: `ec` is live and `info` is a `'static` table entry.
    unsafe {
        kdfctx = kdf_ctx_create(
            c"HKDF".as_ptr(),
            (*info).mdname.as_ptr(),
            ossl_ec_key_get_libctx(ec),
            ossl_ec_key_get0_propq(ec),
        );
        if kdfctx.is_null() {
            return 0;
        }

        /* ikmlen should have a length of at least Nsk */
        if ikmlen < (*info).nsk {
            let mut msg = [0 as c_char; 64];
            // SAFETY: `msg` is a 64-byte buffer and the format is the authority's.
            BIO_snprintf(
                msg.as_mut_ptr(),
                msg.len(),
                c"ikm length is :%zu, should be at least %zu".as_ptr(),
                ikmlen,
                (*info).nsk,
            );
            // SAFETY: a compile-time-constant site; the message is NUL-terminated.
            raise_site_data(&err_sites::PROV_EC_KEM_463, msg.as_ptr());
            cleanse(prk.as_mut_ptr(), prk.len());
            cleanse(privbuf.as_mut_ptr(), privbuf.len());
            EVP_KDF_CTX_free(kdfctx);
            return ret;
        }

        suiteid[0] = ((*info).kem_id / 256) as u8;
        suiteid[1] = ((*info).kem_id % 256) as u8;

        if hpke_labeled_extract(
            kdfctx,
            prk.as_mut_ptr(),
            (*info).nsecret,
            core::ptr::null(),
            0,
            LABEL_KEM,
            suiteid.as_ptr(),
            suiteid.len(),
            OSSL_DHKEM_LABEL_DKP_PRK,
            ikm,
            ikmlen,
        ) == 0
        {
            cleanse(prk.as_mut_ptr(), prk.len());
            cleanse(privbuf.as_mut_ptr(), privbuf.len());
            EVP_KDF_CTX_free(kdfctx);
            return ret;
        }

        // SAFETY: `ec` is live, so its group is.
        let order = EC_GROUP_get0_order(EC_KEY_get0_group(ec));
        loop {
            if hpke_labeled_expand(
                kdfctx,
                privbuf.as_mut_ptr(),
                (*info).nsk,
                prk.as_ptr(),
                (*info).nsecret,
                LABEL_KEM,
                suiteid.as_ptr(),
                suiteid.len(),
                OSSL_DHKEM_LABEL_CANDIDATE,
                &counter,
                1,
            ) == 0
            {
                break;
            }
            privbuf[0] &= (*info).bitmask;
            if BN_bin2bn(privbuf.as_ptr(), (*info).nsk as c_int, priv_).is_null() {
                break;
            }
            if counter == 0xFF {
                raise_site(&err_sites::PROV_EC_KEM_489);
                cleanse(prk.as_mut_ptr(), prk.len());
                cleanse(privbuf.as_mut_ptr(), privbuf.len());
                EVP_KDF_CTX_free(kdfctx);
                return ret;
            }
            counter = counter.wrapping_add(1);
            if !(BN_is_zero(priv_) != 0 || BN_cmp(priv_, order) >= 0) {
                ret = 1;
                break;
            }
        }
        cleanse(prk.as_mut_ptr(), prk.len());
        cleanse(privbuf.as_mut_ptr(), privbuf.len());
        EVP_KDF_CTX_free(kdfctx);
    }
    ret
}
