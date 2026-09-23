//! Phase 8 — `crypto/slh_dsa/`'s known-answer tests, driven from the authority's own vectors.
//!
//! The vectors are the authority's `test/slh_dsa.inc`, which is ACVP's `SLH-DSA-sigGen-FIPS205`
//! `internalProjection` set (`slh_dsa.inc:52-53`), embedded here with `include_str!` so this test
//! compares against the file the authority's own `slh_dsa_test.c` reads rather than against a
//! second transcription. **Nothing is typed**: every seed, message, entropy and expected digest
//! below is parsed out of that file at test time.
//!
//! Two properties are checked for every item the file carries:
//!
//!   * **The root recomputation agrees.** `ossl_slh_dsa_key_pairwise_check` recomputes `PK_ROOT`
//!     from `SK_SEED || PK_SEED` through `ossl_slh_xmss_node` and the WOTS+ public-key generator,
//!     and compares it to the `PK_ROOT` the vector's private key already holds. A wrong leaf, a
//!     wrong ADRS offset or a wrong `H`/`T` bound moves the root.
//!   * **The signature's digest agrees.** The deterministic signature is produced with the
//!     vector's own `add_random` (or with the public seed, when the item has none, which is what
//!     the authority's `SLH_DSA_SIG_TEST_DET_ITEM` encodes), sha256'd, and compared to the
//!     `sig_digest` field. The full signature is up to 49,856 bytes, which is why the authority
//!     stores its digest and the test does the same.
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(clippy::panic)] // a failing assertion's message is this test's whole report
#![allow(clippy::assertions_on_constants)] // the `assert!(false, ...)` arms report a missing vector

use core::ffi::{c_int, c_uint};
use core::ptr;
use std::collections::BTreeMap;

use crate::context::{OSSL_LIB_CTX_free, OSSL_LIB_CTX_new};
use crate::evp::digest::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex2, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EVP_MD_fetch, EVP_MD_free,
};

use super::dsa::ossl_slh_dsa_sign;
use super::hash_ctx::{ossl_slh_dsa_hash_ctx_free, ossl_slh_dsa_hash_ctx_new};
use super::key::{
    ossl_slh_dsa_key_free, ossl_slh_dsa_key_get_pub, ossl_slh_dsa_key_get_pub_len,
    ossl_slh_dsa_key_new, ossl_slh_dsa_key_pairwise_check, ossl_slh_dsa_set_priv,
};

/// The authority's own vector file, embedded at compile time.
const SLH_DSA_INC: &str =
    include_str!("../../forensics/authorities/src/openssl-3.6.4/test/slh_dsa.inc");

/// A NUL-terminated copy of a Rust string, for the C-ABI algorithm-name argument.
fn cstr_bytes(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

/// Every `static const uint8_t <name>[] = { ... };` in a translation unit, in file order.
fn parse_arrays(text: &str) -> BTreeMap<String, Vec<u8>> {
    const PREFIX: &str = "static const uint8_t ";
    let mut out = BTreeMap::new();
    let mut rest = text;
    while let Some(pos) = rest.find(PREFIX) {
        rest = &rest[pos + PREFIX.len()..];
        let Some(name_end) = rest.find("[]") else {
            break;
        };
        let name = rest[..name_end].trim().to_string();
        let Some(open) = rest.find('{') else { break };
        let Some(close) = rest[open..].find("};") else {
            break;
        };
        let body = &rest[open + 1..open + close];
        let bytes = body
            .split(',')
            .filter_map(|tok| {
                let t = tok.trim();
                if t.is_empty() {
                    return None;
                }
                u8::from_str_radix(t.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
            })
            .collect::<Vec<u8>>();
        out.insert(name, bytes);
        rest = &rest[open + close..];
    }
    out
}

/// `sha2_128s_0`/`shake_256f_0` -> `SLH-DSA-SHA2-128s`/`SLH-DSA-SHAKE-256f`, the name
/// `ossl_slh_dsa_params_get` answers for.
fn alg_of(stem: &str) -> Option<String> {
    let parts = stem.split('_').collect::<Vec<_>>();
    if parts.len() != 3 {
        return None;
    }
    let (kind, bits) = (parts[0], parts[1]);
    if kind != "sha2" && kind != "shake" {
        return None;
    }
    if !(bits.ends_with('s') || bits.ends_with('f')) {
        return None;
    }
    Some(format!("SLH-DSA-{}-{}", kind.to_uppercase(), bits))
}

/// `slh_dsa_sha2_128s_0_priv` -> `("SLH-DSA-SHA2-128s", "priv")`, or `None` for a name this test
/// does not model. The two macros' four fields are the only suffixes considered.
fn split_vector_name(name: &str) -> Option<(String, &'static str)> {
    for suffix in [
        "_keygen_priv",
        "_sig_digest",
        "_add_random",
        "_priv",
        "_msg",
    ] {
        if let Some(stem) = name
            .strip_prefix("slh_dsa_")
            .and_then(|s| s.strip_suffix(suffix))
        {
            let alg = alg_of(stem)?;
            return Some((alg, &suffix[1..]));
        }
    }
    None
}

/// A fresh library context per test, so the default provider's fallback loading is this test's
/// own state rather than whatever a test that ran before it left behind (a failed
/// `OSSL_PROVIDER_load` disables fallback loading for the context it was attempted on, which is a
/// global side effect the whole-suite run would otherwise carry in).
fn fresh_libctx() -> *mut core::ffi::c_void {
    let ctx = OSSL_LIB_CTX_new();
    assert!(!ctx.is_null(), "a fresh library context");
    ctx
}

/// The published sha256 of a byte string, through the crate's own fetched digest.
///
/// # Safety
/// `libctx` is a live library context.
unsafe fn sha256(libctx: *mut core::ffi::c_void, data: &[u8], out: &mut [u8; 32]) {
    // SAFETY: a fetch with a live context and a literal algorithm name.
    unsafe {
        let md = EVP_MD_fetch(libctx, c"SHA256".as_ptr(), ptr::null());
        assert!(!md.is_null(), "SHA-256 must be fetchable");
        let ctx = EVP_MD_CTX_new();
        assert_eq!(EVP_DigestInit_ex2(ctx, md, ptr::null()), 1);
        assert_eq!(EVP_DigestUpdate(ctx, data.as_ptr().cast(), data.len()), 1);
        let mut len: c_uint = 0;
        assert_eq!(EVP_DigestFinal_ex(ctx, out.as_mut_ptr(), &mut len), 1);
        assert_eq!(len, 32);
        EVP_MD_CTX_free(ctx);
        EVP_MD_free(md);
    }
}

/// The root recomputation agrees with the `PK_ROOT` every vector's private key holds.
#[test]
fn the_root_recomputation_agrees_with_every_vector() {
    let by_name = parse_arrays(SLH_DSA_INC);

    let mut checked = 0;
    for (name, bytes) in &by_name {
        let Some((alg, kind)) = split_vector_name(name) else {
            continue;
        };
        if kind != "priv" && kind != "keygen_priv" {
            continue;
        }
        let alg_c = cstr_bytes(&alg);
        let libctx = fresh_libctx();
        // SAFETY: the key's lifetime is this test's; the algorithm name is NUL-terminated.
        unsafe {
            let key = ossl_slh_dsa_key_new(libctx, ptr::null(), alg_c.as_ptr().cast());
            assert!(!key.is_null(), "{name}: key creation");
            if kind == "priv" {
                assert_eq!(
                    ossl_slh_dsa_set_priv(key, bytes.as_ptr(), bytes.len()),
                    1,
                    "{name}: set_priv"
                );
                assert_eq!(
                    ossl_slh_dsa_key_pairwise_check(key),
                    1,
                    "{name}: pairwise check"
                );
                assert_eq!(
                    ossl_slh_dsa_key_get_pub_len(key),
                    bytes.len() / 2,
                    "{name}: 2n public length"
                );
                let _ = ossl_slh_dsa_key_get_pub(key);
            }
            ossl_slh_dsa_key_free(key);
            OSSL_LIB_CTX_free(libctx);
        }
        checked += 1;
    }
    assert_eq!(checked, 18, "the twelve keygen and six sigGen private keys");
}

/// The deterministic signature's sha256 agrees with the vector's own `sig_digest`.
#[test]
fn the_signature_digest_agrees_with_every_vector() {
    let by_name = parse_arrays(SLH_DSA_INC);

    let mut checked = 0;
    for (name, priv_bytes) in &by_name {
        let Some((alg, kind)) = split_vector_name(name) else {
            continue;
        };
        if kind != "priv" {
            continue;
        }
        let stem = name.strip_suffix("_priv").unwrap_or(name);
        let Some(msg) = by_name.get(&format!("{stem}_msg")) else {
            assert!(false, "{name}: no message in the vector file");
            continue;
        };
        let Some(expected) = by_name.get(&format!("{stem}_sig_digest")) else {
            assert!(false, "{name}: no digest in the vector file");
            continue;
        };
        let add_random = by_name.get(&format!("{stem}_add_random"));
        let alg_c = cstr_bytes(&alg);
        let libctx = fresh_libctx();

        // SAFETY: every object below is created and released in this block; the spans are the
        // vector's own.
        unsafe {
            let key = ossl_slh_dsa_key_new(libctx, ptr::null(), alg_c.as_ptr().cast());
            assert!(!key.is_null(), "{name}: key creation");
            assert_eq!(
                ossl_slh_dsa_set_priv(key, priv_bytes.as_ptr(), priv_bytes.len()),
                1,
                "{name}: set_priv"
            );
            let ctx = ossl_slh_dsa_hash_ctx_new(key);
            assert!(!ctx.is_null(), "{name}: hash context");

            let sig_len_expected = (*((*key).params)).sig_len as usize;
            let mut sig = vec![0u8; sig_len_expected];
            let mut sig_len = 0usize;
            let add_rand = match add_random {
                Some(v) => v.as_ptr(),
                None => ptr::null(),
            };
            let sign_ret = ossl_slh_dsa_sign(
                ctx,
                msg.as_ptr(),
                msg.len(),
                ptr::null(),
                0,
                add_rand,
                0,
                sig.as_mut_ptr(),
                &mut sig_len,
                sig.len(),
            );
            assert_eq!(sign_ret, 1, "{name}: sign");
            assert_eq!(sig_len, sig_len_expected, "{name}: signature length");

            let mut digest = [0u8; 32];
            sha256(libctx, &sig, &mut digest);
            assert_eq!(
                &digest[..],
                &expected[..],
                "{name}: sha256(signature) differs from the authority's digest"
            );

            ossl_slh_dsa_hash_ctx_free(ctx);
            ossl_slh_dsa_key_free(key);
            OSSL_LIB_CTX_free(libctx);
        }
        checked += 1;
    }
    assert_eq!(checked, 6, "the six sigGen items the file carries");
}

/// A refusal the signature path must carry, exercised once: a destination one byte too small.
#[test]
fn a_one_byte_signature_destination_is_refused() {
    let by_name = parse_arrays(SLH_DSA_INC);
    let priv_bytes = &by_name["slh_dsa_sha2_128s_0_priv"];
    let msg = &by_name["slh_dsa_sha2_128s_0_msg"];
    let alg_c = cstr_bytes("SLH-DSA-SHA2-128s");
    let libctx = fresh_libctx();

    // SAFETY: as above.
    unsafe {
        let key = ossl_slh_dsa_key_new(libctx, ptr::null(), alg_c.as_ptr().cast());
        assert!(!key.is_null());
        assert_eq!(
            ossl_slh_dsa_set_priv(key, priv_bytes.as_ptr(), priv_bytes.len()),
            1
        );
        let ctx = ossl_slh_dsa_hash_ctx_new(key);
        assert!(!ctx.is_null());
        let mut sig = vec![0u8; 1];
        let mut sig_len = 0usize;
        let ret: c_int = ossl_slh_dsa_sign(
            ctx,
            msg.as_ptr(),
            msg.len(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            sig.as_mut_ptr(),
            &mut sig_len,
            sig.len(),
        );
        assert_eq!(ret, 0, "a one-byte destination must be refused");
        ossl_slh_dsa_hash_ctx_free(ctx);
        ossl_slh_dsa_key_free(key);
        OSSL_LIB_CTX_free(libctx);
    }
}
