//! Phase 8 — `crypto/ml_kem/ml_kem.c`'s known-answer tests, driven from the authority's vectors.
//!
//! The vectors are the authority's own `test/recipes/30-test_evp_data/evppkey_ml_kem_*.txt` files,
//! embedded here with `include_str!` so this test compares against the bytes the authority's own
//! `evp_test` driver reads rather than against a second transcription. The three families are all
//! **published** vectors — the keygen and encap KATs from Michael Baentsch's FIPS 203
//! implementation, and the `encapDecap` set generated from NIST's ACVP-Server
//! `ML-KEM-encapDecap-FIPS203/internalProjection.json` (the header of
//! `evppkey_ml_kem_encap_decap.txt` says so). Nothing is typed: every seed, key, entropy,
//! ciphertext and expected output below is parsed out of those files at test time.
//!
//! Three properties are checked, for every variant:
//!
//!   * **The keygen KAT agrees.** A 64-byte `(d, z)` seed goes in through `ossl_ml_kem_set_seed`
//!     and `ossl_ml_kem_genkey`, and both the encoded public key and the encoded private key must
//!     equal the vector's bytes. That closes matrix expansion, the CBD samplers, the NTT and its
//!     inverse, the matrix products and both encoders in one comparison.
//!   * **The encap KAT agrees.** The vector's `Entropy` plus its `EncodedPublicKey` must produce
//!     its `Ciphertext` and its `Output` shared secret, through
//!     `ossl_ml_kem_encap_seed`.
//!   * **The decap KAT agrees.** The vector's `EncodedPrivateKey` and its `Input` ciphertext must
//!     produce its `Output`, through `ossl_ml_kem_decap` — including the implicit-rejection arm,
//!     whose `Output` differs from the encapsulation's when the ciphertext is not the one the
//!     private key's own encapsulation would have produced.
//!
//! A differential court proves two implementations agree; these published vectors are what says
//! the bytes are ML-KEM's (D400's rule).
//!
//! SPDX-License-Identifier: Apache-2.0

#![allow(clippy::panic)]
// a failing assertion's message is this test's whole report
// A record that is missing a field this test needs is this test's own failure mode, and the text
// it carries is the report; `expect` is how the rest of the suite says that.
#![allow(clippy::expect_used)]

use core::ffi::c_int;
use core::ptr;

use crate::context::{OSSL_LIB_CTX_free, OSSL_LIB_CTX_new};

use super::key::{
    ossl_ml_kem_decap, ossl_ml_kem_encap_seed, ossl_ml_kem_encode_private_key, ossl_ml_kem_genkey,
    ossl_ml_kem_get_vinfo, ossl_ml_kem_key_free, ossl_ml_kem_key_new,
    ossl_ml_kem_parse_private_key, ossl_ml_kem_parse_public_key, ossl_ml_kem_set_seed,
};
use super::{
    MlKemVinfo, EVP_PKEY_ML_KEM_1024, EVP_PKEY_ML_KEM_512, EVP_PKEY_ML_KEM_768,
    ML_KEM_SHARED_SECRET_BYTES,
};

/// The authority's nine vector files, three per variant.
const KEYGEN_FILES: [(&str, &str); 3] = [
    (
        "ML-KEM-512",
        include_str!(
            "../../forensics/authorities/src/openssl-3.6.4/test/recipes/30-test_evp_data/evppkey_ml_kem_512_keygen.txt"
        ),
    ),
    (
        "ML-KEM-768",
        include_str!(
            "../../forensics/authorities/src/openssl-3.6.4/test/recipes/30-test_evp_data/evppkey_ml_kem_768_keygen.txt"
        ),
    ),
    (
        "ML-KEM-1024",
        include_str!(
            "../../forensics/authorities/src/openssl-3.6.4/test/recipes/30-test_evp_data/evppkey_ml_kem_1024_keygen.txt"
        ),
    ),
];

const ENCAP_FILES: [(&str, &str); 3] = [
    (
        "ML-KEM-512",
        include_str!(
            "../../forensics/authorities/src/openssl-3.6.4/test/recipes/30-test_evp_data/evppkey_ml_kem_512_encap.txt"
        ),
    ),
    (
        "ML-KEM-768",
        include_str!(
            "../../forensics/authorities/src/openssl-3.6.4/test/recipes/30-test_evp_data/evppkey_ml_kem_768_encap.txt"
        ),
    ),
    (
        "ML-KEM-1024",
        include_str!(
            "../../forensics/authorities/src/openssl-3.6.4/test/recipes/30-test_evp_data/evppkey_ml_kem_1024_encap.txt"
        ),
    ),
];

const DECAP_FILES: [(&str, &str); 3] = [
    (
        "ML-KEM-512",
        include_str!(
            "../../forensics/authorities/src/openssl-3.6.4/test/recipes/30-test_evp_data/evppkey_ml_kem_512_decap.txt"
        ),
    ),
    (
        "ML-KEM-768",
        include_str!(
            "../../forensics/authorities/src/openssl-3.6.4/test/recipes/30-test_evp_data/evppkey_ml_kem_768_decap.txt"
        ),
    ),
    (
        "ML-KEM-1024",
        include_str!(
            "../../forensics/authorities/src/openssl-3.6.4/test/recipes/30-test_evp_data/evppkey_ml_kem_1024_decap.txt"
        ),
    ),
];

/// The ACVP `encapDecap` set, which carries a `Kem` line per record and so needs no per-file split.
const ACVP_ENCAP_DECAP: &str = include_str!(
    "../../forensics/authorities/src/openssl-3.6.4/test/recipes/30-test_evp_data/evppkey_ml_kem_encap_decap.txt"
);

/// `ML-KEM-###` -> the crate's `EVP_PKEY_ML_KEM_###` NID.
fn evp_type_of(name: &str) -> Option<c_int> {
    match name.strip_prefix("ML-KEM-")? {
        "512" => Some(EVP_PKEY_ML_KEM_512),
        "768" => Some(EVP_PKEY_ML_KEM_768),
        "1024" => Some(EVP_PKEY_ML_KEM_1024),
        _ => None,
    }
}

/// One `key = value` record of a `30-test_evp_data` file, in file order.
type Record = Vec<(&'static str, &'static str)>;

/// Every record of one vector file. A record begins at each `Kem = ` or `KeyGen = ` line, which is
/// how the authority's own `evp_test` driver splits them; comments and blank lines are skipped.
fn records(text: &'static str) -> Vec<Record> {
    let mut out: Vec<Record> = Vec::new();
    let mut cur: Record = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        if (k == "Kem" || k == "KeyGen") && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        cur.push((k, v));
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// The first value for `key` in a record, or None.
fn field<'a>(rec: &'a Record, key: &str) -> Option<&'a str> {
    rec.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

/// A lowercase-hex string of even length, decoded.
fn hex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    assert!(b.len().is_multiple_of(2), "even-length hex: {s}");
    (0..b.len() / 2)
        .map(|i| {
            let hi = (b[2 * i] as char).to_digit(16).expect("hex digit");
            let lo = (b[2 * i + 1] as char).to_digit(16).expect("hex digit");
            ((hi << 4) | lo) as u8
        })
        .collect()
}

/// A fresh library context, the way every other unit-level vector test takes one.
fn fresh_libctx() -> *mut core::ffi::c_void {
    let ctx = OSSL_LIB_CTX_new();
    assert!(!ctx.is_null(), "a fresh library context");
    ctx
}

/// The variant's `MlKemVinfo`, asserted present.
fn vinfo_of(evp_type: c_int) -> &'static MlKemVinfo {
    // SAFETY: the answer is a pointer into this module's static table.
    let vinfo = unsafe { ossl_ml_kem_get_vinfo(evp_type) };
    assert!(!vinfo.is_null(), "vinfo for {evp_type}");
    // SAFETY: the static table outlives the test.
    unsafe { &*vinfo }
}

/// **The keygen KAT agrees.** `hexseed` -> `hexpub` and `hexpriv`, for every record.
#[test]
fn the_keygen_kats_agree_with_every_vector() {
    for (name, text) in KEYGEN_FILES {
        let evp_type = evp_type_of(name).expect("a known variant");
        let vinfo = vinfo_of(evp_type);
        let mut checked = 0;
        for rec in records(text) {
            let Some(seed) = field(&rec, "Ctrl").and_then(|c| c.strip_prefix("hexseed:")) else {
                continue;
            };
            let mut want_pub: Option<Vec<u8>> = None;
            let mut want_prv: Option<Vec<u8>> = None;
            for (k, v) in &rec {
                let _ = k;
                if let Some(hexed) = v.strip_prefix("hexpub:") {
                    want_pub = Some(hex(hexed));
                } else if let Some(hexed) = v.strip_prefix("hexpriv:") {
                    want_prv = Some(hex(hexed));
                }
            }
            let (want_pub, want_prv) = (want_pub.expect("hexpub"), want_prv.expect("hexpriv"));
            let seed = hex(seed);

            let libctx = fresh_libctx();
            // SAFETY: every pointer is this test's own and the lengths come from the vinfo.
            unsafe {
                let key = ossl_ml_kem_key_new(libctx, ptr::null(), evp_type);
                assert!(!key.is_null(), "{name}: key creation");
                assert_eq!(
                    ossl_ml_kem_set_seed(seed.as_ptr(), seed.len(), key),
                    key,
                    "{name}: set_seed"
                );
                let mut pubenc = vec![0u8; vinfo.pubkey_bytes];
                assert_eq!(
                    ossl_ml_kem_genkey(pubenc.as_mut_ptr(), pubenc.len(), key),
                    1,
                    "{name}: genkey"
                );
                assert_eq!(pubenc.len(), want_pub.len(), "{name}: public key length");
                assert_eq!(pubenc, want_pub, "{name}: hexpub");

                let mut prvenc = vec![0u8; vinfo.prvkey_bytes];
                assert_eq!(
                    ossl_ml_kem_encode_private_key(prvenc.as_mut_ptr(), prvenc.len(), key),
                    1,
                    "{name}: encode_private_key"
                );
                assert_eq!(prvenc.len(), want_prv.len(), "{name}: private key length");
                assert_eq!(prvenc, want_prv, "{name}: hexpriv");

                ossl_ml_kem_key_free(key);
                OSSL_LIB_CTX_free(libctx);
            }
            checked += 1;
        }
        assert!(checked > 0, "{name}: no keygen records in the vector file");
    }
}

/// **The encap KAT agrees.** `Entropy` + `EncodedPublicKey` -> `Ciphertext` and `Output`.
///
/// The 768 and 1024 files also carry 120 records each whose `Result` is
/// `TEST_PARSE_PUBLIC_KEY_ERROR` — a deliberately invalid `EncodedPublicKey` whose parse must be
/// refused. Those are checked as refusals rather than skipped, because a refusal is the whole of
/// what such a record asserts.
#[test]
fn the_encapsulation_kats_agree_with_every_vector() {
    for (name, text) in ENCAP_FILES {
        let evp_type = evp_type_of(name).expect("a known variant");
        let vinfo = vinfo_of(evp_type);
        let mut checked = 0;
        let mut refused = 0;
        for rec in records(text) {
            let Some(pubkey) = field(&rec, "EncodedPublicKey") else {
                continue;
            };
            let pubkey = hex(pubkey);
            let expect_refusal = field(&rec, "Result") == Some("TEST_PARSE_PUBLIC_KEY_ERROR");

            let libctx = fresh_libctx();
            // SAFETY: every pointer is this test's own and the lengths come from the vinfo.
            unsafe {
                let key = ossl_ml_kem_key_new(libctx, ptr::null(), evp_type);
                assert!(!key.is_null(), "{name}: key creation");
                let parsed = ossl_ml_kem_parse_public_key(pubkey.as_ptr(), pubkey.len(), key);

                if expect_refusal {
                    assert_eq!(parsed, 0, "{name}: an invalid public key must be refused");
                    ossl_ml_kem_key_free(key);
                    OSSL_LIB_CTX_free(libctx);
                    refused += 1;
                    continue;
                }
                assert!(
                    field(&rec, "Result").is_none(),
                    "{name}: unmodelled Result {:?}",
                    field(&rec, "Result")
                );
                assert_eq!(parsed, 1, "{name}: parse_public_key");

                let entropy = hex(field(&rec, "Entropy").expect("Entropy"));
                let want_ctext = hex(field(&rec, "Ciphertext").expect("Ciphertext"));
                let want_out = hex(field(&rec, "Output").expect("Output"));

                let mut ctext = vec![0u8; vinfo.ctext_bytes];
                let mut secret = vec![0u8; ML_KEM_SHARED_SECRET_BYTES];
                assert_eq!(
                    ossl_ml_kem_encap_seed(
                        ctext.as_mut_ptr(),
                        ctext.len(),
                        secret.as_mut_ptr(),
                        secret.len(),
                        entropy.as_ptr(),
                        entropy.len(),
                        key,
                    ),
                    1,
                    "{name}: encap_seed"
                );
                assert_eq!(ctext, want_ctext, "{name}: Ciphertext");
                assert_eq!(secret, want_out, "{name}: Output");

                ossl_ml_kem_key_free(key);
                OSSL_LIB_CTX_free(libctx);
            }
            checked += 1;
        }
        assert!(checked > 0, "{name}: no encap records in the vector file");
        if name != "ML-KEM-512" {
            assert_eq!(refused, 120, "{name}: the invalid-public-key records");
        }
    }
}

/// **The decap KAT agrees**, implicit-rejection and refusal records included.
///
/// The 768 and 1024 files also carry 120 `TEST_PARSE_PRIVATE_KEY_ERROR` records (an invalid
/// `EncodedPrivateKey`) and 20 `TEST_DECAPSULATE_ERROR` records (a ciphertext the decapsulator
/// must refuse — the empty `Input` is a zero length against the variant's `ctext_bytes`).
#[test]
fn the_decapsulation_kats_agree_with_every_vector() {
    for (name, text) in DECAP_FILES {
        let evp_type = evp_type_of(name).expect("a known variant");
        let mut checked = 0;
        let mut refused_parse = 0;
        let mut refused_decap = 0;
        for rec in records(text) {
            let Some(prvkey) = field(&rec, "EncodedPrivateKey") else {
                continue;
            };
            let prvkey = hex(prvkey);
            let result = field(&rec, "Result");
            let input = hex(field(&rec, "Input").unwrap_or(""));

            let libctx = fresh_libctx();
            // SAFETY: every pointer is this test's own and the lengths come from the vector.
            unsafe {
                let key = ossl_ml_kem_key_new(libctx, ptr::null(), evp_type);
                assert!(!key.is_null(), "{name}: key creation");
                let parsed = ossl_ml_kem_parse_private_key(prvkey.as_ptr(), prvkey.len(), key);

                let mut secret = vec![0u8; ML_KEM_SHARED_SECRET_BYTES];
                match result {
                    Some("TEST_PARSE_PRIVATE_KEY_ERROR") => {
                        assert_eq!(parsed, 0, "{name}: an invalid private key must be refused");
                        refused_parse += 1;
                    }
                    Some("TEST_DECAPSULATE_ERROR") => {
                        assert_eq!(parsed, 1, "{name}: parse_private_key");
                        assert_eq!(
                            ossl_ml_kem_decap(
                                secret.as_mut_ptr(),
                                secret.len(),
                                input.as_ptr(),
                                input.len(),
                                key,
                            ),
                            0,
                            "{name}: an invalid ciphertext must be refused"
                        );
                        refused_decap += 1;
                    }
                    other => {
                        assert!(other.is_none(), "{name}: unmodelled Result {other:?}");
                        assert_eq!(parsed, 1, "{name}: parse_private_key");
                        assert_eq!(
                            ossl_ml_kem_decap(
                                secret.as_mut_ptr(),
                                secret.len(),
                                input.as_ptr(),
                                input.len(),
                                key,
                            ),
                            1,
                            "{name}: decap"
                        );
                        assert_eq!(
                            secret,
                            hex(field(&rec, "Output").expect("Output")),
                            "{name}: Output"
                        );
                        checked += 1;
                    }
                }

                ossl_ml_kem_key_free(key);
                OSSL_LIB_CTX_free(libctx);
            }
        }
        assert!(checked > 0, "{name}: no decap records in the vector file");
        if name != "ML-KEM-512" {
            assert_eq!(
                refused_parse, 120,
                "{name}: the invalid-private-key records"
            );
            assert_eq!(refused_decap, 20, "{name}: the invalid-ciphertext records");
        }
    }
}

/// A self-check on the one primitive the encapsulation's `v` half alone uses.
///
/// `scalar_decode_decompress_add` (`ml_kem.c:1095`) is `ByteDecode_1` + `Decompress_1` + add in
/// one unrolled pass, and it is reached from nowhere else in the unit. The two-step form is
/// written out independently here — `Decompress_1` maps the bit 1 to `(q >> 1) + 1` and the bit 0
/// to 0, which is what `decompress(x, 1)` computes for `x` in {0, 1} — so a disagreement between
/// the two says which of the pair is wrong rather than only that one of them is.
#[test]
fn the_one_shot_decode_and_decompress_agrees_with_the_two_step_path() {
    use super::arith::{decompress, scalar_add, scalar_decode_decompress_add};
    use super::Scalar;

    // A fixed, non-degenerate bit pattern and base scalar, so the comparison is exhaustive over
    // all 256 coefficients rather than over a random sample.
    let mut input = [0u8; 32];
    for (i, b) in input.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(0x5a);
    }
    let mut base = Scalar::ZERO;
    for i in 0..256 {
        base.c[i] = ((i as u16).wrapping_mul(7).wrapping_add(11)) % 3329;
    }

    let mut combined = base;
    // SAFETY: both are live stack scalars and the input is 32 bytes.
    unsafe { scalar_decode_decompress_add(&mut combined, input.as_ptr()) };

    let mut one = Scalar::ZERO;
    for i in 0..256 {
        let bit = (input[i / 8] >> (i % 8)) & 1;
        one.c[i] = decompress(bit as u16, 1);
    }
    let mut two = base;
    // SAFETY: both are live stack scalars.
    unsafe { scalar_add(&mut two, &one) };

    assert_eq!(combined.c, two.c);
}

/// **The ACVP `encapDecap` set agrees**, both arms of every record it carries.
/// The authority's own `evp_test` driver reads this file through its KEM section, where an
/// `Entropy` field makes the record an encapsulation: the produced ciphertext and shared secret
/// are both compared against the file's own bytes (`test/evp_test.c:2390-2401`). The file carries
/// 78 encapsulation records and 30 decapsulation ones.
#[test]
fn the_acvp_encap_decap_set_agrees() {
    let mut encapped = 0;
    let mut decapped = 0;
    for rec in records(ACVP_ENCAP_DECAP) {
        let Some(kem) = field(&rec, "Kem") else {
            continue;
        };
        let Some(evp_type) = evp_type_of(kem) else {
            continue;
        };
        let vinfo = vinfo_of(evp_type);

        if let Some(entropy) = field(&rec, "Entropy") {
            let pubkey = hex(field(&rec, "EncodedPublicKey").expect("EncodedPublicKey"));
            let want_ctext = hex(field(&rec, "Ciphertext").expect("Ciphertext"));
            let want_secret = hex(field(&rec, "Output").expect("Output"));
            let entropy = hex(entropy);

            let libctx = fresh_libctx();
            // SAFETY: every pointer is this test's own.
            unsafe {
                let key = ossl_ml_kem_key_new(libctx, ptr::null(), evp_type);
                assert!(!key.is_null(), "{kem}: key creation");
                assert_eq!(
                    ossl_ml_kem_parse_public_key(pubkey.as_ptr(), pubkey.len(), key),
                    1,
                    "{kem}: parse_public_key"
                );
                let mut ctext = vec![0u8; vinfo.ctext_bytes];
                let mut secret = vec![0u8; ML_KEM_SHARED_SECRET_BYTES];
                assert_eq!(
                    ossl_ml_kem_encap_seed(
                        ctext.as_mut_ptr(),
                        ctext.len(),
                        secret.as_mut_ptr(),
                        secret.len(),
                        entropy.as_ptr(),
                        entropy.len(),
                        key,
                    ),
                    1,
                    "{kem}: encap_seed"
                );
                assert_eq!(ctext, want_ctext, "{kem}: Ciphertext");
                assert_eq!(secret, want_secret, "{kem}: Output");
                ossl_ml_kem_key_free(key);
                OSSL_LIB_CTX_free(libctx);
            }
            encapped += 1;
        }

        if let Some(prvkey) = field(&rec, "EncodedPrivateKey") {
            let input = hex(field(&rec, "Input").expect("Input"));
            let want = hex(field(&rec, "Output").expect("Output"));
            let prvkey = hex(prvkey);

            let libctx = fresh_libctx();
            // SAFETY: every pointer is this test's own.
            unsafe {
                let key = ossl_ml_kem_key_new(libctx, ptr::null(), evp_type);
                assert!(!key.is_null(), "{kem}: key creation");
                assert_eq!(
                    ossl_ml_kem_parse_private_key(prvkey.as_ptr(), prvkey.len(), key),
                    1,
                    "{kem}: parse_private_key"
                );
                let mut secret = vec![0u8; ML_KEM_SHARED_SECRET_BYTES];
                assert_eq!(
                    ossl_ml_kem_decap(
                        secret.as_mut_ptr(),
                        secret.len(),
                        input.as_ptr(),
                        input.len(),
                        key,
                    ),
                    1,
                    "{kem}: decap"
                );
                assert_eq!(secret, want, "{kem}: Output");
                ossl_ml_kem_key_free(key);
                OSSL_LIB_CTX_free(libctx);
            }
            decapped += 1;
        }
    }
    assert!(encapped > 0, "the ACVP file's encapsulation records");
    assert!(decapped > 0, "the ACVP file's decapsulation records");
}
