//! Phase 7 — the EVP framework: the fetch layer, the method stores and the `EVP_*` objects.
//!
//! `docs/PHASE-7-SUBPHASES.md` is this stratum's plan and `forensics/phase7-obligations.json`
//! is its arithmetic: nine hundred and fifty rows, nine hundred and twenty-four of them the
//! atlas's for this stratum and twenty-six handed over by Phase 5.
//!
//! ## What the stratum is
//!
//! The **algorithm-independent** half of `libcrypto`'s public surface. Phase 6 built the
//! provider registry: a provider can be loaded, activated, queried and torn down, and its
//! `OSSL_ALGORITHM` arrays can be asked for. What Phase 6 did *not* build is the path that
//! turns a name and a property query into a method — which is this stratum, and which is why
//! two of Phase 6's subphase rows could not be written there:
//! `crypto/core_algorithm.c`'s `ossl_algorithm_do_all` and `crypto/core_fetch.c`'s
//! `ossl_method_construct` have their only caller in `crypto/evp/evp_fetch.c`
//! (`docs/DECISIONS.md` D132, D134). Both are 7.1's first work, and the first lands here.
//!
//! ## The shape of the path
//!
//! ```text
//! EVP_MD_fetch(libctx, "SHA2-256", "provider=default")
//!   -> evp_generic_fetch             (7.2)  the property query, the cache, the store
//!        -> ossl_method_construct    (7.1)  the walk over every activated provider
//!             -> ossl_algorithm_do_all (7.1) per provider, per operation
//!                  -> query_operation  (Phase 6)  the provider's OSSL_ALGORITHM array
//!                  -> fn(provider, algorithm, no_store, data)  the constructor
//! ```
//!
//! Reading it bottom-up is the point: nothing in the stratum can be written before
//! `ossl_algorithm_do_all`, and `ossl_algorithm_do_all` needs a provider that can be queried,
//! which is what Phase 6 finished.
//!
//! ## What is not here
//!
//! The algorithms. AES, SHA, RSA, the KDFs' derivations, the MACs' compressions and the
//! signature schemes' arithmetic are Phase 8's, Phase 9's and Phase 13's. What this stratum
//! owns is the machinery they are *reached through*, plus — because the atlas assigns
//! ownership by the header that promises a symbol and not by the directory it was written in —
//! some glue that lives outside `crypto/evp/`: `crypto/asn1/ameth_lib.c`'s
//! `EVP_PKEY_ASN1_METHOD` accessors, `crypto/asn1/i2d_evp.c` and its three `d2i_` siblings, and
//! `crypto/pem/pem_pkey.c`. Those are 7.4's and 7.5's, and the plan says so per row.
//!
//! SPDX-License-Identifier: Apache-2.0

pub mod algorithm;
pub mod asymcipher;
pub mod bio_enc;
pub mod bio_ok;
pub mod cipher;
pub mod cipher_ctx;
pub mod digest;
pub mod encode;
pub mod evp_pbe;
pub mod exchange;
pub mod fetch;
pub mod kdf;
pub mod kem;
pub mod keymgmt;
pub mod keymgmt_lib;
pub mod legacy_blake2;
pub mod legacy_evp;
pub mod legacy_md5;
pub mod legacy_ripemd;
pub mod legacy_sha;
pub mod legacy_sha3;
pub mod mac;
pub mod method_store;
pub mod p5_crpt;
pub mod p5_crpt2;
pub mod p5_scrypt;
pub mod p_legacy;
pub mod pbe;
pub mod pem_bridge;
pub mod pkey;
pub mod pkey_asn1;
pub mod pkey_ctx;
pub mod pmeth_check;
pub mod pmeth_gn;
pub mod rand;
pub mod signature;
pub mod skeymgmt;
