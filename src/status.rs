//! Machine-readable project status and evidence binding.
//!
//! This module is the single source of truth for *which authority the binary was
//! built against*, and it types the **static** phase contract: the
//! dependency-ordered conservation-stratum list from `docs/RELEASE_GATES.md` §1.
//!
//! It types no stratum *state* on purpose. The derived state lives in
//! `forensics/phase-state.json`, computed from artefact existence by
//! `forensics/tools/phase_state.py`, so the crate must not carry a second copy:
//! the copy that used to stand here read "Phase 1 in progress" while the derived
//! state read `complete`. A state is a derived fact, and a derived fact belongs
//! to its generator. That generator enforces the rule that a stratum reports
//! `complete` only when every earlier stratum is complete.
//!
//! The phase list is ordered on purpose: it is a dependency graph, not a backlog.
//! The ordering itself is a contract, and `tests/evidence_binding.rs` guards it.

/// One conservation stratum.
#[derive(Debug, Clone, Copy)]
pub struct Phase {
    /// Phase number, matching `docs/RELEASE_GATES.md` §1.
    pub id: u8,
    /// Short human name.
    pub name: &'static str,
    /// What the stratum conserves.
    pub stratum: &'static str,
}

/// The dependency-ordered conservation strata.
///
/// This mirrors `docs/RELEASE_GATES.md` §1 exactly. A mismatch between the two
/// is a defect; `tests/evidence_binding.rs` guards the ordering property. A
/// stratum carries no state here: the derived state is `forensics/phase-state.json`.
pub const PHASES: &[Phase] = &[
    Phase {
        id: 0,
        name: "constitution",
        stratum: "Constitution, authorities, claim algebra",
    },
    Phase {
        id: 1,
        name: "archaeology",
        stratum: "Complete archaeology / API / ABI atlas",
    },
    Phase {
        id: 2,
        name: "distribution-shell",
        stratum: "Distribution / ABI shell",
    },
    Phase {
        id: 3,
        name: "core-runtime",
        stratum: "Core runtime: allocation, threads, ERR, refcounts, ex_data, stacks, objects",
    },
    Phase {
        id: 4,
        name: "bio-conf-objects",
        stratum: "BIO + CONF + object database",
    },
    Phase {
        id: 5,
        name: "bn-asn1-der-pem",
        stratum: "BN + ASN.1 + DER/PEM",
    },
    Phase {
        id: 6,
        name: "libctx-provider",
        stratum: "OSSL_LIB_CTX + provider core",
    },
    Phase {
        id: 7,
        name: "evp",
        stratum: "EVP framework",
    },
    Phase {
        id: 8,
        name: "algorithms",
        stratum: "Native cryptographic primitives",
    },
    Phase {
        id: 9,
        name: "rand-drbg",
        stratum: "RAND / DRBG + entropy",
    },
    Phase {
        id: 10,
        name: "key-formats",
        stratum: "Key formats + PKCS + STORE",
    },
    Phase {
        id: 11,
        name: "x509",
        stratum: "X.509 + verification",
    },
    Phase {
        id: 12,
        name: "protocol-families",
        stratum: "CMS / OCSP / CMP / CT / TS and remaining libcrypto families",
    },
    Phase {
        id: 13,
        name: "legacy",
        stratum: "Legacy / deprecated compatibility",
    },
    Phase {
        id: 14,
        name: "tls-dtls",
        stratum: "TLS / DTLS (libssl)",
    },
    Phase {
        id: 15,
        name: "quic-ech",
        stratum: "QUIC / ECH and modern SSL surface",
    },
    Phase {
        id: 16,
        name: "cli-config",
        stratum: "CLI / config / filesystem contract",
    },
    Phase {
        id: 17,
        name: "downstream",
        stratum: "Downstream replacement court",
    },
    Phase {
        id: 18,
        name: "hostile-hardening",
        stratum: "Hostile fuzz / security / side-channel hardening",
    },
    Phase {
        id: 19,
        name: "performance",
        stratum: "Performance / CPU dispatch",
    },
    Phase {
        id: 20,
        name: "custodian-seal",
        stratum: "3.6.4 custodian seal",
    },
    Phase {
        id: 21,
        name: "maintenance-delta",
        stratum: "Maintenance delta machinery",
    },
];

/// The production authority id, injected by `build.rs` from the admitted
/// registry. A build cannot exist without this.
pub const PRODUCTION_AUTHORITY_ID: &str = env!("OPENSSL_RS_AUTHORITY_ID");

/// The production authority version (for example `3.6.4`).
pub const PRODUCTION_AUTHORITY_VERSION: &str = env!("OPENSSL_RS_AUTHORITY_VERSION");

/// SHA-256 of the verified authority source archive.
pub const AUTHORITY_ARCHIVE_SHA256: &str = env!("OPENSSL_RS_AUTHORITY_ARCHIVE_SHA256");

/// Root hash over the authority's per-file source manifest.
pub const AUTHORITY_SOURCE_ROOT_HASH: &str = env!("OPENSSL_RS_AUTHORITY_SOURCE_ROOT_HASH");

/// The first admitted build profile, as recorded in the authority build record.
pub const PRIMARY_BUILD_PROFILE: &str = "linux-x86_64-default-shared-legacy-notests";

/// Whether the FIPS provider behaviour of this build is formally validated.
///
/// Always `false`. Behavioural parity with the FIPS provider is **not**
/// validation, and OpenSSL's certification is never inherited. See
/// `docs/FIPS_CLAIMS.md`.
pub const FIPS_VALIDATED: bool = false;
