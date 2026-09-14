//! Machine-readable project status and evidence binding.
//!
//! Prose status drifts; machine-readable status does not. This module is the
//! single source of truth for *which phase the project is in* and *which
//! authority the binary was built against*.
//!
//! The phase list is the conservation-stratum order from
//! `docs/RELEASE_GATES.md` §1. It is ordered on purpose: it is a dependency
//! graph, not a backlog. Nothing may be marked complete before its evidence
//! exists, and the ordering itself is a contract.

/// The state of a conservation stratum.
///
/// `Unknown` is deliberately available and distinct from `NotStarted`:
/// `docs/PARITY_MODEL.md` §1 requires that unknown be an honest research result
/// rather than being collapsed into a negative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseState {
    /// The phase's exit rule has been satisfied and receipts exist.
    Complete,
    /// Work is under way; the exit rule is not yet satisfied.
    InProgress,
    /// Not begun.
    NotStarted,
    /// Deliberately deferred pending evidence or architecture.
    Blocked,
}

/// One conservation stratum.
#[derive(Debug, Clone, Copy)]
pub struct Phase {
    /// Phase number, matching `docs/RELEASE_GATES.md` §1.
    pub id: u8,
    /// Short human name.
    pub name: &'static str,
    /// What the stratum conserves.
    pub stratum: &'static str,
    /// Current state.
    pub state: PhaseState,
}

/// The dependency-ordered conservation strata.
///
/// This mirrors `docs/RELEASE_GATES.md` §1 exactly. A mismatch between the two
/// is a defect; `tests/phase_order.rs` guards the ordering property.
pub const PHASES: &[Phase] = &[
    Phase {
        id: 0,
        name: "constitution",
        stratum: "Constitution, authorities, claim algebra",
        state: PhaseState::Complete,
    },
    Phase {
        id: 1,
        name: "archaeology",
        stratum: "Complete archaeology / API / ABI atlas",
        state: PhaseState::InProgress,
    },
    Phase {
        id: 2,
        name: "distribution-shell",
        stratum: "Distribution / ABI shell",
        state: PhaseState::NotStarted,
    },
    Phase {
        id: 3,
        name: "core-runtime",
        stratum: "Core runtime: allocation, threads, ERR, refcounts, ex_data, stacks, objects",
        state: PhaseState::NotStarted,
    },
    Phase {
        id: 4,
        name: "bio-conf-objects",
        stratum: "BIO + CONF + object database",
        state: PhaseState::NotStarted,
    },
    Phase {
        id: 5,
        name: "bn-asn1-der-pem",
        stratum: "BN + ASN.1 + DER/PEM",
        state: PhaseState::NotStarted,
    },
    Phase {
        id: 6,
        name: "libctx-provider",
        stratum: "OSSL_LIB_CTX + provider core",
        state: PhaseState::NotStarted,
    },
    Phase {
        id: 7,
        name: "evp",
        stratum: "EVP framework",
        state: PhaseState::NotStarted,
    },
    Phase {
        id: 8,
        name: "algorithms",
        stratum: "Native cryptographic primitives",
        state: PhaseState::NotStarted,
    },
    Phase {
        id: 9,
        name: "rand-drbg",
        stratum: "RAND / DRBG + entropy",
        state: PhaseState::NotStarted,
    },
    Phase {
        id: 10,
        name: "key-formats",
        stratum: "Key formats + PKCS + STORE",
        state: PhaseState::NotStarted,
    },
    Phase {
        id: 11,
        name: "x509",
        stratum: "X.509 + verification",
        state: PhaseState::NotStarted,
    },
    Phase {
        id: 12,
        name: "protocol-families",
        stratum: "CMS / OCSP / CMP / CT / TS and remaining libcrypto families",
        state: PhaseState::NotStarted,
    },
    Phase {
        id: 13,
        name: "legacy",
        stratum: "Legacy / deprecated compatibility",
        state: PhaseState::NotStarted,
    },
    Phase {
        id: 14,
        name: "tls-dtls",
        stratum: "TLS / DTLS (libssl)",
        state: PhaseState::NotStarted,
    },
    Phase {
        id: 15,
        name: "quic-ech",
        stratum: "QUIC / ECH and modern SSL surface",
        state: PhaseState::NotStarted,
    },
    Phase {
        id: 16,
        name: "cli-config",
        stratum: "CLI / config / filesystem contract",
        state: PhaseState::NotStarted,
    },
    Phase {
        id: 17,
        name: "downstream",
        stratum: "Downstream replacement court",
        state: PhaseState::NotStarted,
    },
    Phase {
        id: 18,
        name: "hostile-hardening",
        stratum: "Hostile fuzz / security / side-channel hardening",
        state: PhaseState::NotStarted,
    },
    Phase {
        id: 19,
        name: "performance",
        stratum: "Performance / CPU dispatch",
        state: PhaseState::NotStarted,
    },
    Phase {
        id: 20,
        name: "custodian-seal",
        stratum: "3.6.4 custodian seal",
        state: PhaseState::NotStarted,
    },
    Phase {
        id: 21,
        name: "maintenance-delta",
        stratum: "Maintenance delta machinery",
        state: PhaseState::NotStarted,
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
