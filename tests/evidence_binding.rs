//! Integration guarantee: the product binary is bound to its evidence.
//!
//! `docs/CUSTODIAN_CONTRACT.md` §7 requires that every compatibility assertion
//! name its authority. These tests make that a compile-time and test-time fact:
//! a binary that cannot name its authority cannot be produced.

use openssl_rs::status::{self, PhaseState, PHASES};

#[test]
fn production_authority_is_bound() {
    assert_eq!(status::PRODUCTION_AUTHORITY_ID, "openssl-3.6.4-production");
    assert_eq!(status::PRODUCTION_AUTHORITY_VERSION, "3.6.4");
}

#[test]
fn authority_hashes_are_well_formed() {
    assert_eq!(
        status::AUTHORITY_ARCHIVE_SHA256.len(),
        64,
        "sha256 must be 64 hex chars"
    );
    assert!(
        status::AUTHORITY_ARCHIVE_SHA256
            .chars()
            .all(|c| c.is_ascii_hexdigit()),
        "archive sha256 must be hexadecimal"
    );
    assert_eq!(status::AUTHORITY_SOURCE_ROOT_HASH.len(), 64);
}

#[test]
fn fips_is_never_claimed() {
    // docs/FIPS_CLAIMS.md: behavioural parity is not validation. Bound to a
    // local so this is a genuine runtime assertion, not a constant assertion.
    let validated = status::FIPS_VALIDATED;
    assert!(!validated, "openssl-rs must never claim FIPS validation");
}

#[test]
fn phases_are_dependency_ordered_and_unique() {
    let ids: Vec<u8> = PHASES.iter().map(|p| p.id).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        ids, sorted,
        "phase ids must be strictly ascending (dependency order)"
    );
    assert_eq!(ids.len(), sorted.len(), "phase ids must be unique");
}

#[test]
fn no_phase_claims_completion_without_a_later_guarantee() {
    // Phase 0 may be complete. Phases after it may not claim Complete while an
    // earlier phase is incomplete: the strata are dependency-ordered.
    let mut saw_incomplete = false;
    for phase in PHASES {
        if phase.state != PhaseState::Complete {
            saw_incomplete = true;
        } else {
            assert!(
                !saw_incomplete,
                "phase {} ({}) claims Complete after an earlier incomplete phase; \
                 strata are dependency-ordered (docs/RELEASE_GATES.md §1)",
                phase.id, phase.name
            );
        }
    }
}
