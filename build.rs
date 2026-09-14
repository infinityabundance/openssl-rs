//! Build script for the openssl-rs implementation crate.
//!
//! Its job in Phase 0/1 is to **bind the product to its evidence**. A build that
//! cannot see its admitted authority is a build whose claims cannot be checked,
//! so it fails rather than silently producing an unattributed binary.
//!
//! Specifically this script:
//!
//!   1. requires the Phase 0 constitution and the Phase 1 authority registry to
//!      be present, and fails with an actionable message otherwise;
//!   2. reads the admitted production authority identity and the verified
//!      archive hash from `forensics/authorities/AUTHORITIES.json` and exposes
//!      them to the crate as `OPENSSL_RS_AUTHORITY_*` compile-time environment
//!      variables, so evidence can always name the authority it was produced
//!      against;
//!   3. re-runs when the registry or the constitution changes.
//!
//! It deliberately does NOT embed wall-clock time or host paths.
//!
//! The registry is parsed by a tiny, dependency-free reader below rather than by
//! a JSON crate: adding a dependency purely for build metadata would itself be a
//! supply-chain decision, and this project's dependency surface is a contract
//! (`Cargo.toml`, `docs/CUSTODIAN_CONTRACT.md` §3).

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

/// Documents that must exist before any product code is built.
///
/// Phase 0 is "constitution before implementation" (`docs/RELEASE_GATES.md` §1).
/// Enforcing it here makes the ordering a compile-time fact rather than a
/// convention someone can forget.
const REQUIRED_CONSTITUTION: &[&str] = &[
    "docs/CUSTODIAN_CONTRACT.md",
    "docs/PARITY_MODEL.md",
    "docs/AUTHORITY_POLICY.md",
    "docs/SECURITY_DIVERGENCE_POLICY.md",
    "docs/OWNERSHIP_MODEL.md",
    "docs/ABI_POLICY.md",
    "docs/PROVIDER_MODEL.md",
    "docs/FIPS_CLAIMS.md",
    "docs/CONCURRENCY_MODEL.md",
    "docs/RELEASE_GATES.md",
    "docs/NON_CLAIMS.md",
    "docs/REPRODUCIBILITY.md",
    "docs/UNSAFE.md",
];

const PRODUCTION_AUTHORITY: &str = "openssl-3.6.4-production";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("openssl-rs build error: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").map_err(|_| "CARGO_MANIFEST_DIR is not set")?);

    for rel in REQUIRED_CONSTITUTION {
        let p = manifest_dir.join(rel);
        if !p.is_file() {
            return Err(format!(
                "required constitution document is missing: {rel}\n\
                 Phase 0 must precede implementation (docs/RELEASE_GATES.md)."
            ));
        }
        println!("cargo:rerun-if-changed={}", p.display());
    }

    let registry_path = manifest_dir.join("forensics/authorities/AUTHORITIES.json");
    println!("cargo:rerun-if-changed={}", registry_path.display());

    let registry = fs::read_to_string(&registry_path).map_err(|e| {
        format!(
            "cannot read the authority registry at {}: {e}\n\
             Run, inside the court container:\n\
             \x20 python3 forensics/tools/authority_acquire.py --all",
            registry_path.display()
        )
    })?;

    let authority = enclosing_object(&registry, &format!("\"id\": \"{PRODUCTION_AUTHORITY}\""))
        .ok_or_else(|| {
            format!(
                "the production authority {PRODUCTION_AUTHORITY} is not admitted in \
                 forensics/authorities/AUTHORITIES.json"
            )
        })?;

    let version = string_field(authority, "version")
        .ok_or_else(|| "production authority record has no version".to_string())?;

    // `sha256` also appears inside the nested `source_tree` object; we want the
    // artifact digest, so search the `artifact` sub-object explicitly.
    let artifact = enclosing_object(authority, "\"artifact\"")
        .ok_or_else(|| "production authority record has no artifact object".to_string())?;
    let archive_sha256 = string_field(artifact, "sha256")
        .ok_or_else(|| "production authority artifact has no sha256".to_string())?;

    let source_tree = enclosing_object(authority, "\"source_tree\"")
        .ok_or_else(|| "production authority record has no source_tree object".to_string())?;
    let source_root_hash = string_field(source_tree, "root_hash")
        .ok_or_else(|| "production authority source_tree has no root_hash".to_string())?;

    if archive_sha256.len() != 64 || !archive_sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "production authority archive sha256 is not a 64-hex digest: {archive_sha256:?}"
        ));
    }

    println!("cargo:rustc-env=OPENSSL_RS_AUTHORITY_ID={PRODUCTION_AUTHORITY}");
    println!("cargo:rustc-env=OPENSSL_RS_AUTHORITY_VERSION={version}");
    println!("cargo:rustc-env=OPENSSL_RS_AUTHORITY_ARCHIVE_SHA256={archive_sha256}");
    println!("cargo:rustc-env=OPENSSL_RS_AUTHORITY_SOURCE_ROOT_HASH={source_root_hash}");

    Ok(())
}

/// Return the `{...}` object that *encloses* the first occurrence of `needle`.
///
/// A plain "find the next `{` after the needle" is wrong here, because JSON keys
/// are nested: the first `{` after `"id": "..."` is a *child* object
/// (`source_tree`), not the enclosing authority object. This walks forward
/// tracking brace depth and string state, so it identifies the object actually
/// containing the needle.
fn enclosing_object<'a>(text: &'a str, needle: &str) -> Option<&'a str> {
    let target = text.find(needle)?;
    let bytes = text.as_bytes();

    // Pass 1: find the start of the innermost object open at `target`.
    let mut stack: Vec<usize> = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    let mut start = None;
    for (i, &b) in bytes.iter().enumerate() {
        let c = b as char;
        if i == target {
            start = stack.last().copied();
            break;
        }
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
        } else if c == '{' {
            stack.push(i);
        } else if c == '}' {
            stack.pop();
        }
    }
    let start = start?;

    // Pass 2: brace-match from `start` to find the object's end.
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        let c = b as char;
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
        } else if c == '{' {
            depth += 1;
        } else if c == '}' {
            depth -= 1;
            if depth == 0 {
                return Some(&text[start..=i]);
            }
        }
    }
    None
}

/// Extract the string value of the first top-level `"key": "value"` in `text`.
///
/// Only the *first* occurrence is returned, and callers restrict `text` to the
/// object of interest first, so nested identically-named keys cannot shadow the
/// intended field.
fn string_field(text: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let at = text.find(&pat)?;
    let rest = text[at + pat.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}
