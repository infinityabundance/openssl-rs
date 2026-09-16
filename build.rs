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
//!   3. re-runs when the registry or the constitution changes;
//!   4. compiles the C-variadic ABI adapters (`src/runtime/err_variadic.c`) into
//!      the crate, because Rust cannot define a C-variadic function on stable
//!      and those three entry points therefore have to be built from C. The
//!      compiled archive is a *crate artifact*, not a link-time afterthought: a
//!      Rust consumer of this crate gets the same symbol set the distribution
//!      artifacts get.
//!
//! It deliberately does NOT embed wall-clock time or host paths.
//!
//! The registry is parsed by a tiny, dependency-free reader below rather than by
//! a JSON crate: adding a dependency purely for build metadata would itself be a
//! supply-chain decision, and this project's dependency surface is a contract
//! (`Cargo.toml`, `docs/CUSTODIAN_CONTRACT.md` §3).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

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

    // The compiled-in modules directory, which `provider_init` uses when a provider module is
    // loaded by name and neither the store's search path nor `OPENSSL_MODULES` answers one.
    //
    // A *distribution* fact rather than an authority one: the authority bakes its own
    // configure-time `MODULESDIR` into the library, and a substitute has a different one, so
    // the two strings can never be equal and the value is not compared by any court. An unset
    // variable emits the empty string, which `crate::runtime::defaults` reads as "no
    // compiled-in directory" and answers NULL for -- a state `provider_init` already has to
    // handle. Injecting a fabricated path would send `dlopen` somewhere the distribution never
    // intended, which is worse than admitting there is no default.
    // A NUL would make the value unrepresentable as a C string, and `clippy::panic` is denied
    // in this crate including its build script -- so the refusal is a `Result` reported the
    // way the build script's other refusals are.
    let modulesdir = std::env::var("OPENSSL_RS_MODULESDIR").unwrap_or_default();
    if modulesdir.contains('\0') {
        eprintln!("error: OPENSSL_RS_MODULESDIR must not contain a NUL byte");
        std::process::exit(1);
    }
    println!("cargo:rustc-env=OPENSSL_RS_MODULESDIR={modulesdir}");
    println!("cargo:rerun-if-env-changed=OPENSSL_RS_MODULESDIR");

    build_c_adapters(&manifest_dir)?;

    Ok(())
}

/// Compile the C-side ABI shims and make them part of this crate.
///
/// Two unrelated needs put code here, and both are ABI constraints rather than
/// behaviour:
///
/// * `ERR_set_error`, `ERR_add_error_data` and `ERR_add_error_vdata` are
///   printf-style C-variadic functions, which stable Rust cannot define. They are
///   argument-marshalling shims in C that call back into the Rust core
///   (`src/runtime/err.rs`); no behaviour lives in the C. The same constraint is
///   already documented in `docs/UNSAFE.md` and the module docs.
/// * `struct dirent` and `struct stat` are read through the platform's own
///   headers (`src/runtime/dir_posix.c`), so that no field offset is assumed.
///
/// The archive is linked as a *static* library so that the archive-form crate
/// output (`staticlib`) contains those symbols, and so that `cargo test` links
/// them too. `build_phase2.sh` then only has to compile the scaffolds.
fn build_c_adapters(manifest_dir: &Path) -> Result<(), String> {
    // Each entry is (source, object stem). All of them exist for the same
    // reason: a C-variadic function of the public ABI cannot be defined in
    // stable Rust, so only the argument marshalling is written in C and every
    // behavioural decision is made by the Rust core it calls back into.
    let sources = [
        ("src/runtime/err_variadic.c", "openssl_rs_err_variadic"),
        ("src/runtime/bio/bio_variadic.c", "openssl_rs_bio_variadic"),
        ("src/runtime/bio/bio_va.c", "openssl_rs_bio_va"),
        // Not a variadic adapter: `struct dirent` and `struct stat` are read on
        // the C side of the ABI so that no field offset is assumed. See the
        // file's own header.
        ("src/runtime/dir_posix.c", "openssl_rs_dir_posix"),
    ];

    let out_dir = PathBuf::from(env::var("OUT_DIR").map_err(|_| "OUT_DIR is not set")?);
    // `CC`/`AR` are honoured so a cross build can point at its own toolchain;
    // the defaults match every platform this project admits so far.
    let cc = env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let ar = env::var("AR").unwrap_or_else(|_| "ar".to_string());

    let archive = out_dir.join("libopenssl_rs_c_adapters.a");
    let mut objects: Vec<PathBuf> = Vec::new();
    for (rel, stem) in sources {
        let src = manifest_dir.join(rel);
        println!("cargo:rerun-if-changed={}", src.display());
        let obj = out_dir.join(format!("{stem}.o"));
        run_tool(
            &cc,
            &[
                "-c",
                "-O2",
                "-fPIC",
                "-fno-strict-aliasing",
                "-o",
                &obj.to_string_lossy(),
                &src.to_string_lossy(),
            ],
        )
        .map_err(|e| format!("compiling {} failed: {e}", src.display()))?;
        objects.push(obj);
    }

    // One archive with every adapter: the archive-form crate output must contain
    // the same symbol set the distribution artifacts get.
    let mut ar_args: Vec<String> = vec!["crs".into(), archive.to_string_lossy().into_owned()];
    for obj in &objects {
        ar_args.push(obj.to_string_lossy().into_owned());
    }
    run_tool(&ar, &ar_args.iter().map(String::as_str).collect::<Vec<_>>())
        .map_err(|e| format!("archiving {} failed: {e}", archive.display()))?;

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=openssl_rs_c_adapters");
    Ok(())
}

fn run_tool(program: &str, args: &[&str]) -> Result<(), String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("cannot execute {program}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{program} exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
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
