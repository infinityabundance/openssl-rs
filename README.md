# openssl-rs

A native Rust reimplementation of OpenSSL 3.6.4 targeting source, ABI, and
observable behavioural compatibility.

`openssl-rs` reconstructs the OpenSSL distribution contract — `libcrypto`,
`libssl`, providers, public headers, static libraries, and the `openssl` CLI —
without using OpenSSL or another cryptographic library as its implementation
backend. It is not a wrapper around OpenSSL, `rustls`, AWS-LC, BoringSSL,
LibreSSL, or `ring`.

| | |
|---|---|
| OpenSSL authority | `openssl-3.6.4-production` (3.6.4) |
| Platform | `linux-x86_64` |
| Build profile | `linux-x86_64-default-shared-legacy-notests` |
| Implementation | one first-party Rust crate, zero dependencies |

> **Status:** active reconstruction, not yet a general OpenSSL replacement.
> `IMPLEMENTED` means the crate's compiled output defines a symbol with that
> name. It does not mean `PARITY_VERIFIED`, and it is not a compatibility claim.
> Current state is reported by the generated evidence, not by this file.

**Current state:**
[`STATUS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/forensics/STATUS.md) ·
[`SEAL-CENSUS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/SEAL-CENSUS.md) ·
[`PARITY_MODEL.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/PARITY_MODEL.md)

## Compatibility target

The goal is substitution: an unmodified OpenSSL consumer should be able to
compile, link, load, execute, and observe the same externally visible behaviour
against the stated authority and build profile. The reconstructed distribution
artifacts are `libcrypto.so.3`, `libssl.so.3`, `libcrypto.a`, `libssl.a`,
`legacy.so`, provider modules, public headers, pkg-config metadata, and the
`openssl` executable, with their own symbol namespaces, SONAMEs and version
nodes. See
[`CUSTODIAN_CONTRACT.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/CUSTODIAN_CONTRACT.md).

Compatibility is evaluated independently across ABI, semantics, ownership,
error behaviour, state transitions, concurrency, correctness vectors, and
downstream behaviour. Passing evidence is scoped to the surface actually
exercised; unknown behaviour remains unknown.

## Verification

Compatibility is tested against the pinned OpenSSL build using **differential
courts**: one probe compiled against the authority and against the candidate,
whose transcripts are compared line by line. Construction correctness is a
separate plane of published test vectors, and ABI, symbol-ownership, prototype
and dispatch planes are checked independently. Results are retained as
machine-readable evidence and are not converted directly into compatibility
claims — promotion to `PARITY_VERIFIED` is per dimension, by court.

Every symbol is `SCAFFOLDED` or `IMPLEMENTED`, and none is `PARITY_VERIFIED`.

> Generated evidence is authoritative over descriptive prose. Where a document
> and a generated artifact disagree, the artifact is right.

Evidence and method:
[`PARITY_MODEL.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/PARITY_MODEL.md) ·
[`REPRODUCIBILITY.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/REPRODUCIBILITY.md) ·
[`SEAL-CENSUS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/SEAL-CENSUS.md) ·
[`DECISIONS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/DECISIONS.md)

## Build and test

Authority-bearing execution — differential courts, forensic probes, benchmarks
and authority builds — runs only in the isolated, resource-capped court
container, never on the host
([`CUSTODIAN_CONTRACT.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/CUSTODIAN_CONTRACT.md) §11).
Unit tests and static derivation may run outside it.

```bash
# build the pinned court image and start it with OOM protection
bash docker/openssl-rs-court.sh build
bash docker/openssl-rs-court.sh up
bash docker/openssl-rs-court.sh verify

# admit and build the pinned authorities, then generate the atlas
bash docker/openssl-rs-court.sh exec bash forensics/tools/build_atlas.sh

# build and test the implementation crate (fmt + clippy + tests)
bash docker/openssl-rs-court.sh exec sh -c 'cd /work && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test'

# long-lived evidence and sensitivity testing use a second, separately pinned
# tooling container (see docs/REPRODUCIBILITY.md §1.2 for why)
bash docker/openssl-rs-frf-court.sh up
bash docker/openssl-rs-frf-court.sh exec bash forensics/frf/run_courts.sh
```

The court applies hard resource caps (`--memory=8g --memory-swap=8g`,
`--pids-limit=2048`, `--cpus=8`, `--restart=no`) so a runaway court OOM-kills
inside the container rather than pressuring the host.

## Architecture

One Cargo package. One first-party implementation crate. No workspace, no
component crates, and no implementation dependencies: everything the product
does is implemented here. Internal modules may be arbitrarily numerous.

The single implementation still emits the multiple runtime artifacts the
distribution contract requires, with their own symbol namespaces, SONAMEs and
version nodes preserved. The crate's own type and the link machinery that
produces those artifacts are described in
[`Cargo.toml`](https://github.com/infinityabundance/openssl-rs/blob/main/Cargo.toml)
and [`ABI_POLICY.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/ABI_POLICY.md);
the directory layout of the evidence is documented in
[`REPRODUCIBILITY.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/REPRODUCIBILITY.md).

## Documentation

| document | governs |
|---|---|
| [`CUSTODIAN_CONTRACT.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/CUSTODIAN_CONTRACT.md) | mission, the single-crate rule, what "custodian compatible" means |
| [`PARITY_MODEL.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/PARITY_MODEL.md) | obligation states, evidence planes, promotion rules, residuals |
| [`RELEASE_GATES.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/RELEASE_GATES.md) | stratum order, maturity levels, court taxonomy |
| [`REPRODUCIBILITY.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/REPRODUCIBILITY.md) | receipts, determinism, court venue |
| [`SEAL-CENSUS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/SEAL-CENSUS.md) | the generated obligations and courts census |
| [`DECISIONS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/DECISIONS.md) | the engineering decision record |

Additional policies — ABI, provider architecture, ownership and lifetimes,
concurrency, FIPS claims, `unsafe` Rust, security divergences, and non-claims —
are under [`docs/`](https://github.com/infinityabundance/openssl-rs/tree/main/docs).

## Limitations

- **Not FIPS validated.** Behavioural parity with the FIPS provider is not
  validation.
- **No cryptographic-security claim follows from OpenSSL parity.** Passing the
  OpenSSL oracle proves compatibility over the observed surface; it does not
  prove an implementation is cryptographically sound. Conversely, a perfect
  standards implementation can still be OpenSSL-incompatible.
- **No universal claims from finite evidence.** Every claim names its authority,
  profile and platform.
- **Unknown is a research result.** `UNKNOWN` is reported, not traded for
  confidence.

See [`NON_CLAIMS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/NON_CLAIMS.md).

## Licence

Apache-2.0 OR MIT. Provenance for any OpenSSL interface material used for
archaeology is recorded in
[`NOTICE`](https://github.com/infinityabundance/openssl-rs/blob/main/NOTICE).
