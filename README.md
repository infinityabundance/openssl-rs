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

> **Status:** the implementation state is generated, not typed here. `IMPLEMENTED`
> (a symbol the crate's compiled output defines) and `SCAFFOLDED` (a shell-only
> abort) are counted in [`STATUS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/forensics/STATUS.md)
> and [`SEAL-CENSUS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/SEAL-CENSUS.md),
> which are authoritative; this page does not restate the counts. `IMPLEMENTED` is
> neither `PARITY_VERIFIED` nor a compatibility claim.

**Current state:**
[`STATUS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/forensics/STATUS.md) ·
[`SEAL-CENSUS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/SEAL-CENSUS.md) ·
[`PARITY_MODEL.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/PARITY_MODEL.md)

## Where the conservation strata stand

The twenty-two strata and their subjects are in `docs/RELEASE_GATES.md` §1. Their
**derived state** is generated in
[`forensics/phase-state.md`](https://github.com/infinityabundance/openssl-rs/blob/main/forensics/phase-state.md)
by `forensics/tools/phase_state.py` and rendered into
[`STATUS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/forensics/STATUS.md);
that generated file is authoritative over any prose, and this page does not restate
which strata are complete. For shape, the strata group as:

| strata | subject |
|---|---|
| 0–2 | the constitution, the archaeology, and the distribution shell — the `libcrypto.so.3` / `libssl.so.3` / `libcrypto.a` / `libssl.a` / `legacy.so` / `openssl` artefacts, headers, pkg-config and install tree, with the ABI courts that prove a binary built against the authority runs against the candidate unmodified |
| 3–17 | the substantive library strata: the runtime, BIO/CONF, `BN`/`ASN.1`/DER/PEM, the provider core, the EVP framework, the native primitives, RAND/DRBG, the key formats, X.509, the protocol families, legacy compatibility, TLS/DTLS, QUIC/ECH, the CLI/config contract, and the downstream replacement court |
| 18 | the hostile fuzz / security / side-channel hardening stratum |
| 19–21 | performance / CPU dispatch, the 3.6.4 custodian seal, and the maintenance-delta machinery |
| 22 | authority exhaustiveness and the whole-program compatibility atlas |

<!-- BEGIN GENERATED: downstream-blockers -->

## Downstream-1000 biggest movers (generated)

Every one of the 1000 counted families, partitioned by its **deepest blocker** and the classes ranked by **mover potential**, with the feasible recipe queue, is in the
[generated report](https://github.com/infinityabundance/openssl-rs/blob/main/docs/PHASE-24-BIGGEST-MOVERS.md) (`docs/PHASE-24-BIGGEST-MOVERS.md`); the same table is cited by
`docs/SEAL-CENSUS.md`. This block is generated from
`forensics/downstream/shared-blockers.json` — **do not edit it by hand.**

| blocker class | families | mover potential | fixability | per-fix leverage |
|---|---|---|---|---|
| `no-admitted-recipe` | 965 | 965 | `recipe-admission` | 1.0 |
| `recipe-build-system-unsupported` | 2 | 2 | `recipe-build-system` | 2.0 |

**967 of the 1000 counted families are blocked; 33 are `DROP_IN_PASS`** (967 are `DROP_IN_NOT_APPLICABLE`, 33 measurable). The funnel: 1000 counted → 35 with-admitted-recipe → 33 configured → 33 linked → 8 loaded → 8 runtime → 8 functional → 33 drop-in-pass.

* a selected population is not a random sample: the 1,000 counted families are selected from frozen ranking evidence, so their blocker shares do not generalise to all downstream software
* 1000/1000 is not a security proof: a full pass is not a guarantee that any consumer is safe, and the analysis makes no statement about an unmeasured consumer
* a build is not a functional proof: the configure/link/load rungs are not behaving, and only the functional levels are behavioural evidence
* direct and transitive consumers are different evidence: the two are never summed
* a heuristic ranking is not a measurement of buildability: the feasible recipe queue is ranked by frozen breadth signals, and no family in it has been built by this analysis

<!-- END GENERATED: downstream-blockers -->

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

Which symbols are `SCAFFOLDED` and which are `IMPLEMENTED` — per library — is
generated in [`STATUS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/forensics/STATUS.md)
under "Implementation state"; this page types none of those counts. No symbol is
`PARITY_VERIFIED`; that state is promoted only by a court, dimension by dimension
(`docs/PARITY_MODEL.md`).

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
- **Memory safety is measured, not established.** The memory-safety benefit of
  Rust is not asserted here: the crate still carries a large `unsafe` surface,
  measured per module by `forensics/tools/unsafe_footprint.py` and rendered in
  `forensics/STATUS.md` (58,767 unsafe sites and 10,860 `extern "C" fn` at the
  Phase 18 revision, 90.1% of them in the parser/algorithm modules rather than a
  boundary shim). `docs/UNSAFE.md` cites the generated table and the
  `UNSAFE-FOOTPRINT` growth ceiling; the count is a footprint, not a proof that
  the unsafe code is correct.
- **No universal claims from finite evidence.** Every claim names its authority,
  profile and platform.
- **Unknown is a research result.** `UNKNOWN` is reported, not traded for
  confidence.

See [`NON_CLAIMS.md`](https://github.com/infinityabundance/openssl-rs/blob/main/docs/NON_CLAIMS.md).

## Licence

Apache-2.0 OR MIT. Provenance for any OpenSSL interface material used for
archaeology is recorded in
[`NOTICE`](https://github.com/infinityabundance/openssl-rs/blob/main/NOTICE).
