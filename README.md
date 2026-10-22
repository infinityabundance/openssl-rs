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

## What is achieved

Measured at the source identity rendered below. Every row names its own
machine-readable evidence; none of them is a claim of completeness.

<!-- BEGIN GENERATED: readme-achievements -->
Source identity: crate version `0.0.31`; `libcrypto.so.3` sha256 `ae1cdd4f6a0e8960480a456a1c42538225b080a36ea83b692d800badf4de4982`; `libssl.so.3` sha256 `bdee7fda78813d4eb90dddd87073fa40dfae0d9e43bf2bbc7d6625553cdac8df`. Derived by `forensics/tools/render_docs.py`; `--check` fails if a block and its evidence disagree.

| Dimension | Result | Evidence |
|---|---|---|
| **Downstream drop-in, Safe-33 cohort** | **33 / 33 families at `L7-functional`**, candidate and authority | `forensics/downstream/runtime-functional-atlas.json` (`body.runs`) |
| **Downstream drop-in, 1000-family corpus** | **111 / 1000 at `L7-functional`**; candidate 111 = authority 111; **0 failed**; 112 loaded; 888 not attempted | same atlas, `body.counts.by_subject` |
| **Library test suite** | **1,747 passing, 0 failing, 42 ignored** | `atlas-refresh/publish-0.0.30.json` |
| **Memory safety: mechanisms** | **5 mechanisms discharged at mechanism scope** — RC-1 refcounting, OB-1 OwnedBuf release state, OB-2 OwnedStr string ownership, OB-3 OwnedCtx/RawCtx context ownership, ERR-1 ERR error-queue ownership and allocator file-coordinate seam | `CAMPAIGN-STATUS.json` (`mechanism_discharges`) |
| **Memory safety: boundaries** | 5 scoped boundary discharges (B23, B25, B27, B28, B29); **B39–B40 independently checked**; B41–B43 batch-checked; B44 author-evidenced | `atlas-refresh/boundary-sweep-*.json` |
| **Memory safety: file census** | **877 files**: 92 `ZERO_UNSAFE`, 18 `BOUNDARY_COVERED`, 761 `PARTIAL` (audited 761/761), 6 `TEST_ONLY`, **0 unaccounted** | `atlas-refresh/unsafe-census.json`, `atlas-refresh/post-census-delta.json` |
| **`SAFE_COMPATIBLE` consumers** | **0 / 33** — no family has a proven dependency closure | `CAMPAIGN-STATUS.json` (`consumers`) |
| **Release** | **0.0.31** on crates.io (2026-10-22), checksum `d574588e…` | `atlas-refresh/publish-0.0.31.json` |
<!-- END GENERATED: readme-achievements -->

### The families at `L7-functional`

<!-- BEGIN GENERATED: readme-l7-families -->
**111 of 1000 counted corpus families are `L7-functional`** — candidate and authority rows agree (111 = 111); 0 failed, 112 loaded, 888 not attempted.

`aircrack-ng`, `apache2-utils`, `appx-util`, `apr-util`, `arm-trusted-firmware-tools`, `axel`, `bannergrab`, `cowpatty`, `curl`, `curl-minimal`, `cyrus-sasl`, `dcap-tunnel-ssl`, `dovecot`, `duo_unix`, `eggdrop`, `elinks`, `epic5`, `exim`, `fetchmail`, `fido2`, `fossil`, `fsverity-utils`, `gensio`, `getdns`, `gmnisrv`, `gostsum`, `haproxy`, `hcxtools`, `hiredis-ssl`, `hitch`, `httperf`, `httping`, `httrack`, `icecast`, `iperf3`, `irssi`, `isync`, `jimtcl`, `jwt`, `kea`, `keepalived`, `kmod`, `ldns`, `lftp`, `libarchive`, `libcoap`, `libesmtp`, `libevent`, `libjose`, `libnetconf2`, `liboauth2`, `librdkafka`, `libre`, `libretls`, `libssh`, `libstrophe`, `libtins`, `libtpms`, `libu2f-server`, `libwebsockets`, `libzip`, `links`, `lua-luaossl`, `lua-sec`, `lynx`, `makepasswd`, `memcached`, `mini-httpd`, `minizip-ng`, `mktorrent`, `monit`, `mosquitto`, `mumble-server`, `net-snmp`, `nginx`, `nmap`, `nrpe`, `nsd`, `opendkim`, `openssh`, `openssh-client`, `openssh-server`, `openvpn`, `osslsigncode`, `partclone`, `proftpd`, `prosody`, `proxytunnel`, `pure-ftpd`, `radsecproxy`, `redis`, `rhash`, `rsync`, `s-nail`, `siege`, `slrn`, `socat`, `sofia-sip`, `squid`, `sslscan`, `sslsplit`, `ssmtp`, `stunnel`, `swtpm`, `tcpdump`, `tinc`, `tnftp`, `u-boot-tools`, `w3m`, `wrk`, `znc`.
<!-- END GENERATED: readme-l7-families -->

Client, server, library, signing, interception, VPN, mail, DNS, IMAP, IRC,
XMPP, FTP, MQTT, Kafka, TPM, SNMP and digest/KDF faces are all represented. Each
was built against this crate's headers and libraries, linked with
`-Wl,--no-as-needed` so the subject libraries are provably loaded, and exercised
by a deterministic local workload with a negative control.

### Memory safety is partial — precisely what that means

This project does **not** claim to be memory-safe yet. The honest ledger is
derived from the receipts:

<!-- BEGIN GENERATED: readme-memory-safety -->
| Status | What it covers |
|---|---|
| **Discharged (mechanism scope)** | **5** — RC-1 shared reference counting; OB-1 OwnedBuf release state; OB-2 OwnedStr string ownership; OB-3 OwnedCtx/RawCtx context ownership; ERR-1 ERR error-queue ownership and allocator file-coordinate seam. Mechanism scope only; not a file-level or consumer-level graduation. |
| **Discharged (scoped boundary)** | **5 receipts** — B23 (`B23-WPKT-1`, `B23-WPKT-2`), B25 (`B25-RL-4`, `B25-RL-5`), B27 (`B26-X1`), B28 (`B27-X2`), B29 (`B29-UI-1`, `B29-UI-2`, `B29-UI-3`). Retained boundaries stay `CONTRACTED`. |
| **Independently checked (not discharged)** | B39–B40 boundary-checked (memory-BIO constructor/destructor, connect-BIO descriptor); B41–B43 batch-checked; B44 **author-evidenced only**. |
| **STOP-class defects** | **0 open** — `B27-X2` (`STOP-CLASS`, B27) **closed by B28**; `NEO-ERR-1` (`STOP_LEVEL`, B33) **fixed in B33**. |
| **Audited but not converted** | **761 `PARTIAL` files**; 761/761 audited, 0 remaining. Audit completion is not discharge. |
| **Not discharged** | Receipt-backed mechanisms still open: `BIO`, `RUNTIME_ALLOC_OWNERSHIP`; `SAFE_COMPATIBLE` remains 0/33. |
| **`SAFE_COMPATIBLE` consumers** | **0 / 33** — no consumer family has a proven dependency closure. |
<!-- END GENERATED: readme-memory-safety -->

The planned conversion order is attacker exposure × eliminability: TLS state
machines and record processing first, then key schedule and targeted AEAD, then
the CMS mechanisms behind the unresolved CVE replays, then ASN.1/X.509 decode
and verification, then ML-DSA, then the remaining provider and algorithm cores.

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

> **Safe-33 conversion status (2026-10-20, reconciled 2026-10-22).** The
> generated blocker block below is frozen at the Phase-24 derivation and is
> superseded for current counts by
> `forensics/downstream/runtime-functional-atlas.json`: it records **101
> candidate and 101 authority `L7-functional` rows**, **102 loaded under each
> subject**, **898 not attempted**, **0 failed**, and **33/33 cohort families
> at `L7-functional`**. For conversion, discharge, test-count and consumer
> claims read
> [`forensics/memory-safety/campaign/safe-c33/STATUS-2026-10-20.md`](forensics/memory-safety/campaign/safe-c33/STATUS-2026-10-20.md);
> `forensics/STATUS.md` is generated and requires regeneration by
> `forensics/tools/render_status.py` before its downstream figures can be
> quoted.

<!-- BEGIN GENERATED: downstream-blockers -->

## Downstream-1000 biggest movers (generated)

Every one of the 1000 counted families, partitioned by its **deepest blocker** and the classes ranked by **mover potential**, with the feasible recipe queue, is in the
[generated report](https://github.com/infinityabundance/openssl-rs/blob/main/docs/PHASE-24-BIGGEST-MOVERS.md) (`docs/PHASE-24-BIGGEST-MOVERS.md`); the same table is cited by
`docs/SEAL-CENSUS.md`. This block is generated from
`forensics/downstream/shared-blockers.json` (the frozen Phase-24 derivation);
**do not edit it by hand.** Its figures describe that frozen plane; current
corpus counts come from `forensics/downstream/runtime-functional-atlas.json`.

| blocker class | families | mover potential | fixability | per-fix leverage |
|---|---|---|---|---|
| `no-admitted-recipe` | 965 | 965 | `recipe-admission` | 1.0 |
| `recipe-build-system-unsupported` | 2 | 2 | `recipe-build-system` | 2.0 |

**Frozen Phase-24 partition: 967 of the 1000 counted families are blocked; 33 are `DROP_IN_PASS`** (967 are `DROP_IN_NOT_APPLICABLE`, 33 measurable); of those 33, 25 were at L4-linked and 8 reached L5 or above in that plane. **Current atlas:** 101 candidate and 101 authority families are `L7-functional`, 102 are loaded under each subject, 898 are not attempted, 0 failed, and the 33-family cohort is **33/33 at `L7-functional`** (`runtime-functional-atlas.json`, `body.counts.by_subject`; restated in `STATUS-2026-10-20.md`). The `drop-in-pass` figure is a baseline-normalized verdict count, not a rung.

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
