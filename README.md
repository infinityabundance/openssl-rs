# openssl-rs

A native-Rust, **custodian-level** reconstruction of the externally observable
contract of a pinned OpenSSL distribution.

This is not a TLS library inspired by OpenSSL. It is not an OpenSSL wrapper,
binding, or FFI shim. It is not an OpenSSL-shaped façade over `rustls`,
`aws-lc`, BoringSSL, LibreSSL, `ring`, OpenSSL itself, or any other
cryptographic implementation. It is not a subset sufficient for one consumer.

The objective is that **unmodified OpenSSL consumers can compile, link, load,
execute and behave correctly** with `openssl-rs` substituted for OpenSSL — for an
explicitly stated authority, build profile and platform.

## Status

Read **[`forensics/STATUS.md`](forensics/STATUS.md)**. It is generated from the
atlas and receipts, never hand-edited.

At a glance, and *only* for
`openssl-3.6.4-production / linux-x86_64 / linux-x86_64-default-shared-legacy-notests`:

- **Phase 0 (constitution)** — complete.
- **Phase 1 (archaeology / atlas)** — in progress.
- **No product subsystem is implemented, and none is claimed.** The implementation
  crate exists so the archaeology, the court machinery and the product share one
  home, and so that the authority binding is a compile-time fact.

There is no compatibility percentage here. A headline percentage is a derived
quantity that requires proved obligations; Phase 1 generates *what must be
proved*, which is 33,823 obligations for the production authority — not one of
which is `PARITY_VERIFIED`.

## Architecture in one paragraph

One Cargo package. One first-party implementation crate. No workspace, no
component crates; internal modules may be arbitrarily numerous. The single
implementation must still emit the multiple runtime artifacts the distribution
contract requires — `libcrypto.so.3`, `libssl.so.3`, static archives, provider
modules, public headers, pkg-config metadata, the `openssl` executable — with
their own symbol namespaces, SONAMEs and version nodes preserved. See
[`docs/CUSTODIAN_CONTRACT.md`](docs/CUSTODIAN_CONTRACT.md).

## Constitution (Phase 0)

| document | governs |
|---|---|
| [`docs/CUSTODIAN_CONTRACT.md`](docs/CUSTODIAN_CONTRACT.md) | mission, single-crate rule, definition of "custodian compatible" |
| [`docs/PARITY_MODEL.md`](docs/PARITY_MODEL.md) | obligation states, evidence planes, promotion rules, residuals |
| [`docs/AUTHORITY_POLICY.md`](docs/AUTHORITY_POLICY.md) | admitted authorities, build profiles, court container |
| [`docs/SECURITY_DIVERGENCE_POLICY.md`](docs/SECURITY_DIVERGENCE_POLICY.md) | 3.6.3 → 3.6.4 trajectory; no vulnerability reintroduction |
| [`docs/OWNERSHIP_MODEL.md`](docs/OWNERSHIP_MODEL.md) | `get0`/`get1`/`set0`/`set1` and lifetime contracts |
| [`docs/ABI_POLICY.md`](docs/ABI_POLICY.md) | source vs binary compatibility, symbol versioning |
| [`docs/PROVIDER_MODEL.md`](docs/PROVIDER_MODEL.md) | provider architecture; third-party provider court |
| [`docs/FIPS_CLAIMS.md`](docs/FIPS_CLAIMS.md) | FIPS behavioural parity ≠ FIPS validation |
| [`docs/CONCURRENCY_MODEL.md`](docs/CONCURRENCY_MODEL.md) | thread-local state, error queue, model checking |
| [`docs/RELEASE_GATES.md`](docs/RELEASE_GATES.md) | phase order, maturity levels, court taxonomy |
| [`docs/NON_CLAIMS.md`](docs/NON_CLAIMS.md) | what is explicitly **not** claimed |
| [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md) | receipts, determinism, court venue |
| [`docs/UNSAFE.md`](docs/UNSAFE.md) | where `unsafe` is permitted and how it is tested |

## Running things

**Everything executes inside the court container; nothing runs on the host.**

```bash
# build the pinned court image and start it with OOM protection
bash docker/openssl-rs-court.sh build
bash docker/openssl-rs-court.sh up
bash docker/openssl-rs-court.sh verify

# admit + build both authorities, then generate the whole Phase 1 atlas
bash docker/openssl-rs-court.sh exec bash forensics/tools/build_atlas.sh

# prove the atlas is reproducible byte-for-byte
bash docker/openssl-rs-court.sh exec python3 forensics/tools/atlas_receipt.py --verify

# build and test the implementation crate (fmt + clippy + tests)
bash docker/openssl-rs-court.sh exec sh -c 'cd /work && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test'

# FRF trajectory courts + Gemel checkpoints run in a SECOND, separately pinned
# tooling container (see docs/REPRODUCIBILITY.md §1.2 for why)
bash docker/openssl-rs-frf-court.sh up
bash docker/openssl-rs-frf-court.sh exec bash forensics/frf/run_courts.sh
```

The court applies hard resource caps (`--memory=8g --memory-swap=8g`,
`--pids-limit=2048`, `--cpus=8`, `--restart=no`) so that a runaway or
memory-hungry court OOM-kills **inside the container** rather than pressuring the
host. See [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md) §1.

## Phase 1 evidence

```
forensics/
├── authorities/AUTHORITIES.json        admitted authorities, verified hashes
├── authorities/src/                    verified upstream source trees (ignored)
├── authorities/prefix/                 built authorities + installed headers (ignored)
├── receipts/EVIDENCE_RECEIPT.*.json    immutable run receipts
├── STATUS.md                           generated status projection
├── tools/                              atlas generators, all run in the court
├── frf/                                FRF court declarations + reference wrappers
└── atlas/
    ├── BUILD_RECORDS.json
    ├── ATLAS_INDEX.json                per-file hashes + aggregate root hash
    └── openssl-3.6.4-production/
        ├── ATLAS.md                    rendered projection of every document below
        ├── symbols-libcrypto.json      .num vs version script vs DSO exports
        ├── symbols-libssl.json
        ├── symbol-versions.json        version namespaces and ABS markers
        ├── functions.json  typedefs.json  structs.json  enums.json
        ├── variables.json  macros.json    header-graph.json
        ├── abi-layout.json             measured sizeof/alignof/offsetof probes
        ├── ownership-obligations.json   get0/get1/set0/set1/up_ref/free/dup
        ├── provider-inventory.json     providers + algorithm classes
        ├── cli-commands.json           every command and its options
        ├── configs.json  corpus-inventory.json   (per-file, content-addressed)
        ├── surface-reconciliation.json cross-plane agreement + residuals
        ├── coverage.json
        ├── parity-obligations.json     one obligation per contract item
        └── PARITY_MATRIX.md            presentation projection
```

FRF claims and Gemel memory:

```
.frf/                     FRF store: authorities, captures, residuals, receipts, claims
forensics/frf/courts/     four 3.6.3 -> 3.6.4 oracle-vs-oracle trajectory courts
forensics/frf/refs/       authority/candidate reference wrappers
```

The trajectory courts measured the 3.6.3 → 3.6.4 movement directly, and the
result is narrow: the **version banner diverged** (disposed `oracle_version`),
while **digest output, the disabled-feature set and the cipher inventory did
not** — independently corroborating the atlas, which found identical symbol and
algorithm inventories. See `forensics/frf/README.md`.

Authorities admitted and content-addressed:

| id | role | version | archive sha256 (verified) |
|---|---|---|---|
| `openssl-3.6.4-production` | production | 3.6.4 | `9bffaa1a…7333ef` |
| `openssl-3.6.3-historical` | historical | 3.6.3 | `243a8664…c7f1` |

## Non-claims

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

See [`docs/NON_CLAIMS.md`](docs/NON_CLAIMS.md).

## Licence

Apache-2.0 OR MIT. Provenance for any OpenSSL interface material used for
archaeology is recorded in [`NOTICE`](NOTICE).
