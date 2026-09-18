# Reproducibility

Status: **constitution** (Phase 0).

All evidence runs must record enough state to be reproduced. A result that
cannot be re-derived is not evidence.

## 1. Venue

**No authority-bearing execution runs on the host.** Every differential court,
forensic probe, fuzz campaign, benchmark and authority build executes inside an
isolated container. There are **two** venues, kept separate on purpose:

Non-authority environments (including CI runners) may additionally perform pure
implementation-unit tests, static analysis and formatting, and re-derivation of
evidence from already-committed inputs. Those may never contribute forensic
parity evidence — see `docs/CUSTODIAN_CONTRACT.md` §11.

### 1.1 The forensic court — `openssl-rs-court`

The venue for authority builds, the atlas and the implementation crate.

```
docker/openssl-rs-court.Dockerfile   the pinned court image definition
docker/openssl-rs-court.sh           lifecycle + resource caps + exec
```

Pinned by digest:

```
base: debian@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
```

### 1.2 The FRF/Gemel tooling court — `openssl-rs-frf-court`

The venue for FRF courts and Gemel checkpoints. It exists as a *second*
container because the FRF and Gemel binaries are built against glibc 2.39 while
the forensic court is pinned to bookworm (glibc 2.36). Changing the forensic
court's base to accommodate them would invalidate every recorded receipt, so the
venues are separate:

```
docker/openssl-rs-frf-court.sh       lifecycle + resource caps + exec
base: debian@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132
      (debian:trixie-slim, glibc 2.41)
```

Authority binaries are built for bookworm and run forward-compatibly on trixie.
No authority binary is ever executed on the host.

### 1.3 Resource caps (OOM protection)

Applied at `docker run` time, identically for both venues:

| flag | value | purpose |
|---|---|---|
| `--memory` | `8g` | hard cgroup memory cap |
| `--memory-swap` | `8g` | pinned equal to memory: no growth via swap; overrun OOM-kills inside the container |
| `--pids-limit` | `2048` | fork-bomb containment |
| `--cpus` | `8`, clamped to `nproc` | runaway-court CPU containment. Docker rejects a cap above the machine's count, so a smaller machine lowers the cap and the clamp is printed; an explicit `OPENSSL_RS_COURT_CPUS` is clamped the same way, and a non-integer is rejected |
| `--restart` | `no` | a killed court stays dead |

`docker/openssl-rs-court.sh verify` and `docker/openssl-rs-frf-court.sh verify`
assert the caps are in force.

### 1.4 Host containment is enforced, not assumed

The host has a complete toolchain (`clang`, `cargo`, `rustc`, `nm`, `readelf`,
`ar`) and the repository is bind-mounted into the court at `/work`. So a command
mistyped on the host would *look* like it worked, and the only thing preventing
host execution would be care. Care is not a control.

Every build and court entry point therefore sources
`forensics/tools/require_court.sh`, which refuses to continue unless
`/.dockerenv` exists, and exits `97` with instructions. There is deliberately no
override: an escape hatch would be used.

```
bash docker/openssl-rs-court.sh exec bash forensics/tools/build_atlas.sh
bash docker/openssl-rs-court.sh exec bash forensics/tools/build_phase2.sh
bash docker/openssl-rs-court.sh exec python3 forensics/tools/phase3_courts.py
bash docker/openssl-rs-frf-court.sh exec bash forensics/frf/run_courts.sh
```

Note the distinction the guard encodes: files written inside the court appear on
the host through the bind mount, and that is intended -- it is how evidence
persists. It is **execution** on the host that is forbidden.

Because the bind mount is shared, court scratch output must be confined to
`/court` (container only) or to the git-ignored `court/` directory in the
repository, so that raw court material never enters the tracked history.

## 2. Determinism

Derived evidence (the atlas) must be reproducible byte-for-byte from
(a) the admitted authorities and (b) the generator sources. Therefore atlas
files contain **no** wall-clock time, PID, hostname, absolute host path or
environment value. JSON is emitted with `sort_keys=True` and a trailing newline,
and all set-like structures are emitted as sorted lists.

Wall-clock and environment belong in **captures** and **receipts** (the record of
an execution *event*), never in the derived atlas.

Determinism is verified by regeneration, not asserted:

```
python3 forensics/tools/atlas_receipt.py --verify
# hash every atlas file, regenerate, hash again, require byte equality
```

## 3. What a run record contains

Every evidence run records:

- source revision (once version control is initialised);
- candidate binary hash;
- authority binary hash and full runtime closure;
- compiler, linker, target;
- environment and CPU feature state;
- build flags and configure argv;
- config;
- fixture identity;
- court implementation identity;
- comparator and normalizer identity and version;
- result.

Uncontrolled wall-clock dependence is avoided. Where time matters, it is made an
**explicit experiment axis**.

## 4. Normalizers

Raw authority captures are immutable and are **never** rewritten to make
comparison easier. Normalization operates on a separately recorded *comparison
surface* and the original capture is preserved.

Every normalizer must be explicit, versioned, content-addressed, justified,
applied symmetrically, and challenged by negative controls. A difference is
**never** normalized merely because it is inconvenient. Legitimate normalization
is limited to cases such as intentionally random nonces, timestamps or memory
addresses where the court tests a semantic property rather than exact byte
identity — and even then the raw bytes are retained.

## 5. Clean-build test

At every release candidate, prove:

```
clean machine/container
  -> build openssl-rs
  -> install to empty prefix
  -> remove OpenSSL development/runtime packages where possible
  -> inspect dynamic closure        (no hidden OpenSSL runtime dependency)
  -> compile consumers
  -> run courts
```

This prevents accidental oracle contamination.

## 6. Continuous invariants (CI)

At all times:

```
cargo fmt --check
cargo clippy
cargo test
forensic atlas regeneration is clean            (byte-identical)
generated headers are reproducible
parity matrix is reproducible
no stale receipt references
no missing authority hashes
no unexplained symbol drift
no panic across FFI
no hidden OpenSSL runtime dependency
no implementation dependency on prohibited crypto backends
```

Produced binaries are inspected with dynamic-loader tooling. A build that
accidentally links a system `libcrypto` is a **hard failure**.
