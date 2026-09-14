# Authority Policy

Status: **constitution** (Phase 0).

An **authority** is an exact, content-addressed OpenSSL build against which
claims are made. A claim is always a claim *of a specific authority, version,
build profile and platform*. Nothing in this project may infer behaviour from
one configure profile and assert it for all builds.

## 1. Admitted authority set

| id | role | version | archive sha256 | source root hash |
|---|---|---|---|---|
| `openssl-3.6.4-production` | production | 3.6.4 | `9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef` | `27d9917bd7c63d9bb056e674cc08c809b44cde50f9e474cd30041b8b66385432` |
| `openssl-3.6.3-historical` | historical | 3.6.3 | `243a86649cf6f23eeb6a2ff2456e09e5d77dd9018a54d3d96b0c6bdd6ba6c7f1` | `b996e7f0e239da1cafc8fd40c94e15032cc07dc5259303e0e5969e325b16d72d` |

- **Production authority**: `3.6.4`. The candidate targets 3.6.4 behaviour.
- **Historical authority**: `3.6.3`, retained because extant downstream
  archaeology (bind9-rs) observed 3.6.3. It exists to explain historical
  residuals and to drive the oracle-vs-oracle trajectory court. It is **not** a
  production target.

The registry is `forensics/authorities/AUTHORITIES.json`. Admission is performed
by `forensics/tools/authority_acquire.py`; the tool **fails closed** — a
checksum mismatch aborts and is never recorded as a successful admission.

## 2. Admission requirements

For every authority, the registry records:

- upstream release identity and series;
- source URL and the upstream-published checksum URL;
- the archive SHA-256, **verified** against the published value;
- the source tree as a per-file SHA-256 manifest plus a root hash;
- the build profile, configure argv, toolchain and platform;
- the build's produced artifacts with sizes and paths.

Re-running admission on unchanged material reproduces byte-identical evidence.

### 2.1 Acquisition hazard (recorded incident)

The initially configured source URL
`https://mirror.openssl-library.org/source/openssl-3.6.4.tar.gz` **served an
HTML page**, not the archive. The mirror's own `/source/` index links the real
release asset on the GitHub release host. Admission caught this in two ways:

1. the artifact hash did not match the published digest; and
2. the archive-magic guard rejected a non-gzip artifact.

Both guards are retained: `validate_archive()` runs before checksum verification
so that a wrong-URL response is reported as a content error, and the checksum
check remains the authoritative gate. The tool never admits a 31 KB HTML page as
a 55 MB source tree.

## 3. Build profiles

A parity claim is **build-profile dependent**. The first admitted profile is:

```
linux-x86_64-default-shared-legacy-notests
  target        linux-x86_64
  shared        yes        (libcrypto.so.3 / libssl.so.3 required for Phase 1)
  legacy        enabled    (legacy provider participates in provider/CLI surface)
  tests         not built  (`no-tests`; the upstream suite is inventoried from
                            source and, where re-run, run as its own court)
```

`no-tests` removes no public symbol and does not change the provider algorithm
inventory; it is recorded in the build record so no claim is ever made about an
unbuilt surface.

An **authority matrix**, not one magical build, is the long-term goal. Planned
additional profiles include:

```
default        no-deprecated       legacy-enabled      FIPS-capable
shared         static              no-asm              platform variants
```

Dimensions are combined with pairwise/combinatorial design plus targeted
exhaustive tests for dimensions known to interact — not a blind Cartesian
explosion. Every receipt binds its exact build profile.

## 4. The court container

All execution happens inside `docker/openssl-rs-court.Dockerfile`, driven by
`docker/openssl-rs-court.sh`. Constraints:

- Base image pinned **by digest**, never by tag.
- OOM protection applied at run time: `--memory` and `--memory-swap` pinned
  equal (so exceeding the cap OOM-kills inside the container rather than
  pressuring the host), plus `--pids-limit` and `--cpus`.
- `--restart=no`: a killed court stays dead.

### 4.1 Known contaminant

A Debian userspace cannot be made free of a non-authority OpenSSL runtime:
`libcurl4` (needed for `curl` and `git`) links `libssl3` 3.0.x. Policy:

- The non-authority **`openssl` CLI binaries are deleted** from the image, and
  the build asserts `! command -v openssl`. (The *package* is not purged, because
  `ca-certificates` depends on it for its trust-store trigger; purging would
  remove the trust store and break HTTPS acquisition.)
- The remaining `libssl3`/`libcrypto3` shared objects are treated as a **known
  contaminant**, recorded with their hashes in `/court/non-authority-openssl.txt`.
- Courts must **prove non-contamination**: any produced artifact whose dynamic
  closure resolves to a non-authority `libcrypto`/`libssl` is a **hard failure**.
  This is the `libcrypto-contamination` court.

This is also the honest modelling of reality: downstream environments *do* have
a system OpenSSL. A candidate that only works when no other OpenSSL is present is
not a drop-in replacement.

## 5. Authority identity is never inferred

- Authority ids are explicit; extending the admitted set is a reviewable act.
- Version profiles are architected from the beginning so later 3.6.x patch
  releases, the 3.5 LTS family, and eventually OpenSSL 4.x can be admitted as
  separate authorities without corrupting existing evidence.
- A claim is never silently generalised across versions, profiles or platforms.
  `docs/RELEASE_GATES.md` §"Future version policy" defines the delta procedure.
