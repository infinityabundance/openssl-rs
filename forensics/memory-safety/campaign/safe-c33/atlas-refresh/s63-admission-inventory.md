# S63 phase A — read-only admission inventory

Source HEAD `00f2f5e7e1635f31f852ade2f2eddf80998a666b`; frozen P1000 `1000` families; generator `forensics/tools/downstream_admission_discover.py`.

This inventory is read-only: it built nothing, downloaded no source archive into the repository, and modified no recipe or atlas.

## Population accounting

| status | count | meaning |
|---|---:|---|
| `ADMITTED_RECIPE` | 307 | an admitted recipe exists (complement; not legacy SOURCE-UNREACHABLE) |
| `NO_SOURCE_MAPPING` | 288 | no trustworthy source identity; no URL or hash inferred |
| `NO_ADMITTED_RECIPE` | 403 | source identified from trusted metadata; no recipe yet |
| `ACQUISITION_FAILED` | 0 | a URL was tried and failed, not evidence the source is gone |
| `SOURCE_UNREACHABLE_CONFIRMED` | 2 | recorded evidence shows the source is gone |
| **total** | **1000** | |

The four fine-grained statuses partition the 693 unadmitted families: `NO_SOURCE_MAPPING`=288, `NO_ADMITTED_RECIPE`=403, `ACQUISITION_FAILED`=0, `SOURCE_UNREACHABLE_CONFIRMED`=2.  `ADMITTED_RECIPE`=307 is the already-admitted complement.  Together they sum to 1000.

## Source identities

Debian metadata: `https://snapshot.debian.org/archive/debian/20241001T000000Z/dists/bookworm/main/source/Sources.xz` (origin `snapshot`, suite `bookworm/main`, snapshot `20241001T000000Z`, SHA-256 `7886b608b908d79b9c0012dfbd269975bd6a53c0bf0bd4ede707c8c772bf9e5e`, 34346 source stanzas).

- Debian-metadata identity resolved with a **published** SHA-256: **677**
- Debian-metadata identity resolved but the index published no archive hash: **0**
- No Debian-metadata identity: **323**
- Primary source-identity hash resolved (Debian or recipe pin): **710**; UNRESOLVED: **290**
  Of the 323 without a Debian-metadata identity, **33** are recipe-backed families whose source is not a Debian source package.
- Primary source-identity basis: `debian-sources-index`=403, `recipe-catalogue`=307, `UNRESOLVED`=290

The four fields kept distinct per family are:

- `binary_identity` — frozen family and Debian binary package names
- `source_identity` — source package/archive, version, origin and hash
- `upstream_project` — project homepage/repository/packaging page
- `executable_name` — the family's own program, or `UNRESOLVED` for a library

## Samples by status

### `ADMITTED_RECIPE` (307)

- `family:libssh` — an admitted recipe is recorded in the shared catalogue (recipe:libssh:0.10.6)
- `family:jwt` — an admitted recipe is recorded in the shared catalogue (recipe:jwt:2.1.3)
- `family:coturn` — an admitted recipe is recorded in the shared catalogue (recipe:coturn:4.6.3)
- `family:curl` — an admitted recipe is recorded in the shared catalogue (recipe:curl:8.10.1)
- `family:dnsdist` — an admitted recipe is recorded in the shared catalogue (recipe:dnsdist:1.7.3)

### `NO_SOURCE_MAPPING` (288)

- `family:bind` — no exact Debian binary-package or source-package identity is present in the frozen registry or bookworm/main
- `family:freerdp` — no exact Debian binary-package or source-package identity is present in the frozen registry or bookworm/main
- `family:gitui` — no exact Debian binary-package or source-package identity is present in the frozen registry or bookworm/main
- `family:libcouchbase` — no exact Debian binary-package or source-package identity is present in the frozen registry or bookworm/main
- `family:mariadb-connector-c` — no exact Debian binary-package or source-package identity is present in the frozen registry or bookworm/main

### `NO_ADMITTED_RECIPE` (403)

- `family:cargo` — source identity resolved from the Debian Sources index (cargo 0.66.0+ds1-1); no admitted recipe is recorded
- `family:alpine` — source identity resolved from the Debian Sources index (alpine 2.26+dfsg-1); no admitted recipe is recorded
- `family:borgbackup` — source identity resolved from the Debian Sources index (borgbackup 1.2.4-1); no admitted recipe is recorded
- `family:cargo-c` — source identity resolved from the Debian Sources index (rust-cargo-c 0.9.14-1); no admitted recipe is recorded
- `family:clamav` — source identity resolved from the Debian Sources index (clamav 1.0.5+dfsg-1~deb12u1); no admitted recipe is recorded

### `ACQUISITION_FAILED` (0)

_No family has this status._

No per-family acquisition attempt in the committed evidence failed and remained unresolved in this phase.  S44 records two transient failures (libssh, sslscan) that were retried successfully and are now admitted recipes; those failed URLs are preserved in each family's acquisition_history, not relabelled ACQUISITION_FAILED.

### `SOURCE_UNREACHABLE_CONFIRMED` (2)

- `family:podofo` — the recorded Debian pool directory is absent (no pool directory)
- `family:unrealircd` — the recorded Debian-pool attempt returned 404 and no Debian orig archive exists; upstream was not pinned

## Contradictions (reported, not fixed)

- `prior_source_unreachable_contradicted_by_metadata` — `family:weex`: prior `SOURCE-UNREACHABLE` ("the Debian pool directory carries no orig archive (listing empty); SOURCE-UNREACHABLE without a verified URL") is contradicted by bookworm/main: source `weex` version `2.8.4.2` with published SHA-256 `29db3f990dc332ae003807db28b234e11f791d0bd15281e2d16fac09481ac132`.

Informational notes (not contradictions): `recipe_version_differs_from_bookworm_main`=119.  A recipe and the bookworm/main candidate are allowed to be different releases of the same source package.

## Shared source hashes

- Debian-published hashes shared across different source packages: **0** (asserted; a non-zero count would be a copied-hash defect)
- Recipe-pinned hashes shared by more than one family: **36** groups. These are families that name the same source archive (for example `curl`/`curl-minimal` or `nmap`/`nmap-ncat`), not copied hashes.
  - `c9d69b5ddcf61c3d…` is independently pinned by `family:hcxkeys`, `family:hcxtools` from different URLs: https://deb.debian.org/debian/pool/main/h/hcxtools/hcxtools_6.2.7.orig.tar.gz, https://github.com/ZerBea/hcxtools/archive/refs/tags/6.2.7.tar.gz.

## Unresolved, stated plainly

- Families with no source identity at all: **290**
- Families with a resolved source identity but no hash: **0**
- Families with no executable name in the metadata (library-only or artifact is a shared object): **782**
- Families with no upstream homepage / repository in the frozen registry: **1000** / **1000**.  These fields are `UNRESOLVED`, not guessed from a source package or project name.
- Families with no Debian-metadata identity: **323**
- Ambiguous exact-name matches (kept unresolved, not guessed): `family:serf`

A family absent from bookworm/main is recorded `NO_SOURCE_MAPPING`; the resolver does not turn `bind` into `bind9`, `exim` into `exim4`, or an upstream project name into a guessed GitHub URL.

## Non-claims

- An inventory is not an admission and not a build: a resolved source identity says nothing about whether the family builds or behaves.
- The Debian Sources index is bookworm/main metadata at a pinned snapshot.  A family absent from that suite is not thereby proven absent from every Debian suite or every upstream host.
- A recipe catalogue pin is repository-authored evidence, not Debian-published metadata; the two provenance kinds are recorded separately.
- The four fine-grained statuses describe the unadmitted cohort.  ADMITTED_RECIPE is the complement and is not a claim that the recipe is safe, correct or complete.
