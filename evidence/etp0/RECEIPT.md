# ETP-0 — baseline and trust-gap inventory

Status: **PARTIAL** — the identity freeze and the three inventories are complete;
the reproducibility result is **stale at S** and was not re-run.

Date: 2026-11-22 (UTC).
Task: ETP-0 of `docs/ETP-TODO.md`.
Branch: `staging`.
Source candidate: `9372bb28b2fbe2f71cf2aa2ab501414d45e87d42`.
Worktree at start: clean (`git status --porcelain` empty).

This receipt is a read-only inventory. No file under `src/`, `courts/`, `docker/`
or any existing receipt was modified. The deliverable files are
`evidence/etp0/CLAIMS.json`, `evidence/etp0/TRUST-GAPS.json`,
`evidence/etp0/RECEIPT.md`, and the ETP-0 row in `docs/ETP-TODO.md`.

---

## 1. Frozen source candidate `S`

`S` is commit `9372bb28b2fbe2f71cf2aa2ab501414d45e87d42` on `staging`. Every later
ETP item must name this commit and these tree hashes, or a successor freeze.

Tree-hash rule: sha256 over canonical JSON (`sort_keys`, separators `,` and `:`)
of the sorted `[relpath, size, sha256]` entries, restricted to **tracked files**
(`git ls-files`) under the named path. The rule is the
`atlas_common.content_hash` / `phase7_courts._source_tree_digest` rule applied to
the tracked set, so the digest is reproducible from a clean checkout.

| tree | files | sha256 |
|---|---|---|
| `src`, `Cargo.toml`, `Cargo.lock`, `build.rs` | 893 | `51568028bc902bee1fe3e4cdb5f401c9cf4a66aef501d95a42e2f35bfbd19981` |
| `src` | 890 | `942e89754a4f28eafea9bb05b6d2bddd757810f56c31488c598d2354bcd537ff` |
| `Cargo.toml`, `Cargo.lock`, `build.rs`, `rust-toolchain.toml` | 4 | `f06a5e1f53a30e661df75a30ab845deb3b598a669db8ba295cd2ceb40dd4f2fc` |
| `forensics/tools` (build scripts, verification tools, recipes) | 309 | `a5fefdc660c6d8289519828402a67e0a595cb4721b930611f685fde0ef9520c9` |
| `courts/phase18/timing` | 27 | `fd3c31747b9ebfe699f4346f89d6e027f75e3bb447d9c4e6dcc9a99c455a3745` |
| `courts/phase18/interop` | 48 | `036c83fbf70b08e88bc7341e1fc5d0b306568121aa91dc0d4d9854c362425e39` |
| `courts/phase18` (all; includes the probe source and fixtures) | 303 | `83245ade509cbde30c5c16821e54244985fe8a1f2404c91ce430fd3abe5c4337` |
| `artifacts/phase2/libcrypto.ld` (version script) | 1 | `a358415aced62fd9cf4f64c7b0661c19ed2f0b2a25ed8f517f9eb248a59807cb` |
| `tests` (test definitions outside `src/`; inline tests are covered by `src`) | 2 | `60838cd01afe6529ee322bbd28445cb85159b45465e6bb8a7d9f8c26775afeeb` |
| `docker` | 15 | `1bd35f44fd06a894eb89a5494f2f1b4ce7edc810bd9433c82b9a431142e4899c` |
| `docs` constitution build inputs (`REQUIRED_CONSTITUTION` in `build.rs`) | 13 | `cbd60c73e050eaf1112c69539267446d51f1a8c6e4759fc45e3c83175765fa48` |
| `forensics/authorities/AUTHORITIES.json` | 1 | `707ec86933107eae941f74c727cb677aefd36424428c510c686140b9f12ba12b` |

Tracked-file count at `S`: **13,708**.

Notes:

- `build.rs` reads the thirteen constitution files listed in
  `REQUIRED_CONSTITUTION` under `docs/`, plus the authority registry, so those
  files and `forensics/authorities/AUTHORITIES.json` are the build inputs and
  are hashed above. `docs/ETP-TODO.md` is not read by `build.rs`; the ETP-0 row
  edit belongs to the evidence commit `E`, not to `S`. For completeness, the
  whole `docs` tree at `S` hashes to
  `f3a4f684be38540f762b38f3c840ba760a180b2295834b5316366cb32e69e4ed` over 72
  files; it includes `docs/ETP-TODO.md` and will differ in `E`, and it is not
  part of the build-relevant identity of `S`.
- The `forensics/tools` tree contains 309 tracked files. An unfiltered walk sees
  328 because untracked scratch files exist; only the tracked set is in the
  digest.
- The existing `evidence/baseline-20261120.json` names commit `0500fa9ef` and
  source digest `ca7d39b9` over 888 files. `0500fa9ef` is an ancestor of `S`
  72 commits behind. That baseline is an accurate record of its own commit and
  is **not** an identity for `S`.

---

## 2. Claim inventory

File: `evidence/etp0/CLAIMS.json` — 35 claims, `ETP0-CLM-001` … `ETP0-CLM-035`.

Each claim carries orthogonal fields:

| field | meaning |
|---|---|
| `artefact` | path, introducing commit, last-change commit |
| `property` | identity / compatibility / memory-safety / timing / cryptographic-assurance / reproducibility / consumer-graduation / claim-governance |
| `scope` | subject, population, venue |
| `quantification` | boolean / count / ratio / set, with the value |
| `identity` | bound candidate, commit, artefact digests, binding state |
| `evidence` | cited artefacts, present in Git, reconstructable |
| `verdict` | SUPPORTED / PARTIAL / CONTRADICTED / SUPERSEDED / WITHDRAWN / UNKNOWN, with basis |

Verdict distribution:

| verdict | count | claims |
|---|---|---|
| SUPPORTED | 17 | 001, 002, 003, 006, 007, 010, 018, 019, 020, 021, 024, 025, 026, 027, 029, 031, 034 |
| PARTIAL | 13 | 008, 009, 011, 012, 013, 014, 015, 016, 017, 022, 023, 028, 035 |
| CONTRADICTED | 4 | 004, 005, 030, 032 |
| SUPERSEDED | 1 | 033 |

The authoritative per-claim verdicts are the `verdict.state` fields in
`CLAIMS.json`; the table above is a reading aid, not a generated projection.

The inventory covers, at minimum: `evidence/` claim records, the
`courts/phase18/interop/` receipts and manifests, the
`courts/phase18/timing/` receipts, the Phase-18 registry and seal,
`forensics/phase18-obligations.json`, the safe-c33 campaign ledger and status
documents, the OpenSSH graduation and adjudication records, the runtime-functional
atlas, the Phase-25 summary, the authority registry, and the constitution files
`docs/NON_CLAIMS.md`, `docs/RELEASE_GATES.md` and `docs/FIPS_CLAIMS.md`.

---

## 3. Trust-gap inventory

File: `evidence/etp0/TRUST-GAPS.json` — 37 gaps, `ETP0-GAP-001` … `ETP0-GAP-037`,
each in exactly one class.

| class | count | ids |
|---|---|---|
| contradiction | 7 | 001–007 |
| evidence_not_reconstructable | 8 | 008–014, 037 |
| asserted_without_evidence | 3 | 015–017 |
| identity_mismatch | 8 | 018–025 |
| assumption_not_stated | 5 | 026–030 |
| UNKNOWN | 6 | 031–036 |
| **total** | **37** | |

Top findings by class:

- **Contradiction.** The Phase-18 seal says `all_pass` true and 5/5 obligations
  implemented; the tracked registry says `all_pass` false with
  `HOSTILE-BOUNDARY-REGISTER` failing on 56 bound violations, and the tracked
  ledger says implemented 4 / open 1. The CT threshold is stated as 110, 50 and
  150 percent in different tracked places; the probe source and machine record
  agree on 150. The SAFE_COMPATIBLE graduation coexists with cited closure
  receipts whose `verdict.safe_compatible` is false, a freeze that records
  `not_graduated`, and an independent `NOT ESTABLISHED` adjudication. The cohort
  counter is recorded as both 1/33 and 0/33 in the same ledger, and PROGRESS.md
  says it was not advanced.
- **Evidence not reconstructable.** 1,929 tracked references point at
  `court/tmp/`; `git ls-files court/tmp` returns 0. The T20 reproducibility
  result exists only there. T20 also calls `artifacts/phase2/libcrypto.so.3`
  "committed" although `.gitignore:41` excludes it. The `--distribution` arm
  compiles `artifacts/phase2/shell/libcrypto.shell.rs`, and that directory is
  excluded by `.gitignore:44`; no shell source is tracked. O6 names no log, O9
  cites `/tmp`, and O8 cites `/tmp` and `court/tmp`. The b85c sidecars, predicate
  controls, Miri transcripts and freeze generator are under `court/` and are
  untracked.
- **Asserted without evidence.** T27 names no receipt at all. T29 names no
  receipt and one untracked binary. The constitution's rule that claims are
  generated from evidence is a convention with no tracked checker for
  hand-authored receipts.
- **Identity mismatch.** O4/O5/O11 bind build B to `3c3a68c1`; O7 binds it to
  `ee7fa27c`. The baseline is 72 commits behind `S`. The tracked install DSOs
  were last rebuilt 32 source-touching commits before `S`. The T20 result was
  measured at `abb315a01`, 39 source files before `S`. The runtime atlas binds
  consumer rows to `1c03ec0a`. The campaign ledger is at `afcfdc47e` / 0.0.44.
  The Phase-25 summary is at 0.0.27.
- **Assumption not stated.** The graduation's safety premise depends on reading
  closure `DISCHARGED` as re-audited rather than receipt-covered, and on
  65 `REVIEW_REQUIRED` rows being counted as discharged. The 33/33 L7 statement
  is used as current evidence although 301 of 307 atlas rows are carried forward
  with `candidate_identity_match=false`. The O7 matrix's build B is not bound to
  the tracked consumer artefact. Digest pinning is read as authentication
  although two signatures are unverified. The seal's `all_pass` has no bound
  commit or date.
- **UNKNOWN.** Six questions remain open; each names its settling evidence in
  `TRUST-GAPS.json`. They are: whether the two build-B digests are one build;
  whether reproducibility holds at `S`; whether the tracked install matches the
  `S` source; whether the 116 contract-bounded sites are individually sound;
  whether all four O7 cells ran the same script set; and whether the external
  provider pointer-type obligation is the only ABI residual.

---

## 4. Known-item findings

1. **O7 withdrawal.** Resolved. At commit `cc2e5fa32`, `RECEIPT-o7.json` carried
   `status` `WITHDRAWN` and `withdrawn` true. The current receipt (last changed
   at `5b04fa06f`) records `ESTABLISHED`, `withdrawn` false, and names the
   withdrawn revision as superseded. The four current per-cell receipts record
   `withdrawn` false and carry the cell-level DSO digests. The withdrawal was
   machine-readable, and the old claim was replaced rather than silently
   restored.
2. **`court/tmp/` log paths.** Open. 1,929 tracked references; 0 tracked files
   under `court/tmp/`.
3. **OpenSSH graduation versus `NOT ESTABLISHED`.** Preserved contradiction.
   `SAFE-COMPATIBLE-openssh-b85c.json` records a principal-decided risk
   acceptance; `b85c-adjudication.json` records `NOT ESTABLISHED` at the same
   candidate; the graduation record preserves the dissent and says it is not
   withdrawn or reinterpreted.
4. **T27/T29 evidence.** Open. Neither row names a receipt; T27 names no path;
   T29 names an untracked binary.
5. **DSO digest divergence.** Open. The interop cells link `ee7fa27c`; O4/O5/O11
   name `3c3a68c1`; other claim families name `aaa32f21`, `5d0f9098`,
   `fd25cc9e`, `06b5f338` and `1c03ec0a`. No tracked build record joins them.

---

## 5. Initial threat model

The architecture is a source-to-binary assurance campaign whose evidence is
stored in the same repository as the artefact. The adversary classes below are
the ones this architecture must resist. The table states what each current
mechanism actually covers and what it does not.

| adversary class | current mechanism | what it covers | what it does not cover |
|---|---|---|---|
| operator error | court-gated build scripts; `require_court.sh` refuses host execution with exit 97; §6.1 memory caps | a mistyped command cannot silently compile on the host; builds are bounded | a correct command with the wrong argument; a receipt written by hand; a test run at the wrong candidate |
| selective publication | `MANIFEST`/receipt pair; O11 derives counts from logs; negative controls | a manifest is self-verifying against a published log; omission of a failed script is detectable when the log is present | a producer that never publishes the log; the 1,929 `court/tmp` references; a summary that omits a scope |
| historical revision | append-only-style supersession (`supersedes`, `withdrawn`, preserved dissent) | O7's withdrawal is machine-readable; the graduation preserves the adjudication dissent | silent edits to a tracked receipt; force-push outside the repository's control; prose documents that are rewritten in place |
| artefact substitution | sha256 bindings in receipts; content-addressed copies in the reproducibility recipe | a changed DSO or consumer binary is detectable when the digest is recorded | receipts that name paths but not digests (O6, O7 top level); two different DSOs under one "build B" name (O4/O5/O11 versus O7) |
| instrument false negative | negative controls (O10 7/7; CT control; dudect `cmpnaive`; ASan/TSan canaries) | a control that does not trigger fails the court | a control that is vacuous (O10 records two such controls were found and fixed); an instrument that is insensitive to a defect class it was not challenged on |
| candidate/evidence mismatch | frozen candidate tags, freeze files, `source_head`, DSO digests | the b85c freeze records nine artefact digests and two builds | evidence for one candidate cited for another (baseline at `0500fa9ef`; T20 at `abb315a01`; atlas at `1c03ec0a`; ledger at `afcfdc47e`); the tracked install is 32 source-touching commits old |
| dependency compromise | O2 pins six archives by digest; `AUTHORITIES.json` records the authority checksum | a changed archive is detected when the digest is pinned and verified | Dropbear and PuTTY signatures are unverified; Dropbear's digest is a first-fetch pin; no dependency provenance beyond the pinned archives |
| key compromise | no admitted evidence-signing trust root in the tracked tree | nothing to compromise: no DSSE envelope, Sigstore bundle, Rekor entry or signed manifest is present | no rotation, revocation, expiry or anti-rollback. Addendum A and Addendum B are open; the PEM files under `courts/phase17/fixtures` are test fixtures, not evidence signers. This baseline cannot claim key-compromise resistance |

Honesty constraints that bind every later ETP item:

- **A C-invalid pointer is not silently assumed safe.** The C ABI is valid input
  space plus a documented contract. No receipt in this tree proves that an
  arbitrary invalid pointer is safe, and none may be read as doing so.
- **An unverified dependency blocks `SAFE_COMPATIBLE`.** The O2 pin state and the
  atlas reuse state are dependencies of the OpenSSH and curl consumer claims.
  Until they are discharged or excluded with evidence, the consumer family is
  not graduated.
- **Absence of detection is not proof.** A clean ASan, TSan, Miri, dudect or
  fuzz run is a bounded observation under one instrument. The CT threshold is a
  screen, not a proof of constant-time behaviour. A green differential court is
  not a memory-safety result.

No current mechanism covers: an adversarial evidence producer who controls both
the run and the receipt; a compromised host or compiler; a split view of a
transparency log (none exists); compromise of an evidence-signing trust root
(none is admitted); or a consumer binary rebuilt from different source than the
receipt names when the receipt records no binary digest.

---

## 6. Binary reproducibility — exact scope and current status

The experiment is defined by `forensics/tools/build_reproducibility.sh` and was
measured at HEAD `abb315a01` on 2026-11-21. Its record is
`court/tmp/t20/NOTES.md`, which is **untracked**.

| axis | value |
|---|---|
| measured commit | `abb315a01` (branch `staging`, clean at start) |
| toolchain | rustc/cargo 1.98.1 (`48a229cea`), Debian cc 12.2.0, GNU ar 2.40 |
| venue | `openssl-rs-court` container; the toolchain was re-confirmed at `S` as rustc 1.98.1, cc 12.2.0, ar 2.40, valgrind 3.19.0 |
| build A | `/court/repro/build-a`, `LC_ALL=C.UTF-8`, `TMPDIR=/court/repro/tmp-a`, `HOSTNAME=repro-a` |
| build B | `/court/repro/build-b/nested`, `LC_ALL=C`, `TMPDIR=/court/repro/tmp-b`, `HOSTNAME=repro-b` |
| pinned across both | `SOURCE_DATE_EPOCH=1609459200`, `CARGO_BUILD_JOBS=4`, same image and toolchain |
| path handling | source and target roots remapped to `/build/src` and `/build/target`; C adapters compiled with `-ffile-prefix-map`; `ar` in deterministic mode |
| compared | `libopenssl_rs.a` and the linked `libcrypto.so.3` byte-for-byte; with `--distribution`, the distribution DSO too; whole-file `cmp`, section mapping on any difference |
| result | byte-identical `.a` and `.so`; distribution DSO byte-identical; no byte normalised or stripped |
| recorded digests | archive `acbef482…`; measurement DSO `aaa32f21…`; distribution DSO `5d0f9098…`; `--build-id none` variant `df9807e4…` |

Status at `S`: **stale, not re-run.**

- The recipe archives `HEAD`, so running it at `S` would measure `S`. It has not
  been run at `S`.
- The recorded result is 40 commits and 39 source files behind `S`
  (+4356/−839 between `abb315a01` and `S`). Its digests are not digests of an
  `S` build.
- The distribution DSO named in T20 as "committed"
  (`artifacts/phase2/libcrypto.so.3`) is excluded by `.gitignore:41` and is not
  tracked. The `--distribution` arm also compiles
  `artifacts/phase2/shell/libcrypto.shell.rs`; that directory is excluded by
  `.gitignore:44` and no shell source is tracked. The tracked
  `artifacts/phase2/libcrypto.ld` matches the digest recorded in
  `artifacts/phase2/SHELL_MANIFEST.json`, but the source the link compiles is
  absent from a clean checkout. The tracked install DSO is
  `artifacts/phase2/install/lib/libcrypto.so.3` (`fd25cc9e`), last rebuilt at
  `1e7c221f0`, 32 source-touching commits before `S`.
- Re-running requires two release builds plus (with `--distribution`) two
  shell compiles in the capped court:

  ```
  OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
  OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g \
    bash docker/openssl-rs-court.sh exec bash \
      forensics/tools/build_reproducibility.sh --out /court/repro --distribution
  ```

- No byte was normalised to manufacture a match. The historical 0.0.40/0.0.41
  differential remains unexplained for its own toolchain, as
  `docs/REPRODUCIBILITY.md` records.

This receipt makes no reproducibility claim at `S`. The claim is: the tracked
recipe exists, its variation matrix is explicit, and its last recorded result is
stale at `S`.

---

## 7. Environment and memory discipline (§6.1)

At session start:

```
total 45 GiB  used 17 GiB  free 1 GiB  buff/cache 27 GiB  available 28 GiB
Swap: total 45 GiB  used 13 GiB  free 32 GiB
```

- The 24 GiB guard was met (`available` 28 GiB).
- The computed cap is `min(8g, available - 16g)` = `min(8g, 12g)` = **8g**.
- One light court command was run, not a build:
  `OPENSSL_RS_COURT_MEM=8g OPENSSL_RS_COURT_MEMSWAP=8g` with
  `docker/openssl-rs-court.sh exec`. It returned rustc 1.98.1 (`48a229cea`),
  cc 12.2.0, GNU ar 2.40 and valgrind 3.19.0.
- No compilation, linking or test suite ran on the host. No heavy command ran
  concurrently. No reproducibility build was attempted.

The `free -g` and court readings above are the values observed at the time of
this receipt; they are not a standing guarantee.

---

## 8. Files written and validation

| path | content |
|---|---|
| `evidence/etp0/CLAIMS.json` | 35 claims with orthogonal fields |
| `evidence/etp0/TRUST-GAPS.json` | 37 gaps in six classes, with settling evidence for every UNKNOWN |
| `evidence/etp0/RECEIPT.md` | this freeze, threat model, reproducibility scope and counts |
| `docs/ETP-TODO.md` | ETP-0 row updated to `PARTIAL` with these paths |

Validation performed:

```
python3 -m json.tool evidence/etp0/CLAIMS.json > /dev/null
# exit 0

python3 -m json.tool evidence/etp0/TRUST-GAPS.json > /dev/null
# exit 0
```

A class-count check read both JSON files and compared the declared `counts`
object with the actual array: 3 asserted-without-evidence, 8
evidence-not-reconstructable, 8 identity-mismatch, 5 assumption-not-stated,
7 contradiction, 6 UNKNOWN, total 37.

---

## 9. What this baseline does not establish

1. It does not establish that any consumer family is `SAFE_COMPATIBLE`. The
   graduation record is a principal risk acceptance over evidence whose own
   machine verdicts are false or not established.
2. It does not establish that the project is reproducible at `S`. The recipe is
   tracked; the result is stale, and its distribution arm cannot run from a
   clean checkout because the phase-2 shell sources are untracked.
3. It does not establish that the tracked binaries are the `S` build. They
   predate 32 source-touching commits.
4. It does not establish that the interop matrix, the O11 manifests and the
   timing instruments used one candidate. They name at least two build-B
   digests, and the tree does not reconcile them.
5. It does not establish that the Phase-18 seal is the current state. The seal
   and the live registry disagree.
6. It does not establish cryptographic assurance, constant-time behaviour,
   memory safety, FIPS validation or drop-in compatibility for any scope.
7. It does not resolve any of the six UNKNOWN items. It names the evidence that
   would.
8. It does not audit the source. It indexes claims and their evidence identity.

The next ETP item (ETP-1) can type the claim inventory in
`evidence/etp0/CLAIMS.json`. The first claims it must refuse to type as
`SUPPORTED` are `ETP0-CLM-004`, `ETP0-CLM-005`, `ETP0-CLM-030` and
`ETP0-CLM-032`, which are contradicted by other tracked artefacts at `S`.
