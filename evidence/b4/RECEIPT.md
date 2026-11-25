# B4 receipt — a publishable bundle is not a published one

## 1. Identity of this batch

| field | value |
|---|---|
| item | B4 (`docs/ETP-ADDENDUM-B.md` §B.15, §B.16, §B.30): an admitted public-good Rekor v2 profile, only classified release-critical material published, independently executable verification demonstrated |
| status | **`PARTIAL`** — the offline half (policy, classifier, bundle, verifier, controls, measurement) is implemented and gated; **nothing was published**, no endpoint exists, and no external party ran the verifier |
| branch | `staging` |
| HEAD at the start | `dc5855733` (`b3: a campaign may close with failures, not with them missing`) |
| worktree at the start | clean (`git --no-pager status --porcelain` printed nothing) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 36 5 0 3 9` (available **9** GiB); `Swap: 45 45 0` |
| `free -g` before the suite | `Mem: 45 37 5 0 3 8` (available **8** GiB); `Swap: 45 45 0` |
| court | the already-running `openssl-rs-court`, `HostConfig.Memory` = `HostConfig.MemorySwap` = `6442450944` (6 GiB), repository bind-mounted at `/work`; **reused, not restarted** |
| interpreter | CPython 3.11.2 in the court |
| heavy commands | one at a time; no Rust build |

Available memory was below the 24 GiB floor `AGENTS.md` §6.1 sets before a
build. No build was needed or attempted: every gate is Python. The derived cap
`min(8g, available − 16g)` is negative, so **no new court was started**; the
existing 6 GiB court was reused and every command ran inside it. `docker/` was
not modified and no command was retried at a larger size.

## 2. What was delivered

| path | lines | role |
|---|---:|---|
| `forensics/tools/publication.py` | 1,481 | the classifier, the bounded tree scan, `build`, `verify`, `claim`, and the generated bundle verifier; 13 `PB_REFUSED_*` codes |
| `forensics/tools/tests/test_publication.py` | 574 | 49 controls: one per refusal code, the private/unclassified/missing-release/absolute-path refusals, the real bundle, the stripped-environment run, a mutated member, determinism, CLI exit codes, document synchronisation |
| `docs/PUBLIC-TRANSPARENCY.md` | 360 | the normative document: what may be published, the four classes, the refusal table, the bundle and manifest, the verifier, the real counts, the real result, controls, non-claims, `NOT_RUN` |
| `evidence/b4/build_evidence.py` | 1,108 | the deterministic producer of the four records and the bundle; `--check` recomputes and compares bytes |
| `evidence/b4/CLASSIFICATION.json` | produced | the policy, the per-artefact rules, the bounded scan, the counts and the bundle table |
| `evidence/b4/PUBLICATION.json` | produced | what would be published and to which profile; `admittedService: false`, `published: 0`, `externalVerification: PENDING` |
| `evidence/b4/CONTROLS.json` | produced | 14 `control-only` fixtures, 14 fired, one per refusal code (two routes to `PB_REFUSED_UNBOUND_MEMBER`) plus a canary |
| `evidence/b4/VERIFICATION.json` | produced | the two in-venue runs of the bundled verifier in a stripped environment |
| `evidence/b4/BUNDLE/` | produced | 8 members, `MANIFEST.json`, `verify.py`, `verify.sh`, `README.md` |
| `docs/ETP-TODO.md` | 1 row | the B4 row changed from `TODO` to `PARTIAL`; no other row touched |
| `evidence/b4/RECEIPT.md` | this file | the receipt |

Record digests (SHA-256, full):

| file | sha256 |
|---|---|
| `CLASSIFICATION.json` | `04d8b44d04af10a66fb660b5646a4cec9969b163c744cd1af75abfe7a13b2548` |
| `PUBLICATION.json` | `036aeaac24c8c13434c12ef14d71d9254102a65f6169017938c1dc9f68a72244` |
| `CONTROLS.json` | `30d76ee02409f64ba099f9dc105b8d6394f30f36256e1e1cfd715ebba835ab7f` |
| `VERIFICATION.json` | `ed585464f3d47a02c1b49925af813a70a5d41893e0206c555ae52407f4cbe946` |
| `BUNDLE/MANIFEST.json` | `e5fa3dc41704ccf984c5680ba4974f21807f9f6826f51589d0b8add9281977f1` |

## 3. Classification, bundle and result

### 3.1 The policy and the four classes

`evidence/b4/CLASSIFICATION.json` declares exactly four classes —
`PUBLIC_RELEASE_CRITICAL`, `PUBLIC_SUPPORTING`, `INTERNAL_NOT_PUBLISHED`,
`PRIVATE_NEVER_PUBLISHED` — with the default `UNCLASSIFIED`. Precedence is a
private pattern first, then an exact rule, then a named scope, then the default.
A private pattern therefore outranks an exact promotion: a secret-bearing file
cannot be published by naming it. A bundle containing an internal, private or
unclassified artefact is refused, never partially redacted.

### 3.2 The measurement, and its bound

The declared population is the tracked evidence tree at the pinned base commit
`dc5855733` (924 files) plus the bundle under test (9 files) = **933**. Pinning
the commit makes the measurement reproducible.

| measure | value |
|---|---:|
| population | 933 |
| classified | 933 |
| unclassified | 0 |
| private | 0 |
| `PUBLIC_RELEASE_CRITICAL` | 8 |
| `PUBLIC_SUPPORTING` | 6 |
| `INTERNAL_NOT_PUBLISHED` | 919 |
| explicit rule / named scope | 14 / 919 |
| private-reference artefacts (inspected bytes) | 377 |
| absolute-path artefacts (inspected bytes) | 13 |

The bound: 1,200 files, 65,536 bytes per member, 33,554,432 bytes total.
933 files considered and scanned, none skipped, **233 truncated** at the
per-member cap, 22,466,845 bytes read. The classification uses the path and
covers the whole population; the two reference counts are **lower bounds** over
the uninspected tail of those 233 members. `reached: true` because of the
per-member cap.

`0 unclassified` is structural: every tracked evidence directory is named as an
internal scope, so no tracked file falls through. Unclassified can only arise
for a path outside those scopes, and that is what the refusal control exercises.

### 3.3 The bundle

`evidence/b4/BUNDLE/` — 8 members, 4 release-critical, manifest digest
`fd46c75910d0a7b03b2b459894457813b204b037ca54d7d6a7777adb501ba24a`, embedded
policy digest `c2d91666a1823fe6424600380dbefc072d5b93bdcf8c84a999200029855acebd`.

| member | class | bytes | sha256 | source |
|---|---|---:|---|---|
| `members/a9-statement-a8-shard-000.json` | `PUBLIC_RELEASE_CRITICAL` | 714 | `ea67963abf16e9b1e33a86d0eec5e35354f3a890497055867e942eac41d22582` | `evidence/a9/STATEMENTS/a8-shard-000.json` |
| `members/a10-envelope-a8-shard-000.json` | `PUBLIC_SUPPORTING` | 1,130 | `5bf418cc5b014d985199ce9e17cde859647303327f6bbd111279d3ed299503a9` | `evidence/a10/ENVELOPES/a8-shard-000.json` |
| `members/b1-publication.json` | `PUBLIC_RELEASE_CRITICAL` | 3,729 | `765fcdf5a1db612ab43e2d56294ddc48528d0e0e4eabc85ff07244f2d77ab6b9` | `evidence/b1/PUBLICATION.json` |
| `members/a5-admission.json` | `PUBLIC_RELEASE_CRITICAL` | 5,120 | `d4871ec97ae3a27b8ec820896e292429e44b4db4d11d2671a69b9dc0230ddc0a` | `evidence/a5/ADMISSION.json` |
| `members/a17-freeze-forward.json` | `PUBLIC_RELEASE_CRITICAL` | 4,948 | `19b3bd00bcadd8a52332fdc944895edec8f25abd23e796c3aa4cd4d938a9e4f0` | `evidence/a17/FREEZE-forward.json` |
| `README.md` | `PUBLIC_SUPPORTING` | 2,753 | `451d454e9414a4a76d6267154f6686e78f17ea46dcdffe57bd5113c918750e23` | generated |
| `verify.py` | `PUBLIC_SUPPORTING` | 10,378 | `11d74675d00515b1d0a84e383d95346a587210848b31e79373306d2fcf763a36` | generated |
| `verify.sh` | `PUBLIC_SUPPORTING` | 299 | `3bf63f990b974a30315c3260388286eacdca5abd16eba4792f09727043935937` | generated |

The B1 record carries `identity: FIXTURE-1`, a six-leaf test fixture, and a
test-only HMAC-SHA256 checkpoint key; the A10 envelope is test-only in the same
way. The manifest declares `subjectLabels` and the verifier checks each label
occurs in its member.

### 3.4 The in-venue run and the real result

`evidence/b4/VERIFICATION.json` records **two runs** of `BUNDLE/verify.py`, each
from a fresh temporary directory outside the project tree, with an environment of
exactly `PATH`, `HOME`, `TMPDIR`, `LANG`, `LC_ALL` (one `PATH` entry, no
`PYTHONPATH`) under `-I -S -B`. Both exited 0 with identical output; the audit
reported **0 reads outside** the copied bundle, the temporary root, the standard
library and the interpreter directory, and **0 socket or HTTP audit events**.
The recorded outcome is `PUBLIC_BUNDLE_VERIFIED_IN_VENUE` with
`venue: in-venue`, `external: NOT_RUN`.

| claim | state |
|---|---|
| admitted public-good Rekor v2 profile | **not admitted** (no endpoint, log key, client, witness, timestamp or network; the only pinned digest is the AWS asset, not the POSIX-backend server) |
| `admittedService` | `false` |
| `endpoint` | `null` |
| `published` | **0** |
| `externalVerification` | **`PENDING`** |

**No external party has run the verifier.** The in-venue run is a
self-reproduction, not external evidence.

## 4. Controls

`evidence/b4/CONTROLS.json`: **14 `control-only` fixtures, 14 fired**, covering
all 13 refusal codes plus a canary. Every control is marked `controlOnly`; a
control that fires proves the refusal works, not that the substituted form
occurs in the tree.

| control | code observed |
|---|---|
| `unclassified-member` | `PB_REFUSED_UNCLASSIFIED` |
| `private-member` | `PB_REFUSED_PRIVATE_MATERIAL` |
| `internal-member` | `PB_REFUSED_INTERNAL_MATERIAL` |
| `private-reference` | `PB_REFUSED_PRIVATE_REFERENCE` |
| `absolute-path` | `PB_REFUSED_ABSOLUTE_PATH` |
| `unbound-member`, `digest-mismatch` | `PB_REFUSED_UNBOUND_MEMBER` |
| `release-member-missing` | `PB_REFUSED_RELEASE_MEMBER_MISSING` |
| `classification-mismatch` | `PB_REFUSED_CLASSIFICATION_MISMATCH` |
| `publication-without-service` | `PB_REFUSED_NO_PUBLIC_SERVICE` |
| `external-verification-claimed` | `PB_REFUSED_EXTERNAL_NOT_RUN` |
| `manifest-invalid` | `PB_REFUSED_MANIFEST_INVALID` |
| `missing-bundle` | `PB_REFUSED_IO` |
| `usage-error` | `PB_REFUSED_USAGE` |
| `control-valid-bundle` (canary) | `PB_OK` |

Every `build` control records `wroteNothing: true`.

## 5. Defects found

**No defect in an existing record was found or contradicted.** The producer and
the classifier read `evidence/a9/STATEMENTS/a8-shard-000.json`,
`evidence/a10/ENVELOPES/a8-shard-000.json`, `evidence/b1/PUBLICATION.json`,
`evidence/a5/ADMISSION.json`, `evidence/a17/FREEZE-forward.json`,
`evidence/b0/REGISTRY.json`, `evidence/b0/SERVICE-CONFIGURATION.json` and the
pinned base tree. No existing file was edited and no check was relaxed.

**Development defects in this item's own machinery**, preserved because a
refusal that fires for the wrong reason is the defect this item exists to catch:

1. **The first classifier put an exact rule before the private patterns.** A
   path promoted by an exact rule and also matching `*.pem` was returned as
   `PUBLIC_RELEASE_CRITICAL`. Old: exact first, so a promotion could outrank the
   private class. New: private patterns first, so a secret-bearing path cannot
   be promoted by naming it. Found by
   `test_a_private_pattern_outranks_an_exact_public_rule` (observed
   `PUBLIC_RELEASE_CRITICAL`, expected `PRIVATE_NEVER_PUBLISHED`).
2. **Two controls were wrong in a way that made them pass or miss.** The
   classification-mismatch control mutated `members[0]`, which is `README.md`,
   so the downgrade was a no-op and the control observed `PB_OK`; and the usage
   control mapped exit 2 to `PB_OK` instead of `PB_REFUSED_USAGE`. Old/new:
   the mismatch now finds the public member by path; the usage control maps the
   usage exit to its refusal. Both were observed failing before the repair.
3. **The bundle directory was created mode `0700` by `mkdtemp`.** The host
   orchestrator could not read it, so the bundle could not have been committed.
   Old: private mode; new: the staging directory is chmod-ed `0755` before the
   rename. The first attempt to add the fix failed with `NameError: name 'os' is
   not defined`; `os` is now imported.
4. **The absolute-path scan counted JSON pointers as filesystem paths.** Values
   such as `/actions/release/context/evidenceProducer` matched the first
   pattern, inflating the count to 21. New: a value must begin at a conventional
   filesystem root (`/home`, `/Users`, `/root`, `/tmp`, `/var`, `/usr`, `/etc`,
   `/opt`, `/mnt`, `/srv`, `/work`, `/data`, `/proc`, `/sys`, `/dev`, `/run`) or
   a drive letter; the count is **13** and the examples are genuine absolute
   paths (`/usr/bin/openssl`, `/work/court/freeze-b83/review11/miri/sysroot`).
5. **The test helper copied the real bundle while verifying with the synthetic
   policy.** Two controls then observed `PB_REFUSED_CLASSIFICATION_MISMATCH`
   instead of the code they were meant to exercise; the helper now copies the
   synthetic bundle for the synthetic tests and the real bundle for the real one.
6. **The audit recorded `urllib` as a network module.** `pathlib` imports
   `urllib.parse` in the standard library, so a module-name test reported a
   network module with no network access. The audit now records `socket.*` and
   `http.*` audit events plus the `socket`/`ssl`/`http`/`ftplib`/`telnetlib`
   modules, and records **0** events.
7. **The normative document carried a stale manifest digest** after a legitimate
   change to the generated verifier. The digest was corrected and a test now
   asserts the document quotes the current `manifestDigest` and `policyDigest`.

## 6. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| 1. memory | `free -g` (host) | before: `Mem: 45 36 5 0 3 9` (available **9** GiB), `Swap: 45 45 0`; before the suite: `Mem: 45 37 5 0 3 8` (available **8** GiB), `Swap: 45 45 0` |
| 1. court and cap | `docker inspect openssl-rs-court` | `memory=6442450944 memoryswap=6442450944 status=running` (6 GiB), `/work` bind-mounted; reused, no new court, no build |
| 2. whole tools discovery | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 2256 tests in 454.910s`; `OK`; `closure discipline self-test: 7 control groups passed`. The **2,207 pre-existing tests are present** (2,207 + 49 = 2,256), none removed, none ignored |
| 3. documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`; `DOCS_EXIT=0` (the named Phase-7 exemption printed) |
| 4. JSON well-formedness | `python3 -m json.tool` on each created JSON | `json.tool ok` for `CLASSIFICATION.json`, `PUBLICATION.json`, `CONTROLS.json`, `VERIFICATION.json`, `BUNDLE/MANIFEST.json` |
| 5. producer, twice | `python3 evidence/b4/build_evidence.py` twice, then `diff` of every produced file's SHA-256 | `BYTE-IDENTICAL-RUNS`; run 2: `code=PB_OK b4: base=dc5855733 population=933 classified=933 unclassified=0 private=0 privateReference=377 bundleMembers=8 controls=14/14`; `b4: venue outcome=PUBLIC_BUNDLE_VERIFIED_IN_VENUE verified=True external=NOT_RUN` |
| 5. producer check | `python3 evidence/b4/build_evidence.py --check` | `code=PB_OK b4: check ok records=4 bundleMembers=9`; `CHECK_EXIT=0` |
| 6. scan | `python3 forensics/tools/publication.py scan` | `code=PB_OK outcome=SCAN_COMPLETE population=933 base=dc5855733 classified=933 unclassified=0 private=0 releaseCritical=8 supporting=6 internal=919 privateReferenceArtefacts=377 absolutePathArtefacts=13 boundReached=true`; `SCAN_EXIT=0` |
| 6. verify | `python3 forensics/tools/publication.py verify --policy evidence/b4/CLASSIFICATION.json` | `code=PB_OK outcome=PUBLIC_BUNDLE_VERIFIED bundle=BUNDLE members=8 releaseCritical=4 supporting=4 publishable=true venue=in-venue external=PENDING`; `VERIFY_EXIT=0`. **No refusal code fires on the real bundle.** |
| 6. classify | `publication.py classify …` | `path=evidence/a9/STATEMENTS/a8-shard-000.json classification=PUBLIC_RELEASE_CRITICAL rule=publish-evidence-a9-STATEMENTS-a8-shard-000-json`; `path=src/bn/mont.rs classification=UNCLASSIFIED rule=no-rule`; `path=evidence/b4/RECEIPT.md classification=INTERNAL_NOT_PUBLISHED rule=b4-record-RECEIPT-md` |
| 6. claims | `publication.py claim`, `--publish`, `--external-verified` | `code=PB_OK admittedService=false published=0 externalVerification=PENDING`; `code=PB_REFUSED_NO_PUBLIC_SERVICE` (`CLAIM_PUBLISH_EXIT=1`); `code=PB_REFUSED_EXTERNAL_NOT_RUN` (`CLAIM_EXT_EXIT=1`) |
| 7. specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`; `SG_EXIT=0` |
| 8. worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`; `?? docs/PUBLIC-TRANSPARENCY.md`; `?? evidence/b4/`; `?? forensics/tools/publication.py`; `?? forensics/tools/tests/test_publication.py` — nothing else |

The full discovery ran on the final tree, after the code, document and queue-row
edits; only this receipt was written afterwards, and that text changes no code
path or test. No test was removed, skipped, ignored or weakened.

## 7. Obligations retained

* **The profile is described, not admitted.** No endpoint, log key, client,
  witness or trusted timestamp exists; the only pinned digest is the AWS release
  asset.
* **A publishable bundle is not a published one.** It is internally consistent
  and classified for publication; it sits in this repository.
* **The manifest is not self-authenticating.** A rewritten bundle can carry a
  rewritten manifest with a recomputed digest; a recipient must obtain the
  digest through a trusted channel.
* **The in-venue run is not external evidence.** It was run by the producing
  project in the producing venue.
* **A classification is a publication decision**, not a safety, compatibility or
  cryptographic result.
* **`0 private` is a bounded measurement**, not proof that no secret exists in
  the tree.
* **The reference counts are lower bounds** because 233 members were truncated
  at the per-member cap.
* **The 377 scratch-path records and 13 absolute-path records are counted, not
  sanitised.** A future publication must sanitise or exclude them.
* **`0 unclassified` is structural**, from the named internal scopes.
* **The producer is the validator.** The same module produces and checks the
  records; no independent reviewer ran.

## 8. `NOT_RUN`

* **Publication itself**: no admitted public endpoint, log key, client, witness,
  trusted timestamp or network exists. `published` is `0`.
* **Independent verification by an outside party**: the verifier ran in the
  producing venue only; `external` is `NOT_RUN`, `externalVerification` is
  `PENDING`.
* **An admitted public-good Rekor v2 profile**: every B0 service claim is
  unestablished.
* **Log inclusion, a log receipt, a signed checkpoint from an admitted key, a
  witness cosignature**: none exists.
* **Sanitisation** of the 377 records that name a court scratch path and the 13
  that name an absolute path.
* **The uninspected tail** of the 233 truncated members.
* Independent review, `BOUNDARY`, `SEAL` and the Rust suite (no Rust source was
  modified, so no `cargo` command ran).

## 9. Forward-freeze member and worktree

The A17 forward-freeze member `b4-receipt` (`evidence/b4/RECEIPT.md`, predicate
"a receipt records the publication profile and independent verification") is
**satisfied**: this receipt and the four records name the profile, the bundle,
the in-venue run and the `PENDING` external state. The freeze itself was not
closed.

Worktree after this batch: `M docs/ETP-TODO.md`; `?? docs/PUBLIC-TRANSPARENCY.md`;
`?? evidence/b4/`; `?? forensics/tools/publication.py`;
`?? forensics/tools/tests/test_publication.py`. Nothing else. This subagent did
not commit and did not push.
