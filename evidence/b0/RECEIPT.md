# B0 receipt — what is pinned, what is installed, and what is refused

## 1. Identity of this batch

| field | value |
|---|---|
| item | B0 (`docs/ETP-ADDENDUM-B.md` §B.30; section F of `docs/ETP-TODO.md`) |
| branch | `staging` |
| HEAD at the start | `5015b623900f655454d23e55782c0a06c3ead4c9` (`a27: take one finding through every stage, and stop where it stops`) |
| worktree at the start | clean (`git --no-pager status --porcelain` printed nothing) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 34 4 0 7 11` (available **11** GiB); `Swap: 45 42 2` |
| `free -g` before the final suite | `Mem: 45 32 7 0 6 12` (available **12** GiB); `Swap: 45 45 0` |
| court | the already-running `openssl-rs-court`, image `openssl-rs-court-tools:1`, memory cap **6 GiB** (`HostConfig.Memory` and `HostConfig.MemorySwap` both `6442450944`; cgroup `memory.max` `6442450944`), CPU quota **8 cores** (`cpu.max = 800000 100000`), repository at `/work`; reused, not restarted |
| interpreter in the court | CPython **3.11.2** |
| peak court memory observed | 121 MiB of 6 GiB |
| heavy commands | one at a time; no Rust build |

Available memory was 11 GiB before the work and 12 GiB before the final suite,
below the 24 GiB floor `AGENTS.md` §6.1 sets before a build. No build was needed:
every gate is Python, the derived cap (`min(8g, available − 16g)`) is below the
2 GiB floor, and **no new court was started**. The already-running 6 GiB court
was reused and every gate ran inside it. The `docker/` launcher was not modified.

## 2. What was delivered

| path | lines | role |
|---|---:|---|
| `forensics/tools/protocol_audit.py` | 1,280 | the checker: clause extraction, sourced version/date/commit/digest, presence, features, service claims, witnesses, trust assumptions, observation re-reading, freeze members; CLI `registry`, `audit`, `claims`, exit 0/1/2, code always printed; 13 stable codes |
| `forensics/tools/tests/test_protocol_audit.py` | 599 | 69 controls: one per refusal code, every entry sourced, no invented digest, presence cited, the service claim refused, the witness claim refused, the real audit passes, determinism, the producer's byte identity, the CLI exit codes, document synchronisation |
| `docs/PROTOCOL-AUDIT.md` | 328 | the normative document: what is and is not established, the registry and its sources, pinned versus installed, the finding, the tensions, witness availability, the trust assumptions, the refusal table, the non-claims, `NOT_RUN` |
| `evidence/b0/build_evidence.py` | 1,254 | the deterministic producer: parses §B.3.2, joins it with the declared adoption profile, validates with the checker, writes both records |
| `evidence/b0/REGISTRY.json` | 794 | 15 components with source, version, date, commit, artefact, role, features and presence |
| `evidence/b0/SERVICE-CONFIGURATION.json` | 577 | six client-support modules, the finding, three tensions, fourteen claims, five witnesses, six trust assumptions |
| `docs/ETP-TODO.md` | 1 row | the B0 row replaced from `TODO`; no other row touched |
| `evidence/b0/RECEIPT.md` | this file | the receipt |

Content digests (SHA-256, full):

| file | sha256 |
|---|---|
| `protocol_audit.py` | `7e54f4fb6078846a751381e03e4902ac9e889d2c4917469e6f481f34a2d4b1a4` |
| `test_protocol_audit.py` | `0093f76c19d15f879b4c4cccca0607a43f9cd567b218adce6780079378208f6c` |
| `PROTOCOL-AUDIT.md` | `a4e5fead87deffb4fa43a3f0990088ea715f808688a52c46ec45d4b1aeceafb4` |
| `build_evidence.py` | `918ba7ee41aac18b47d6300df682fa2d55a0f71ab23ded3d0c16af6a238ab56d` |
| `REGISTRY.json` | `f863b280e52240efc28ec8ddfaa10a073dbf3058c09685e21ea3593cb75eb7a0` |
| `SERVICE-CONFIGURATION.json` | `403531c121eb1b5849ed6d37c1dda98af23890caaf6084ee1fdc252cc716cfa8` |

The producer stamps both records with the same canonical serialisation the files
carry, so an edit to the producer or the addendum is visible until it is re-run
(`test_the_committed_records_are_the_current_build`).

## 3. The registry

Fifteen components, each with its clause, version, release date, upstream
commit where recorded, role, features and presence:

| family | ids | clause |
|---|---|---|
| `rekor-tiles` tags | `rekor-tiles-v2.0.0` … `rekor-tiles-v2.4.2` (nine) | B.3.2 |
| C2SP specifications | `c2sp-tlog-tiles-v1.0.0`, `c2sp-tlog-checkpoint-v1.1.0`, `c2sp-tlog-cosignature-v1.1.0` | B.3.2 |
| entry representation | `dsse-entry-type-change-v2.3.0` | B.3.2 (features cite B.3.3, B.5) |
| post-quantum mechanism | `ml-dsa-44` | B.3.3 |
| recorded finding | `sigstore-signing-config-v1-endpoint` | B.3.3 |

**One digest is recorded.** §B.3.2 records the `linux/amd64`
`rekor-server-aws` asset of `v2.4.2`:

```
sha256:3af252cd59adea029eea7ff325dee8adb65074e45d0c03aaa6c083eb2461e8a6
```

Every other artefact is `null` with a written reason: the clause records a tag or
a specification version, not an asset digest. No digest is invented, and the
checker refuses any version, date, commit or digest that is not verbatim in its
cited clause.

**Presence is four separate facts**: 14 pinned, **0 installed, 0 executable,
0 services reachable**. `command -v` returned absent for `rekor-server`,
`rekor-cli`, `rekor-tiles`, `cosign`, `sigstore` and `tsget`; only
`/usr/bin/openssl` resolved, and that is a TLS toolkit, not a timestamp
authority. A tracked-path search found no Rekor endpoint, log key or witness
outside `docs/`.

**A gap in the pin itself.** The only recorded digest names the **AWS** server
asset, while §B.3.2 records the **POSIX** backend as the one this project uses
for local and CI instances. The recorded digest therefore does not admit the
server B1 intends to run. B1 must record a digest for the exact artefact it
installs; the AWS digest may not be reused as its identity. This is recorded in
`REGISTRY.json` as a note on `rekor-tiles-v2.4.2` and in §3.2 of the document,
not presented as a passing identity.

## 4. The service-configuration finding

**SCF-1.** The Sigstore `signing_config` inspected on 2026-10-22 advertised a
Rekor **v1** endpoint (§B.3.3 item 2). It is recorded as `RECORDED`, with
`verifiedHere: false`: this item has no network access and did not repeat the
inspection.

The consequence for B1 is stated in the record and the document: B1 may not
assume a v2 endpoint exists, may not inherit one from a client default, must
deploy and pin its own POSIX-backed instance (§B.21), and must read the service
metadata it actually uses (§B.10). A v1 fallback is not admitted.

## 5. Controls

`forensics/tools/tests/test_protocol_audit.py` is **69 tests, 0 failures**. It
holds one control per refusal code:

| code | control |
|---|---|
| `PA_REFUSED_UNSOURCED_VERSION` | an unsourced version, a null version with no reason, an unsourced date, a finding date outside its clause |
| `PA_REFUSED_INVENTED_DIGEST` | a 64-hex digest absent from the clause, and a malformed digest |
| `PA_REFUSED_UNCHECKED_PRESENCE` | installed with no `checkedBy`, with an absent check, and with an unrecorded check |
| `PA_REFUSED_UNSOURCED_FEATURE` | a supported feature with no clause, and a client-support code absent from its module |
| `PA_REFUSED_SERVICE_CLAIM` | a component `serviceClaim`, top-level `serviceReachable`, a verified finding, a resolved tension, a met trust assumption, an established service claim |
| `PA_REFUSED_MISSING_MEMBER` | a missing component, tension, witness class, trust assumption and freeze member |
| `PA_REFUSED_CLAUSE_UNKNOWN` | an unknown clause, and a feature with an unknown clause |
| `PA_REFUSED_WITNESS_CLAIM` | a witness class marked available, and a population above zero in each of its four fields |
| `PA_REFUSED_ENTRY_INCOMPLETE` | an unknown role and an unknown state |
| `PA_REFUSED_DIGEST_UNSTATED` | a null digest with no reason |
| `PA_REFUSED_UNEVIDENCED_CLAIM` | an established claim whose evidence path is absent |
| `PA_REFUSED_OBSERVATION_DRIFT` | a declared count that disagrees with its record and pointer |
| `PA_REFUSED_USAGE` | a malformed and an empty command line |

It also asserts the real registry and service record pass, every version, date,
commit and digest appears in its clause, every client-support code is present in
its module, all five witnesses are unavailable and all six trust assumptions are
unmet, no service claim is established, the checks and the producer are
deterministic, the committed bytes are the current build, the CLI exits 0/1/2 and
the document names every code, component, witness, trust assumption and
`NOT_RUN`.

## 6. Defects found

**Existing records: none contradicted by this item.** Every source record the
service configuration cites re-reads to the value it declares (A9 4, A10 4, A11
211/386/0, A12 0/4/4, A16 0/0/0, A18 0/1/0); the two freeze members are declared
at the exact paths this item wrote; `docs/ETP-TODO.md` was the only existing file
modified and only the B0 status cell changed. No check was relaxed and no other
item's record was modified.

**A gap in the pinned identity, reported rather than repaired.** The only
recorded digest is the v2.4.2 AWS server asset; the POSIX backend this project
uses is a different build. Owning item: **B1**, which must record the digest of
the server it installs. This item does not invent that digest.

**Development defects in this item's own machinery**, recorded because a control
that passes for the wrong reason is the defect this item exists to catch:

* The first producer declared a `claimsMade` evidence path and a trust record
  that pointed at `evidence/b0/REGISTRY.json`. The record did not exist until the
  producer wrote it, so a first run from a clean checkout refused its own output.
  Both now point at records that exist independently (`docs/ETP-ADDENDUM-B.md`
  and `evidence/a16/INVENTORY.json`) and name the registry in prose instead. The
  check was not weakened.
* The first registry listed the same unsupported feature twice for a
  non-adopted tag (the explicit exclusion and the tag's own substance). The
  producer now de-duplicates by feature and clause, and the v2.4.0 leaf type was
  added as its own exclusion rather than being covered only by the combined
  substance. The refusal rules were unchanged.
* The document-synchronisation control first compared case-sensitively against
  non-claim sentences that the document writes with a capital letter. The test
  now compares lower-cased text; the document was not reworded to satisfy the
  test.

## 7. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| 1. memory | `free -g` (host) | before: `Mem: 45 34 4 0 7 11` (available 11 GiB), `Swap: 45 42 2`; before the suite: `Mem: 45 32 7 0 6 12` (available 12 GiB), `Swap: 45 45 0` |
| 1. court and cap | `docker inspect`; cgroup | `6442450944 6442450944 8000000000 running`; `memory.max 6442450944`; `cpu.max 800000 100000`; CPython 3.11.2; peak 121 MiB of 6 GiB |
| 2. whole tools discovery | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 2006 tests in 441.526s`; `OK`; `closure discipline self-test: 7 control groups passed`. The 1,937 pre-existing tests are present (1,937 + 69), none removed, none ignored, no skips reported |
| 3. documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`; `DOCS_EXIT=0` (the named Phase-7 exemption printed) |
| 4. JSON well-formedness | `python3 -m json.tool` on both records | `REGISTRY_JSON_OK`; `SERVICE_JSON_OK` |
| 5. producer, twice | `python3 evidence/b0/build_evidence.py` twice | each: `b0: components=15 pinned=14 installed=0 executable=0 servicesReachable=0 clients=6 witnesses=0 trust=6/unmet codes=NONE`; `sha256sum` before run 1, after run 1 and after run 2 all `f863b280…7eb7a0` (registry) and `403531c1…16cfa8` (service): **BYTE-IDENTICAL** |
| 6. audit | `python3 forensics/tools/protocol_audit.py audit` | `registry components=15 pinned=14 installed=0 executable=0`; `service clientSupport=6 statements=4 envelopes=4 bundles=0 repositories=0 independentlyVerified=0/4`; `finding=SCF-1 state=RECORDED clause=B.3.3 observed=2026-10-22`; `tensions=3`; `witnesses=5 available=0`; `trust=6 unmet=6`; `codes=NONE`; `AUDIT_EXIT=0` |
| 6. claims | `python3 forensics/tools/protocol_audit.py claims` | 14 claim lines (CLM-01…CLM-07 `kind=service established=False`; CLM-08 false; CLM-09…CLM-13 true with an existing evidence path; CLM-14 false), five `witness=… available=False`, six `trust=TA-Bn state=UNMET`, `witnessSet operators=0 keys=0 quorum=None independent=False`; `codes=NONE`; `CLAIMS_EXIT=0` |
| 6. registry | `python3 forensics/tools/protocol_audit.py registry` | 15 `component=…` lines, `components=15 pinned=14 installed=0 executable=0 servicesReachable=0`; `codes=NONE`; `REG_EXIT=0` |
| 7. specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`; `SG_EXIT=0` |
| 8. worktree | `git --no-pager status --porcelain` | `M docs/ETP-TODO.md`; `?? docs/PROTOCOL-AUDIT.md`; `?? evidence/b0/`; `?? forensics/tools/protocol_audit.py`; `?? forensics/tools/tests/test_protocol_audit.py` — nothing else |

After gate 2 ran, the B0 row was replaced and this receipt was written. Both are
documentation/evidence edits. `spec_guard.py check` and `docs_consistency.py`
were re-run after the row edit and pass (gates 3 and 7 above), and the B0 row
introduced no new specification token, so the recorded nonconformance set is
unchanged. A final wording edit to `docs/PROTOCOL-AUDIT.md` (making the A11 reader
vocabulary exact) came after the full discovery; the 69-test module was re-run
against it and passed, and no executable file changed.

## 8. Obligations retained

* **A registry is not a deployment.** No component was downloaded, installed,
  started or configured. A pinned version is not an admitted service.
* **The one recorded digest is an AWS asset.** It does not admit the POSIX
  server B1 must run; B1 owns recording that digest.
* **`RECORDED` is not `VERIFIED`.** The `signing_config` finding is preserved as
  §B.3.3 recorded it; it was not re-observed.
* **`SELF_ISSUED` is not a pass.** A12 records 0 of 4 envelopes independently
  verified. The only root is the A10 test-only HMAC key.
* **Presence is dated.** The observations are 2026-11-24, not a live guarantee;
  the live re-check can only withdraw a positive claim.
* **A null digest is not an absence result.** It is a digest no tracked record
  contains.
* **The registry is not a census of the ecosystem.** It covers the components
  the addendum names plus the change, mechanism and finding the item requires.
* **Currency is not established.** §B.5's security-advisory recheck happens at
  admission and was not run here.
* **The forward freeze remains `OPEN`.** Producing the two declared members
  satisfies their predicate; it does not close the freeze.

## 9. `NOT_RUN`

* Any download, installation, execution or configuration of `rekor-tiles`, a
  Rekor client, `cosign`, a Sigstore client or a witness.
* Any network request, including a fresh `signing_config` inspection.
* Any log-key generation, checkpoint signing or cosignature verification.
* Any RFC 3161 timestamp request or token verification.
* Any witness admission, quorum evaluation or split-view simulation.
* Any independent verification of a real envelope (A12 records 0 of 4).
* Any tile, entry bundle, inclusion-proof or consistency-proof operation.
* The §B.5 security-advisory recheck.
* Independent review, BOUNDARY and SEAL evidence, and the Rust suite (`src/` was
  not modified).

## 10. The forward-freeze members

`evidence/a17/FREEZE-forward.json` declares:

* `b0-registry` — `path: evidence/b0/REGISTRY.json`, predicate "a tracked
  registry names each admitted version, digest and unsupported feature";
* `b0-service-configuration` — `path: evidence/b0/SERVICE-CONFIGURATION.json`,
  predicate "the recorded service-configuration finding".

Both files exist at those exact paths. The registry names every admitted version
with its clause, its digest or a written reason for `null`, and its supported and
unsupported features; the service record carries SCF-1 with its clause, state and
consequence for B1. The two member predicates are satisfied. The freeze itself
remains `OPEN` and is not moved by a member landing; A17 closes it at its own
record.

## 11. Correction (2026-11-25): the A11 and A16 observations were re-read

**Cause.** A11 re-froze its population at the rewritten HEAD
(`b26552e21a7465405ad542edeaef7b9104c0298d`), because every commit id from Phase
5.5 onward changed and the evidence tree had grown since A10. This record
re-reads three pointers into `evidence/a11/SCAN.json`, so two of its declared
observations moved with it.

**Old and new** (`evidence/b0/SERVICE-CONFIGURATION.json`, regenerated by
`evidence/b0/build_evidence.py`, old digest
`403531c121eb1b5849ed6d37c1dda98af23890caaf6084ee1fdc252cc716cfa8`, new digest
`b9257332f8f99ee39b3255642c32375da74ac67d0cf3cc54b9000ac6f4f1655a`):

| pointer | old `equals` | new `equals` |
|---|---:|---:|
| `evidence/a11/SCAN.json#/summary/strictOk` | 211 | **331** |
| `evidence/a11/SCAN.json#/summary/files` | 386 | **506** |
| `evidence/a11/SCAN.json#/summary/refused` | 0 | 0 |
| `evidence/a16/INVENTORY.json#/bundles` | 0 | 0 |
| `evidence/a16/INVENTORY.json#/certificates` | 0 | 0 |
| `evidence/a16/INVENTORY.json#/transparencyLogs` | 0 | 0 |

`evidence/b0/REGISTRY.json` did not change.

**Failing test fixed.** The producer itself refused to write, with
`PA_REFUSED_OBSERVATION_DRIFT`: `A11: evidence/a11/SCAN.json#/summary/strictOk is
211, the record says 331` and the same for `summary/files`. That is the
observation-drift rule working as designed; `protocol_audit` would have refused
the stale record, and
`test_protocol_audit.ServiceRecords.test_the_real_service_configuration_passes`
would have failed. It passes now.

**Retained.** Nothing about the service finding, the pinned stack, the six
clients, the six unmet trust paths or the nine unresolved tensions changed. This
is still a record of what the tree does **not** have.
