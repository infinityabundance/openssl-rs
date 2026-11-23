# Release Gates

Status: **constitution** (Phase 0).

## 1. Conservation strata (dependency-ordered phases)

Work proceeds in this order. Nothing is permitted to masquerade as complete
before its evidence exists.

| Phase | Conservation stratum |
|---|---|
| 0 | Constitution, authorities, claim algebra |
| 1 | Complete archaeology / API / ABI atlas |
| 2 | Distribution / ABI shell |
| 3 | Core runtime (allocation, threads, ERR, refcounts, ex_data, stacks, objects) |
| 4 | BIO + CONF + object database |
| 5 | BN + ASN.1 + DER/PEM |
| 6 | `OSSL_LIB_CTX` + provider core |
| 7 | EVP framework |
| 8 | Native cryptographic primitives |
| 9 | RAND / DRBG + entropy |
| 10 | Key formats + PKCS + STORE |
| 11 | X.509 + verification |
| 12 | CMS / OCSP / CMP / CT / TS and remaining `libcrypto` families |
| 13 | Legacy / deprecated compatibility |
| 14 | TLS / DTLS (`libssl`) |
| 15 | QUIC / ECH and modern SSL surface |
| 16 | CLI / config / filesystem contract |
| 17 | Downstream replacement court |
| 18 | Hostile fuzz / security / side-channel hardening |
| 19 | Performance / CPU dispatch |
| 20 | 3.6.4 custodian seal |
| 21 | Maintenance delta machinery |
| 22 | Authority exhaustiveness / whole-program compatibility atlas |
| 23 | Multitrack authority compatibility and OpenSSL lineage |
| 24 | Downstream-1000 replacement atlas and empirical drop-in corpus |
| 25 | Memory-safety atlas, unsafe trusted-computing-base census and historical CVE extinction court |

**Phase 25 is dependency-ordered after the downstream-1000 stratum, not after the highest
number.** It is admitted once Phase 24 is complete, and because Phase 24 requires Phase 23 (which
requires Phase 21, which requires Phase 22) the single edge transitively requires the multitrack
authority lineage, the maintenance-delta machinery and the authority archaeology; its crosswalks
additionally read Phase-18 hostile-fuzz evidence and Phase-22 whole-program reachability evidence,
so it depends on Phases 18, 22, 23 and 24. No existing phase is renumbered. The dependency is
declared rather than read off the numbers (`forensics/tools/phase_state.py`'s `REQUIRES`;
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md` section 0).

**Phase 24 is dependency-ordered after the multitrack authority stratum, not after the highest
number.** It is admitted once Phase 23 is complete, and because Phase 23 requires Phase 21 (which
requires Phase 22) the single edge transitively requires the authority archaeology, the
maintenance-delta machinery and the multitrack authority lineage; no existing phase is renumbered.
The dependency is declared rather than read off the numbers (`forensics/tools/phase_state.py`'s
`REQUIRES`; `docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md` section 0).

**Phase 23 is dependency-ordered after the authority archaeology and the maintenance-delta
machinery, not after the highest number.** It is admitted once Phase 21 is complete, and because
Phase 21 requires Phase 22 the edge covers both; no existing phase is renumbered. The dependency
is declared rather than read off the numbers (`forensics/tools/phase_state.py`'s `REQUIRES`;
`docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 0).

**Phase 22 is dependency-ordered out of number order.** Its evidence is the whole-program
archaeology every later implementation stratum leans on -- the X.509 verification engine most of
all -- so it must exist *before* Phase 11 finishes even though it is numbered 22. The dependency is
declared as a DAG rather than read off the numbers (`forensics/tools/phase_state.py`'s `REQUIRES`;
`docs/PHASE-22-SUBPHASES.md` section 8):

    0 -> 1 -> ... -> 10 -> 22 -> 11 -> 12 -> ... -> 21

Phase numbers remain historical names; the dependency is represented by the dependency.

**Not** the start: AES, SHA, RSA, TLS. That feels productive and works against
the architecture.

## 2. Phase exit rule

A phase does **not** end on implementation presence. Each phase ends with:

```
1  authority identity
2  obligation inventory
3  court manifests
4  raw captures
5  residual set
6  mutation / sensitivity evidence
7  resolution runs
8  FRF receipts
9  generated parity projection
10 Gemel checkpoint
```

Any open residual intersecting the claim scope **blocks** the claim.

## 3. Maturity levels

Evidence-backed, machine-enforced exit criteria. These are not marketing names.

```
L0  archaeology complete
L1  source / API shell
L2  ABI-load compatible
L3  libcrypto core semantic parity
L4  provider / EVP parity
L5  complete libcrypto claimed surface
L6  libssl protocol parity
L7  CLI / distribution parity
L8  downstream custodian court
L9  high-assurance custodian seal
```

## 4. Court taxonomy

Stable court families. A court observes **only** dimensions it can actually
detect, and is challenged with seeded mutations:

```
API-HEADER  ABI-SYMBOL  ABI-VERSION  ABI-LAYOUT  ABI-LINK  ABI-LOAD
MEM-OWNERSHIP  ERR-QUEUE  THREAD-STATE  BIO-STATE  CONF  OBJ-NID
BN  ASN1  DER  PEM  PARAM  LIBCTX  PROVIDER-LOAD  PROVIDER-DISPATCH
FETCH-PROPERTY  EVP-DIGEST  EVP-CIPHER  EVP-MAC  EVP-KDF  EVP-RAND
EVP-KEYMGMT  EVP-SIGNATURE  EVP-KEX  EVP-KEM  ENCODER  DECODER  STORE
X509  X509-PATH  PKCS  CMS  OCSP  CMP  SSL-STATE  SSL-WIRE  SSL-CALLBACK
DTLS  QUIC  CONFIG  CLI  DOWNSTREAM  BUILD-MATRIX
libcrypto-contamination
```

## 5. Priority order when the project becomes large

1. fix evidence infrastructure if it cannot observe the required behaviour;
2. fix architectural residuals;
3. fix ownership / error / state / concurrency residuals;
4. complete missing foundational machinery;
5. complete dependent API families;
6. expand hostile cases;
7. expand downstream coverage;
8. optimise.

Trivial APIs are never chosen merely to improve a completion percentage.

## 6. Safety testing

Continuously run appropriate combinations of `Miri`, address/thread/UB sanitizers,
fuzzing, property tests, stress tests and model tests. The **authority may
contain C undefined behaviour; the candidate must not reproduce it** merely
because one observed run yielded a certain result. Such cases are recorded as
compatibility boundaries.

No Rust panic may unwind through a C ABI boundary. Every exported FFI function
establishes an unwind boundary or otherwise guarantees non-unwinding behaviour.

## 7. Security review gates

Before promoting cryptographic families, review for: integer overflow; length
conversions; bounds; parser recursion; secret-dependent behaviour; panic
reachability across FFI; use-after-free; double free; refcount overflow; null
handling; allocator mismatch; unchecked pointer arithmetic; concurrency;
invalid state-machine transitions; provider unload races.

## 8. Future version policy

Seal one authority before moving. For later 3.6.x:

```
admit new authority -> regenerate atlas -> oracle/oracle differential
-> identify added/removed/changed obligations -> implement delta
-> re-run affected courts -> re-run selected global downstream courts
-> emit new receipts
```

OpenSSL 4.x is a major-family transition and gets a **new compatibility
profile**. An OpenSSL 3 receipt is never silently reinterpreted as evidence for
OpenSSL 4.

### Cutting a release of this crate

A release is a **sequence**, and one step of it is not optional: the crate version
is an input to generated evidence. Written down here because the first 0.0.10
attempt skipped step 3 and the `static gates` job's
`gen_frf_courts.py --check` is what caught it — the gate working, and a reminder
that a gate is not a procedure.

Step 0 is `python3 forensics/tools/release_gate.py --candidate "$(git rev-parse
HEAD)" --require-clean --package <etp6-unpacked>` in the court venue. A refusal
stops the sequence; the output is retained. The later steps make the candidate
green on its own account; they do not substitute for the gate.

1. Land the stratum on `main` with the pipeline green (`court/pipeline.sh`, or the
   two CI jobs, which run the same steps).
2. Bump `version` in `Cargo.toml` **and** regenerate `Cargo.lock`, which records the
   crate's own version. `cargo publish --dry-run` refuses a dirty tree, which is how
   the second file was found.
3. Re-run every generator whose output carries the version:
   `python3 forensics/tools/gen_frf_courts.py`. Each court's `version_or_commit` comes
   from `Cargo.toml` through this tool, deliberately — the alternative is 143 YAML
   files edited by hand at every release, and the tool's `--check` is the guard that
   makes skipping it a failure rather than a silent lie. `grep -rl "$(cargo metadata
   --format-version 1 --no-deps | python3 -c 'import json,sys;
   print(json.load(sys.stdin)["packages"][0]["version"])')" .` lists the carriers.
4. `python3 forensics/tools/gen_frf_courts.py --check`,
   `python3 forensics/tools/render_docs.py --check` and `cargo fmt --all --
   --check` locally, so the release commit is green on its own account rather than
   on the strength of CI.
5. Push, and let `main` go green. A red `main` is not a state this project keeps, and since
   D138 it cannot be reached: `main` requires the three CI jobs, requires the branch to be up to
   date, requires a pull request, and enforces that for admins too. So a release lands by opening
   a pull request from the release branch and merging it once the three jobs report.
6. `cargo publish --dry-run`, then `cargo publish`, with `CARGO_TARGET_DIR` outside
   the repository so the packaging target directory does not collide with the
   crate's own.

OpenSSL 4.x is a major-family transition and gets a **new compatibility
profile**. An OpenSSL 3 receipt is never silently reinterpreted as evidence for
OpenSSL 4.

## The release gate (ETP-7)

`forensics/tools/release_gate.py` is the one machine decision a release is
required to pass. It is standard-library Python and refuses by default: an item
whose checker cannot run, whose package was not supplied, or whose evidence does
not exist is a refusal with a named rule, never a skip.

A release candidate passes only when all six items pass:

1. **candidate identity** — `HEAD` is the commit named by `--candidate`, and
   under `--require-clean` the worktree has no uncommitted tracked or untracked
   path (ignored paths excluded), because `cargo publish` packages the working
   tree;
2. **claim set** — `evidence/etp/claims.json` validates under the claim algebra
   and no claim is `CONTRADICTED`, `REFUTED`, or `WITHDRAWN`; no claim is
   `NOT_ESTABLISHED` while a graduation is requested; and no positive verdict
   rests on evidence whose declared state is `WITHDRAWN`, `REFUTED` or
   `NOT_ESTABLISHED`; and no current claim requires evidence that the identity
   triage marks `UNCERTIFIABLE` (`RG_CLAIM_UNCERTIFIABLE_EVIDENCE`) or
   `HISTORICAL` (`RG_CLAIM_HISTORICAL_EVIDENCE`). Both rules name the artefact;
   a `PARTIAL` claim is a current assertion and is included, while a claim
   already refused by its verdict is named once. A `RISK_ACCEPTED` claim (an
   authorised principal decision to proceed with named unresolved obligations)
   is recorded but does not satisfy the claim set as a positive result; a
   `SAFE_COMPATIBLE` verdict without the §7 closure is still refused by the
   algebra (`EG_GRADUATED_WITH_OPEN_OBLIGATION`,
   `EG_GRADUATED_WITHOUT_CLOSURE`), and a reconciliation may not raise a
   contradicted claim to it (`EG_RECONCILIATION_PROMOTION`);
2b. **identity triage** — `evidence/etp-t9/IDENTITY-TRIAGE.json` is present and
   bound to the committed dependency registry. An absent triage is
   `RG_TRIAGE_MISSING`; one bound to another registry, with a class outside the
   closed set, or with counts that disagree with its records is
   `RG_TRIAGE_STALE`. The triage's derivation and residual are described in
   `evidence/etp-t9/IDENTITY-TRIAGE.md` and `docs/EVIDENCE-FRESHNESS.md` §7;
3. **interop receipts** — `courts/phase18/interop/check_receipts.py` holds over
   the evidence (rules R1–R5);
4. **instrument register** — `forensics/tools/instrument_qualify.py check`
   validates the register and every executable control passes in the venue that
   ran it;
5. **external package** — a built ETP-6 package is present and its own
   `verify.sh` (or `etp6_verify.py`) passes; `--package` accepts the unpacked
   root or the `.tar.gz`, and an absent package is `RG_PACKAGE_MISSING` rather
   than "not applicable";
6. **documentation consistency** — `forensics/tools/docs_consistency.py` holds.

```bash
python3 forensics/tools/release_gate.py \
  --candidate "$(git rev-parse HEAD)" --require-clean \
  --package /tmp/etp6-unpacked --json > release-gate.json
```

The command exits `0` only when nothing is refused. Otherwise it prints one line
per refused item naming the rule and the artefact, and exits `1`:

```
REFUSED RG_CLAIM_CONTRADICTED ETP0-CLM-004: verdict CONTRADICTED -- <basis>
REFUSED RG_CLAIM_UNCERTIFIABLE_EVIDENCE ETP0-CLM-034/artifacts/phase25/summary.json: ...
REFUSED RG_CLAIM_HISTORICAL_EVIDENCE ETP0-CLM-029/forensics/.../CLOSURE.md: ...
REFUSED RG_PACKAGE_MISSING -: no --package was supplied; ...
```

The gate's real output on the tree that introduced it is recorded verbatim in
`evidence/etp7/RECEIPT.md`. It refuses, because the committed claim set conjoins
to `CONTRADICTED`; that refusal is the gate working, not a defect in it.

`--self-test` proves the gate refuses each failure class it claims to cover: a
contradicted claim, a positive verdict over withdrawn evidence, an uncertifiable
dependency, a historical dependency, a missing triage, a stale triage, a failing
receipt, an invalid register, a missing package, a failing package verifier and a
documentation inconsistency, plus positive controls for a derived dependency and
the real documentation checker. The self-test calls the real checkers on
constructed fixtures; it does not assert against the current evidence state.

### Release policy

> **A release published without a passing `release_gate.py` run is a policy
> violation.** The gate's output — the identity line, the recorded checks and
> every `REFUSED` line — is retained with the release record (`--json` for the
> machine-readable form). A green CI run is not a release gate; CI is not a
> release and this gate is not a test suite.
>
> The gate is run in the qualified court venue. Its instrument item is
> venue-bound and fails closed elsewhere; running it on a bare host does not
> produce a weaker pass, it produces a refusal.

### Known gap: no automatic enforcement

There is no release script and no tag-triggered `cargo publish` path in this
repository, so the gate is a documented, mandatory **manual** step in the
release sequence above. Nothing in automation currently prevents a maintainer from
publishing without it. The change that would close the gap is a tag-triggered
workflow that (a) runs `release_gate.py` in the qualified court image, (b)
requires the ETP-6 package as an uploaded artefact, and (c) protects the release
tag on the gate's check. That is CI/infrastructure work with its own
justification, and it is recorded here rather than implied to exist.

## 9. Definition of success

The project is successful when, for explicitly stated authority versions, build
profiles and platforms, all of `docs/CUSTODIAN_CONTRACT.md` §6 holds, including
binary substitution where the ABI contract allows, and FRF can compile the parity
claim from immutable receipts. Nothing less is a custodian seal.

When behaviour remains unknown, say `UNKNOWN` with precision. Unknown is a
research result. It is never traded for confidence theatre.

## 10. Earned-trust constitution gate (ETP-T14)

`docs/EARNED-TRUST.md` states the standing commitments this project makes about
claims, one article each. This section wires the constitution into release
policy.

**A release is admissible only when every article whose scope the release enters
is satisfied, and only the gate items below may evidence that satisfaction.** An
article is *covered* by a gate item when that item refuses a condition the
article names in its `Refused when` field, for a release artefact. An article is
not covered by an item that merely mentions the same subject.

| gate item | articles it evidences | what the item refuses |
|---|---|---|
| `gate-1` — candidate identity (`release_gate.py` item 1) | Article 2 | `HEAD` is not the commit named by `--candidate` (`RG_CANDIDATE_UNRESOLVED`, `RG_CANDIDATE_NOT_CHECKED_OUT`), or the worktree is dirty under `--require-clean` (`RG_CANDIDATE_DIRTY`) |
| `gate-2` — claim set (`release_gate.py` item 2) | Article 1, Article 2, Article 3, Article 4, Article 10, Article 11 | the claim set fails its schema or laws (`RG_CLAIMS_INVALID`); a claim is contradicted, refuted or withdrawn (`RG_CLAIM_CONTRADICTED`, `RG_CLAIM_REFUTED`, `RG_CLAIM_WITHDRAWN`); a graduation is requested over `NOT_ESTABLISHED` (`RG_CLAIM_NOT_ESTABLISHED`); a positive verdict rests on withdrawn, uncertifiable or historical evidence (`RG_CLAIM_WITHDRAWN_EVIDENCE`, `RG_CLAIM_UNCERTIFIABLE_EVIDENCE`, `RG_CLAIM_HISTORICAL_EVIDENCE`); the validator also refuses an outrunning verdict, a graduation with an open obligation, a blocked aggregate cell, an unbound or failing `SAFE_COMPATIBLE` closure, a self-declared policy and an unresolved contradiction |
| `gate-2b` — identity triage (`release_gate.py` item 2b) | Article 2, Article 10 | the triage is absent (`RG_TRIAGE_MISSING`) or bound to another registry, with an out-of-set class or counts that disagree with its records (`RG_TRIAGE_STALE`) |
| `gate-3` — interop receipts (`release_gate.py` item 3) | Article 4 | a receipt fails rules R1–R5 (`RG_RECEIPT`): a withdrawal that names no successor, a live receipt marked withdrawn, a non-zero harness exit with no failed-script record, a manifest log that is absent or digest-mismatched, or a count the manifest did not derive |
| `gate-4` — instrument register (`release_gate.py` item 4) | Article 3, Article 8 | the register is absent or invalid (`RG_INSTRUMENT_REGISTRY_MISSING`, `RG_INSTRUMENT`); an executable control fails; a `RECORDED` control is presented as a pass; an instrument entry states no soundness limits, scope, failure modes or disclaimer |
| `gate-5` — external package (`release_gate.py` item 5) | Article 2 | no package was supplied (`RG_PACKAGE_MISSING`), the package cannot be unpacked or verified (`RG_PACKAGE_INVALID`), or its own `verify.sh` fails (`RG_PACKAGE`) |
| `gate-6` — documentation consistency (`release_gate.py` item 6) | none | a hand-written document contradicts generated evidence (`RG_DOCS`), and — through `forensics/tools/docs_consistency.py` — a constitution that cites an article that does not exist, an article with no enforcement and no declaration of that, a rule identifier absent from the tool it credits, or a gate section that does not name every uncovered article (`ET_*` rules) |

`gate-6` is the meta-item: it refuses a broken or miscited mapping. It does not
evidence any article's substance, so it covers no article.

**Articles no gate item covers: 5, 6, 7, 9.** For those, the release gate
evidences nothing. The tools those articles name — `independence.py`,
`spec_guard.py`, `binary_assurance.py`, `hazard_register.py` and
`side_channel_erasure.py` — must be run and their outputs retained with the
release record, but that run is not a release-gate item today. A release whose
claim scope enters one of those articles is therefore **not admissible on the
gate's authority alone**, and closing that gap means adding the tool as a gate
item, not relaxing the article.

The limits stated in the third column are part of each item's scope. An item
listed above evidences its articles only in the respect it states; where an
article names a condition an item does not refuse, the article is enforced by the
tool it names and not by this gate.
