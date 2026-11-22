# Earned Trust Protocol — Addendum B

## Publicly auditable cryptographic transparency

**Rekor v2 · tiled transparency logs · independent witnessing · trusted time ·
permanent scientific accountability**

Repository: `https://github.com/infinityabundance/openssl-rs`
Reference implementation: `https://github.com/sigstore/rekor-tiles`

This addendum is normative and cumulative with the Earned Trust Protocol
(`docs/ETP-TODO.md`) and with Addendum A (SARIF / DSSE / in-toto / SLSA /
Sigstore, section E of the queue). It extends the assurance architecture without
weakening any established requirement concerning correctness, memory safety,
compatibility, formal verification, independent reproduction or evidence
integrity.

Status vocabulary is inherited: `TODO`, `IN_PROGRESS`, `PARTIAL`, `DONE`,
`BLOCKED` (with the blocker), `NOT_APPLICABLE` (with the reason). The execution
queue for this addendum is section F of `docs/ETP-TODO.md`; the identifiers there
(`B0`–`B8`) come from §B.30 below and are distinct from the `Tn` identifiers of
section B (timing safety).

---

## B.1. Mission

Establish a cryptographically accountable, independently auditable and durably
reconstructable public history of this project's security-critical evidence and
release claims.

The architecture shall make unauthorised historical revision, artefact
substitution, concealed contradictions, selective evidence publication, rollback
and conflicting release histories detectable under explicitly declared
assumptions.

The project shall not merely publish conclusions. It shall publish authenticated
commitments to the evidence and procedures from which those conclusions were
derived.

Trust must be independently earned across time, not merely at the moment of
release.

---

## B.2. Constitutional distinctions

The following distinctions are permanent and bind every artefact, receipt,
report, commit message and review in this programme:

| # | distinction |
|---|---|
| 1 | authentication is not truth |
| 2 | inclusion is not completeness |
| 3 | inclusion is not consistency |
| 4 | consistency is not global non-equivocation |
| 5 | witness approval is not substantive code review |
| 6 | timestamp validity is not experiment validity |
| 7 | public commitment is not public evidence availability |
| 8 | historical authenticity is not present authorisation |
| 9 | log availability is not evidence availability |
| 10 | cryptographic accountability is not software correctness |

No transparency result may substitute for an unresolved implementation or
verification obligation. A transparently published incorrect claim remains
incorrect.

---

## B.3. Research and standards baseline

### B.3.1. Instruments to study, pin and incorporate

- Rekor v2 and its supported client protocols.
- Tessera, the tile-backed transparency-log infrastructure.
- C2SP tiled transparency logs.
- C2SP transparency-log checkpoints.
- C2SP signed notes.
- C2SP offline transparency proofs.
- C2SP witness protocol and cosignature formats.
- C2SP transparency-log trust policies.
- RFC 6962 Merkle-tree construction, where referenced by the adopted protocol.
- RFC 9162 Certificate Transparency auditing principles.
- RFC 3161 trusted timestamping.
- RFC 5816 timestamp-token updates.
- RFC 4998 Evidence Record Syntax and long-term evidence-preservation
  principles.
- Sigstore bundles and trusted-root distribution.
- The Update Framework.
- Sigsum and independent transparency-witness architectures.
- Research on collective witnessing, split-view attacks, software transparency
  and secure software distribution.

An immutable, versioned standards registry records for each adopted mechanism:
the exact properties adopted, the implementation location, unsupported features,
the conformance tests, and the known limitations.

Different transparency protocols do **not** use interchangeable leaf formats,
checkpoint encodings or signature domains. No encoding is reused across
protocols on the assumption that "a Merkle proof is a Merkle proof".

### B.3.2. Pinned baseline as observed on 2026-11-22

The values below were read from the upstream release and specification pages on
that date. They are a **starting** identity, not a permanent one: §B.5 requires a
recheck against the admitted release and its security advisories before any
implementation step.

`sigstore/rekor-tiles` releases:

| tag | date | commit | substance relevant here |
|---|---|---|---|
| `v2.4.2` | 2026-11-10 | `a30bd31` | latest; reverts identity-log `extraData` to `string:string` and a hex context digest — a **breaking** change confined to identity-serve mode |
| `v2.4.1` | 2026-10-30 | `14044fd` | ML-DSA Tink keyset support in the upstream Sigstore library |
| `v2.4.0` | 2026-10-26 | `16bc64c` | new leaf type and ML-DSA signatures, explicitly **experimental**; identity-based transparency API and `serve-identity`; pure Ed25519 rejected in `hashedrekord`; signature algorithms restricted |
| `v2.3.0` | 2026-06-10 | `fa390b1` | **DSSE entry type dropped**; all Sigstore SDKs upload DSSE as `hashedrekord` |
| `v2.2.1` | 2026-02-19 | `e028746` | large-leaf corruption fix; signature and verifier limits |
| `v2.2.0` | 2026-02-06 | `d76764d` | AWS backend; GCP CloudSQL + GCS backend |
| `v2.1.0` | 2026-01-16 | `69bc24a` | **POSIX storage backend** — the backend this project uses for local and CI instances |
| `v2.0.1` | 2025-11-10 | `266d249` | **log witnessing enabled** |
| `v2.0.0` | 2025-10-10 | `f231500` | tile-backed redesigned log |

Release-asset digests are recorded per artefact at admission time; the
`linux/amd64` `rekor-server-aws` asset of `v2.4.2` was published as
`sha256:3af252cd59adea029eea7ff325dee8adb65074e45d0c03aaa6c083eb2461e8a6`
and is the identity against which a downloaded server binary is checked before
execution. No binary is executed without its recorded digest.

C2SP specifications, all at version date 2026-10-07:

| spec | version | what it fixes |
|---|---|---|
| `c2sp.org/tlog-tiles` | v1.0.0 | static resource layout, tile geometry, entry bundles, pruning |
| `c2sp.org/tlog-checkpoint` | v1.1.0 | checkpoint body, note signature algorithms |
| `c2sp.org/tlog-cosignature` | v1.1.0 | checkpoint and subtree cosignature inputs, monotonicity |

Facts that bind the implementation and are therefore recorded here rather than
rediscovered later:

- Merkle hashing is SHA-256, constructed as in RFC 6962 §2.1. A tile at level
  `l`, index `n` holds the 256 hashes
  `MTH(D[(n·256 + i)·256^l : (n·256 + i + 1)·256^l])` for `i` in `0..=255`. A
  full tile is exactly 256 hashes, 8,192 bytes.
- Tile paths are `<prefix>/tile/<L>/<N>[.p/<W>]`; `<N>` is encoded as zero-padded
  3-digit path elements of which all but the last begin with `x`
  (`1234067` → `x001/x234/067`); `<W>` is the partial-tile width, 1–255. Entry
  bundles are `<prefix>/tile/entries/<N>[.p/<W>]` and are sequences of
  big-endian `uint16` length-prefixed entries.
- Checkpoint resources are `text/plain; charset=utf-8`; tile and bundle
  resources are `application/octet-stream`, immutable, long-lived cacheable.
  Resources **must not** serve redirects; a log may expose several prefixes that
  must serve the same content up to propagation delay.
- A checkpoint body is exactly three mandatory lines — origin, tree size as
  ASCII decimal, base64 root hash — followed by optional extension lines, an
  empty line and one or more note signature lines.
- A checkpoint cosignature signs an eight-byte big-endian POSIX timestamp
  concatenated with the signature value over (origin, size, hash); checkpoint
  cosignatures must be monotonically increasing in tree size. The Ed25519
  *log* signature carries no timestamp; the Ed25519 *cosignature* input begins
  with the domain-separation line `cosignature/v1` then `time <N>`.
- The ML-DSA-44 cosignature input is a `CosignedSubtree` structure labelled
  `subtree/v1\n\0`. Its key id is
  `SHA-256(name || "\n" || 0x06 || pk)[:4]`; the Ed25519 cosignature key id uses
  `0x04` and a 32-byte key.

### B.3.3. Recorded tensions (not defects, not resolved by preference)

1. **ML-DSA-44 is recommended by C2SP for new deployments, and is experimental
   in the implementation.** `c2sp.org/tlog-checkpoint` v1.1.0 states that ML-DSA-44
   checkpoint cosignatures *should* be used; `rekor-tiles` v2.4.0 introduces
   ML-DSA support and explicitly labels the related mode experimental and
   subject to breaking change. §B.26 therefore keeps post-quantum mechanisms on
   a separately tested research track; §B.3.3 records that this is a deliberate
   divergence from the C2SP recommendation, reversible only when the
   implementation's own stability claim changes.
2. **Service configuration is not implied by client version.** The Sigstore
   `signing_config` inspected on 2026-10-22 still advertised a Rekor **v1**
   endpoint. Installing a recent client does not activate a v2 log. §B.10
   requires the authenticated service metadata to be read and recorded.
3. **Entry representation.** Older documentation still describes a dedicated
   DSSE entry type. Since `v2.3.0` there is one supported representation, and
   DSSE statements are published as `hashedrekord`. The protocol-required digest
   for that representation must be the one the admitted client computes from the
   exact DSSE envelope; §B.5 forbids substituting the envelope JSON, the payload
   alone, or an unrelated manifest hash.

---

## B.4. Architectural boundaries

Rekor integration is implemented entirely **outside** the delivered OpenSSL-RS
runtime. No transparency, networking, signing or evidence-processing dependency
enters `libcrypto` or `libssl` in order to support assurance infrastructure.

Distinct layers are maintained, and a layer never becomes the authority for a
property that belongs to another:

1. native observations and formal proofs;
2. SARIF findings;
3. authoritative obligation ledgers;
4. content-addressed evidence manifests;
5. in-toto statements;
6. DSSE authentication;
7. Rekor transparency publication;
8. trusted timestamping;
9. witness and monitor observations;
10. independent archival;
11. ETP policy evaluation;
12. release acceptance and revocation.

The transparency service is never an authoritative source of substantive
security verdicts.

---

## B.5. Rekor v2 protocol conformance

A specific, reviewed client and server compatibility profile is admitted, with
its version and digests recorded. Before implementing against it, the supported
release and its security advisories are rechecked.

The breaking changes introduced in `v2.3.0` are accounted for explicitly.

For the conventional Rekor v2 service:

- the supported `hashedrekord` representation is used, with its exact API
  version read from the admitted client rather than from documentation;
- DSSE remains the attestation **authentication** format;
- for a DSSE submission, the protocol-required digest is derived from the exact
  DSSE Pre-Authentication Encoding, as the admitted client derives it;
- the original envelope signature and the appropriate signer verification
  material are bound;
- the hash and signature algorithms are those the admitted profile permits —
  for `v2.4.x` that excludes pure Ed25519 in `hashedrekord`;
- the log entry's original serialised representation is preserved;
- kind, API version, subject binding and signature material are verified.

Implementation against obsolete examples that describe a dedicated DSSE log
entry is forbidden. Unsupported signature algorithms are not introduced, and
pure Ed25519 is not confused with Ed25519ph.

Established, maintained Sigstore implementations are preferred over bespoke
cryptographic protocol implementations.

---

## B.6. Cryptographic inclusion verification

For every required transparency registration, the following are verified, in
this order:

1. admitted log identity;
2. authorised checkpoint-signing key;
3. checkpoint origin;
4. checkpoint signature;
5. authenticated tree size and root hash;
6. exact leaf representation;
7. leaf index;
8. correct Merkle hashing and domain separation;
9. inclusion-proof validity;
10. the binding between the log entry and the original authenticated statement.

The authoritative tree size and root hash are derived from the **verified
checkpoint**, never from duplicated unsigned response fields. Contradictory
duplicated fields are rejected where the local semantic profile requires it.

Malformed proofs, unsupported entries, invalid indices, incorrect digest
lengths, truncated data, integer overflow and mismatched identities fail closed.

Enough data is preserved to repeat the verification entirely offline. A
successful submission response is not sufficient: inclusion must be
independently verified.

---

## B.7. Checkpoint and consistency verification

A persistent, rollback-resistant inventory of accepted checkpoints is maintained
for each admitted log shard. For every transition:

- log identity is correct;
- both checkpoints are authentic;
- tree sizes are correctly ordered;
- the consistency proof is valid;
- roots are equal when tree sizes are equal;
- the applicable freshness policy holds.

A smaller tree must not silently replace a later accepted checkpoint. An
equal-size checkpoint with a different authenticated root is an **equivocation
incident**. A larger checkpoint without a valid consistency relationship to the
previously accepted one does not automatically receive append-only assurance
credit.

Cryptographic contradiction is distinguished from missing proof material,
temporary unavailability and operational failure. Conflicting signed checkpoints
and their verification records are preserved as independently examinable
incident evidence.

Checkpoints from distinct shards are never compared as though they belonged to
one Merkle tree.

---

## B.8. Tiled verification and independent proof reconstruction

Independently executable tile-reading and proof-reconstruction tooling is
implemented or integrated. It accounts for:

- full and partial tiles;
- entry bundles;
- exact leaf ordering;
- tile and bundle encodings;
- boundary conditions at tile transitions;
- tree growth;
- historical checkpoint reconstruction;
- shard retirement and pruning;
- network interruption;
- malicious or inconsistent mirrors.

Downloaded tiles are untrusted until their cryptographic relationship to an
authenticated checkpoint is verified. Independent observers can reconstruct
inclusion and consistency proofs without trusting the log operator's
proof-generation code.

Required historical proof material is preserved before it becomes unavailable
(see also §B.7 pruning semantics: the minimum index moves, the indices and
hashes do not).

Ordinary verifiers are not required to download the entire public log: compact
proofs serve ordinary verification, and dedicated monitoring infrastructure
serves wider auditing.

---

## B.9. Trusted signing time

Rekor v2 does not provide the Rekor v1 integrated-time trust mechanism. An
`integratedTime` of zero, a Git timestamp, a CI timestamp or a checkpoint's local
observation time is **not** authoritative signing time.

An admitted RFC 3161 timestamp authority is used. The following are verified:

- timestamp-token signature;
- message-imprint algorithm and digest;
- binding to the required signature or artefact material under the admitted
  Sigstore profile;
- TSA certificate chain;
- appropriate timestamping extended key usage;
- certificate validity at the relevant time;
- timestamp policy, where applicable;
- nonce correspondence, when used;
- relevant revocation and historical-validity requirements.

The following times are recorded separately and never conflated:

1. source creation;
2. experimental execution;
3. evidence production;
4. statement authentication;
5. trusted timestamping;
6. transparency inclusion;
7. witness observation;
8. release promotion;
9. subsequent correction or revocation.

Experiment execution time is never inferred solely from a later timestamp. For
historical evidence imported into this architecture, the original claimed
execution date is preserved and the actual contemporary authentication and
publication event is recorded separately. A transparency commitment is never
backdated.

---

## B.10. Service discovery and shard lifecycle

Authenticated Sigstore SigningConfig and TrustedRoot metadata are used,
including the applicable TUF validation. An active Rekor shard URL is never
hardcoded as a permanent trust assumption.

Multiple log instances, overlapping validity periods, key rotation, retired
shards and migration between supported protocol versions are supported.

Recorded per log: origin, checkpoint key identity, operator identity, protocol
version, applicable validity interval, trust-metadata identity, shard identity,
and the relevant historical verification material.

The default public signing configuration is **not** assumed to select Rekor v2.
Authenticated service metadata and client behaviour are verified. Where a
separately configured v2 endpoint is required, its authorisation is established
explicitly from independently trusted information.

A weaker protocol profile is never adopted by silent fallback. A shard
transition is not an extension of the old shard's Merkle tree; project-level
continuity across shard transitions is carried by authenticated campaign and
release-manifest relationships.

---

## B.11. Independent witnessing

Interoperable transparency-log witnessing is adopted wherever supported.
Witnesses verify log authenticity and consistency with previously accepted
state before cosigning new checkpoints.

Explicit witness policies identify:

- authorised witness keys;
- independent administrative domains;
- quorum requirements;
- supported logs;
- freshness requirements;
- persistence and recovery requirements;
- assumed compromise tolerance.

Multiple keys belonging to one operator are not independent witnesses, and
witness signatures are not independent software verification. The actual
cosignatures present in the verified proof are used, not an assumed policy.

If the public service does not provide the required witness support, the
witness-dependent property is marked pending or unsupported. Witness assurance
is never manufactured by operating several services under one maintainer
account.

Quorum-intersection requirements are investigated formally. A fixed population
of three independent witnesses with a two-witness threshold does **not**
guarantee that conflicting quorums share an honest witness when one may be
malicious; a three-of-four policy does, under a model permitting at most one
compromised witness, given correct persistence, log-identity binding and
protocol behaviour. A threshold count is never presented without its security
assumptions.

---

## B.12. Independent monitoring

A project-specific transparency monitor:

- tracks admitted log shards;
- verifies checkpoints and consistency transitions;
- detects unexpected signing identities;
- detects conflicting release statements;
- detects unauthorised policy transitions;
- tracks registered campaign commitments;
- reconciles campaign-open and campaign-close records;
- detects overdue or abandoned campaigns;
- monitors corrections and revocations;
- detects repeated publication of obsolete but previously authentic assertions;
- reports stale or unavailable evidence.

Rekor v1 search APIs are not relied upon: Rekor v2's core interface does not
provide equivalent online search and arbitrary proof lookup. A derived project
index is constructed from authenticated evidence manifests and verified log
observations. That index is a convenience, never an authority. Its coverage and
monitoring gaps are documented.

A monitor that has observed only a subset of a log cannot assert complete global
observation. Checkpoint continuity and monitor-coverage receipts are published.

---

## B.13. Preregistered verification campaigns

An authenticated campaign-opening commitment is introduced. Before a
release-critical verification campaign executes, the following are frozen and
published:

- candidate identity;
- production artefact scope;
- requirements;
- threat model;
- applicable assumptions;
- required verification activities;
- test and instrument populations;
- mutation controls;
- statistical acceptance criteria;
- permitted exclusions;
- verification resource limits;
- applicable adjudication policy;
- required independent roles;
- campaign completion expectations.

The exact opening manifest is preserved, authenticated with DSSE, and published
with its required transparency commitment **before** the campaign activities for
which temporal preregistration is claimed.

The committed design is not changed retrospectively. Where methodology must be
amended, an authenticated amendment references the original plan, explains the
change and identifies the affected activities.

Preregistered verification is distinguished from exploratory research.
Exploratory work remains valuable and must not masquerade as preregistered
confirmation.

---

## B.14. Campaign closure and omission resistance

At completion, an authenticated reconciliation manifest reconciles every
preregistered requirement and activity against actual results, accounting for
each of: `PASS`, `FAIL`, `BLOCKED`, `UNKNOWN`, `UNSUPPORTED`, `INCONCLUSIVE`,
`NOT_RUN`, authorised exclusion, superseded activity, abandoned activity.

Each executed activity is bound to its raw evidence and applicable receipt.

No required activity may disappear between opening and closure. A closure record
that omits an applicable failed experiment is **refused**, even when its
signature and inclusion proof are valid.

Explicit relationships are maintained among opening commitments, amendments,
execution events, closure records, adjudications and release decisions. Every
registered campaign requires an authenticated closure or explicit abandonment.
An incomplete campaign remains visibly incomplete.

This architecture supports accountability for declared verification activities;
it does not prove that no undisclosed experiments exist.

---

## B.15. Publication policy

Transparency commitments are required for applicable:

- release source manifests;
- production artefact manifests;
- build provenance;
- reproducibility results;
- campaign-opening records;
- campaign-closing records;
- independent adjudications;
- external reproduction attestations;
- `SAFE_COMPATIBLE` promotion decisions;
- high-assurance claim promotions;
- material corrections and retractions;
- release withdrawals;
- trust-policy transitions;
- historical evidence migration manifests.

Content-addressed aggregation avoids unnecessary external log entries: a signed
campaign manifest may commit to thousands of individual evidence objects while
their inclusion and complete enumeration remain independently verifiable.
Manifest construction and object identities are deterministic.

High-frequency developmental observations remain local unless policy requires
their public registration. Public-good infrastructure is not flooded with
redundant per-test or per-function entries; upstream service limits, terms and
operational expectations are respected.

---

## B.16. Confidentiality and irreversible publication

Every transparency-log submission is treated as potentially permanent and
public. The following are never submitted:

- secret keys;
- production credentials;
- authentication tokens;
- secret-bearing diagnostics;
- confidential fuzzing inputs;
- unredacted personal information;
- embargoed vulnerability details;
- proprietary third-party material without authorisation.

A digest of low-entropy sensitive material may permit guessing attacks; where
necessary a carefully defined randomised commitment is used under an appropriate
disclosure policy.

The original evidence, commitment mechanism, opening procedure and access
boundaries are documented. A commitment to unavailable evidence is not
confused with public reproducibility.

An explicit prepublication data-classification and sanitisation gate is
executed. Sanitised public evidence and controlled original evidence are
distinguished. No claim is made that irreversible publication can subsequently
be undone.

---

## B.17. Evidence availability and durable archives

Rekor is a transparency log, not an archival store for full attestations and
experimental evidence. Independent storage is maintained for:

- original DSSE envelopes;
- exact in-toto statement payloads;
- SARIF reports;
- native receipts;
- proof artefacts;
- raw experimental observations;
- requirements and specifications;
- evidence manifests;
- timestamp tokens;
- Rekor inclusion proofs;
- signed checkpoints;
- required consistency proofs;
- witness cosignatures;
- historical trust metadata;
- verification-tooling identities;
- correction and revocation records.

Every required object is retrievable through at least the admitted archival
mechanism, with content-addressed identifiers and independently verifiable
mirrors. Durable archival repositories and persistent research identifiers are
investigated.

Currently retrievable evidence is distinguished from evidence merely committed
to in a transparency log. If a required referenced object is unavailable, the
corresponding independent-reconstruction claim does not pass.

---

## B.18. Offline verification

Given the complete assurance bundle and independently established trust
material, an external party shall be able to verify:

- artefact digests;
- DSSE signatures;
- predicate identities;
- log-entry bindings;
- checkpoint authenticity;
- Merkle inclusion proofs;
- archived consistency relationships;
- witness cosignatures;
- trusted timestamp tokens;
- evidence completeness;
- formal proof artefacts;
- release-policy evaluation.

Access to a live Rekor instance is not required to authenticate archived
historical evidence.

Which current-state properties cannot be established offline is reported
plainly. Historical verification and current release authorisation are separate
questions: an offline verifier cannot establish that no newer revocation exists
beyond its authenticated knowledge horizon.

---

## B.19. Corrections, dissent and claim revocation

The existing ETP correction system is extended with authenticated transparency
publication. For each material correction, the following are bound:

- original claim identity;
- original statement digest;
- original transparency reference;
- affected artefact identities;
- contradictory evidence;
- corrected verdict;
- applicable dependencies;
- responsible adjudication;
- actual correction-publication event.

The original log entry is never deleted or rewritten. The historical existence of
the original assertion is preserved while its current applicability is marked
accurately. An authenticated current-state publication mechanism — the admitted
TUF-backed release metadata or an equivalent established mechanism — communicates
active revocations.

Logging a revocation is not sufficient to ensure discovery by every verifier.
Validators enforcing current-state policy must demonstrably refuse a withdrawn
claim even while its original inclusion proof remains valid.

---

## B.20. Transparency versus release availability

Verification is separated from external publication availability. These are
distinct states, not a single progression that would imply software correctness:

1. local evidence complete;
2. statement authenticated;
3. trusted timestamp verified;
4. publication pending;
5. inclusion verified;
6. consistency verified relative to a named anchor;
7. required witness quorum verified;
8. archive availability established;
9. current-state policy established;
10. transparency requirements satisfied.

A Rekor outage must not prevent development, security investigation or local
proof checking. A release must not claim compliance with a transparency profile
whose mandatory publication requirements remain unsatisfied.

Durable publication queues and bounded retry policies are maintained; ambiguous
network outcomes and duplicate submissions are handled safely.

For urgent security releases, a separately preauthorised and clearly labelled
emergency policy preserves timely remediation without pretending the normal
transparency gate passed. Assurance is never silently degraded.

---

## B.21. Independent trust domains

Public-good transparency infrastructure and independently established
cryptographic verifiers are used initially. A local POSIX-backed Rekor instance
serves development, reproducible integration testing and deliberately
adversarial experiments; it is never presented as independent public
accountability.

Operating an unnecessary production transparency service merely for prestige is
avoided. Independently operated secondary logs and witness networks are
investigated when actual participation becomes available.

Multiple shards, mirrors or infrastructure accounts operated by the same entity
are not independent trust domains. Operator independence and common dependencies
are represented explicitly. The architecture stays compatible with a future
federation of academic, industry and independent maintainers.

---

## B.22. Verifier independence and non-circularity

The transparency verification root must not depend on the unverified OpenSSL-RS
candidate. Independently established signature-verification implementations are
used, and their actual runtime linkage and cryptographic dependencies are
inspected and recorded.

Accidental use of the candidate's `libcrypto` or `libssl` during authoritative
verification is prevented. Where practical, the acceptance behaviour of two
separately implemented verification paths is compared; they must agree on
representative valid and adversarial proof populations. Differences and shared
trust assumptions are recorded.

Strong implementation diversity is not claimed where both verifiers depend on
the same unverified critical parser or cryptographic backend.

---

## B.23. Formal verification of transparency acceptance

The ETP verification-policy model is extended with transparency-specific
invariants. TLA+, suitable theorem provers, bounded model checkers and deductive
verification tools are investigated. Priority invariants:

- a false inclusion proof cannot satisfy inclusion verification;
- an unauthenticated checkpoint cannot authorise an accepted tree root;
- an unrelated log entry cannot authenticate a DSSE statement;
- a smaller checkpoint cannot silently roll back accepted state;
- equal-size conflicting authenticated roots produce an incident;
- unrelated log shards cannot satisfy a same-tree consistency obligation;
- duplicate witness credentials cannot satisfy independence thresholds;
- an omitted required campaign activity cannot permit promotion;
- a revoked claim cannot satisfy a sufficiently fresh current-state policy;
- missing timestamp evidence cannot satisfy a timestamp-dependent claim;
- unavailable evidence cannot satisfy reconstruction requirements;
- a publication failure cannot masquerade as transparent acceptance.

Crash recovery, persistent witness state, retries, partial writes, concurrent
publication and shard transitions are modelled.

The abstract model stays small and independently reviewable, and its relationship
to the production verification machinery is established. A verified abstract
state machine is not presented as a verified implementation without a
refinement relationship.

---

## B.24. Mandatory adversarial controls

The transparency machinery is qualified against representative defects and
attacks. At minimum:

1. tampered Merkle leaves;
2. incorrect leaf indices;
3. incorrect sibling order;
4. truncated inclusion proofs;
5. excess proof elements;
6. incorrect checkpoint roots;
7. incorrect checkpoint tree sizes;
8. forged checkpoint signatures;
9. cross-log proof substitution;
10. cross-shard proof substitution;
11. incorrect DSSE PAE digests;
12. valid log entries for unrelated attestations;
13. unsupported protocol versions;
14. malformed tiles;
15. reordered entry bundles;
16. incorrect partial-tile boundaries;
17. corrupted mirror data;
18. stale checkpoint replay;
19. same-size conflicting checkpoints;
20. invalid consistency proofs;
21. witness-state rollback;
22. duplicate witness credentials;
23. correlated witness populations;
24. incorrect timestamp imprints;
25. untrusted timestamp authorities;
26. backdated historical submissions;
27. omitted campaign failures;
28. missing archived evidence;
29. stale revocation state;
30. incorrect trust-root rotation;
31. interrupted publication;
32. logging-service unavailability;
33. ambiguous submission retries.

Expected cryptographic rejection is distinguished from operational failure. Each
control requires mutation, refusal, restoration and a successful positive-control
replay. Official conformance vectors and independently constructed cases are used
where available.

Local split-view simulations are performed without attacking or degrading public
infrastructure.

An instrument does not earn verification credit for an attack class that its
controls demonstrate it cannot detect.

---

## B.25. Long-term cryptographic evidence preservation

The design targets multi-decade verification. The following are preserved:
original signed bytes, original digest algorithms, original public keys and trust
chains, algorithm identifiers, original timestamps, original checkpoints and
witness signatures, historical verification policies, and the applicable
verification implementations.

Archival timestamp renewal and evidence-renewal mechanisms, including RFC 4998
principles, are investigated. Before an existing digest or signature algorithm
becomes inadequate, a new authenticated commitment covers the historical evidence
and its verification material. Both the original and renewed authentication
relationships are preserved.

Old cryptographic identities are never rewritten in place. A new signature over
old material cannot retroactively prove that the original signature was valid
before a compromise or cryptographic break. Trusted-time and renewal assumptions
are documented.

---

## B.26. Post-quantum research track

A non-production experimental track investigates:

- ML-DSA-44 checkpoint signatures;
- post-quantum witness cosignatures;
- emerging identity-transparency protocols;
- hybrid classical and post-quantum assurance profiles;
- long-term commitment renewal;
- algorithm transition and downgrade resistance;
- proof and signature size;
- verification cost;
- interoperability and archival implications.

As of the pinned baseline, the identity-transparency mode is experimental and
subject to breaking changes. It is not admitted into production merely because
the underlying algorithms are standardised. Admission requires stable protocols,
independent implementation review, successful interoperability testing, explicit
security assumptions and appropriate trust-policy design.

Experimental results are isolated from production assurance claims. The
divergence from the C2SP recommendation recorded in §B.3.3 is a deliberate,
documented choice for as long as the implementation labels the mechanism
experimental.

---

## B.27. Public verification interface

The ETP verifier is extended with operations equivalent to:

```
verify transparency
verify log-entry
verify inclusion
verify checkpoint
verify consistency
verify witnesses
verify timestamp
verify campaign-completeness
verify archives
verify revocations
verify transparency-policy
```

Monitor operations equivalent to:

```
monitor sync
monitor checkpoints
monitor publications
monitor campaigns
monitor revocations
monitor audit
```

These are interface contracts, not assertions that the commands already exist.
Each operation emits its exact inputs, observed properties, assumptions,
verification outcomes and specific refusal reasons. The full policy decision is
independently reproducible from the archived inputs. Network accessibility is
never a hidden verification prerequisite.

---

## B.28. Repository-specific demonstrations

**Demonstration 1 — BN verification.** Register an authenticated campaign plan
covering a narrowly scoped production BN mechanism. Bind subsequent findings to
exact source, production and instrumented artefact identities. Publish a closure
manifest containing all successful, failed and unresolved observations.
Demonstrate that removing an original unresolved timing or allocation obligation
invalidates campaign completeness.

**Demonstration 2 — curl element-7.** Import the historical closure population
and its associated refusals using honest contemporary publication metadata.
Register a new verification campaign against a frozen candidate. Demonstrate that
unresolved indirect-call obligations cannot disappear through truncation,
publication filtering or selective evidence aggregation.

**Demonstration 3 — OpenSSH adjudication.** Preserve historical graduation and
independent-adjudication records as distinct statements. Authenticate their
contemporary archival registration without claiming that the signatures existed
at the original execution date. Demonstrate that verifying both statements'
inclusion does not resolve their substantive disagreement; a separately justified
reconciliation is required.

**Demonstration 4 — reproducible release.** Register build provenance for one
frozen production artefact profile. Execute independent clean rebuilds. Publish
their reproduction receipts and comparison evidence. Demonstrate offline
verification from the archived bundle.

**Demonstration 5 — transparent correction.** Publish an explicitly synthetic
test claim through the local experimental log, then publish its correction.
Demonstrate that the original inclusion proof remains valid while the revoked
claim fails current-state acceptance.

**Demonstration 6 — split-view simulation.** Operate a controlled local test log
and produce inconsistent authenticated histories. Demonstrate detection by the
admitted checkpoint-comparison or witness mechanism. Record which attacker and
witness-compromise assumptions the demonstration covers. This is never presented
as a test of the real public-good log.

---

## B.29. Verification economics

The FAST / BATCH / BOUNDARY / SEAL / EXTERNAL tiers are preserved:

| tier | transparency obligations |
|---|---|
| FAST | local format, schema, digest and policy checks; no external publication |
| BATCH | native evidence, deterministic manifests, applicable local attestations |
| BOUNDARY | authenticate frozen evidence, execute transparency-adapter controls, publish applicable campaign commitments |
| SEAL | complete required external publication, trusted timestamping, inclusion and consistency verification, witness-policy evaluation, archival, release reconciliation |
| EXTERNAL | independent parties publish their own authenticated review and reproduction results |

Full proof verification and re-upload of unchanged evidence are not repeated for
every source edit. Content-addressed caching is bound to complete applicability
identities. Court resource caps and existing isolation requirements are
respected.

---

## B.30. Implementation sequence

**B0 — Protocol and infrastructure audit.** Inspect the current ETP, SARIF, DSSE
and release infrastructure. Pin admitted Rekor, Sigstore, timestamping and C2SP
protocol versions. Identify actual client support, signing configuration, witness
availability and trust assumptions.

**B1 — Local vertical slice.** Deploy a pinned POSIX-backed Rekor v2 test
instance. Publish one real frozen ETP statement through the supported
`hashedrekord` path. Verify its binding, inclusion and checkpoint. Archive the
complete evidence. Execute the relevant corruption controls.

**B2 — Trusted timestamping and offline verification.** Integrate RFC 3161
timestamp evidence. Demonstrate verification without access to the original live
service.

**B3 — Campaign accountability.** Implement campaign-opening, amendment, closure
and abandonment records. Enforce omission-sensitive reconciliation.

**B4 — Public transparency.** Integrate the admitted public-good Rekor v2
profile. Publish only appropriately classified release-critical material.
Demonstrate independently executable verification.

**B5 — Consistency, monitoring and witnesses.** Implement persistent checkpoint
state, consistency verification and monitoring. Admit genuinely independent
witness services when available. Demonstrate split-view controls.

**B6 — Archival and revocation.** Implement durable evidence reconstruction,
current-state metadata, authenticated correction and anti-rollback controls.

**B7 — Formal assurance.** Verify critical transparency-policy invariants.
Qualify the verification tools and preserve their assumptions.

**B8 — Continuous enforcement.** Integrate the admitted profile into `AGENTS.md`,
release gates, ETP claim schemas, CI and public non-claims. Prevent silent
regression of the transparency guarantees.

---

## B.31. Infrastructure admission gate

Before resuming expansion into additional downstream consumer families, at
least the following are established:

1. a working Rekor v2 integration against a pinned compatible profile;
2. correct DSSE-to-`hashedrekord` binding;
3. independent verification of checkpoint signatures and inclusion proofs;
4. verified RFC 3161 timestamp integration;
5. an executable offline-verification package;
6. persistent checkpoint-state and consistency-verification mechanisms;
7. preregistered verification-campaign commitments;
8. omission-sensitive campaign reconciliation;
9. authenticated correction and revocation relationships;
10. explicit witness and administrative-independence status;
11. executed adversarial controls;
12. a public verifier independent of the candidate cryptographic runtime;
13. preservation of all existing ETP gates;
14. explicit handling of unavailable public services and experimental features.

External witness participation, institutional review and advanced formal proofs
remain separately graded properties. Fabricated external participation is never
imposed as a prerequisite for honestly reporting local infrastructure readiness.
Stronger release profiles may require genuinely independent witness quorums and
external reproduction.

---

## B.32. Mandatory non-claims

Never assert that:

1. Rekor inclusion proves software correctness;
2. a single signed checkpoint establishes a globally consistent history;
3. two log instances necessarily represent two independent operators;
4. a witness has reviewed the underlying implementation;
5. witnessing proves all evidence was disclosed;
6. a timestamp proves an experiment occurred;
7. a public commitment establishes availability of its original payload;
8. a transparency log replaces a revocation system;
9. an authentic historical assertion remains currently valid;
10. experimental post-quantum features establish production post-quantum
    security;
11. transparency infrastructure confers aerospace certification;
12. registration in a public-good log implies endorsement by its operator.

---

## B.33. Final execution discipline

This addendum is not implemented as documentation alone. It begins with one
small, complete, independently reproducible chain:

```
frozen verification campaign
  → authenticated opening commitment
  → Rekor v2 inclusion
  → actual verification activities
  → complete native evidence
  → SARIF projection
  → authenticated closure manifest
  → trusted timestamp
  → Rekor v2 inclusion
  → consistency verification
  → archival reconstruction
  → independent policy evaluation
```

The positive chain and deliberately corrupted counterparts are both executed.
Actual observations are preserved. External signatures, witnesses, timestamps,
publication records and independently reproduced results are never fabricated.

The design optimises for a small trusted implementation, standards
interoperability, explicit assumptions, independent falsifiability and long-term
maintainability.

---

## Final governing principle

The project's history must be as accountable as its implementation.

- Every published claim has an immutable identity.
- Every material verification campaign has an auditable declared scope.
- Every relevant failure remains consequential.
- Every chronological assertion identifies its time authority.
- Every transparency guarantee identifies its trust assumptions.
- Every correction remains connected to the original assertion.
- Every historical release remains independently examinable.

The architecture must make the history of how trust was earned independently
challengeable and verifiable, not only the claim that it was earned.
