# AGENTS.md — memory-safety conversion guideline (standing standard)

The standing engineering standard for the `openssl-rs` unsafe→safe conversion
campaign (`integrate/safe-c33`). **Tracked in Git** (not an admitted forensic
artifact): it is a living working document, so re-read it at the point of use
rather than assuming a session already has it.

**Load this file at the start of every fresh session.**

The goal is not "uses Rust". The goal is **sound abstractions with genuinely safe
interiors**: every unsafe assumption either eliminated (made inexpressible) or
confined to a narrow, auditable abstraction with a sound interface.

Compatibility is preserved, but compatibility is never an excuse to reproduce a
known-unsafe operation: preserve OpenSSL behaviour where required, and **record**
any deliberate safety improvement that deviates from it.

### How to read this file

- **§0–§7 are the always-enforced conversion contract** — apply them to every
  batch.
- **§8–§20 are specialized procedures**, invoked when a change touches the
  relevant concern (a reusable unsafe abstraction, a security-sensitive
  algorithm, protocol handling, a promotion, research instrumentation). Do not
  treat every technique below as a requirement for every small edit — that
  recreates the verification bottleneck this campaign exists to escape.

---

## 0. The standard to hold (good ≠ exceptional)

| | pattern | what it guarantees |
|---|---------|--------------------|
| good (foundation) | `*mut T → NonNull<T> → Drop` | consolidates cleanup; provenance/uniqueness still caller obligations |
| **exceptional (target)** | `validated ownership boundary → borrowed/owned Rust state → safe internal algorithms` | unsafe assumptions live only at auditable boundaries; types, lifetimes and borrow rules enforce the interior |

We are moving from the first to the second. Every conversion must state which
unsafe assumptions were **eliminated** (became inexpressible), which were merely
**relocated** (into one documented boundary), and which remain **hidden**
(unreported obligations). Hidden must be zero; if you find a hidden obligation,
report it and block graduation — never reclassify it to satisfy the target.

**On "the C ABI edge".** Unsafe code cannot always be confined to the C ABI edge
alone. Allocators, operating-system interfaces, CPU intrinsics, and specialized
internal representations each require their own unsafe operations. The real
requirement is that every such operation live inside an appropriately narrow,
auditable abstraction with a sound interface — not that unsafe appears in
exactly one place.

---

## 1. Ownership adoption is a proof obligation, not a function call

An ownership-adoption constructor turns a caller-supplied raw pointer into an
owning handle whose `Drop` frees it. Such a constructor MUST be `unsafe fn` with
a `# Safety` contract.

The contract must establish, at minimum:

- **provenance** (which allocator seam produced it);
- **allocation identity and extent** (the whole block, not a sub-range);
- **alignment**;
- **initialization state** valid for every operation the owner performs
  (including the cleansing length, which must be valid for that allocation);
- **exclusive ownership** (no other owner will release it);
- **the exact release mechanism** (plain vs cleansed vs secure).

> An `unsafe fn` declaration **transfers** a proof obligation to its caller; it
> does **not** discharge it. Marking a constructor `unsafe` without making its
> callers establish the preconditions is not a fix.

- A **safe** `fn` whose body can trigger an invalid free is a soundness bug even
  if today's call sites are correct.
- Prefer *design* over documentation where cheap: when a block comes from a
  known allocator call in the same function, construct the owner directly from
  that call (`new`/`new_zeroed`) so provenance is not re-asserted by hand.
  Reserve `adopt`/`take` for genuine helper-allocated blocks and justify each.
- Never add a new `unsafe fn` with a safe-looking signature that hides raw work.

Audited constructors (fix any regression): `OwnedBlock::take`, `OwnedBuf::take`,
`OwnedStr::take`, `OwnedRaw::adopt`, `adopt`/`adopt_cleansed`, `from_raw`, across
`runtime/bio/owned.rs`, `store/store_lib.rs`, `evp/{pkey_ctx,digest,e_aes}.rs`,
`pem/pvkfmt.rs`, `ui/ui_lib.rs`, `hpke/mod.rs`, `ssl/{ssl_lib.rs,statem/statem_srvr.rs}`,
`x509/v3_utl.rs`, `ec/smpl.rs`, `provider/{cipher,kdf}.rs`.

## 2. Valid Rust values are an explicit invariant

**Allocated storage and initialized Rust values are separate states.**
`CRYPTO_zalloc` returning zeroed bytes does not, by itself, establish that those
bytes represent a valid initialized `T`; validity must be established for the
actual type and for every subsequent operation. (Zero initialization *may* be a
valid value for some types — that must be justified per type, not assumed.)

- An owner may hold `NonNull<MaybeUninit<T>>` while constructing an object.
- **No `&T`, `&mut T`, initialized read, or full destructor is permitted before
  the required initialization invariants hold.** Zeroing does not make a value
  valid when `T` contains references, `NonNull`, valid-range-restricted enums, or
  other fields with validity requirements.
- Partially initialized objects must release **only the resources actually
  acquired** — never run a complete destructor on a partially constructed value
  (this is the `OwnedRaw<T>` vs `OwnedCtx<T>` distinction; keep it).

### Borrowing
- Prefer owner-derived borrowing: `&mut OwnedTree`, `&mut OwnedNode`,
  `split_at_mut`/`get_mut` partitioning — instead of raw `from_raw_parts_mut`.
- `from_raw_parts_mut` requires exclusive access to the whole range for the
  entire returned borrow; derive that from an owner rather than asserting it.
- Audit: `unsafe fn tree_levels<'a>(tree) -> &'a mut [...]` (caller-chosen
  lifetime; no tie to the tree's owner) and `Node::parent_mut(&self)` (uniqueness
  the type system does not establish).

## 3. Fallible arithmetic and allocation

- Any `count * size_of::<T>()`, length/size sum, or offset used for allocation
  MUST use `checked_mul`/`checked_add` and translate overflow to the OpenSSL
  failure semantics (`None`/error), **not** rely on a panic boundary.
  Audit: the generic alloc helper in `src/asn1/owned.rs`.
- Make allocation failure, overflow and partial initialisation explicit through
  `Option`/`Result` (or the module's established outcome type).

## 4. Panic safety across the C ABI

- `guard_ffi` catches unwinding, but uses `AssertUnwindSafe`; catching a panic
  does not repair partially mutated state.
- For stateful contexts require one of: failure-atomic mutation, explicit
  rollback, or a **poisoned** state that forbids reuse after an interrupted
  operation. An error code alone is not sufficient.

## 5. Secret-bearing memory is a distinct category

Classify memory by *security* requirement, not only by allocation mechanism and
destructor — and distinguish **secret contents**, **public metadata**, and
**sensitive state**. (IVs/nonces are often public, yet their uniqueness and
lifecycle can be security-critical.)

1. **Lifetime + cleansing.** Cleansing must cover the *actual secret-bearing
   storage*, including copies, temporary representations, partially initialized
   states and **failure paths**. **Release and cleansing are separate
   obligations**: a destructor that merely frees memory is not a secret-safe
   destructor. Keep every `OPENSSL_clear_free` arm through conversion.
2. **Constant-time.** Separate secret-dependent operations from public-data
   parsing; keep the full-length `CRYPTO_memcmp` accumulation; never introduce
   secret-dependent branches or early exits. Source-level intent is **not**
   constant-time behaviour after optimization: for secret-dependent operations,
   preserve the intended timing discipline under optimisation and review
   generated code or use leakage-testing methods where the change warrants it.
   Never claim constant-time behaviour from source inspection alone.
3. **Initialised vs uninitialised.** `MaybeUninit<T>` + initialisation state.
4. **Reference/alias ownership.** Express shared/exclusive access through types;
   minimise unconstrained pointer→reference conversions.

No third-party crypto implementations: RustCrypto `zeroize`/`subtle` and similar
are **references for technique only**.

## 6. Per-batch execution contract

- One bounded task at a time; a subagent does not commit or push; the
  orchestrator commits, verifies and merges.
- Everything runs in the court container (`docker/openssl-rs-court.sh`), never on
  the host. **OOM protection is mandatory**: run one heavy command at a time;
  build with `CARGO_BUILD_JOBS=4` and test with `cargo test --lib -- --test-threads=4`
  (the editor and other host work already consume most of RAM and swap is full —
  a build spike has crashed the session before); check `free -g` before a build
  and abort if `available` is small. Never build into a RAM-backed tmpfs.
- Local gate per batch: `cargo fmt --all -- --check`,
  `cargo clippy --all-targets -- -D warnings`,
  **all current library tests pass**. The established baseline is **1183** library
  tests; it will grow, so the rule is *no unexplained removals and no newly
  ignored tests* — not a frozen literal.
- Preserve the `CRYPTO_*` allocator seam at the authority's exact size/`file`/
  `line`; preserve `#[repr(C)]` layouts and every exported symbol/signature;
  never weaken `unsafe_op_in_unsafe_fn` / `undocumented_unsafe_blocks` /
  `missing_safety_doc`.
- **`docker/` is out of scope for conversion agents.** This is a scope boundary,
  not an endorsement of the current launcher: the known isolation defect (host
  checkout bind-mounted read-write at `/work`) is a **standing infrastructure
  task** that must be tracked and fixed deliberately, never silently forgotten.
- Report per batch: mechanism eliminated / relocated / hidden (must be 0),
  unsafe ops removed vs relocated, boundary size, obligations discharged /
  retained / **newly introduced**, compatibility tested, and whether every
  remaining unsafe op has an explicit validity contract.
- Defer full Phase-25 forensic regeneration to seal points; keep the local gate.

## 7. Graduation states

- `OWNERSHIP_RECONSTRUCTED` — a safe ownership model exists and its residual
  boundary is identified.
- `SAFETY_DISCHARGED` — **materially harder.** A mechanism is `SAFETY_DISCHARGED`
  only when, within its defined scope:
  1. every remaining unsafe operation has an explicit validity contract;
  2. every required precondition is established by its callers or by an external
     ABI contract; and
  3. no safe-Rust caller can cause undefined behaviour through the safe
     interfaces.
  All retained, introduced and unresolved obligations must be enumerated.
  **Documentation alone does not discharge an obligation.**
- `SAFE_COMPATIBLE` — the only graduation state for a consumer family. A family
  graduates only when **every applicable mechanism in its conservatively
  established dependency closure is `SAFETY_DISCHARGED`**, unresolved
  dependencies are accounted for, and compatibility is confirmed against the
  **exact converted implementation**. L4 build/link and L7 functional evidence
  remain separate (an L4 pass is not an L7 pass). An unresolved or unknown
  safety-relevant dependency **blocks** `SAFE_COMPATIBLE` graduation until its
  applicability is excluded with evidence or its safety obligations are
  discharged: recording an unknown is necessary, but recording it does not
  establish safety. No family inherits safety graduation solely from a shared
  mechanism's successful conversion: a consumer like curl depends on many
  mechanisms, and discharging one does not make the whole consumer safe.

An unproven raw-pointer boundary never becomes `SAFETY_DISCHARGED` merely because
a `Drop` wrapper exists, and `hidden = 0` is a target, never a reporting
incentive.

---

## 8. Three axes of evidence (compatibility ≠ safety ≠ cryptography)

Compatibility is necessary for our objective but **not sufficient**: a faithful
port can reproduce a security defect. Every subsystem must be able to answer,
separately:

- **Compatibility** — does it preserve OpenSSL's intended public behaviour?
  (differential courts, downstream replay.)
- **Safety** — can its ownership, aliasing, initialisation, concurrency and FFI
  contracts prevent UB? (contracts, Miri, sanitizers, negative controls.)
- **Cryptography** — are results, protocol decisions, secret handling and
  timing protections correct? (Wycheproof/ACVP vectors, dudect, proofs.)

Never let one axis's evidence stand in for another. A green differential court is
not a safety result; a clean `grep` for `unsafe` is not a cryptographic result.

## 9. Safe abstractions (the RustBelt standard)

A safe interface must not let safe clients cause UB. For every reusable unsafe
abstraction (owner types, adoption ctors, `CtxDestroy`, freefunc tables):

- give it a **contract**: what a caller must establish, and what an implementer
  must guarantee;
- prefer deriving ownership from the known allocation result and restrict raw
  adoption to genuine transfer boundaries;
- **review the traits** — `CtxDestroy`-style destructor traits impose an
  obligation on *implementers*. A wrong `destroy_body` (releasing the enclosing
  allocation, or freeing a member twice) invalidates every generic owner. State
  the destructor contract (frees its owned members exactly once, handles the
  declared initialisation state, never the enclosing block) and, where feasible,
  make the trait `unsafe`.

## 10. Aliasing and architecture layering

Aliasing correctness is a conversion property, not an afterthought. Prefer, by
layer:

| Layer | Preferred representation |
|-------|--------------------------|
| C ABI façade | raw pointers with defined C contracts |
| allocation / ownership | `NonNull`, typed owners, explicit transfer |
| interior structures | borrowing, checked slices, discriminated states |
| algorithms and parsers | safe Rust wherever feasible |
| CPU-specific cryptography | small, documented intrinsic/assembly boundary |

The target is not fewer `unsafe` expressions but **fewer ways to construct
conflicting references**. At focused checkpoints run Miri under both Stacked
Borrows and Tree Borrows where supported; do not require full-library Miri. Miri
is a research instrument, not the normative aliasing spec — record what it did
and did not cover.

## 11. Cryptographic assurance instruments (distinct, not interchangeable)

| Property | Instrument | Scope |
|----------|-----------|-------|
| algorithm correctness | Wycheproof / NIST ACVP/CAVP vectors | malformed + edge inputs |
| unsafe-code soundness | Miri + contract review | ownership, aliasing, init |
| bounded functional props | Kani | bounds, invariants, arithmetic |
| mathematical equivalence | hax/Lean (or F*) for small pure interiors | proofs, not tests |
| secret-dependent flow | ctgrind | branching/memory access |
| statistical timing | dudect | optimised crypto ops |
| protocol robustness | Rustls/BoringSSL/NSS-style fuzzing | handshake/record parsing |

Absence of detected leakage is not proof of constant-time behaviour, and ACVP
vectors are not a NIST validation certificate. State coverage and limits.

## 12. Secret classification

Tag security-sensitive operations with an explicit classification (engineering
metadata first, safe wrappers over time):

`PUBLIC_DATA`, `SECRET_DATA`, `SECRET_DEPENDENT_CONTROL`,
`CLEANSING_REQUIRED`, `DECLASSIFICATION_BOUNDARY`.

A constant-time comparison should yield an internal choice-like value until the
authorised decision point; secret-dependent branching is forbidden before it.
Any constant-time claim must name the target arch, compiler version, feature
dispatch and build profile that were measured.

## 13. Two fuzzing courts (never merge their verdicts)

- **Deep-state exploration** — test-only deterministic crypto / controlled
  verification bypasses to reach otherwise unreachable protocol states. Claim:
  *protocol-state robustness under the modified model*.
- **Authentic execution** — real crypto, real provider behaviour, full
  handshakes. Claim: *observed behaviour of the real implementation*.

Bypasses must never appear in the release configuration.

## 14. Proof-carrying conversion receipt

Each landed conversion batch writes a compact receipt (template:
`forensics/memory-safety/campaign/safe-c33/RECEIPT.template.md`) with: source
identity, authority contract, ownership before/after, unsafe eliminated /
retained / introduced, compatibility delta, safety checks, residuals. The point
is to let a fresh session resume without reconstructing the reasoning.

## 15. Agent roles and independence

Run sequentially in the same container; separation is about independent judgment:
**contract analyst** (authority requirements, no code), **conversion engineer**
(smallest coherent safe change), **adversarial reviewer** (can a safe interface be
misused? do aliases escape? can destruction double-release? does failure leave
inconsistent state?), **evidence adjudicator** (reads actual outputs; cannot
certify from another agent's description).

> The agent that writes a safety claim must not be the sole authority deciding
> whether its evidence proves that claim.

## 16. Negative controls

If a court claims to detect an unsafe-ownership violation, introduce an isolated
**test-only canary** of that defect class (aliasing, wrong release path,
overflow, secret-dependent flow) and confirm the instrument fires. Keep canaries
out of production artefacts and classify unsupported detectors honestly.

## 17. Divergence classification (vs OpenSSL *and* the standard)

| Divergence | Treatment |
|-----------|-----------|
| documented OpenSSL behaviour | conserve it |
| implementation-defined | state the compatibility scope; test it |
| UB in the C authority | do not reproduce UB; document the boundary |
| known vulnerability mechanism | eliminate the mechanism; test the correction |
| standards nonconformance | establish normative behaviour; record the compat consequence |
| harness/environmental difference | keep separate from implementation findings |

Never imitate a flawed implementation and call it correctness.

## 18. Verification schedule

| Frequency | Evidence |
|-----------|----------|
| every coherent conversion | fmt, clippy, compile, focused tests, contract review |
| every integrated subsystem | library tests, relevant differential/lifetime tests, targeted Miri |
| security-sensitive algorithm change | applicable Wycheproof/ACVP vectors, constant-time checks |
| protocol handling change | targeted adversarial fuzzing + authentic workload |
| reusable unsafe abstraction change | misuse analysis, negative controls, cross-caller audit |
| Safe-33 promotion | whole-cohort dependency closure, downstream replay, broader sanitizers, refreshed forensics |
| release candidate | full security + compatibility campaign, reproducibility, independent review |

## 19. Measuring progress (five dimensions, not one %)

1. **Ownership reconstruction** — mechanisms converted (not files touched).
2. **Safe-interior coverage** — functions/mechanisms whose safe interfaces
   enforce their invariants.
3. **Discharged safety obligations** — verified contracts, with retained and
   unknown obligations reported alongside.
4. **Cryptographic assurance** — vectors, timing evidence, checked properties.
5. **Safe-compatible consumers** — families past their dependency closure + compat.

Plus a **trust-boundary budget** per subsystem: number/complexity of unsafe
interfaces, scope of caller obligations, and the amount of code relying on them.
A correctly scoped SIMD intrinsic and a safe fn that can build two exclusive
references to the same memory are not the same risk.

## 20. Conversion-aware residual fuzzing (FRF-Fuzz), kept outside the crate

FRF-Fuzz is a **standalone external instrument**: never an implementation
dependency of the single crate, never anything `src/` links against. It lives in
the court/venue, with pinned authority + exact converted candidate binaries.
The distinctive idea is to try to discover where an unsafe→safe conversion
changed observable behaviour (allocator, lifetime, protocol state, error paths),
not just where a crash exists.

Three initial targets, each with a pinned OpenSSL authority executable, the
**exact** converted-candidate executable, a normalised transcript contract and
deterministic replay:

1. **allocator / ownership** — differential cleanup, partial initialisation,
   failed allocation, refcount transitions;
2. **ASN.1 / X.509** — parsing boundaries, object lifetime, policy evaluation,
   error and rejection differences;
3. **TLS state machines** — unexpected transitions, fragmented inputs,
   renegotiation / post-handshake where applicable.

The experiment that matters runs **across** a conversion: capture a subsystem's
behavioural residuals → apply the ownership reconstruction → replay the *same*
corpus against the new candidate and the authority → **FRF-Fuzz's exploration /
DSFB machinery** prioritises new structural differences and proposes
discriminating inputs → promote only replay-confirmed findings to **FRF**, which
**independently adjudicates** each promotion, carrying its exact source
identities and disposition → let Gemel preserve the history of
discovered/fixed/reopened/unresolved divergences. Keep hypothesis generation
(FRF-Fuzz) separate from verification (FRF); that separation is the framework's
principal strength.

**Executable adapters.** FRF-Fuzz's authority interface expects an executable
that speaks its fixture protocol. The pinned OpenSSL executable and the exact
converted candidate therefore each need a **compatible case-harness adapter**
that normalises the same observables (allocator events, return values, error
codes, transcript bytes), preserves allocator and error semantics, and records
the exact candidate build identity (commit + binary hash). Without those
adapters §20 would describe the intended experiment but not how the existing
FRF-Fuzz implementation executes it.

- Keep the fast compare-guided exploration and the ASan-confirmation builds
  **separate** until the documented ASan/trace-compare instrumentation
  incompatibility is resolved. Never trade memory-safety detection for guidance.
- Bypasses/fuzz modes are test-only and must never appear in the release
  configuration (see §13).

### Earning the claim (rigorous, honest evaluation)

The four-arm ablation is `coverage → coverage+compare → residual → full`. To
claim the original mechanisms add value, compare FRF-Fuzz against AFL++,
libFuzzer and an appropriate LibAFL configuration under **equal CPU, time,
corpus and instrumentation**, and measure: verified unique defects,
time-to-first-confirmed-divergence, reproducible boundary witnesses, and
performance on previously-unseen defects. Include at least one external
benchmark corpus not designed around FRF's strengths. Report censoring,
held-out defects, negative controls, reproducibility and statistics.

The claim FRF must earn: the `residual`/`full` arms outperform `coverage+compare`
on **held-out conversion defects**, and findings survive independent replay.
Until then, do not claim frontier-level superiority. A preserved negative result
is a valid result.

---

## 21. Safe-33 assurance protocol (read at relevant gates)

**The existing §§0–20 remain authoritative.** Specialized procedures and
research-grounded operational checklists live in
`forensics/memory-safety/campaign/safe-c33/ASSURANCE_PLAYBOOK.md` §§21–32.
This split keeps first-read agent context bounded. Load only the playbook
sections required by the touched trust boundary; do not run its full suite on
every mechanical conversion.

### Mandatory new decisions for every changed unsafe *boundary*

1. **State the exact external contract.** A C-valid hostile input or legitimate
   application callback must not cause UB. A C-invalid pointer is not silently
   assumed safe. State OpenSSL authority, ABI, target, object lifecycle and
   candidate binary identity.
2. **Prove the whole boundary, not the `unsafe` expression.** Assign a stable
   boundary ID. Include every constructor, raw alias/escape, mutation, callback,
   duplicate/up-ref, partial-init failure, release and safe caller. A private
   field, `unsafe trait`, owner-token or `SAFETY:` comment is NOT discharge.
3. **Treat FFI callbacks and hooks as reentrancy edges.** No unjustified `&mut`
   or non-reentrant lock across an application-controlled callback, even when
   owned member fields are private. Audit allocator hooks, BIO callbacks,
   provider/ENGINE dispatch, ex_data and TLS callback families. A failure must
   leave a valid reusable, rolled-back, or explicitly poisoned state.
4. **Establish validity before references.** Prove provenance, alignment, extent,
   initialization, lifetime alias exclusivity, `(ptr,len)` consistency and
   `Send`/`Sync` claims. `debug_assert!` cannot uphold a safety invariant in
   release. Preserve pointer provenance through transformations where needed.
5. **Keep three independent evidence axes.** ABI/functional parity (including
   loader and callback behavior), Rust soundness, and cryptographic/security
   properties require different proofs and courts. Use negative controls.

### Highest-value Safe-33 prioritization

Retain the historical **33-family** cohort. Rank actionable obligations by
**importance of the consumer × demonstrated reachability × security consequence
÷ engineering effort**, never raw file/token/unsafe-block counts. First deepen
current-candidate functional courts for curl, nginx, OpenSSH, HAProxy and Redis;
recover the missing per-family symbol fingerprints. Preserve 25 L4-only
families as build/link results until each earns meaningful L7 evidence.
Additional candidates (Git/CPython/Apache HTTP Server) must first earn their
own precise compatibility evidence and are not retroactively counted in 33.

### New evidence promotion rule

Every obligation has a candidate-bound lifecycle:
`UNKNOWN -> CONTRACTED -> ESTABLISHED -> INDEPENDENTLY_CHECKED -> DISCHARGED`.
Record an explicit source witness for each precondition, an independent reviewer,
relevant runtime/static checks and negative controls, exact source/build hashes,
and retained/unknown obligations. Unknown/unsupported instruments are NOT PASS.
A method is not `SAFETY_DISCHARGED` because a document names it; the existing
§7 full dependency-closure rule for `SAFE_COMPATIBLE` is unchanged.

### Verification economics and stop conditions

Continue the existing cheap per-batch court, one heavy command at a time. Add
focused alias/callback/adversarial tests whenever a reusable safety boundary
changes. Run native sanitizers and model tools where supported, protocol and
cryptographic courts on corresponding changes, and the full forensic seal
**only at the designed subsystem/promotion gates**. Never turn absent evidence
into a green result. A counterexample, newly hidden assumption, ABI regression,
weakened detector or newly unsafe safe-API is STOP even if 1,196+ unit tests pass.

Before untrusted external pilots, fix the court container's documented writable
host bind mount and prepare the maintainer-specific source/binary identity,
replay/rollback and security-response evidence bundle. The precise court and
bundle contracts are in the playbook §§24–32.
