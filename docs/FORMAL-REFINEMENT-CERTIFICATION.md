# Formal Refinement and Certification

**FRC · the assurance track above the timing, evidence and performance tracks**

Queue: `docs/FRC-TODO.md` (items `FRC-0` … `FRC-10`).
Evidence root: `evidence/frc/`.

The FRC track does not replace `docs/ETP-TODO.md` or
`docs/PERFORMANCE-FRONTIER.md`; it consumes their outputs. Its claims are ETP
claims under `docs/ETP-CLAIM-ALGEBRA.md`, and every FRC claim is bound to an
exact artefact.

---

## 0. North star

> Every supported security property is connected to an independently specified
> requirement, a mechanically checked implementation argument, an exact
> executable artefact, and reproducible evidence of its behaviour in the real
> consumer environment.

Two rules keep that honest:

1. **Match the frontier before claiming to exceed it.** More tools, more tests
   and more proof scripts are not stronger assurance. The measure is what the
   combined evidence proves, within a stated scope.
2. **A published verification gap is not a bug.** If research concludes that a
   competitor's implementation is correct within its claimed scope, that is a
   valid and valuable result. The objective is a methodology strong enough to
   find real defects, including in this project.

---

## 1. The bar to meet, stated precisely

Any claim of "beyond the frontier" is meaningless without naming what the
frontier establishes and what it assumes. These are the reference standards.

### 1.1 s2n-bignum / AWS-LC

From `s2n-bignum/SOUNDNESS.md` (read 2026-11-22):

- The proof is a HOL Light Hoare triple over the **actual object-code byte
  sequence**, checked against the object file the build produces, so compiler
  and assembler correctness are not direct assumptions. Frame conditions
  constrain what may change.
- **Since late 2025** the same safety infrastructure proves, alongside
  functional correctness: (a) the instruction sequence and all memory addresses
  are independent of secret inputs; (b) no variable-timing microarchitectural
  event occurs. All routines currently used by AWS-LC — P-256, P-384, P-521,
  X25519, Ed25519, Montgomery operations, Karatsuba multiplications and ML-KEM,
  on ARM and x86 — carry these formal constant-time and memory-safety proofs.
- This supersedes the older phrasing in the repository README that timing is not
  machine-checked; the README sentence is stale relative to `SOUNDNESS.md`, and
  the register records both documents with their dates rather than choosing the
  convenient one.

Its own documented residual risks are the research agenda, not a weakness to be
mocked:

| id | gap, in their terms |
|---|---|
| A1 | the functional specification could be wrong (typo, wrong constant, wrong definition) |
| A2 | preconditions (aliasing, reduced inputs, excluded degenerate points) may surprise callers; no complete machine-checked link between `s2n-bignum.h` and the formal statements |
| A3 | the proof fixes instruction sequence and addresses; hardware execution of those instructions is not guaranteed constant time (Hertzbleed-class, variable-latency instructions); DIT/DOITM help where present, AMD offers no equivalent, power/frequency channels are out of scope |
| A4 | out-of-bounds reads and transient writes are not excluded by functional correctness alone; **stack discipline is not checked** (reads/writes below SP rely on discipline and Valgrind) |
| B1 | the hand-written ISA models could be wrong; mitigated by co-simulation, inherently incomplete |
| B2 | the ELF loader could extract the wrong bytes |
| B3 | the model is sequential user-mode single-core: no caches, interrupts, virtual memory, speculation, privilege levels, physical faults |
| C1 | HOL Light kernel and OCaml runtime are in the TCB |
| D1 | environment assumptions: 64-bit, little-endian, alignment checking off, mapped memory |
| D2 | C header / assembly signature agreement is cross-checked heuristically, not machine-checked |
| D3 | **"There is no end-to-end machine-checked proof from the C API through assembly to the cryptographic specification."** The mlkem-native bridge is manual. |
| — | **reassembly in downstream projects is not checked**: importing the `.S` files elsewhere and assembling with a different toolchain can in principle produce different bytes than the proofs cover |

### 1.2 seL4

Refinement from an abstract specification to an implementation, binary
correctness connecting the executable to the proof, and confidentiality and
integrity theorems for supported configurations. The transferable lesson is the
*shape* of the argument — specification → implementation → binary — not the
size of the proof.

### 1.3 DO-178C, DO-330, DO-333

Objective-based assurance tied to a system's assigned safety level: planning,
high- and low-level requirements, architecture, requirements-based verification,
structural coverage including MC/DC where required, robustness, configuration
management, quality assurance, **tool qualification** (DO-330) and **formal
methods justification** (DO-333). Certifying an airborne system is a separate
act with a system safety assessment; satisfying objectives is not certification.
AC 20-115D recognises DO-178C for that purpose.

### 1.4 What "exceeding" would require

| dimension | requirement |
|---|---|
| Beyond s2n-bignum | match its machine-code arithmetic, timing and memory-safety proofs on the routines we ship, **then** prove additional caller, integration or lifecycle properties — in particular D3, D2 and the reassembly gap |
| Beyond AWS-LC | stronger applicable end-to-end correctness and security properties through the complete crypto API, not only the assembly kernels |
| seL4-style depth | specification-to-implementation refinement plus exact binary correspondence, for declared configurations |
| Aerospace | objective-by-objective DO-178C conformance evidence with real tool qualification and independence, for a declared system context |
| Performance | independently reproduced leadership on specified hardware and workloads, with no weakened security |
| Compatibility | verified admitted legal behaviours and actual downstream execution, with every divergence recorded |
| Assurance reproducibility | the whole claim dependency graph reconstructable and adversarially challengeable by a third party |

Each completed scope is a result in its own right. None is implied by
completing an implementation TODO.

---

## 2. The compositional obligation (the central technical idea)

A verified kernel has a theorem of the form `{P} K {Q}`. `P` may require
canonical operands, correct modulus geometry, valid buffers and non-overlapping
memory. The theorem can be perfectly true, and the cryptographic operation can
still be wrong, because nothing established that its caller satisfies `P`.

The obligation this track makes **mechanically checked** rather than documented:

```
∀ c ∈ ReachableCallSites(K) :  Pre(c) ⇒ P
```

and then, in the other direction, that `Q` satisfies the precondition of the
next consumer. That chain — kernel `P` established at every reachable call site,
including FFI and callback reachability, and kernel `Q` sufficient for the
caller's need — is the difference between a verified arithmetic routine and a
verified cryptographic pipeline.

Timing is stated relationally, with the leakage model named:

```
∀ p, s₁, s₂ :  Trace(K, p, s₁) ≡_L  Trace(K, p, s₂)
```

where `p` holds public inputs, `s₁`/`s₂` secret inputs, and `≡_L` is equivalence
under a **declared** observation model. That model states whether it covers
branches, addresses, instruction latency, caches, speculation, OS behaviour or
anything else. No single constant-time proof covers every physical side channel,
and a source-level argument is not a binary-level one.

---

## 3. The FRC chain

Each link is a separate claim with its own evidence, TCB and invalidation rule.
A later link inherits nothing from an earlier one without an explicit refinement
argument.

| id | claim | what would discharge it (scope stated per instance) |
|---|---|---|
| **FRC-1** | mathematical correctness of the kernel against an independent specification, for all admitted inputs, with explicit bounds | machine-checked proof or a checked-generation argument; specification independent of the implementation |
| **FRC-2** | Rust memory correctness: allocation, ownership, aliasing, lifetime, initialisation, destruction and every unsafe contract on the path | proof or checked contracts for the safe interior; enumerated, justified unsafe boundaries |
| **FRC-3** | relational timing safety under a named leakage model | proof for the exact compiled code, or a qualified instrument result with a stated model; positive and negative controls |
| **FRC-4** | source-to-binary refinement: the deployed code preserves the verified source properties | object-code correspondence for the exact artefact, including the reassembly question |
| **FRC-5** | cryptographic composition: the whole signing / verification / key-exchange / AEAD operation satisfies its specification | the `Pre(c) ⇒ P` obligation discharged at every reachable site |
| **FRC-6** | protocol and consumer composition: the actual caller respects every precondition and boundary | verified call sites in the real consumer, at the loaded DSO identity |
| **FRC-7** | independently checkable evidence: certificates, trust assumptions, tool identities and exact artefacts reproduce | clean-checkout reconstruction, independent checker where available |

---

## 4. Queue

See `docs/FRC-TODO.md`. Summary:

- `FRC-0` — frontier-gap register and the single specification hierarchy.
- `FRC-1` … `FRC-7` — the chain above.
- `FRC-8` — DO-178C objective-conformance matrix (system context required).
- `FRC-9` — Adversarial Soundness Laboratory.
- `FRC-10` — flagship campaign: P-256 ECDSA signing through the OpenSSL API and
  an OpenSSH consumer.

---

## 5. Tooling, and how a tool is admitted

Choose the mechanism by the theorem, and check the resulting artefact through an
independently justified trust base.

| purpose | candidates to compare |
|---|---|
| Rust source verification | Verus, Kani, Creusot, Aeneas, Lean, Rocq |
| cryptographic specification and symbolic equivalence | Cryptol, SAW |
| machine-code proof | HOL Light, Isabelle/HOL, translation validation |
| independent kernel checking | Candle; proof-trace checkers |

Admission of any tool requires: a pinned version and digest; the theorem class it
is entitled to establish; its TCB; a positive control (a true theorem it proves)
and a negative control (a false near-miss it refuses); and the rustc/target
compatibility it actually supports.

### 5.1 Three proof categories, kept separate

A proof is a claim about a model at a stated level. The three categories below
are independent: a result in one establishes nothing in the next without an
explicit refinement argument.

| category | what it establishes | what it does **not** establish |
|---|---|---|
| mathematical correctness | the algorithm satisfies an independently defined specification, as a theorem about the algorithm | that the Rust source implements it, or that the shipped binary does |
| Rust source correctness | the Rust implementation refines the specification under stated Rust semantics, including unsafe contracts | anything about the compiled instructions |
| exact binary correctness | the deployed instructions preserve the source properties, or translation validation ties source to binary | that the toolchain, linker or loader preserved it beyond the stated checks |

These categories are the §3 chain, not a second taxonomy: mathematical
correctness is the FRC-1 claim, Rust source correctness is FRC-2 (with FRC-3 for
the timing relation it names), and exact binary correctness is FRC-4. A result
is recorded against the link it actually discharges; it is not promoted across a
link without the refinement argument that link requires.

A proof produced with a compiler other than the pinned one can still establish
the first two categories while establishing nothing about the shipped binary.
That is why the ETP-4 Kani result — run on `nightly-2026-08-21`
(`rustc 1.100.0-nightly`), not the pinned `1.98.1` — is recorded in
`evidence/etp4/VERIFICATION-RECEIPT.md` and is not cited. The same distinction
applies to a bounded test result: it is source-level evidence at one identity,
not a statement about the deployed instructions. Citable binary evidence requires
the exact pinned toolchain and the exact artefact identity named at FRC-4.

**Unverified claim to settle at FRC-0:** SAW 1.5 (reported February 2026) is
reported to support Rust MIR verification beyond experimental status, with a
supported rustc range that may not include this project's pinned 1.98.1. The
register records it as `UNVERIFIED` until the release notes and the supported
range are read and an admission test is run. A tool that cannot process the
pinned compiler is not admitted, and this is not a reason to change the pinned
compiler without a separate decision.

---

## 6. DO-178C conformance (FRC-8)

Producing a matrix, not a certificate:

| assurance area | what this project would supply |
|---|---|
| planning | configuration-specific assurance, development and verification plans |
| high-level requirements | externally observable functional and safety requirements |
| low-level requirements | traceable implementation obligations with unambiguous acceptance criteria |
| architecture | verified boundaries, partitioning, dependency and failure-propagation analysis |
| requirements-based verification | tests and formal analyses derived from requirements, not from the source |
| structural coverage | MC/DC and object-code coverage where required |
| robustness | defined failure behaviour, resource exhaustion, environmental faults |
| configuration management | exact source, toolchain, build and verified-artefact identities |
| quality assurance | independent checks against the governing process |
| tool qualification | DO-330 assessment for the tools whose output the argument depends on |
| formal methods | DO-333 justification, assumptions and proof artefacts |
| change control | machine-readable impact analysis and selective proof invalidation |

Two distinctions stay visible: **satisfying objectives is not certification**, and
**constant-time behaviour is not worst-case execution time** — an aerospace
configuration may additionally require bounded execution, deadline analysis,
deterministic resource behaviour and target-hardware validation.

---

## 7. Adversarial Soundness Laboratory (FRC-9)

Discover weaknesses in this project's own verification infrastructure first, then
apply qualified techniques elsewhere. The experiment classes:

| class | experiment |
|---|---|
| specification attacks | a mathematically consistent but incorrectly scoped specification |
| vacuous proofs | a proof that succeeds because its preconditions are unreachable |
| preconditions | a verified kernel driven by a caller outside its domain |
| proof substitution | a valid proof attached to an unproved binary |
| compiler transformations | source-level secret independence against emitted-code traces |
| dynamic linking | a verified symbol redirected to an unverified runtime implementation |
| instrument false negatives | an execution altered so an instrument silently misses its target defect |
| evidence omission | a failing operation removed while the remaining evidence keeps valid signatures |
| model mismatch | independently implemented instruction semantics compared |
| security-property interaction | allocation safety repaired while confidentiality or failure atomicity weakens |
| concurrency | a lifetime race across individually memory-safe components |
| compatibility | callbacks, providers and error paths absent from ordinary test populations |

Every experiment needs a positive control, a deliberately defective control and
an independently checkable outcome. **Specification mutation is the highest-value
class**: a prover can correctly prove a false requirement relative to what the
product actually needs, and no amount of proof checking detects that.

---

## 8. Flagship campaign (FRC-10)

One complete operation, proved and measured end to end, rather than many partially
verified ones: **P-256 ECDSA signing through the OpenSSL-compatible API, executed
by an OpenSSH consumer.**

| # | step | artefact per step |
|---|---|---|
| 1 | formalise P-256 field and scalar arithmetic | independent specification |
| 2 | prove the optimised Rust arithmetic correct | FRC-1 proof + bounds |
| 3 | verify memory and secret-lifetime invariants | FRC-2 contracts |
| 4 | prove signing-path composition | FRC-5 call-site obligations |
| 5 | establish binary-level leakage properties | FRC-3 result with the leakage model named |
| 6 | reproduce equivalent OpenSSL-visible behaviour | differential court at the exact digest |
| 7 | execute through the exact OpenSSH-loaded DSO | FRC-6 identity evidence |
| 8 | measure against qualified frontier competitors | PFP claim, `SCOPED_OBSERVATION` unless bare metal |
| 9 | publish independently checkable evidence | FRC-7 package |

For every link, preserve: the theorem or requirement, its assumptions and TCB,
the production object it applies to, the evidence, the uncovered behaviours, and
the mechanical invalidation rule. The package must be reproducible from a clean
checkout with a pinned environment; authenticated provenance and transparency
then establish historical accountability for it.

---

## 9. Three strategic rules

1. **A measurable frontier-gap register, not a count of tests.** For each
   competitor result: what it proves, what it assumes, what this project proves,
   and what additional theorem would be a genuine improvement.
2. **One independent specification hierarchy.** Specifications and security
   requirements are never generated by restating the production implementation.
   Proof automation may be aided by any tool, but nothing may weaken the
   specification to close an obligation.
3. **Spend the next major effort on the verified computational core.** Additional
   assurance infrastructure is admitted only when it closes a demonstrated proof
   or evidence gap.

---

## 10. Non-claims

- A proof obligation discharged in a model is not a proof about the deployed
  binary.
- A binary-level timing result is not a physical side-channel guarantee.
- Satisfying DO-178C objectives is not certification.
- Completing an implementation TODO is not establishing its system-level theorem.
- Executing a consumer is not proving all legal API behaviour.
- Passing fuzz targets is not proving absence of memory corruption.
- Matching a competitor's proof depth is not exceeding it, and exceeding it on
  one property is not exceeding it overall.
- A defect found in another project is a claim until it survives reproduction and
  independent examination.
- No claim in this track may cite the project's or the author's reputation as
  evidence.
