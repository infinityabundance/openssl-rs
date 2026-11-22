# Performance Frontier Programme

**PFP · cumulative with the timing-safety queue and the Earned Trust Protocol**

Queue: `docs/PERFORMANCE-FRONTIER-TODO.md` (items `PFP-0` … `PFP-17`).
Evidence roots: `evidence/performance-frontier/`, `forensics/performance/`,
`courts/performance-frontier/`.

This programme does not replace `docs/PHASE-19-PERFORMANCE-SEAL.md`. That seal
records what was measured and explicitly claims no benchmark parity. This
programme sets quantitative, independently reproducible acceptance criteria, and
every one of its claims is an ETP claim under `docs/ETP-CLAIM-ALGEBRA.md`.

---

## 0. Governing standard

> OpenSSL-RS shall pursue the highest independently demonstrated performance
> achievable under its native-Rust, memory-safety, cryptographic-security and
> externally observable compatibility obligations.
>
> Every optimised computational mechanism shall be admitted through precisely
> specified arithmetic domains, ownership invariants, security models,
> correctness arguments, adversarial instrumentation and candidate-bound
> empirical evidence.
>
> Performance improvements shall never be obtained through weakened security
> mechanisms, reduced compatibility, concealed regressions, incomplete
> measurement populations or misleading comparisons.
>
> The original OpenSSL implementation remains an authority for applicable
> compatibility requirements, but its internal architecture shall not constrain
> OpenSSL-RS where a demonstrably superior and observationally compatible
> implementation is possible.
>
> Performance leadership shall be earned separately for each algorithm,
> workload, architecture and security profile, and shall remain independently
> challengeable through complete, reproducible evidence.

Two consequences bind everything below:

1. **Performance never outranks correctness.** A faster arm that has not passed
   the differential courts and the binary constant-time audit **at the same
   digest** is an experiment, not a candidate.
2. **A claim may never exceed its evidence.** A measured regression is published
   alongside a measured win.

---

## 1. Where the programme starts

Measured at the candidate named in `docs/ETP-TODO.md`; these are historical
points, not a fresh benchmark of any later tree. The authority column is the
admitted OpenSSL production build (`611e511d`), assembly enabled.

| operation | candidate / authority | candidate allocations | authority allocations |
|---|---|---|---|
| ECDSA P-256 sign | **34.71×** slower (441.7 µs vs 12.7 µs) | 249 (census) / 276 (probe) | 29 |
| RSA-2048 private, CRT, blinded | 5.43× | 173 | 19 |
| DH-2048, full-width exponent | 4.64× | 27 | 8 |
| DH-3072 | 4.77× | 27 | 8 |
| BN modexp 2048 | 4.63× | 18 | 5 |
| BN modexp 8192 | 4.90× | 18 | 5 |

Allocation counts from two different instruments are **not** interchangeable;
PFP-0 unifies the instrument and re-measures every subject, including the
authority, in one recipe.

Structural causes, from source reading at `79c98c60`:

- arithmetic is `Vec<u64>` limbs with `u128` schoolbook multiply and a separate
  REDC pass — no dedicated squaring, no `mulx`/`adcx`/`adox`, no IFMA;
- exponentiation is a constant-pattern binary ladder performing a multiply **and**
  a square per exponent bit, with no window;
- P-256 resolves to `EC_GFp_simple_method` under the recorded divergence, so
  every field operation goes through generic BIGNUM code;
- P-384 and P-521 take the same generic path, which is where the authority is
  weakest;
- `BN_mod_exp_mont_consttime` accepts a `BN_MONT_CTX` and does not use it, so
  `R²` is recomputed per operation while DH already maintains a context cache;
- `BN_mod_exp_mont_consttime_x2` runs the two CRT halves sequentially;
- the measurement venue is a virtualised host with **no exposed PMU**.

The gap is therefore mostly structural rather than algorithmic, and the first
phase of this programme is the same work as the open timing obligations (T23,
T24 and T29's residuals): fixed-width secret storage and allocation-free
arithmetic. **Performance and constant-time safety share their first phase.**

---

## 2. The frontier, stated as literature rather than as measured fact

No row in this table was measured by this project. Each is a published result or
an implementation claim, recorded to direct work — never to support a claim.
`PFP-0` admits the comparator and re-measures what it uses.

| implementation | operation | technique | reported |
|---|---|---|---|
| OpenSSL `nistz256` (Gueron–Krasnov) | P-256 sign/verify/ECDH, x86-64 and ARMv8 | hand-written Montgomery field asm, large precomputed table for `G`, constant-time Booth windows | ≈2.3× signing over prior OpenSSL on Haswell |
| OpenSSL `rsaz` AVX-512 IFMA | RSA-2048/3072/4096 CRT | two half-size exponentiations interleaved in radix 2^52 with 256-bit vectors | ≈2× RSA-2048 sign on Ice Lake |
| AWS-LC + `s2n-bignum` | RSA on Graviton | Karatsuba, separate Montgomery reduction, NEON offload, vectorised constant-time table lookup, HOL Light object-code proofs | +81% RSA-2048 and +94% RSA-4096 sign over prior AWS-LC code |
| AWS-LC P-521 | P-521 | fiat-crypto field arithmetic plus precomputed tables, replacing generic Montgomery | sign ≈5.9×, ECDH ≈3.9×, verify ≈2.4× on Xeon 8124M |
| BoringSSL | P-256 verify | variable-time point multiplication for public data; compare `r` against Jacobian `X` without an inversion | 1.15–1.19× verify on Kaby Lake/Skylake |
| Pornin `bingcd` | constant-time modular inversion | most iterations of binary GCD on a one-register approximation; mechanised iteration-bound proof | ≈6,253 vs ≈9,175 cycles for Fermat at 255 bits |
| Intel `crypto_mb` | RSA/ECDSA/ECDH throughput | eight independent operations in AVX-512 lanes | 4.6–6.3× RSA-2048 private **throughput** over OpenSSL 1.1.1, per-operation after dividing by 8 |
| AWS-LC (HAProxy) | TLS handshakes, 64 Graviton4 cores | light locks, C11 atomics, tuned RSA | >63,000/s vs ≈42,500/s for OpenSSL 3.1–3.4 |

The pattern: every frontier result pairs **fixed-width, size- or curve-specific
code** with **platform-specific instruction selection**. The authority's weak
rows are the ones where it still runs generic code (P-384, P-521, FFDHE) and the
ones where its architecture costs throughput (lock contention).

**Consequence for planning.** The largest honest margins are on the rows where
the authority is generic; P-256 margins are smaller because the authority is
hand-tuned there; RSA on IFMA hardware is parity-first. Any of those statements
is a planning estimate until `PFP-0`'s measurement says otherwise.

---

## 3. The architectural change: a fixed computational interior

Preserve the externally observable OpenSSL object model. Stop making generic
`BIGNUM` operations, normalised vectors and C-compatible objects the fundamental
representation of every internal cryptographic computation.

```
unmodified consumers (OpenSSH, curl, nginx, Python, PostgreSQL)
        │  OpenSSL-compatible API and ABI: symbols, providers, callbacks,
        │  error queue, ownership semantics
        ▼
validated computational admission boundary
        │  domain validation, representation conversion, method eligibility
        ▼
first-party high-performance kernels (single crate, native Rust)
        │  EC field arithmetic · fixed-width residues · scalar arithmetic
        │  curve-order domains · Montgomery workspaces · vector kernels
        ▼
ABI-compatible output boundary
        observable values, ownership and error semantics preserved
```

### 3.1. Drop-in rules that make a fast path a faithful candidate

1. **`BIGNUM` only at the boundary.** Convert once on entry to a fixed-width
   value (`[u64; 4]`, `[u64; 6]`, `[u64; 9]`, `[u64; 32]`), compute, convert
   once on exit. Inner loops never touch `Vec`, `BN_CTX` or the allocator.
2. **Dispatch where the authority dispatches.** EC per curve through the group's
   method; RSA only when the default `RSA_METHOD` is in force, so a consumer's
   own `bn_mod_exp`/`rsa_mod_exp` hook is still called; FFDH only for named
   groups whose parameters are byte-identical to the built-in tables.
3. **Keep observable representation where it is observable.** The method pointer
   identity returned by `EC_GROUP_method_of`, the deprecated Jacobian getters,
   the readable contents of `BN_MONT_CTX`, `BN_FLG_CONSTTIME` propagation and
   `RSA_FLAG_CACHE_PRIVATE` caching are decided per case by a court, not by
   argument. Where the authority switches P-256 to a dedicated method, matching
   that method **closes** the recorded divergence rather than widening it.
4. **Honour `OPENSSL_ia32cap`.** Every assembly path checks the same capability
   bits the authority checks, so masking a feature off selects the same arm on
   both sides.
5. **Byte-identical results.** Same signatures for deterministic nonces, same
   shared secrets, same error queue on refusal. Each fast path lands behind the
   existing differential courts with a portable reference kept as the oracle.
6. **No eligibility by assumption.** A fast path must prove or check that the
   machinery it bypasses is not observably required. An externally mutable
   object is not immutable because most applications never mutate it.

### 3.2. Representation types

Curve-field and curve-order residues are different types because they are
residues modulo different values; four limbs in common does not make them
interchangeable. Montgomery-encoded and ordinary residues are separated where the
type system can carry it.

```rust
struct P256Field  { limbs: [u64; 4] }   // mod p
struct P256Scalar { limbs: [u64; 4] }   // mod q
struct P256Projective { x: P256Field, y: P256Field, z: P256Field }
```

Secret ownership, cleansing, canonicality and representation invariants are
specified before any of these types is implemented — they are ordinary secret
storage, not an exemption from AGENTS §5.

---

## 4. ECDSA

### 4.1. Field arithmetic

Three candidate kernels, compared rather than assumed:

| candidate | mechanism | role |
|---|---|---|
| `P256-MONT` | unrolled four-limb Montgomery, `R = 2^256` | primary portable candidate; matches the authority's representation |
| `P256-SOLINAS` | fixed-pattern reduction from `p = 2^256 − 2^224 + 2^192 + 2^96 − 1` | alternative; measure dependency chains, not assertion |
| `P256-ARCH` | `mulx`/`adcx`/`adox` (x86) and `mul`/`umulh` (AArch64) | frontier candidate |

Solinas is **not** assumed to beat Montgomery. The comparison is on dependency
chains, instruction count, multiplication latency, register pressure and
reduction cost per target. The precedent (fiat-crypto / BoringSSL) is that
specialisation through partial evaluation reaches competitive performance with a
correctness proof, not that a particular reduction wins.

No generic division, no dynamic limb length and no heap allocation inside the
admitted field-computation loop.

### 4.2. Scalar multiplication is not one workload

| workload | example | strategy |
|---|---|---|
| fixed-base secret | ECDSA sign, keygen: `k·G` | signed-window or comb precomputation for the standard generator, secret-independent selection |
| variable-base secret | ECDH | fixed-pattern multiplication over validated points |
| public double-scalar | ECDSA verify | interleaved `wNAF`, variable-time permitted |

Precomputation for `G` requires an exact generator and group-parameter match.
Modified generators, custom curves, foreign methods and unsupported parameter
configurations keep their own semantics and are **not** silently dispatched to
the standard P-256 kernel.

OpenSSL's own standard-generator path uses Booth-encoded windows over 37 tables
of 64 affine entries. Its geometry is evidence of the gap, not a requirement to
copy it: window width, comb configuration, cache footprint and selection cost
are measured on the target.

### 4.3. Point formulas

Compare Renes–Costello–Batina complete formulas against verified
mixed-coordinate Jacobian formulas and `a = −3` doubling, weighting
`C = N_M·C_M + N_S·C_S + N_A·C_A` with empirically determined costs, and account
for register pressure, loads, stores, selection and exceptional-point handling.
The cheapest formula on paper is not always the fastest emitted code.

### 4.4. Inversion

Keep the existing fixed-iteration binary extended GCD as the known baseline and
compare against fixed-addition-chain Fermat inversion, Bernstein–Yang divsteps,
architecture-specialised divsteps and batch inversion where table construction
amortises it.

A `secp256k1` iteration bound is not transplanted to another representation or
modulus without establishing the applicable theorem; where a published bound was
later corrected, the corrected, mechanised bound is the one used. The distinction
between field inversion modulo `p` and nonce inversion modulo the group order `q`
is preserved.

### 4.5. Keep the whole signature in its specialised representation

```
generate nonce (approved RNG, rejection semantics preserved)
  → fixed-width scalar admission (domain validated, confidential ownership)
  → k·G  (fixed-base precomputation, specialised point arithmetic)
  → r     (fixed-pattern field-to-order reduction)
  → s = k⁻¹(m + r·d) mod q   (specialised scalar arithmetic and inversion)
  → ECDSA_SIG export (OpenSSL-compatible, error behaviour preserved)
```

No repeated transition to normalised `BIGNUM` intermediates is necessary inside
the eligible computation. `ECDSA_sign_ex`, supplied nonce values, custom methods,
provider contracts and retry conditions keep their behaviour.

### 4.6. Targets

Engineering objectives, revised by measurement:

| milestone | target |
|---|---|
| specialised field arithmetic | measure toward ≤10× |
| specialised fixed-base multiplication and scalar arithmetic | measure toward parity |
| architecture-tuned backend | beat the fastest qualified comparator on that platform |
| production API | retain the win through `EVP` and TLS |

The goal is not to beat a historical 12.7 µs number. It is to beat whatever the
fastest admissible comparator achieves on the same hardware.

---

## 5. RSA

1. **Window the exponentiation.** Fixed window of 5–6 bits replacing the
   bit-at-a-time ladder; table lookup is a constant-time scatter/gather full
   scan, never an index. At 2048 bits this removes most multiplies the ladder
   spends on zero bits.
2. **Integrated Montgomery core.** Interleaved CIOS with `mulx`/`adcx`/`adox`
   (two independent carry chains) plus dedicated Montgomery squaring; on AArch64
   separate multiply from reduction and offload to NEON where it pays.
3. **Karatsuba** at 1024- and 2048-bit half sizes, after a measured crossover.
4. **Dual CRT.** Scalar interleaving of the two independent exponentiation chains
   first; IFMA radix-2^52 vector pairing only on hardware that has it. Two OS
   threads per RSA operation are **not** the default optimisation.
5. **Reuse prepared Montgomery domains.** A prepared context binds width, modulus,
   radix, backend identity and representation invariants; it is reused under the
   existing RSA and DH ownership lifecycles. A context reused for the wrong
   modulus is a correctness defect, not an optimisation. Setup-inclusive and
   prepared-key latency are measured separately.

Bounds are proved before they are used to remove a reduction: the usual
single-subtraction REDC argument requires `T < m·R`, and "both operands fit in
`R`" does not establish it. Lazy or almost-reduced representations carry explicit
composition arguments.

**Untouchable by any optimisation:** blinding lifecycle, CRT fault verification,
private-operation result check, required randomness, padding validation, implicit
rejection, secret cleansing, failure semantics. Faults are injected in each CRT
half and during recombination. A signature that got faster because a security
operation disappeared is a failed optimisation.

---

## 6. DH

One Montgomery engine serves RSA, DH and BN; DH adds admission profiles.

- **Fixed-base comb tables** for RFC 7919 FFDHE and RFC 3526 MODP groups,
  generated from tracked group data at build time and checked against the
  authority's group bytes. Key generation then spends a fraction of the squarings
  a windowed exponentiation needs, with full constant-time scans.
- **Generator 2 is a doubling.** Without a table, `g = 2` is a shift plus one
  conditional subtraction under a square-and-always-double pattern.
- **Exponent length is part of the contract.** `dh->length` from the named-group
  table is preserved exactly; a shorter exponent would be faster and would be a
  divergence.
- **Validity checks stay.** Peer-key range checks and the subgroup check where
  `q` is known remain exactly as the authority performs them.

Benchmarks use real FFDHE and MODP fixtures, not only the synthetic odd modulus
in the current API bench.

---

## 7. Shared engineering

| piece | obligation |
|---|---|
| assembly inside the crate | `core::arch::global_asm!` or `.S` through `build.rs`, C-ABI Rust signatures over fixed-size arrays, outlined so the analysed symbol is one function; portable Rust remains the oracle |
| dispatch | resolved once at initialisation from CPUID masked by `OPENSSL_ia32cap`, stored in an immutable static; each arm carries its own timing and binary-audit evidence |
| AArch64 | first-class target, not a port of x86 assumptions; set DIT around secret-bearing routines where supported — it is the only hardware-level data-independent-timing guarantee |
| dispatch contention | immutable published tables, per-thread fetch caches and relaxed atomics where ordering permits, preserving the authority's semantics; contention is measured, not assumed |
| async batching | only behind the existing `ASYNC_JOB` interface, only for consumers that already request it, and it changes no single-operation result |

---

## 8. Provenance of the fast arithmetic

Speed code is where assurance usually breaks. The route is chosen deliberately,
and it is a decision for the project principal, not for an agent:

| route | gives | does not give | precedent |
|---|---|---|---|
| adopt `s2n-bignum` assembly | HOL Light proofs that the object code meets its spec, x86-64 and AArch64; P-256/384/521 field and point routines; Apache-2.0 / ISC / MIT-0 | **constant time is not machine-checked** — its own README says functional correctness is proved while the timing discipline is a coding practice plus tests, except where ARM DIT applies; third-party code inside the custodian boundary | Graviola, AWS-LC |
| generate with fiat-crypto / CryptOpt | Coq-proved field arithmetic; generated Rust for P-256/384/521 and their scalars; CryptOpt emits asm with a proof to x86-64 semantics | field layer only — scalar multiplication, tables and inversion remain ours; portable fiat code is not assembly speed | BoringSSL, AWS-LC |
| write and prove our own | full independence; proof style matches the planned hax/Lean or Kani work | the largest effort; a proof of hand-written assembly is a multi-year effort per routine family | — |

**Recommendation recorded for decision:** take fiat-crypto Rust as the portable
reference and differential oracle for every curve field; make the fast path
`s2n-bignum`-grade assembly — adopted or written and proved. Treat constant time
as a **separate** obligation discharged on the built DSO by this project's own
instruments (ctgrind, dudect, BINSEC `-checkct`, the branch audit) for every
dispatch arm, and bind the inversion iteration count to the mechanised bound.

A functional proof of a routine is not constant-time evidence, and source-level
constant time is not binary constant time. A fast path enters only with both.

---

## 9. Measurement

### 9.1. Five levels

| level | scope | examples |
|---|---|---|
| L1 | arithmetic | limb multiply, modular multiply, square, reduction, inversion |
| L2 | primitive | RSA, ECDSA, ECDH, DH, AEAD, ML-KEM |
| L3 | API | BN, EVP, RSA, EC, provider-facing operations |
| L4 | protocol | TLS 1.2/1.3 handshake, resumption, records |
| L5 | downstream | OpenSSH, curl, nginx, Python, PostgreSQL |

Increasing integration scope, not a quantitative scale. An L1 win does not imply
an L5 win; it establishes that a particular arithmetic optimisation is valuable
in its measured scope.

### 9.2. Competitor identities

Two reference classes are maintained and never conflated:

- **compatibility authority** — the admitted OpenSSL version and build profile;
- **performance authorities** — the best admitted contemporary stable
  implementations of OpenSSL, AWS-LC, BoringSSL, rustls with its crypto
  provider, wolfSSL and relevant specialised kernels, plus a separately labelled
  research-frontier track.

Each identity records: commit, compiler and flags, enabled assembly, CPU
features, build profile, provider configuration and security mechanisms. An
OpenSSL comparison against an assembly-disabled build belongs only to a clearly
labelled portable comparison. A competitor that does not expose the API or
support the algorithm is `NOT_APPLICABLE` for that row, not a loser. rustls's
cryptographic provider is part of its identity.

### 9.3. Dimensions

Single-operation latency; throughput; tail latency (p95/p99/p99.9 where the
sample supports it); parallel scaling; memory (peak RSS, per-connection, scratch);
allocator behaviour (calls, bytes, reallocations); retired instructions and
cycles where a PMU is available; cache and branch behaviour; energy per
operation where genuinely measurable; startup behaviour.

**Never merged into one score.** A batched backend may lead in throughput and lose
single-request latency; a larger table may improve signing and worsen startup and
footprint. The honest result is a frontier, not a winner.

### 9.4. Empirical discipline

Each experiment freezes its measurement population and stopping rule **before**
execution, retains raw samples, reports variation, publishes every result
including regressions, and states exactly what each timing includes. Independent
process-level repetitions, randomised blocked comparison order, confidence
intervals for paired ratios and appropriate multiple-comparison handling are
required. Thousands of operations inside one timing batch are not thousands of
independent replications.

Result-line counts alone are not completeness: exact workload identifiers and the
expected population are matched.

### 9.5. Venue

The current court is a virtualised host with no exposed PMU. That is sufficient
for ratios, correctness and mutation experiments, and **insufficient** for a
frontier claim. A frontier claim requires bare metal with hardware counters, the
frequency pinned, turbo and SMT disabled for latency runs, core isolation, and
the microcode and kernel recorded — on every platform the claim covers.

Until that venue exists, results are labelled **`SCOPED_OBSERVATION`** with the
venue named. They are not frontier results.

---

## 10. What a performance claim means

For workload `w`, hardware `h`, build profile `b` and aligned security contract
`s`:

```
R(w, h, b, s) = T_candidate(w, h, b, s) / min over qualified j of T_j(w, h, b, s)
```

Smaller is faster for latency; a corresponding throughput ratio is defined
against the highest qualified comparator throughput.

| classification | acceptance condition |
|---|---|
| `MEASURED` | a valid, reproducible benchmark was executed |
| `COMPETITIVE` | within a **preregistered** competitiveness margin |
| `PARITY_ESTABLISHED` | a preregistered equivalence or noninferiority criterion is satisfied |
| `AHEAD` | a statistically supported advantage against the declared comparator |
| `FRONTIER_LEADING` | an advantage against every qualified comparator in the frozen population |
| `INDEPENDENTLY_REPRODUCED_FRONTIER` | a frontier result reproduced independently within its stated scope |

These are performance classifications and are **disjoint from** `SAFE_COMPATIBLE`
and from semantic assurance. A material win needs a preregistered practical
margin — for example 5% lower median latency with an appropriate confidence
bound. The lowest observed time is not a statistically credible lead.

Wording discipline: never "fastest in the world". Instead: *the fastest measured
RSA-2048 signing implementation among these five admitted libraries, on this CPU,
under this security profile, at these digests*. That is a stronger claim because
someone else can challenge it.

---

## 11. Admission rule

An optimisation is admitted only by the conjunction:

```
correctness
  ∧ memory-safety obligations discharged for the changed boundary
  ∧ timing requirements met at the same digest
  ∧ ABI and semantic compatibility preserved
  ∧ evidence valid under the ETP claim algebra
  ∧ performance improvement measured against the preregistered criterion
```

No disjunction, no compensation, no weighting. Every fast path carries its own
eligibility and fallback obligations.

Refused regardless of speed:

| attempted shortcut | gate |
|---|---|
| disable RSA blinding | refuse the security-equivalent claim |
| secret-indexed lookup replacing secret-independent selection | refuse |
| remove cleansing | refuse |
| skip certificate validation | refuse |
| reduce key sizes or exponent requirements | refuse |
| reuse stale Montgomery parameters | refuse |
| ignore custom methods or callbacks | refuse |
| benchmark a stale binary | refuse |
| change the benchmark population silently | refuse |
| compare against a deliberately slowed competitor | refuse |
| publish only winning cases | refuse the completeness claim |

---

## 12. Non-claims

- A faster operation is not a safer operation.
- An assembly routine with a functional-correctness proof is not thereby
  constant time.
- A source-level constant-time argument is not binary constant time.
- A win at L1 is not a win at L5.
- A win on one microarchitecture does not transfer to another; evidence does not
  inherit across targets.
- A throughput win is not a latency win.
- A benchmark result on the court's virtualised host is not a frontier result.
- Passing the differential courts is not a correctness proof; it is bounded
  differential evidence.
- No result in this programme weakens, or is permitted to weaken, an open
  obligation in the timing queue or the ETP queue.

---

## 13. Reading programme

Primary references, to be read before the item that depends on them. Each entry
states the item it informs; anything cited but not read is marked as such in the
item's receipt.

| reference | informs |
|---|---|
| Erbsen, Lim, et al., *Simple High-Level Code for Cryptographic Arithmetic — With Proofs, Without Compromises*, IEEE S&P 2019 (fiat-crypto) | PFP-2, PFP-9 |
| Koç, Acar, Kaliski, *Analyzing and Comparing Montgomery Multiplication Algorithms*, IEEE Micro 1996 | PFP-6 |
| Bernstein, Yang, *Fast constant-time gcd computation and modular inversion*, ePrint 2019/266, TCHES 2019 | PFP-10 |
| Pornin, *Faster modular inversion and Legendre symbol, and an X25519 speed record* | PFP-10 |
| Renes, Costello, Batina, *Complete addition formulas for prime order elliptic curves*, EUROCRYPT 2016 (ePrint 2015/1060) | PFP-3 |
| Almeida et al., *The Last Mile: High-Assurance and High-Speed Cryptographic Implementations* | PFP-9, methodology |
| `s2n-bignum` (AWS): object-code proofs, `SOUNDNESS.md`, `non_ct_functions.txt` | PFP-9, PFP-17 |
| Gueron, Krasnov, *Fast prime field elliptic-curve cryptography with 256-bit primes*, ePrint 2013/816 | PFP-2, PFP-3 |
| Drucker, Gueron, *Fast modular squaring with AVX512IFMA*, ePrint 2018/335 | PFP-6, PFP-7 |
| OpenSSL `rsaz` dual-exponentiation design; Intel `crypto_mb` | PFP-7 |
| Didier et al., truncated multiplication and batch SIMD Montgomery arithmetic (preprint) | PFP-7 — replicate before adopting |
| `mlkem-native` (PQCA): portable implementation, native backends, bounded verification contracts | PFP-13 |
| `libsecp256k1` safegcd documentation and the mechanised iteration-bound work | PFP-10 |
| eBACS / SUPERCOP measurement discipline | PFP-0 |
| rustls comparative benchmark methodology | PFP-0, PFP-15 |
| HAProxy, *The state of SSL stacks* | PFP-14 |

---

## 14. Repository layout

Reconciled with the existing tree; nothing here duplicates Phase 19.

```
docs/PERFORMANCE-FRONTIER.md          this document
docs/PERFORMANCE-FRONTIER-TODO.md     the queue (PFP-0 … PFP-17)
docs/PERFORMANCE-METHODOLOGY.md       PFP-0 output: the measurement protocol
docs/KERNEL-VERIFICATION.md           PFP-9 output: kernels, proofs, obligations

courts/performance-frontier/
  arithmetic/  asymmetric/  symmetric/  post-quantum/  tls/  downstream/  controls/

forensics/performance/
  AUTHORITIES.json   TARGETS.json   WORKLOADS.json   KERNELS.json   OBLIGATIONS.json

evidence/performance-frontier/
  campaigns/  raw-results/  comparisons/  receipts/  attestations/
```

Product code stays inside the existing first-party implementation crate. No new
cryptographic backend dependency is introduced by this architecture.
