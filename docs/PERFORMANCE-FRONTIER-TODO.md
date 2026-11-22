# Performance Frontier Programme — work queue

Single tracked queue for `docs/PERFORMANCE-FRONTIER.md`. Status vocabulary is the
same as `docs/ETP-TODO.md`: `TODO`, `IN_PROGRESS`, `PARTIAL`, `DONE`, `BLOCKED`
(with the blocker), `NOT_APPLICABLE` (with the reason).

Every item's result is an ETP claim: it carries its candidate identity, its
instrument identity, its population, its scope, its threat model and its
obligations. A performance classification (§10 of the programme) is disjoint from
`SAFE_COMPATIBLE` and from any semantic assurance.

Rules that bind this queue:

- performance never outranks correctness, memory safety, timing or compatibility;
- a faster arm without the differential courts and the binary constant-time audit
  **at the same digest** is an experiment, not a candidate;
- a measured regression is published, never dropped;
- an optimisation is admitted only by the conjunction in §11 of the programme;
- a result on the virtualised court is `SCOPED_OBSERVATION`, not a frontier
  result;
- no item may weaken an open obligation in the timing queue, and PFP-1 and PFP-2
  are expected to *discharge* some of them;
- **do not omit, do not stop, push often.**

---

## Queue

| id | work package | status |
|---|---|---|
| PFP-0 | **Reconstruct the performance baseline.** Freeze the exact release artefacts and their DSO digests; unify the allocation instrument across candidate and every comparator; fix competitor inventory in `forensics/performance/AUTHORITIES.json`; preregister the measurement protocol (ordering, repetition, stopping rule, statistic, confidence method) in `docs/PERFORMANCE-METHODOLOGY.md`; re-measure every row of the current table with the authority in the same recipe. Acceptance: every number bound to both DSO digests, raw samples retained, population and workload identifiers matched, and a published list including any row where the candidate is worse than previously reported. Evidence: `evidence/performance-frontier/campaigns/PFP-0/`; protocol: `docs/PERFORMANCE-METHODOLOGY.md`. **Hardening (2026-11-22):** the reconstruction now requires the exact preregistered process-identity population (58 rows: warm-up, 15 repetitions, allocation probe, six cross-verification repetitions × two signer roles × two subjects), unique repetition identifiers and the realised balanced per-repetition order, a correctness-check population declared by `WORKLOADS.json` (an empty side and any missing, duplicate or extra check identifier are refused), and exactly the twelve `(repetition, signer, verifier)` cross-verification tuples. Campaign and workload JSON with duplicate keys or non-finite numbers is refused with the offending JSON pointer. Re-running the hardened analyser over the committed campaign reproduces `results.json` **byte for byte**; 34 tests in `forensics/tools/tests/test_analyse_bench_api.py` (mutation controls plus one positive reconstruction), 0 failures. No measurement changed, no exclusion was introduced, and no frontier claim is made. Evidence commit: the commit introducing `evidence/etp/INTEGRITY-HARDENING.md` (`git log -1 --format=%H -- evidence/etp/INTEGRITY-HARDENING.md`). | DONE |
| PFP-1 | **Prepared Montgomery domains.** Reuse validated context parameters (`R`, `R²`, `n0`, width) instead of recomputing them; bind width, modulus, radix, backend and representation to the prepared object; wire through the existing RSA and DH ownership lifecycles; refuse a context reused for a different modulus. Acceptance: setup-inclusive and prepared-key latencies measured separately; no stale-state or ownership regression; the T6/T11 RSA obligations unchanged; ctgrind at the same digest shows no new secret-dependent flow. **Done:** prepared domain in `MontCtx`; setup/prepared paired ratios `modexp2048` 1.0215, 2048-bit DH ≈1.021, `modexp8192` 1.0054, RSA setup-inclusive 5.01× prepared; the before-control shows the old entry point ignored `in_mont` (modexp ratio 0.9996); ctgrind RSA CRT 96,541/106 and 96,836/112 inside the recorded 105–112 band, ECDSA 97,217/186. **Discharges no timing obligation**: T6/T11 are unchanged and T23/T24/T29 residuals remain. Evidence: `evidence/performance-frontier/campaigns/PFP-1/`. | DONE |
| PFP-2 | **Fixed-width P-256 field engine.** Implement `P256Field`/`P256Scalar` with the three kernels (`MONT`, `SOLINAS`, `ARCH`) behind one interface; measure dependency chains, instruction count and reduction cost rather than asserting a winner; keep the generic path as the oracle and fallback. Acceptance: division-free admitted hot path; differential evidence against the generic reduction over an adversarial population and a pseudorandom sweep; mutation control (force the generic kernel) showing the fast path is load-bearing; ctgrind and branch audit at the same digest. | TODO |
| PFP-3 | **Fixed-base P-256 multiplication.** Precompute generator multiples from tracked curve data, checked against the authority's generator; constant-time selection; exact generator/group match as an admission precondition, with modified generators, custom curves and foreign methods keeping their own semantics. Compare Renes–Costello–Batina complete formulas against verified Jacobian and `a = −3` doubling by weighted cost. Acceptance: point-level differential over thousands of scalar/point combinations against the authority; equivalence for the fixed-base and variable-base paths; refusal tests for non-standard generators. | TODO |
| PFP-4 | **Specialised ECDSA scalar arithmetic.** Complete the signing pipeline of §4.5 in-representation: fixed-width scalar admission, `k·G`, field-to-order reduction, `s = k⁻¹(m + r·d) mod q`, export. Preserve `ECDSA_sign_ex`, supplied nonces, custom methods, retries and error behaviour. Acceptance: signature equality with the authority on deterministic-nonce samples, the defining-equation test, verify round-trip, blind/blinding behaviour unchanged, and the T27 constant-pattern addition retained. | TODO |
| PFP-5 | **Fixed-window BN exponentiation.** Replace the bit-at-a-time ladder with a constant-pattern window; table selection by full constant-time scan; precomputation cost included in the accounting. Acceptance: measured arithmetic-operation reduction with the timing obligations intact; ctgrind at the same digest no worse than the current ladder; dudect under the preregistered protocol; the T3/T8 fixed-width storage rules preserved. | TODO |
| PFP-6 | **Integrated Montgomery multiply and squaring.** Compare CIOS, FIOS, product-scanning/Comba and almost-Montgomery schedules; dedicated squaring; measured crossover for Karatsuba. Every bound (`T < m·R`, lazy-representation composition) proved before it removes a reduction. Acceptance: independent differential evidence per kernel, bound arguments recorded, measured crossover table, and no reliance on a debug assertion as a safety argument. | TODO |
| PFP-7 | **RSA CRT dual engine.** Scalar interleaving first; IFMA radix-2^52 vector pairing only where the hardware has it. No OS threads by default. Acceptance: fault injection in each CRT half and in recombination; blinding lifecycle, result check and implicit rejection unchanged; single-operation latency and throughput reported separately. | TODO |
| PFP-8 | **DH prepared-group optimisation.** Comb tables for RFC 7919 and RFC 3526 groups generated from tracked data; generator-2 doubling; `dh->length` preserved exactly; peer validation and subgroup checks unchanged. Acceptance: real group fixtures in the benchmark population; key generation and shared secret measured separately; validation-refusal tests. | TODO |
| PFP-9 | **Architecture-specialised backends.** x86-64 (`mulx`/`adcx`/`adox`, AVX2, AVX-512/IFMA where available) and AArch64 (`mul`/`umulh`, NEON, DIT) as separate tuning targets; outlined routines with fixed symbols; portable Rust retained as oracle; `docs/KERNEL-VERIFICATION.md` records per-kernel provenance, proof status and the constant-time obligation. Acceptance: per-platform evidence, no inheritance across targets, and a stated provenance decision from §8 of the programme. | TODO |
| PFP-10 | **Fast inversion.** Compare the existing fixed-iteration binary GCD against fixed-addition-chain Fermat, Bernstein–Yang divsteps, architecture-tuned divsteps and batch inversion; bind iteration counts to the mechanised bound; keep field and order domains distinct. Acceptance: constant-time evidence at the same digest, correctness differential, and a measured crossover per domain and size. | TODO |
| PFP-11 | **Remaining high-impact curves.** P-384, P-521, X25519, Ed25519 — each with its own field representation, reduction and scalar strategy; P-521 uses its Mersenne structure rather than Montgomery. Acceptance: per-curve differential and timing evidence; no shared assumption carried over from P-256. | TODO |
| PFP-12 | **Symmetric and AEAD acceleration.** AES-GCM (VAES/VPCLMULQDQ on x86, AES/PMULL on AArch64), ChaCha20-Poly1305, SHA-2 extensions; complete AEAD operation including tag verification and AAD. Acceptance: 64-byte latency and 16 KiB throughput reported separately; fallback paths for CPUs without the extensions. | TODO |
| PFP-13 | **Post-quantum optimisation.** ML-KEM and ML-DSA NTT, sampling, SHAKE; bounded arithmetic representations and independently justified reduction arguments; separate research-frontier track for unadmitted mechanisms. Acceptance: correctness vectors, timing evidence, and an explicit statement of which proofs cover which backend. | TODO |
| PFP-14 | **EVP and provider hot-path optimisation.** Reduce repeated resolution of immutable selections, context initialisation, refcounting and registry contention; dispatch contention measured against the HAProxy-class evidence. Acceptance: semantics preserved for custom providers and callbacks; contention measured, not assumed. | TODO |
| PFP-15 | **TLS and X.509 performance.** Handshake, resumption, record layer and certificate processing measured end to end at L4, with rustls-style methodology. Acceptance: full-handshake and resumption rates, memory per connection, and bulk transfer reported as separate rows. | TODO |
| PFP-16 | **Multicore scaling.** Strong scaling and tail latency, with the dispatch and registry work of PFP-14 included. Acceptance: scaling curve by worker count, p99 under load, and a control showing the pre-change behaviour. | TODO |
| PFP-17 | **Independent frontier verification.** External reproduction of the frozen population, correctness and security evidence at the exact candidate; honest `INDEPENDENTLY_REPRODUCED_FRONTIER` only when it happens. Acceptance: an external party's receipt, or the item stays `EXTERNAL_REVIEW_PENDING`. | TODO |

---

## The first six changes

These are the PFP items that address demonstrated architectural limitations and
should be taken first, in this order. They are a view of the queue, not a second
queue.

| # | change | item |
|---|---|---|
| 1 | repair and freeze the benchmark: exact shipping DSO, all competitor identities, per-operation accounting, cross-verification, reproducible measurement | PFP-0 |
| 2 | reuse Montgomery contexts instead of recomputing `R²` | PFP-1 |
| 3 | specialised P-256 multiplication and reduction, division-free | PFP-2 |
| 4 | keep the whole P-256 computation fixed-width; normalise only at justified boundaries | PFP-3 |
| 5 | fixed-base generator multiplication | PFP-3 |
| 6 | fixed-window BN exponentiation | PFP-5 |

Deliberately **not** first: compiler-flag experimentation, blanket
`#[inline(always)]`, alternative global allocators, aggressive `unsafe`. They are
not substitutes for reducing the fundamental mathematical work.

---

## Dependencies and gating

- `PFP-0` gates every claim: nothing is classified `MEASURED` before the protocol
  exists.
- `PFP-1` and `PFP-2` overlap the open timing obligations T23, T24 and T29's
  residuals. Their receipts must name which timing obligation they discharge,
  and no timing obligation is discharged by a performance result.
- `PFP-3`, `PFP-4`, `PFP-5`, `PFP-6`, `PFP-7` are independent of each other once
  `PFP-2` exists and may proceed concurrently where resources permit.
- `PFP-9` gates any claim that depends on emitted machine code.
- `PFP-17` is a release gate for a frontier claim and for nothing less.
- Bare-metal access with a PMU is a prerequisite for `FRONTIER_LEADING` and for
  any `INDEPENDENTLY_REPRODUCED_FRONTIER`. Until then every result is
  `SCOPED_OBSERVATION` and says so.
