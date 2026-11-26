# PFP-21 — DSO-level constant-time evidence for the exact candidate

**Status: PARTIAL — the taint run and the mutation control now run against the
candidate DSO at one digest, with a positive sensitivity control; what is not
done is the register move, so the `PFP-2` arm's `constant_time_audit` still names
the earlier digest.** §7 says exactly what remains.

The gap this closes: every ctgrind reading in the PFP-2 record was taken on a
**debug test binary** (`PFP2-CTGRIND-TEST-BINARY`), and the mutation control was
**source-bound** (`PFP2-MUTATION-CONTROL-NOT-AT-DIGEST`). Neither was a statement
about the shipped artefact. PFP-19 requires a constant-time audit *and* a
measurement at the same `candidate_sha256`; the binary branch audit supplied the
former at `553e1b8c`, and this item supplies the taint evidence and the mutation
control at that same digest, against the artefact itself.

Candidate: `staging` `c1d25e10d` (the committed PFP-20 source), whose distribution
DSO is `553e1b8c…`. It was **rebuilt byte-identically in this session** into a
fresh `CARGO_TARGET_DIR`, which independently confirms the PFP-2 identity claim
that a repeat build reproduces the digest.

## 1. The harness

`pfp21_dso_ct.c` (source sha256 `ef137412…`, binary `3a385537…`) links no
libcrypto and includes no OpenSSL header: it `dlopen`s exactly one
`libcrypto.so.3` with `RTLD_NOW | RTLD_LOCAL` and resolves 24 exported entry
points with `dlsym`. Consequences, all deliberate:

* the only crypto code in the process is the named DSO;
* the process prints `LOADED realpath=… dev=… ino=… size=…` from the mapping and
  the number of `/proc/self/maps` entries for it, and the runner compares those
  with `stat(2)` on the expected on-disk file — the court proves **which file it
  mapped**, not which name it asked for;
* `FOREIGN libcrypto=N` counts any *other* mapped file whose path contains
  `libcrypto.so`; the runner requires 0 in every run;
* the DSO digest is checked before and after the whole run.

Taint is placed on the limb **values** only, and the limb pointer is not trusted:
the harness reads it from the documented layout offset, then verifies every live
limb against the same BIGNUM's own big-endian export *before* marking anything. A
layout drift fails the operation (`RESULT … ok=0`) instead of tainting the wrong
bytes, and the runner treats a missing `ok=1` as a STOP. Nothing the harness does
after tainting inspects, compares or prints a secret-derived value; the only
result value read is the operation's success flag, marked defined first because
it is public, and in timing mode the elapsed time — which is the measurement
itself.

## 2. The populations

| mode | marked undefined | marked defined | API calls in scope |
|---|---|---|---|
| `control` | nothing | everything | all of the below, once — negative control |
| `mul-g` | scalar `k`, 4 limb values (256 bits) | group, generator, `k`'s limb count, digest | `EC_POINT_mul` with the generator |
| `mul-p` | scalar `k`, 4 limb values | group, `P = 5*G`, digest | `EC_POINT_mul`, variable base |
| `mul-g-bytes` | the 32 scalar input bytes *before* `BN_bin2bn` (comparison population; also taints the imported length) | group, generator, digest | `EC_POINT_mul` |
| `sign` | the key's private scalar `d`, 4 limb values | group, public key, digest, RNG output | `ECDSA_do_sign` |
| `sign-ex` | `kinv` (caller-supplied nonce inverse) and `d` | group, public key, digest, `r = x(k*G) mod n` (published in the signature) | `ECDSA_do_sign_ex` |
| `sign-ex-k` | `k` *before* `BN_mod_inverse(k)` and `k*G`; then `kinv` and `d` | group, public key, digest, the fixture `(kinv, r)` pair | `BN_mod_inverse`, `EC_POINT_mul`, `ECDSA_do_sign_ex` |

Fixed fixtures (`d`, `k`, digest) are compile-time constants, identical in every
process and in both DSOs, so the population is frozen rather than sampled.

**Nothing that touches a secret is excluded.** The only secret the harness cannot
mark is the nonce that `ECDSA_do_sign` generates *inside* the library: no exported
entry point accepts or exposes it, so marking it would require exposing internals,
which this item forbids. It is not excluded from the measurement, it is
unreachable at the boundary: the sign path is covered through the exported
`ECDSA_do_sign_ex` (nonce inverse supplied and marked) and through `sign-ex-k`,
where the library's own `BN_mod_inverse` and `k*G` run on the tainted `k`. The
`sign` population is therefore reported as the default path with the library's
own RNG nonce (stochastic, supplementary), and the three fixed-fixture
populations are the reproducible admitted population.

Deliberately outside the instrument, and stated: the signature object and result
point are never inspected (so no harness branch can manufacture a finding); the
harness's own clock and `printf` operate on public data only.

## 3. The two DSOs (and the sensitivity control)

| artefact | role | sha256 | size |
|---|---|---|---|
| **A** | candidate (admitted P-256 engine, `Mont` default) | `553e1b8ce1eb7e03a0d92a5614b566b88e49e55d2c2a3f7ba28fc6d78eecc4e4` | 17,032,672 |
| **B** | mutation control (`Solinas` kernel forced) | `86bc63a6746e2e7bad628f7e7e6df477c3355759582e0611109af3e08156765e` | 17,040,592 |
| **C** | sensitivity control, pre-PFP-20 artefact (not a candidate) | `83f67826e2ca53dd8e014fe5442d2e77ba96ee7af35eeb78a312112a4e0a7c4f` | 17,041,264 |

A and B are built from `c1d25e10d` by `build_dsos.sh` with the same recipe
(`cargo build --release --lib --offline`, `CARGO_BUILD_JOBS=4`, fresh
`CARGO_TARGET_DIR`, then the Phase-2 version-script link). The working tree is
`20972901d`; its only `src` difference from `c1d25e10d` is `src/bn/arith.rs`
(PFP-6), so that one file is swapped for the duration of the build. The
fingerprint of all 886 `src/**/*.rs` files is taken before and after and must be
identical, and it is.

**The single build-input difference between A and B is one line** in
`src/ec/p256.rs` `default_kernel_id()` (`Mont` → `Solinas`), recorded as
`raw/kernel-difference.diff`; `src/ec/p256.rs` sha256 `75a2dd1d…` for A and
`676f4bff…` for B. Nothing else differs.

B is a valid population, not a broken build: the campaign's DSO-bound
differential harness with the recorded seed `0x5046503250485032` gives 256 `k*G`
and 256 `k*P` points **identical** to the 3.6.4 authority (`raw/b-equivalence.txt`).

C exists to answer "can this instrument see the engine path at all?". It is the
pre-PFP-20 distribution DSO that still contains the write-back `normalise`
branch. On it the same harness reports, in each of three repetitions, **4
engine-on-path contexts**, and their stack is exactly

```
store_coordinate <- p256_ladder_run::<p256::Mont<p256::FieldDomain>>
                 <- ossl_ec_scalar_mul_ladder <- EC_POINT_mul <- op_mul
```

On A the same harness reports **0**. That is the PFP-20 fix observed at the
artefact, and it is the positive control without which A's silence would be
uninterpretable.

## 4. ctgrind at the artefact

Valgrind 3.19.0 memcheck, `--num-callers=24`, one process per run, three
repetitions per tainted population, one per negative control. Classifier: the
campaign's `repro-2026-11-26/attribute.py` (A test harness, B engine, C generic
bignum, D generic EC/ECDSA driver, E allocator/runtime).

| population | A errors (r1/r2/r3) | A contexts | B errors | B contexts | engine-on-path | engine origins |
|---|---|---|---|---|---|---|
| `control` | 0 / – / – | 0 | 0 / – / – | 0 | 0 | 0 |
| `mul-g` | 3606 / 3645 / 3596 | 196 / 225 / 185 | 3631 / 3606 / 3645 | 211 / 196 / 224 | 0 | 0 |
| `mul-p` | 3635 / 3631 / 3635 | 216 / 212 / 216 | 3670 / 3606 / 3645 | 233 / 197 / 224 | 0 | 0 |
| `mul-g-bytes` | 3597 / 3632 / 3661 | 186 / 211 / 225 | 3632 / 3622 / 3607 | 212 / 201 / 196 | 0 | 0 |
| `sign` | 3723 / 3723 / 3684 | 274 / 275 / 248 | 3669 / 3669 / 3694 | 244 / 244 / 258 | 0 | 0 |
| `sign-ex` | 24 / 24 / 24 | 24 / 24 / 24 | 24 / 24 / 24 | 24 / 24 / 24 | 0 | 0 |
| `sign-ex-k` | 33007 / 33003 / 33017 | 442 / 438 / 450 | 33017 / 33042 / 33017 | 449 / 460 / 450 | 0 | 0 |
| **C `mul-g`** | 1605 / 1615 / 1605 | 199 / 204 / 199 | – | – | **4 / 4 / 4** | 0 |

Error counts are stable to within about one and a half percent across
repetitions; context counts carry the instrument's known spread (185–275)
because which generic branches are taken varies with allocation placement. Both
negative controls read **0 errors from 0 contexts**.

**Origins.** In every tainted population on both DSOs the reported contexts are
the pre-existing generic BIGNUM/EC ladder path, not the engine: `BN_nnmod` (32),
`limbs::divide_fallible` (29), `limbs::mul_fallible` (22), `BN_add`/`BN_sub`/
`BN_uadd`/`BN_mul`/`BN_mod_add_quick`, `BN_num_bits`, `ladder_post`, and the
allocation-size path reached from `BN_num_bits` (`RawVecInner::finish_grow`,
`alloc`). `sign-ex-k` adds `limbs::mod_inverse` (22) and `limbs::shr_fallible`
(14) for the tainted nonce. `sign-ex` is the smallest population — 24 contexts
from 8 sites per repetition: `BN_to_montgomery` (4), `BN_mod_mul_montgomery` (2),
`arith::mod_add_reduced_ct` (1), `ossl_ecdsa_simple_sign_sig` (1), plus
`memmove`/`memset`/`alloc` frames — i.e. the fixed-top secret arithmetic itself.

**What the instrument can and cannot say here.** Memcheck reports *conditional
jumps and moves* that depend on undefined data. It cannot distinguish a branch
from a constant-time conditional move, and it cannot see secret-dependent
arithmetic that has no conditional. The eight `sign-ex` sites are therefore
"control-flow-shaped", consistent with cmov-based selection and *not by
themselves* evidence of a leak; the binary branch audit at the same digest
(9/9 targets resolved, exit 0) is what resolves the branch question. This is
precisely why the admitted kind is the taint run *plus* the audit, never the
taint run alone.

**Kernel independence of the residue.** A and B produce the same origin set up to
0–4 sites per population. Every differing site in either direction is generic
BIGNUM or allocator code (`finish_grow`, `memset`, `BN_usub`,
`BN_mod_sub_quick`, `limbs::sub_fallible`); **no engine site differs in either
direction**. Changing the field kernel does not change what the instrument
reports, on a path where the mutation control shows the kernel is definitely
executing. The population with the largest difference (`sign`, 3 sites) is the
one whose nonce is drawn from the library RNG, so its path is not the same twice.

The two historical readings stay visible as required: the debug test binary's
`3,023 / 123`, and the first release minimal population's `12,371 / 203` on the
pre-fix `467527ae` artefact (whose pre-engine generic comparator read `794 / 29`).
Neither is superseded, and neither is comparable to the rows above without its
own population: the figures here are `3,596–3,670 / 185–236` on the post-PFP-20
candidate with a different fixed scalar, and they agree with the campaign's own
`3,621 / 200` for the same digest.

## 5. The mutation control, in the artefact

Both measurements use the same harness, the same exported entry points and the
same fixtures; only the DSO differs.

| operation | A | B | B/A |
|---|---|---|---|
| `mul-g` instructions per call (callgrind, 64-vs-0 difference) | 4,891,699 | 11,375,102 | **2.325** |
| `mul-g` wall, median of 9×200 calls | 227,820 ns [225,994–246,246] | 536,866 ns [533,578–574,727] | **2.357** |
| `sign` instructions per call | 5,427,886 | 11,809,873 | **2.176** |
| `sign` wall, median of 9×200 calls | 250,605 ns [247,552–256,497] | 563,650 ns [555,453–627,066] | **2.249** |

The instruction counts are deterministic per build and reproduce to better than
0.01% across the two runs of this session (the residual difference is harness and
allocator placement around the operation, not the operation); the wall rows are
`SCOPED_OBSERVATION` (no PMU, no frequency/turbo/SMT control). The wall and instruction ratios agree, and the
`mul-g` figure (227.8 µs, 2.36x) agrees with the source-level ladder measurement
(224.3 µs vs 538.1 µs, 2.40x). **The admitted `Mont` kernel is therefore on the
executed path of the shipped artefact, and forcing the generic kernel costs about
2.3x more instructions.** The fast path is load-bearing in the artefact, not only
in the test profile.

## 6. What this establishes, and what it does not

Established, at digest `553e1b8c` and in the artefact:

1. the taint instrument and the classifier see the engine's call path when a
   secret-dependent branch is present (4 `store_coordinate` contexts on the
   pre-fix artefact, 0 after);
2. on the candidate artefact no reported context has a `p256` frame or origin, in
   18 tainted runs per DSO across six populations;
3. the residual contexts are the pre-existing generic BIGNUM/EC ladder path, are
   kernel-independent, and include the fixed-top Montgomery wrappers and an
   allocation-size dependence reached from `BN_num_bits`;
4. the admitted kernel is load-bearing in the shipped bytes (2.33x instructions).

Not established: that any of this is *constant time* — memcheck sees only
conditional jumps/moves and undefined-memory uses; nothing here covers
value-independent-but-secret-dependent arithmetic inside the kernels; L4/L5 are
not measured; the wall rows are not isolated; the branch audit remains a review
aid (`PFP2-AUDIT-NOT-A-PROOF`); and B's semantic equivalence is established for
512 points at one seed, not for the whole kernel domain.

## 7. Register status and what remains

`ARMS.json` is **unchanged**. Its `PFP-2` arm names `83f67826` as the candidate
and records the `BINARY_BRANCH_AUDIT` at that digest; this evidence is at
`553e1b8c`, which is a *different* digest, so `constant_time_audit` must not be
re-pointed and the kind must not be promoted to `CTGRIND_PLUS_BRANCH_AUDIT`
without also moving the arm. Moving the arm is a register-wide change — the
validator requires `candidate.sha256`, `measurement.candidate_sha256`,
`differential_courts.candidate_sha256` and `constant_time_audit.candidate_sha256`
to be equal — and it needs one thing this item did not produce:

* **a campaign timing measurement at `553e1b8c`** (`courts/phase18/timing/`
  protocol, paired processes, 15 repetitions) bound to that digest. The
  DSO-bound differential at `553e1b8c` exists (`dso-differential-pfp20`), the
  branch audit at `553e1b8c` exists, and the ctgrind + mutation control at
  `553e1b8c` are this item; the registered `measurement` is still the
  `83f67826` timing. **`NOT_RUN` here.**

Once that measurement exists, the arm can move to `553e1b8c`, and then
`constant_time_audit` becomes legitimately updatable to
`CTGRIND_PLUS_BRANCH_AUDIT` with harness
`3a385537cc286cb7c19e0bbbb468c4033ffabb8edc74ac69df29237fc3d2aea1` (source
`ef137412…`), referencing this file. Until then the item's own acceptance is met
in evidence but the register cannot say so.

Also open, unchanged by this item: `PFP2-AUDIT-NOT-A-PROOF`,
`PFP2-DIFFERENTIAL-SCOPE`, `PFP2-DIRTY-CANDIDATE` (the DSO bytes are still not
committed; the rebuild here is now a second independent reproduction of the
digest from the committed source `c1d25e10d`), `PFP2-NO-PMU`, `T23`, `T24`,
`T29`, and the PFP-20 relocation question.

## 8. Reproduce

```
# both DSOs (rebuilds A byte-identically and patches one line for B)
bash docker/openssl-rs-court.sh exec sh \
  evidence/performance-frontier/campaigns/PFP-2/ctgrind/pfp21-2026-11-26/build_dsos.sh

# 41 memcheck runs (36 tainted = 6 populations × 3 reps × 2 DSOs, 2 negative
# controls, 3 sensitivity), 36 wall-time repetitions, 8 callgrind runs,
# identity and digest checks
bash docker/openssl-rs-court.sh exec sh \
  evidence/performance-frontier/campaigns/PFP-2/ctgrind/pfp21-2026-11-26/run_pfp21.sh

# B is point-identical to the 3.6.4 authority (512 points, recorded seed)
bash docker/openssl-rs-court.sh exec sh \
  evidence/performance-frontier/campaigns/PFP-2/ctgrind/pfp21-2026-11-26/b_equivalence.sh
```

Venue: court `openssl-rs-court-tools:1`, container cgroup cap 8 GiB (the running
court; §24.4's new-court ceiling is 4 GiB and reuse is permitted because the
declared peak is far below half of the measured `available`, 25 GiB). One heavy
command at a time, `CARGO_BUILD_JOBS=4`, no OOM (`memory.events` stayed 0), no
release test-profile build.
