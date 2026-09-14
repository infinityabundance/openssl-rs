# Phase 5 — `BIGNUM`, ASN.1 and PEM: seal

**STATUS: IN PROGRESS.** This document is opened while the stratum is under way, and
its status line is the only place in the repository that says so: the derived state
in `forensics/phase-state.json` is computed from the artefacts named below and never
typed. Phase 5's `BN_*` surface is closed — every one of its 201 exports is either
implemented or handed to a named later stratum — and its two other families are not:
ASN.1 (280 exports) and PEM (38) are entirely open.

This is **not** a claim that openssl-rs is a usable OpenSSL. All 603 `libssl` exports
and 5,271 `libcrypto` exports are still `SCAFFOLDED` and abort when called.

- Authority: `openssl-3.6.4-production` (with `openssl-3.6.3-historical` admitted for
  the oracle-versus-oracle trajectory in `docs/SECURITY_DIVERGENCE_POLICY.md`)
- Court results: `artifacts/phase5/COURTS.json` (1 court, 650 observations, 0 residuals)
- Obligation ledger: `forensics/phase5-obligations.json` (1,099 exports covered by the
  stratum's families: 170 implemented, 611 handed to later strata by declaring header
  or by dependency, **318 open**)
- Derived state: `forensics/phase-state.json`

## 1. What this phase owns, and how that was decided

Phase 5 owns 513 of the authority's exports. That number is not typed. It is derived
by `forensics/tools/phase5_obligations.py` from the Phase 1 atlas under one stated
rule: **a symbol belongs to the stratum that owns the header that declares it**.
`d2i_X509` and `d2i_ASN1_INTEGER` look alike and belong to different strata, and the
name cannot separate them; the declaring header can. `pem.h` is the one header whose
exports are not a module, so the tool resolves those by the type in the symbol's name
and fails closed on a name it cannot resolve.

The same tool hands 580 further candidates to the strata that own their headers
(Phase 7: 23 `evp.h`; Phase 8: 58 `dsa.h`/`dh.h`/`rsa.h`/`ec.h`; Phase 10: 12
`pkcs12.h`; Phase 11: 346 `x509*.h`; Phase 12: 141 `cms.h`/`ocsp.h`/`ts.h`/`pkcs7.h`/
`crmf.h`/`cmp.h`/`ess.h`/`ct.h`), each with that header recorded as the reason. Those
are hand-offs, not omissions, and they are subtracted rather than counted.

| module | exported symbols | implemented | handed on |
|---|---|---|---|
| `src/bn/` | 201 (plus the six Phase 4 hand-offs counted under `src/asn1/`) | 170 | 31 |
| `src/asn1/` | 280 (274 declared in `asn1.h`/`asn1t.h`, plus six BIO-to-ASN.1 hand-offs) | 0 | 0 |
| `src/pem/` | 38 | 0 | 0 |

The other 580 hand-offs are decided by the declaring header: 23 to Phase 7 (`evp.h`),
58 to Phase 8 (`dsa.h`, `dh.h`, `rsa.h`, `ec.h`), 12 to Phase 10 (`pkcs12.h`), 346 to
Phase 11 (`x509.h`, `x509v3.h`, `x509_acert.h`) and 141 to Phase 12 (`cms.h`,
`ocsp.h`, `ts.h`, `pkcs7.h`, `crmf.h`, `cmp.h`, `ess.h`, `ct.h`).

## 2. What has been built

| subsystem | what it is |
|---|---|
| `limbs` | pure limb arithmetic — add, subtract, compare, multiply, shift, divide, remainder, GCD, modular inverse — with no FFI and no OpenSSL types. The part that must be provably right, and the only part testable without an authority. |
| `bignum` | the opaque `BIGNUM`: lifetime, predicates, flags, the constant-time flag surface, and the byte/string conversions (`BN_bin2bn` and its signed, little-endian and native relatives; `BN_bn2bin`, `_binpad`, `_lebinpad`, `_mpi`, `_hex`, `_dec`; the five parsers). |
| `arith` | the `BN_*` arithmetic entry points: add/subtract/multiply/square in both signed and unsigned forms, the word family, division and remainder with the authority's sign rules, the `mod` family including the `_quick` variants, shifts, masking, exponentiation (plain, modular, simple), GCD/coprimality, modular inverse and Tonelli–Shanks `BN_mod_sqrt`. |
| `mont` | `BN_MONT_CTX` and the Montgomery arithmetic over it: `set`/`copy`/`set_locked`, the two conversions, the multiply, and the five exponentiation entry points with their odd-modulus requirement. |
| `recp` | `BN_RECP_CTX` and reciprocal division: `set`, `BN_reciprocal`, `BN_div_recp`, `BN_mod_mul_reciprocal`, `BN_mod_exp_recp`. |
| `primes` | the thirteen named primes: the five `BN_get0_nist_prime_*` static objects (cached so two calls answer the same pointer) and the eight `BN_get_rfc*_prime_*` duplicating forms. The values are in `prime_data.rs`, generated from the authority. |
| `nist` | `BN_nist_mod_*` and `BN_nist_mod_func`. |
| `kron` | `BN_kronecker`. |
| `blinding` | `BN_BLINDING`: `new`/`free`, the flag and thread surface, the lock, and `invert`/`invert_ex`. |
| `gf2m` | the fifteen `BN_GF2m_*` entry points: addition, the two array conversions, and reduction, multiplication, squaring, exponentiation, inversion and division in `GF(2)[x]/(p)`, each in both its `_arr` and non-`_arr` spelling. |
| `ctx` | `BN_CTX`, its bracket stack and its temporary pool, and the `BN_GENCB` callback object. |

## 3. The evidence

The court is a C probe compiled twice — once against the admitted authority's headers
and library, once against the candidate's generated headers and `artifacts/phase2` —
run on the same machine, and diffed line by line on `key=value` so one divergence
produces exactly one residual instead of shifting every following line.

| court | observations | what it compares |
|---|---|---|
| `RT-BN` | 650 | the observable surface of the opaque `BIGNUM`: the values read back through the conversions, the sign, the bit length, the predicate answers, the return classes, the error queue after a failure, and the division identity `a == b*q + r` checked in the probe itself so both sides are held to the same property. Also the Montgomery round trip and its even-modulus refusals, reciprocal division against `BN_div`, the thirteen named primes in full, the five NIST reducers and the value-based selector, the Kronecker symbol over sign combinations, and the blinding context's ownership and failing paths. Also all fifteen `BN_GF2m_*` entry points, whose `_arr` and non-`_arr` routes are compared with each other, whose results are checked against the field identities (`a * a^-1 == 1`, `(a/b) * b == a`) and whose invalid-modulus failures are compared with their error coordinates. Also `BN_GENCB`: registration through both the new-style and the deprecated function, which of them `BN_GENCB_call` reaches, the answer it gives in each state, the arguments the callback is handed, and `BN_GENCB_get_arg` across a replacement (D74). |

The probe drives *shapes* rather than one example each: zero, one, a single limb, a
limb boundary, two limbs, a value with the top bit set, and negatives of those, plus
every division sign combination.

## 4. What the first court found

The probe's first run failed on `stage=authority-run` with a segmentation fault. That
was the probe, not the implementation, and the tenth time in this project that the
probe has been the suspect: `BN_free` does not clear the caller's pointer, and the
probe reused a freed `BIGNUM` slot through `BN_asc2bn(&a, ...)`. Clearing the slot
turned a crash into 45 residuals.

Those 45 residuals were real, and they are the reason this court exists. Every one was
a behaviour that a plausible reading of the API would have got wrong:

- **`BN_bn2hex` is byte-oriented.** The authority suppresses leading zero *bytes* and
  then writes both digits of every byte it keeps, so `2` is `"02"` and
  `0x30000000000000000` is `"030000000000000000"`. Thirty-two of the residuals were
  one nibble wide and all of them were this.
- **`BN_cmp` orders by sign before magnitude.** The implementation negated the
  magnitude comparison whenever `a` was negative, which is right for two negatives and
  wrong whenever `a` is negative and `b` is not — it inverted exactly that case.
- **`BN_asc2bn` answers 1 or 0**, not the digit count its two radix-specific relatives
  return.
- **`BN_usub` reports only a limb-count shortfall.** When `a` and `b` are the same
  width and `a < b`, the authority lets the final borrow escape and returns the wrapped
  value; `BN_add(3)` calls it undefined, but a precompiled caller sees the wrap.
- **`BN_mask_bits` refuses a width the value does not have.** `ossl_bn_mask_bits_fixed_top`
  answers 0 when the requested width starts at or past the top limb, so masking a
  value to a width beyond its own is reported rather than accepted as a no-op.
- **The `mod` family reduces last, not first.** `BN_mod_add`, `_sub` and `_mul` are the
  true signed operation followed by one `BN_nnmod`; reducing the operands first is
  equivalent only for inputs already in `[0, m)` and differs by exactly the modulus
  otherwise. The probe's `a = -0x100`, `b = 7`, `m = 0x13` separates the two.
- **The `_quick` variants are their own algorithms.** `BN_mod_lshift_quick` reports
  `BN_R_INPUT_NOT_REDUCED` for an operand outside `[0, |m|)` rather than reducing it,
  and `BN_mod_sub_quick` and `BN_mod_add_quick` have their own guards; sharing one
  implementation with the general forms would be a divergence, not a simplification.
- **A negative exponent is not rejected.** `BN_exp` and `BN_mod_exp` are driven by
  `BN_num_bits` and `BN_is_bit_set`, which read the exponent's magnitude: the
  authority computes `a^|p|`.
- **`BN_signed_lebin2bn` and its relatives return `BIGNUM *`** and allocate when their
  `ret` argument is null. The implementation returned `int` and required a non-null
  `ret`, so every caller passing null got a failure where the authority returns a fresh
  object. This one was found by the probe, and it is the defect that motivated the
  prototype court described in section 6.
- **The error queue is part of the answer.** `BN_div` with a zero divisor raises
  `BN_R_DIV_BY_ZERO` at its own coordinate in `bn_div.c`; `BN_mod_inverse` raises
  `BN_R_NO_INVERSE` after its internal helper reports through a flag; `BN_mod_sqrt`
  raises `BN_R_NOT_A_SQUARE` at its verification step and `BN_R_P_IS_NOT_PRIME` before
  doing any work when `p` is even and not two. `forensics/tools/gen_err_raise_sites.py`
  now covers all nineteen `crypto/bn` translation units that raise, so the coordinates
  are generated from the authority rather than transcribed.

One residual was a panic rather than a wrong value: `BN_mod_inverse(a, 0)` reached
`limbs::rem`'s division-by-zero assertion, which `guard_ffi` caught and turned into a
null return — with no error raised, because the raise happens after the arithmetic.
The fix is at the root: `limbs::mod_inverse` answers `None` for a zero modulus rather
than letting the assertion fire, which is both the mathematically right answer and what
keeps a misuse of a public entry point a reported failure instead of a panic at the ABI
boundary.

## 5. What the second pass over the stratum found

The `BN_*` remainder was implemented after the first court passed, and the court was
extended over it rather than leaving it to unit evidence. The extension found one
defect, and it was the probe's: the first version handed `BN_mod_exp_mont` a
`BN_MONT_CTX` that had been re-set to a *different* modulus, and the authority answered
0 for it — a context is bound to one modulus, and passing a mismatched one is out of
contract. That is the eleventh time in this project that the probe was the suspect
before the implementation was.

With a matching context, everything the extension compares agreed on the first run:

- **`BN_nist_mod_*` is `BN_nnmod` against a fixed prime.** The authority's first line
  inside each reducer is `field = &ossl_bignum_nist_p_192; /* just to make sure */` —
  the caller's `field` argument is overwritten before use, and the small and negative
  cases are dispatched straight to `BN_nnmod`. The probe checks both halves of that:
  that the reducers ignore the `field` they are handed, and that each one's result
  equals the `BN_nnmod` the authority itself calls.
- **`BN_nist_mod_func` selects by value**, so any `BIGNUM` equal to one of the five
  primes selects its reducer and anything else selects nothing.
- **The Montgomery conversions are `a*R` and `a*R^-1`** with `R = 2^ceil(bits/64)*64`,
  so the round trip is the identity and the even-modulus refusal is raised at the
  authority's own coordinates without contradicting `BN_mod_exp`, which *does* accept
  an even modulus (through its reciprocal path).
- **`BN_div_recp` is the same division `BN_div` computes**; the probe checks the
  quotient and remainder against `BN_div` directly rather than against a definition.
- **The static NIST primes are one object**, so two calls compare equal — which is what
  makes the cached allocation observable rather than an implementation detail.
- **`BN_BLINDING_new` with a null modulus returns `NULL`** rather than crashing: the
  authority's `bn_check_top` is a debug-only assertion, and `BN_dup(NULL)` is NULL, so
  the shipped build takes the error path. The probe checks it, and checks that a
  context with no inverse reports `NOT_INITIALIZED`.

The GF(2^m) family then added a **third** pass, and this one found two defects in the
implementation rather than in the probe:

- **The reduction loop tested the wrong bound.** `poly_rem` compared the value's bit
  length against the modulus's, which skips the reduction of a value exactly one bit
  longer than the field — and `0xa5 * 0x57` in the AES field is exactly that. The
  comparison belongs against the *degree*: a bit at index `>= n` is above the field
  whatever the modulus's own length happens to be.
- **`BN_GF2m_mod_inv` did not raise.** The authority reaches an invalid modulus through
  `BN_GF2m_mod_mul`, so that function's `INVALID_LENGTH` coordinate is what a caller
  sees; the direct extended-Euclid route had no reason to notice. It now validates the
  array first and raises at that same coordinate.

Both were caught by the court, not by reading, and both are the kind of defect a
"looks right" implementation keeps: the first produced a plausible field element that
was simply not reduced, and the second produced the right return value with the wrong
error queue.

## 6. Fault boundaries — recorded, not reproduced

A probe cannot compare a crash. Where the authority faults, the probe does not call and
the candidate's safer behaviour is recorded in `docs/SECURITY_DIVERGENCE_POLICY.md`.
For this stratum that is `BN_is_zero(NULL)` and its relatives, which the authority
dereferences.

## 7. Deliberate scaffolding, and what it means

The `scaffold` symbols abort. A scaffold never returns a plausible value, is never
counted as parity, and is rejected by the release gates; `implemented_surface.py`
enforces the separation mechanically and `forensics/REGISTRY` records the classification.

The prototype court is the mechanical answer to the `BN_signed_lebin2bn` class of
defect. `forensics/tools/prototype_court.py` compares every implemented export's Rust
declaration against the prototype the Phase 1 atlas recorded for it, on **two planes**:
the return class and the arity, and — since D74 — the **canonical type of the return and
of every parameter**. Both sides are resolved through their own typedef chains and
reduced to one grammar (`void`, `int:<bytes>:<s|u>`, `float:<bytes>`, `ptr(...)`,
`const(...)`, `fn(...)` for a function type, `fptr(...)` for a function pointer,
`opaque`), so a difference in spelling is never reported as a difference in shape and a
struct pointee's *name* is deliberately discarded while pointer depth, pointee
constness, integer width and function-pointer argument shape are kept. A type the
table cannot canonicalise is a third heading beside pass and mismatch, and fails. It is
in `evidence_determinism.py`'s generator set and in CI's static gates.

The type plane landed before this stratum's ASN.1 surface moved, and found twelve wrong
declarations in code that every Phase 3 and Phase 4 court had already passed — three
extra pointer levels on `BIO_info_cb *`, a callback return type, a return's constness
on six `OPENSSL_sk_*` functions, and two more (D74). Two of the twelve were behavioural
rather than declarative, and correcting them required `RT-BN` to gain a `BN_GENCB`
section, whose first run found a thirteenth defect the signature change had not:
`BN_GENCB_call` answers `0`, not `1`, for a freshly allocated object.

A symbol it cannot check is never a pass. Its report separates the 50 exports the crate
declares from a `macro_rules!` (no declaration to parse), the 8 whose implementation is
a C shim (the variadic and syscall surface stable Rust cannot express), the 2
`ABI_ONLY_EXPORTED` symbols the atlas has no prototype for, and anything unclassifiable.
So `checked` is quoted alongside `mismatches`, never replaced by it: **565 of 625
checked, 0 mismatches**, 0 unclassified, 0 not-found, and — on the type plane — 565
checked, 0 mismatches, 0 unmapped (`forensics/atlas/prototype-court.json`).

## 8. What is explicitly NOT claimed

- No ASN.1 and no PEM surface is implemented; both families are entirely open (280 and
  38 exports).
- No `BN_*` export remains open. The `BN_GF2m_*` family was the last of it, and it is
  implemented and courted.
- The `BN_GF2m_*` arithmetic is **not** the authority's unrolled carry chains, and
  `BN_GF2m_mod_inv` does **not** blind its inversion. Both are recorded as security
  divergences (`D-GF2M-1`, `D-GF2M-2` in `docs/SECURITY_DIVERGENCE_POLICY.md`): the
  values agree, the timing profiles are not claimed to.
- 31 `BN_*` exports are handed to Phase 9 with the dependency as the reason: the RAND
  families, the prime generators, the Miller-Rabin primality tests, the X931
  generators, `BN_generate_dsa_nonce`, the GF2m square-root and quadratic-solver pair,
  and the four blinding entry points that re-create the blinding factor through
  `BN_BLINDING_create_param`.
- The court is a differential-compatibility result for the behaviours it exercises, on
  one platform, for one build profile (D2). It is **not** cryptographic or security
  correctness, and it is **not** evidence about any symbol the probe does not call
  (`docs/PARITY_MODEL.md`). The constant-time property of the Miller-Rabin and
  Montgomery paths is not claimed at all — those paths are the authority's, and the
  RAND-dependent ones are not implemented here.

## 9. Exit criteria

Phase 5 becomes `complete` when the ledger's `open_in_this_stratum` reaches zero and
every court in `artifacts/phase5/COURTS.json` passes. Both are derived, not asserted:
`forensics/tools/phase_state.py` reads the ledger and the court results, and the
dependency-order rule keeps a later stratum from claiming completion first. As of the
current artefacts that is **318 open obligations** (280 ASN.1, 38 PEM) — the
stratum's `BN_*` surface is closed and the remainder is the two families not begun.

## 10. FRF and Gemel

### FRF

The court is admitted as `openssl-rs-rt-bn` and the chain has been run end to end in the
FRF tooling container (`bash forensics/frf/run_courts.sh`). The identities:

- court run — `run-openssl-rs-rt-bn-33d75fee81d80354eda5b7f051aefa6dea3eb9084dc6f1fc00ac1ec0a4948f9b`
- OpenReceipt — `receipt-run-openssl-rs-rt-bn-33d75fee81d80354eda5b7f051aefa6dea3eb9084dc6f1fc00ac1ec0a4948f9b-bbb16ce6b43b3246f0cc7983dc7f9c5b9c3d46ed212defbb6234bce8f286d2b6`
- sensitivity challenges — the axes the harness could isolate on this court:
  - `7894d4ef788712701fb9ce57e5573d93b065b8f0de3ee51e33e413e8576f2702`, the
    `stdout-first-line` mutant on the `stdout` axis, whose challenged run is
    `run-openssl-rs-rt-bn-11b4a581b8e4bcf838801476ef8190b743d7f578a59b70ee781f20e55a825ca8`;
  - `3e8c880cb9f235f254a17298783daca09ba50dee1b005639a62094e6c91801de`, the
    `exit-class` mutant on the `exit` axis, whose challenged run is
    `run-openssl-rs-rt-bn-a56f887f455fbfbae780412629aebaea18903d42db9c2e6ef981e598ab6b11b8`.

  Each saw its seeded defect on its own axis and **nothing else** (`unaffected_axes`
  names the axis it did not disturb, and `specificity_clean` is true on both), which is
  what makes the passing court evidence about the difference class rather than about the
  probe's stability. The court's `observables` are `[stdout, exit]`, so those two
  mutation profiles are the whole of what can isolate on it: the harness reports the
  rest as refused rather than passing them, and D13 records why an honestly refused
  court is better than a falsely passing one.
- claim, `--policy sensitivity-backed`, over the 24 runtime receipts —
  `564889652b055cbffa62df560f376117dffda456ae674120b166a4c5a02a11c5`

The court's declaration is generated from the table in `forensics/tools/gen_frf_courts.py`
(never hand-written) and `gen_frf_courts.py --check` is what holds it there.

When a receipt binds a court whose transcript changed, the store is recreated from
clean rather than appended to (the header of `forensics/frf/run_courts.sh` records why:
FRF's run identity is content-addressed and does not vary with the rebuilt candidate's
hash, so a fresh observation requires a fresh store). The captures for this court are
therefore the clean run above and the two challenged runs, all three committed:
`.frf/captures/run-openssl-rs-rt-bn-33d75fee81d80354eda5b7f051aefa6dea3eb9084dc6f1fc00ac1ec0a4948f9b`,
`.frf/captures/run-openssl-rs-rt-bn-11b4a581b8e4bcf838801476ef8190b743d7f578a59b70ee781f20e55a825ca8`
and
`.frf/captures/run-openssl-rs-rt-bn-a56f887f455fbfbae780412629aebaea18903d42db9c2e6ef981e598ab6b11b8`.
`.frf` is committed because FRF expects its receipts and claims to travel.

A stale capture identity is exactly the kind of thing this project treats as a defect:
an earlier revision of this section named a run from a superseded store generation.
The identity is now the one the claim's `requires` and the challenge records name, and
the three capture directories above are the ones on disk.

A passing court is still only a differential result. The claim above is exactly what
it says it is — that the candidate's transcript matched the authority's for the
behaviours this probe exercises — and not a cryptographic or security claim
(`docs/PARITY_MODEL.md`).

### Gemel

Recorded at this boundary as change `C29`
(`change.d6ee02e950158dab1667c3f72608aa47dacdde651b838e3461d25330e07989b4`),
trajectory `T29`
(`trajectory.a5c3dd8bba70039d5b4f5c99619aa8386595465b88de68fe622df0e0fc9ea6c4`),
state `state.f48f703c3fc7896f18ac74e6848843bd301f48b25869f6d07598966c16e0b4b9`,
and checkpoint `K12`
(`checkpoint.3d4d0ddafc52a6635d9cf963b6fd27888133ca39ccc83243082477e7ddfaec45`).
The previous boundary is change `C21`
(`change.3215032a15ad7bd044c6a87153239e7a61f47e69b731f2143b007ed903e1a60e`) on
trajectory `T21`, with checkpoint `K11`
(`checkpoint.843b3f72da905eec1a0fc67a16ee8f1dc4811f86f51dfa75ae68a4d0c88ac4c6`).
Gemel names changes by derived order, so `C29` is not a stable identity and the
`change.` hash is; a name quoted elsewhere is resolved through
`forensics/GEMEL_TRAJECTORY.md` or `gemel show C29`.
The store is append-only, so a correction is another change rather than an edit; the
Git commit remains the authoritative record of the diff.

Projection in `forensics/GEMEL_TRAJECTORY.md`, rendered by
`forensics/tools/render_gemel_trajectory.sh`. The native store is not Git-tracked
(D17); only its `exchange/` namespace and this projection travel in Git, together with
the human-readable trajectory and the checkpoint identities.

Residuals recorded in the store at this boundary rather than left to be rediscovered:
the `BN_signed_*2bn` signature defect and the prototype gap that let it survive (D65,
now closed by the prototype court); the RAND-dependent exports of this stratum, which
are handed to Phase 9 and are therefore implementable by nobody in this phase; the
two `ABI_ONLY_EXPORTED` symbols the atlas has no prototype for, which the prototype
court reports rather than skipping; and the two `GF(2^m)` divergences, `D-GF2M-1`
(`BN_GF2m_mod_inv` is not blinded, recorded `verification_gap`) and `D-GF2M-2` (the
arithmetic is not the authority's carry chains, recorded `performance_divergence`),
whose obligation `OBL-GF2M-INV-BLINDING` is owned by Phase 9.
