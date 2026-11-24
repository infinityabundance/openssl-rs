# A23 receipt — the rule written down, a reference built from it, and the gap measured

## 1. Identity of this batch

| field | value |
|---|---|
| item | A23 (verifier formalisation: the decision rules as a formal object, an independent reference evaluator, exhaustive enumeration and invariants over stated finite domains) |
| branch | `staging` |
| HEAD at the start | `7c2b5f25fe55e6302b942ed124f4fbec5aff8888` (`a22: re-measure the eight after the repair, and bind witnesses to behaviour`) |
| worktree at the start | clean (`git --no-pager status --porcelain` empty) |
| orchestrator | commits and pushes; this subagent did not |
| `free -g` before the work | `Mem: 45 30 10 0 5 14` (total 45, used 30, free 10, available **14** GiB); `Swap: 45 38 6` |
| `free -g` before the suite | `Mem: 45 32 8 0 5 13` (available **13** GiB); `Swap: 45 38 6` |
| court | the already-running `openssl-rs-court` container, image `openssl-rs-court-tools:1`, memory cap **6 GiB** (`HostConfig.Memory` and `MemorySwap` both `6442450944`), repository at `/work`; reused, not restarted |
| heavy commands | one at a time; no Rust build |

The host had 14 GiB available before the work and 13 GiB before the suite, below
the 24 GiB floor `AGENTS.md` §6.1 sets before a build. No build was needed —
every gate is Python — and the derived cap would have been `min(8, 14 − 16)` and
`min(8, 13 − 16)`, both below the 2 GiB floor, so **no new court was started**;
the already-running court with its hard 6 GiB cap was reused. Every command that
reads or runs the tree ran inside it. No test was edited, skipped, ignored or
removed.

## 2. What was delivered

| path | size | role |
|---|---:|---|
| `forensics/tools/verifier_formalisation.py` | 1,709 lines | the reference evaluators, the domain enumerators, the differential, the invariants, the controls and the CLI |
| `forensics/tools/tests/test_verifier_formalisation.py` | 454 lines | 51 controls: no-import structure, exact domain sizes, the 65,536 differential, each invariant, each refusal code, the wrong-reference control, determinism, CLI exit codes, document synchronisation |
| `docs/VERIFIER-FORMALISATION.md` | 295 lines | the normative document: the problem, the nine rules and eight correction sub-rules, the reference and the no-import rule, the domains and their exact sizes, the invariants, the results, the controls, the refusal table, the limits, `NOT_RUN` |
| `evidence/a23/build_evidence.py` | 360 lines | deterministic producer: writes `SPEC.json`, runs the differential, invariants and controls, writes the three records, exits non-zero on a disagreement |
| `evidence/a23/SPEC.json` | 243 lines | the rules, canonically encoded and hashed |
| `evidence/a23/DIFFERENTIAL.json` | 130 lines | per-domain declared size, compared count, disagreements, cycle observations |
| `evidence/a23/PROPERTIES.json` | 72 lines | each invariant, its domain and its result on both evaluators |
| `evidence/a23/CONTROLS.json` | 87 lines | 10 `control-only` fixtures, one per refusal code, and coverage |
| `docs/ETP-TODO.md` | 1 row | the A23 row replaced from `TODO` to `DONE`; no other row touched |
| `evidence/a23/RECEIPT.md` | this file | the receipt |

Record digests (SHA-256, full):

| file | sha256 |
|---|---|
| `verifier_formalisation.py` | `6dff4ddb2f67423015c7d22388d06320d869069cd3971bc6574e482d25bfbbde` |
| `test_verifier_formalisation.py` | `f456f571db28464039a1bd83b3fe2ed0d4f3faacf18a1a177c381a7c019a126c` |
| `VERIFIER-FORMALISATION.md` | `8b286cde10f051b5d0da5174ad17114fadb086cbeeb1965a6eee91baddb9aa79` |
| `build_evidence.py` | `9c82631b837e2c00b44744f90deb1b5ca09c5ee378e11c2ec51abf1d950ea082` |
| `SPEC.json` | `6a9a7b59b6c8253db07e07ec009c8bf7693af1e81ebce5a5364e79e7a025e886` |
| `DIFFERENTIAL.json` | `517752afb584014564017ab136fdd4464c902a19fd71dd0d9e234b5dd89e03ef` |
| `PROPERTIES.json` | `c3ac6e6da43647a61301455000e594e415fb8928094c925a735e7b30e466dabd` |
| `CONTROLS.json` | `d85218be1557c1df2bc4f5142e9576160372a054e2fd6a9980f5d3fd24b92045` |

## 3. The rule

> A specification written by reading the implementation proves nothing: it
> inherits the defect it is supposed to find (Earned Trust Article 6). A
> reference evaluator built from a written rule, compared with the implementation
> by exhaustive enumeration over a domain whose size is known exactly, is the
> strongest cheap form of the check — and it is still not a theorem (Article 7),
> and a reference by the same author is not independent verification (Article 5).
> All three limits are stated in the document and in `SPEC.json`.

Nine decision rules (`VF-R1` … `VF-R9`) and eight correction sub-rules
(`VF-C1` … `VF-C8`) are declared in `evidence/a23/SPEC.json`. The decision has
the normal form:

```
DENY    if any obligation is UNKNOWN          (VF-R3)
DENY    if no obligation is required          (VF-R5)
ADMIT   iff every required obligation is MET  (VF-R2)
DENY    otherwise
```

with `UNKNOWN` never read as `MET` or `NOT_APPLICABLE`, `NOT_APPLICABLE` on a
required obligation never a pass, and no score, weight, count, threshold or rank
contributing (VF-R6, VF-R7 for order and determinism).

**The reference is built from the rule, not the code.** `reference_decide`,
`reference_threshold_count` and `reference_chain_admissible` read `SPEC.json`
and never import `policy_engine`, `thresholds` or `corrections`; the adapters
import inside the adapter function, so the reference functions' `__globals__`
never contain an implementation name. `assert_reference_independent` checks the
globals and the source text and refuses with
`VF_REFUSED_REFERENCE_IMPORTS_IMPLEMENTATION`; the control
`reference-imports-implementation` builds a stub whose globals resolve
`policy_engine` and observes the refusal; the test
`test_reference_does_not_import_an_implementation` is the structural guard.

## 4. The domains and the result

| domain | declared | compared | disagreements | exhaustive |
|---|---:|---:|---:|---|
| `decision-small` (0..3 obligations, every state vector × every required mask) | 585 | 585 | 0 | yes |
| `decision-policy` (8 obligations, all required) | 65,536 | 65,536 | 0 | yes |
| `threshold` (multisets of 0..4 over 12 archetypes, two inventories) | 9,100 | 9,100 | 0 | declared finite model |
| `correction` (chains of length 0..3 over two subjects, plus 3 cycles) | 386 | 386 | 0 | declared finite model |
| **total** | **75,607** | **75,607** | **0** | |

`4**8 = 65,536` is the *whole* input space of an eight-obligation decision
function, so that differential is exhaustive for that function, not a sample.
`decision-small` is `1 + 8 + 64 + 512 = 585`. `threshold` is
`1,820 multisets × (3 + 2) k values = 9,100`. `correction` is
`1 + 2 + 20 + 360 = 383` chains plus 3 cycle witnesses.

Seven invariants hold on **both** the implementation and the reference over
`4**3 = 64` vectors × 8 required masks = 512 cases:

| id | result |
|---|---|
| VF-P1 determinism | PASS |
| VF-P2 adding a MET obligation to an admitting vector still admits | PASS |
| VF-P3 adding a required UNMET obligation denies | PASS |
| VF-P4 UNKNOWN never admits | PASS |
| VF-P5 NOT_APPLICABLE on a required obligation denies | PASS |
| VF-P6 permuting the vector and its required flags changes no decision | PASS |
| VF-P7 with no UNKNOWN, a non-required obligation never changes the decision | PASS |

## 5. The controls

Ten `control-only` fixtures, one or more per refusal code, in
`evidence/a23/CONTROLS.json`:

| control | code observed |
|---|---|
| `wrong-reference-unknown-as-met` | `VF_REFUSED_DISAGREEMENT` |
| `wrong-reference-not-applicable-as-met` | `VF_REFUSED_DISAGREEMENT` |
| `wrong-threshold-ignores-aliases` | `VF_REFUSED_DISAGREEMENT` |
| `wrong-chain-ignores-digest` | `VF_REFUSED_DISAGREEMENT` |
| `domain-incomplete` | `VF_REFUSED_DOMAIN_INCOMPLETE` |
| `enumeration-truncated` | `VF_REFUSED_ENUMERATION_TRUNCATED` |
| `reference-imports-implementation` | `VF_REFUSED_REFERENCE_IMPORTS_IMPLEMENTATION` |
| `property-violated` | `VF_REFUSED_PROPERTY_VIOLATED` |
| `spec-absent` | `VF_REFUSED_SPEC_ABSENT` |
| `unspecified-rule` | `VF_REFUSED_UNSPECIFIED_RULE` |

Each wrong reference is detected with the exact input, both outputs and the rule
it violates. The differential exits 1 with `VF_REFUSED_DISAGREEMENT` when such a
reference is injected, so the comparison can fail.

## 6. Defects found

**This item's own property statement was wrong, and the enumeration found it.**
The first VF-P7 read "a non-required obligation in MET, UNMET or NOT_APPLICABLE
never changes the decision", unconditionally. The first producer run reported
`allHold=false` with the witness
`states = ["MET", "MET", "UNKNOWN"], required = [true, false, false]`: changing
the advisory `UNKNOWN` to `MET` moved the decision from `DENY` to `ADMIT`,
because VF-R3 makes an `UNKNOWN` a refusal whatever its requirement. Old: the
unconditional property (false). New: the property carries the no-`UNKNOWN`
condition, and the rule VF-R3 was **not** changed. Preserved in this section, in
`docs/VERIFIER-FORMALISATION.md` §5 and in the A23 row.

**The tool's threshold domain count was wrong, and its own completeness check
found it.** The first `_threshold_cases` counted domain *labels* with an
establishment record, so the aliased inventory reported `available = 3` and the
producer compared `1,820 × 6 = 10,920` cases against a declared `9,100`, raising
`VF_REFUSED_ENUMERATION_TRUNCATED`. Old: a case count that did not match the
declared domain. New: availability is the number of distinct establishment
records (the aliased inventory has two), so `1,820 × 5 = 9,100`. The check was
not relaxed; the counter was corrected. Preserved here.

**An observation, recorded not asserted.** Under VF-C2 a cycle is unsatisfiable:
a cycle's predecessor digests would have to equal functions of themselves, so no
canonical-digest cycle exists. The three cycle witnesses are refused by both
sides — the reference reports VF-C4, the implementation refuses the first
appended event with `CR_REFUSED_PREDECESSOR_MISMATCH` — so they agree on
admissibility, and the differential cannot exhibit a cycle that fails *only*
VF-C4. The cycle rule is retained as defence in depth, and the limitation is in
the record rather than hidden.

**No defect in an existing record was rejected by a gate.** No check was relaxed,
no expected value was changed, and no other item's tool or evidence was modified.

## 7. Gates actually run

All commands ran in the reused `openssl-rs-court` container, one at a time.

| gate | command | result |
|---|---|---|
| memory before the work | `free -g` (host) | `Mem: 45 30 10 0 5 14` (available 14 GiB); `Swap: 45 38 6` |
| memory before the suite | `free -g` (host) | `Mem: 45 32 8 0 5 13` (available 13 GiB); `Swap: 45 38 6` |
| court and cap | `docker inspect openssl-rs-court --format '{{.HostConfig.Memory}} {{.HostConfig.MemorySwap}} {{.State.Status}}'` | `6442450944 6442450944 running` (6 GiB); reused, no new court, no build |
| whole tools suite | `python3 -m unittest discover -s forensics/tools/tests` | `Ran 1731 tests in 340.644s`; `OK`; `closure discipline self-test: 7 control groups passed`. The 1,680 pre-existing tests are present (1,680 + 51), none removed, none ignored |
| focused A23 controls | `python3 -m unittest forensics.tools.tests.test_verifier_formalisation` | `Ran 51 tests in 83.644s`; `OK` |
| documentation | `python3 forensics/tools/docs_consistency.py` | `[docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources; the earned-trust constitution is wired`, exit 0 (the named Phase-7 exemption printed) |
| specification guard | `python3 forensics/tools/spec_guard.py check` | `spec-guard: 10 registered specification(s), 5 recorded known nonconformance(s), 6 level(s); 0 unclassified, 0 unjustified exemptions`, exit 0 |
| JSON well-formedness | `python3 -m json.tool` on the four records | `json.tool ok` for `SPEC.json`, `DIFFERENTIAL.json`, `PROPERTIES.json`, `CONTROLS.json` |
| producer, two runs | `python3 evidence/a23/build_evidence.py --out /tmp/a23a` and `--out /tmp/a23b` | `a23: base=7c2b5f25f rules=9 domains=4 compared=75607 disagreements=0 properties=7 allHold=true controls=10 codesCovered=7 codes=VF_OK`, exit 0 |
| producer byte-identity | `cmp` of each name, run 1 vs run 2 vs committed | `identical SPEC.json`, `identical DIFFERENTIAL.json`, `identical PROPERTIES.json`, `identical CONTROLS.json`; and `committed` for each |
| tool, differential | `python3 forensics/tools/verifier_formalisation.py differential` | `vf: domain decision-small declared=585 compared=585 disagreements=0 exhaustive=true`; `decision-policy declared=65536 compared=65536 disagreements=0 exhaustive=true`; `threshold declared=9100 compared=9100 disagreements=0`; `correction declared=386 compared=386 disagreements=0`; `vf: differential domains=4 compared=75607 disagreements=0`; `vf: codes=VF_OK`; exit 0 |
| tool, properties | `python3 forensics/tools/verifier_formalisation.py properties` | seven `vf: property VF-Pn implementation=PASS reference=PASS result=PASS` lines; `vf: properties domain='4**3 = 64 state vectors x 8 required mask(s) = 512 cases' allHold=true`; `vf: codes=VF_OK`; exit 0 |
| worktree | `git --no-pager status --porcelain` | see §10 |

## 8. Obligations retained

* **The enumeration is finite and covers decision functions, not the tool.**
  Only `decision-policy` is a whole state space. `decision-small`, `threshold` and
  `correction` are declared finite models; an input outside them is not covered.
  Record reading, predicates, applicability, pins, signatures, roles and the
  history witness are outside the enumeration and were not re-run here.
* **The reference shares an author with the implementation.** Agreement is
  evidence of a shared reading, not independent verification (Article 5). No
  external party wrote either.
* **No machine-checked theorem and no binary correspondence.** No TLA+, Coq, Lean
  or Kani proof, no refinement edge, no statement about a compiled artefact
  (Article 7).
* **The cycle rule is not independently exhibited.** VF-C4 is unreachable as a
  sole defect under VF-C2; the record states the observation.
* **Evidence identity.** Every record names base `7c2b5f25f`, the tool digest and
  the four record digests. An edit to the tool or the specification invalidates
  the differential until the producer is re-run.

## 9. `NOT_RUN`

* An independent reviewer or a distinct trust domain (Article 5).
* A machine-checked proof of any rule and any source-to-binary correspondence
  (Article 7).
* Re-running the A15, A19 and A20 suites, and any differential that derives
  obligation states from real records rather than from the abstract state vector.
* The threshold domain for `k` above the available domains, for more than 12
  archetypes, for more than four approvals, or for a role model other than A14's.
* Correction chains longer than three events, with `retract`, with signatures or
  roles, or with the history witness (`check_log`).
* The A23 description's signature-versus-semantics and substitution-preservation
  classes beyond the threshold alias rule; signature correctness remains the
  A9/A10 boundary. None is claimed here.
* A BOUNDARY audit, a SEAL, and the Rust test suite — no Rust source was
  modified.

## 10. Forward-freeze member and worktree

`evidence/a17/FREEZE-forward.json` declares **one** A23 member:

* **satisfied:** `a23-receipt` — `evidence/a23/RECEIPT.md` (this file), whose
  predicate is that a receipt records the item's result, gates and `NOT_RUN`
  obligations.

The freeze remains `state: OPEN`; it was not amended and not closed, and this
receipt does not claim any other member.

`git --no-pager status --porcelain` at the end of this batch:

```
 M docs/ETP-TODO.md
?? docs/VERIFIER-FORMALISATION.md
?? evidence/a23/
?? forensics/tools/tests/test_verifier_formalisation.py
?? forensics/tools/verifier_formalisation.py
```

No other path was modified. `docs/ETP-TODO.md` differs in exactly one row (A23);
`git diff --stat` reports one insertion and one deletion for that file.
