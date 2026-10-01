# Phase 22 seal — Authority Exhaustiveness and the Whole-Program Compatibility Atlas

Status: **sealed**, against the authority `openssl-3.6.4-production`, build profile
`linux-x86_64-default-shared-legacy-notests`, platform `linux-x86_64`.

This seal is generated from the evidence: every figure below is read from
`forensics/phase22-obligations.json`, `artifacts/phase22/COURTS.json` and the plane
artefacts under `forensics/atlas/phase22/`, not typed. `forensics/STATUS.md` is the live
projection and this document is the stratum's record.

## 1. What Phase 22 asked

Phase 1's atlas answers *what does this distribution publish*: one synthetic translation unit
over the installed public headers, reconciled with the `.num` inventories, the version script
and the DSO's exports. Phase 22 asked the harder question, because a drop-in replacement
fails on what an atlas omits, not on what it lists:

> Starting from the exact admitted authority's source, build, installed distribution and
> runtime, can every externally relevant compatibility surface be discovered, connected to
> the authority implementation that produces it, assigned a parity obligation, and mapped to
> an implementation phase — with zero unexplained gaps?

It is an **atlas** stratum. It adds no code to the crate, and nothing here is a parity claim
about the candidate.

## 2. The eighteen planes

Phase 22 owns no `libcrypto` export, so its unit is a **compatibility plane**: one extraction
or reconciliation instrument per subphase, implemented when the artefact it names exists.
`forensics/phase22-obligations.json` records **18 of 18 implemented, 0 open**, derived from the
artefacts' existence.

| # | plane | artefact | the instrument that challenges it |
|---|---|---|---|
| 22.0 | plan, dependency edge, freeze | `docs/PHASE-22-SUBPHASES.md` | — |
| 22.1 | exact build commands | `compile-commands.json` | `RT-PHASE22-BUILD-CAPTURE` |
| 22.2 | Doxygen entity graph | `doxygen-entities.json` | `RT-PHASE22-DOXYGEN` |
| 22.3 | every-TU Clang AST | `tu-ast.json` | `RT-PHASE22-TU-AST` |
| 22.4 | preprocessor / conditional graph | `conditional-surface.json` | `RT-PHASE22-CONDITIONAL` |
| 22.5 | generated-source genealogy | `generated-lineage.json` | `RT-PHASE22-GENEALOGY` |
| 22.6 | object / archive / DSO graph | `binary-reference-graph.json` | `RT-PHASE22-BINARY` |
| 22.7 | dispatch, callback, registration | `dispatch-graph.json` | `RT-PHASE22-DISPATCH` |
| 22.8 | installed distribution | `install-manifest.json` | `RT-PHASE22-INSTALL` |
| 22.9 | CLI grammar and aliases | `cli-surface.json` | `RT-PHASE22-CLI` |
| 22.10 | configuration / environment | `config-surface.json` | `RT-PHASE22-CONFIG` |
| 22.11 | canonical POD contract oracle | `pod-contract.json`, `docs/POD-CENSUS.md` | `RT-PHASE22-POD` |
| 22.12 | cross-plane reconciliation | `reconciliation.json` | `RT-PHASE22-RECONCILE` |
| 22.13 | test / fuzz / demo crosswalk | `test-crosswalk.json` | `RT-PHASE22-CROSSWALK` |
| 22.14 | external-root closure | `compatibility-closure.json` | `RT-PHASE22-CLOSURE` |
| 22.15 | FRF challenges and FRF-Fuzz | `frf-challenges.json` | `RT-PHASE22-FRF` |
| 22.16 | Gemel checkpoint | `gemel-checkpoint.json` | `RT-PHASE22-GEMEL` |
| 22.17 | the seal | this document | — |

**16 courts, all passing.** Each is an FRF-style sensitivity challenge, not a file-existence
check: it drives its instrument over the real artefact and over controlled mutations of that
artefact, and fails if the instrument is insensitive to its own defect class. The runner
discovers them; a plane that has not landed contributes `[]`, and a module that raises on
import is a hard failure. `run_courts.py` re-derives the whole record and requires the
committed file to be what the run writes, in every field.

## 3. What the instruments found

Every number is the artefact's own.

**Build.** 22.1 replayed the authority's real compiler invocations through a transparent
wrapper: **2,201 translation units over 1,232 distinct sources**, `producer` GCC and
`analysis_instrument` Clang recorded separately, `capture_method: execution-captured`. 22.6
then walked the binaries and **explained all 1,133 objects** — 1,082 `CAPTURED_COMPILER_OUTPUT`,
41 `PERLASM_OUTPUT`, 10 `LINK_OUTPUT`, **0 unexplained** — so the object graph is an
independent witness that the capture closed.

**Source.** 22.3 replayed 1,216 of 1,216 C translation units with Clang (0 failures):
**35,838 entities**, 16,573 static, **104,192 direct-call edges**, 3,896 address-taken. 22.4
recorded **2,100 macros, 6,436 conditionals, 4,542 skipped source ranges** and classified
2,308 surfaces (1619 active-production, 349 test-only, 96 excluded-by-profile, and the rest).
22.5 recovered **1,279 generated outputs, 1,734 generation edges and 60 generators**.

**Structure.** 22.2's two Doxygen views — configured and lexical — found **70,075 entities**
(4,670 lexical-only, 24,595 configured-only: neither view is a superset) and **323,306
reference edges, 319,253 resolved to a real identity**. 22.7 recovered **373 tables and 1,959
typed indirect edges** (468 corroborated by the binary, 1,137 source-only, 354 binary-only) —
the `OSSL_DISPATCH`/`OSSL_ALGORITHM`/callback-table architecture that has no `caller -> f` edge
anywhere in the source.

**Surface.** 22.9 enumerated the CLI from the authority's own binary: **120 commands** (54
standard, 1 deprecated, 18 digest aliases, 47 cipher aliases) with **4,314 structured options,
0 commands with zero options**. 22.10 found **51 environment variables over 66 read sites, 115
directives, 10 default paths**. 22.8 ran the authority's own install and dispositioned
**7,666 installed entries with 0 `UNKNOWN`**, including the two CMake config files and three
pkg-config files the constitution had not modelled.

**Contract.** 22.11 inventoried **903 canonical POD pages** and extracted **15,044 claims**,
ran OpenSSL's own `util/find-doc-nits` and retained its output, and classified **2,292
disagreements** between the manuals and the atlas. 22.13 mapped **679 tests, 34 fuzzers and 76
demos** to **10,039 edges**, and names **3,967 exported symbols no test reaches** and 17 of 34
fuzz targets attacking parser surfaces.

## 4. The reconciliation, and what it refuses to do

22.12 joined the planes on one canonical identity per authority thing — **110,382 entities**
across symbol, source, install, cli, file, POD and config spaces — making **16 joins** and
recording **5 unjoined** with their reasons. It found **75,227 cross-plane residuals over 15
classes** and **5,910 `UNKNOWN`** entities. Ten-thousand-plus `DOXYGEN_ONLY` residuals are the
macros the configured Doxygen view emits and the AST cannot; `AST_ONLY` is enumerators and
field line-mismatches; neither is a defect, and both are the point of taking two views.

Section 1.1's rule is enforced, not stated: **a fact two planes contradict yields `UNKNOWN`,
never a vote.** `UNKNOWN` is refused as a resting state, so the count matters and is watched.

## 5. The closure, and its bound

22.14 declared the plan's ten compatibility-root families, derived a concrete member list for
each, and traversed the typed edge graph — **148,275 edges over 12 kinds** — from **27,495
members** to **35,436 reachable entities**.

Seven families closed: source-api (25,919 members), binary-abi (6,512), modules (770),
callbacks (332), cli (120), configuration (176), distribution (162).

Three are **declared and not observable**, and the seal records them as unpopulated rather
than closing them:

* `runtime-behaviour` — no plane reads runtime errors, state, ownership or concurrency;
* `protocol` — no plane reads the TLS/DTLS/QUIC wire or state;
* `dynamic-loading` — no plane reads the `dlopen`/`dlsym` lookup path (22.6 sees `DT_NEEDED`
  and 22.7 sees engine registration, but neither sees the lookup itself).

**`unknown_intersecting_roots` is 0.** The two entities that once blocked it —
`_openssl_ascii2ebcdic` and `_openssl_ebcdic2ascii`, declared in `ebcdic.h` and defined by no
translation unit or object — were re-classified from `UNKNOWN` to section 4's
`AUTHORITY_BUG_BOUNDARY`: both complete witnesses agree the authority declares a symbol it does
not define, which is the authority's boundary and not an atlas gap. The X.509 closure slice is
**satisfied** (1,294 members, 12,313 reachable, 0 `UNKNOWN`), and `phase22_x509_gate.py`
therefore permits Phase 11.2.

## 6. FRF: the instruments were challenged, and one defect was found by doing so

22.15 drove a challenge per plane through the plane's own pure builder: **12 of 12 detected,
0 not-detected, 0 not-driven** — dropping a compile flag moves 22.1; restoring the Phase-1
broken option parser drops 22.9's structured count by 4,314; removing a definer un-resolves
three relocations in 22.6; two same-spelled statics stay two destinations in 22.2. The harness
itself carries a court that fails if a mutated challenge result is not reported
`NOT_DETECTED`, proven by replacing its classifier with a rubber stamp.

**The fresh-regeneration path ran end to end, twice, for four planes** — 22.2 from an empty
scratch with both pinned Doxyfiles, 22.3 and 22.4 replaying Clang, 22.1 re-running the capture
— and every hash matched the committed artefact. **FRF-Fuzz seeded six adversarial inputs**
(malformed option row, nested POD, unresolved `#if`, same-spelled static, object with no
compile, split SYNOPSIS); all six produced a residual and none was silently accepted.

And the attempt found a real reproducibility defect: 22.2/22.3/22.4 resolve include roots from
22.1's capture, whose `directory` is ephemeral scratch, so a 22.1 rebuild poisoned them (22.2
jumped 70,075 to 76,222 entities). The runner now removes the scratch before the extractive
planes and runs 22.1 last, and the dependency and deltas are recorded in `body.reproducibility`.

## 7. The checkpoint, and the answer to "regenerate the ledgers"

22.16 bound the atlas identity (the sha256 of all sixteen plane artefacts, read from disk),
the plane ledger, the residual census with the `UNKNOWN` sets **named**, and the Phase-11
continuation state.

It also **measured** the plan's instruction to regenerate the export ledgers: re-running
`symbol_ownership.py`, `implemented_surface.py`, the phase obligation generators and
`atlas_parity.py` moved **zero obligation counts** — five outputs differed only in a stale
recorded input hash. The export universe Phase 22 reads is the one Phase 1 already had, so the
regeneration is a no-op on counts, and the checkpoint says so with the measurement behind it.

What Phase 22 found that an export ledger has **no unit for** is recorded as a proposal rather
than silently written into the ledgers: the CLI surface (120 commands / 4,314 options against
the Phase-1 capture's 55 / 0), the configuration/environment/filesystem surface (176), 5,910
POD-documented names with no implementation, 162 installed entries dispositioned
`REQUIRED_COMPATIBILITY`, and 1,189 dispatch/callback slots with no source-level caller. Each
names a proposed owning phase (CLI/config/filesystem and distribution → 16; POD-documented API
→ the phase owning the declaring header; slots → the phase owning the containing unit).

## 8. Non-claims

* Phase 22 does **not** claim the authority has no bugs. It claims the disagreements between
  the four planes (manuals, source/build, binaries, runtime observation) have nowhere to hide.
* Phase 22 does **not** claim the candidate is any closer to parity. It sharpens the obligation
  set; it adds no code.
* Phase 22 does **not** claim its own instruments are complete. 22.15 challenges each one
  against its own defect class, and a failed challenge is a finding; none failed.
* **The closure claim is bounded.** Three declared root families are unobserved (section 5) and
  are named as the boundary of what this stratum can see.
* A court that ties a committed artefact to the logic that built it is **not** a fresh
  re-derivation. 22.15 executes the fresh path for four planes; the others are recorded with
  that non-claim.
* `AUTHORITY_BUG_BOUNDARY` is a statement about the authority, not a licence for the candidate
  to diverge elsewhere.

## 9. The claim

> **closure-complete over the admitted OpenSSL 3.6.4 source archive, exact production build
> profile, installed distribution, and the seven declared compatibility-root families this
> stratum's instruments observe, with zero unexplained cross-plane residuals; and explicitly
> bounded on `runtime-behaviour`, `protocol` and `dynamic-loading`, which no Phase 22
> instrument observes.**

Not: "proof that nothing can possibly be missing."

SPDX-License-Identifier: Apache-2.0
