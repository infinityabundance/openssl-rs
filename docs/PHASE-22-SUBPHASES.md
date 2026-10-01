# Phase 22 — Authority Exhaustiveness and the Whole-Program Compatibility Atlas

Phase 22 is not a stratum of the port. It is a stratum of the **archaeology**, and it exists
because Phase 1's atlas answers a smaller question than the one a drop-in replacement has to
answer.

Phase 1 built the atlas from the *installed public headers*: one synthetic translation unit over
`include/openssl/*.h`, parsed with Clang, reconciled with the `.num` inventories, the version
script and the DSO's exported symbols. That is the right answer for the question it asked — what
does this distribution *publish* — and every stratum 2 through 21 rests on it.

It cannot answer, and was never meant to answer:

* what the **build** actually compiled, and under which conditional;
* what the **source** contains that the public headers do not name — static functions, file-local
  tables, dispatch initializers, callbacks reached only through a function pointer;
* what the **generated** source was generated *from*;
* what the compiled objects actually **reference**, including assembly and perlasm;
* what the installed **distribution** contains, file for file;
* what the **CLI**, the **configuration** and the **environment** expose;
* what the **canonical POD manuals** claim, independently of the source;
* what the **tests and fuzzers** actually exercise.

Phase 22's question is therefore:

> Starting from the exact admitted `openssl-3.6.4-production` source, build, installed
> distribution and runtime, can every externally relevant compatibility surface be discovered,
> connected to the authority implementation that produces it, assigned a parity obligation, and
> mapped to an implementation phase — with zero unexplained gaps?

## 1. What Phase 22 is, and what it is not

**It is an atlas phase.** It adds no code to the crate. Its outputs are evidence artefacts, and
its inputs are the authority.

**It is not a parity claim.** Nothing here says the candidate behaves like the authority. Every
entity Phase 22 discovers is a *discovered* entity; its disposition is a statement about the
authority, not about this crate.

**It is not exhaustive in the absolute sense.** For a C program with dynamic dispatch, runtime
inputs and undecidable behaviour, "nothing can be missing" is not a claim a machine can support.
The claim Phase 22 makes, and the only one its seal permits, is the bounded one in §7.

**It does not replace Phase 1.** Phase 1's public-contract atlas remains the authority for the
public contract. Phase 22 is the *closure* around it: the whole-program graph that Phase 1's
header-only view cannot see. Where the two disagree, that is a residual, not a preference.

### 1.1 The four planes, and the rule between them

    canonical POD manuals      say what OpenSSL claims
    source/AST/build/preproc   say what OpenSSL contains
    objects/DSO/archives       say what OpenSSL publishes
    runtime observation        say what OpenSSL does

**No plane may silently overrule another.** A disagreement becomes a residual with a
disposition. A candidate implementation may not reproduce a suspected documentation error, and
may not ignore an explicit documented contract because one runtime observation disagreed with
it. `docs/AUTHORITY_POLICY.md` and `docs/SECURITY_DIVERGENCE_POLICY.md` already carry the rule;
Phase 22 extends it across four planes instead of two.

## 2. The compatibility roots

Phase 22's organising abstraction is the **external compatibility root**: a place where a
consumer can meet the library. Everything reachable from a root receives a disposition;
everything not reachable from any root is internal and is recorded as such rather than ported
by reflex.

| root family | what it is |
|---|---|
| source API | public functions, static inlines, macros, types, `SYNOPSIS` declarations |
| binary ABI | shared exports, static-archive public symbols, globals, symbol versions |
| modules | provider entrypoints, registrations, dispatch tables |
| CLI | commands, aliases, digest/cipher pseudo-commands, options, streams, TTY |
| configuration | directives, sections, environment variables, default paths |
| distribution | installed files, symlinks, modes, pkg-config, CMake metadata, config samples |
| callbacks | callback types and the routes that invoke them |
| runtime behaviour | errors, state, ownership, concurrency |
| protocol | TLS/DTLS/QUIC externally observable wire and state |
| dynamic loading | module/engine/provider symbol lookup |

The closure is:

    root -> declaration -> definition -> direct calls -> callbacks and tables
         -> registrations -> data dependencies -> relocations -> runtime observations

## 3. The typed edge graph

A call graph is not enough, and this is the part a header-only atlas most reliably misses:

```c
static const OSSL_DISPATCH foo_functions[] = {
    { OSSL_FUNC_FOO_NEWCTX, (void (*)(void))foo_newctx },
};
```

There is no `foo()->foo_newctx()` edge anywhere in the source. The architecture *is* the table.
Phase 22 therefore records a **typed** edge graph, not a call graph:

    DIRECT_CALL        ADDRESS_TAKEN      CALLBACK_SLOT     DISPATCH_SLOT
    REGISTRATION       GLOBAL_REFERENCE   RELOCATION_REFERENCE   DYNAMIC_LOOKUP
    ALIAS              GENERATED_FROM     INCLUDED_BY       BUILT_INTO
    EXPORTED_AS        DOCUMENTED_BY      TESTED_BY         FUZZED_BY
    CLI_DISPATCH       CONFIG_DISPATCH    ENV_READ          DEFAULT_PATH

`docs/DECISIONS.md` is where each edge kind's extraction rule is recorded as it lands; the
atlas must not carry an edge kind whose extractor has no sensitivity challenge (22.14).

## 4. The disposition model

Every discovered entity receives exactly one disposition:

    REQUIRED_COMPATIBILITY       INTERNAL_REACHABLE        INTERNAL_UNREACHABLE_PROFILE
    EXCLUDED_BY_BUILD_PROFILE    PLATFORM_EXCLUDED         TEST_ONLY
    DEMO_ONLY                    TOOLING_ONLY              GENERATED_INTERMEDIATE
    AUTHORITY_BUG_BOUNDARY       UNKNOWN

`UNKNOWN` is not a resting state. **The Phase-22 seal is refused while any `UNKNOWN` intersects a
declared compatibility root.** "We discovered a hundred thousand things" is not exhaustiveness;
exhaustiveness is "nothing is unclassified".

## 5. The subphases

| # | Subphase | Produces |
|---|---|---|
| 22.0 | constitution amendment, the dependency DAG, and the freeze | `docs/PHASE-22-SUBPHASES.md`, the `REQUIRES` DAG in `phase_state.py`, the frozen Phase-11 baseline |
| 22.1 | exact build-command capture | `compile-commands.json` from the authority's own invocations |
| 22.2 | exhaustive Doxygen corpus | pinned `Doxyfile`, Doxygen XML, the entity graph |
| 22.3 | every-translation-unit Clang AST | declaration/definition graph, per-TU entity census |
| 22.4 | preprocessor and conditional graph | `conditional-surface.json` |
| 22.5 | generated-source genealogy | `generated-lineage.json` |
| 22.6 | object, archive, DSO and module graph | `binary-reference-graph.json` |
| 22.7 | indirect dispatch, callback and registration graph | `dispatch-graph.json` |
| 22.8 | installed-distribution manifest | `install-manifest.json` |
| 22.9 | CLI grammar, aliases and dynamic-command surface | `cli-surface.json` (and the Phase-16.0 defect fixed here) |
| 22.10 | configuration, environment and default-path surface | `config-surface.json` |
| 22.11 | canonical POD contract oracle and the POD↔runtime differential | `pod-contract.json`, `pod-atlas-reconciliation.json`, `docs/POD-CENSUS.md` |
| 22.12 | cross-plane reconciliation | the reconciled whole-program atlas |
| 22.13 | test / demo / fuzz semantic crosswalk | `test-crosswalk.json` |
| 22.14 | external-root reachability and compatibility closure | `compatibility-closure.json` |
| 22.15 | FRF challenges and FRF-Fuzz sensitivity | receipts, promoted findings |
| 22.16 | Gemel checkpoint and regenerated ledgers | the checkpoint, regenerated phase ledgers |
| 22.17 | the seal | `docs/PHASE-22-ATLAS-SEAL.md` |

## 6. What each subphase must not assume

* **22.1** must capture the compiler invocations the authority build actually made. It may not
  reconstruct flags from `Configure`. If the production authority is GCC-built, the Clang parse
  is a **shadow analysis instrument**, and the atlas records that distinction rather than
  quietly redefining the authority as a Clang build.
* **22.2** must treat Doxygen as one oracle among several. OpenSSL's own policy makes the POD
  manual canonical for public APIs and the Doxygen block a navigation aid; Doxygen absence must
  never be read as surface absence. Two views are taken: a **configured** view (the production
  profile, seeded with 22.1's captured defines and include paths) and a **lexical** view
  (discovery-only, deliberately reduced preprocessing) for material the production profile hides.
  The two views disagree in **both** directions and that is the honest shape: the lexical view
  contributes entities the production profile preprocesses away (`lexical_only`), and the
  configured view contributes the macros and bodies the un-preprocessed parse cannot see
  (`configured_only`), so neither is a superset. **Doxygen 1.9.4 has no Clang frontend**, so the
  configured view is Doxygen's own preprocessor seeded from the capture, not a Clang-assisted
  parse; reading the captured commands with Clang is 22.3's job, and 22.2's artefact records the
  distinction rather than implying one instrument did the other's work.
* **22.3** must parse **every** active translation unit, not a synthetic aggregate. The public
  −header view of Phase 1 remains, and is joined, not replaced.
* **22.4** must answer *why* a function exists in this build and *why* another does not, with a
  conditional lineage rather than a configuration guess.
* **22.5** must parse both the original and the generated source, and record the edge between
  them. Parsing either alone loses provenance.
* **22.6** exists because assembly and perlasm are invisible to Clang, and because link-time
  resolution is where the real dependency graph is confirmed.
* **22.7** exists because the architecture of this library is function-pointer tables.
* **22.8** must let the authority's own install define the distribution surface. The
  constitution's list of what matters is not the input; it is an output to be reconciled.
* **22.9** must not model the CLI as "the 55 standard commands". The digest and cipher
  pseudo-commands (`openssl sha256 file`) and the `openssl list -digest-commands` /
  `-cipher-commands` surfaces are part of it. The already-recorded archaeology defect
  (`cli_option_list_parse`, a Phase-16.0 prerequisite) is discharged or transferred here.
* **22.10** must treat an environment variable and a configuration directive as contract items
  with a name, a default, a scope, a security filter and an effect.
* **22.11** must use the exact 3.6.4 manual corpus from the admitted source tree, resolve
  `.pod.in` templates as the build does, run OpenSSL's own `util/find-doc-nits` as one
  instrument (and test that instrument's sensitivity), parse POD into a content-addressed claim
  graph, and turn every mechanically testable claim into a differential probe against the
  admitted authority. Undocumented is not nonexistent, and documented-but-divergent is evidence.
* **22.12–22.14** must not create a disconnected documentation atlas: a surface discovered by
  any plane propagates into the primary atlas, the ownership model and the phase ledgers, or it
  is not closed.
* **22.15** must challenge each extractor with a controlled mutation of its own defect class. A
  scanner that cannot detect the defect class it claims to inventory is not evidence.
* **22.16** must regenerate symbol ownership, phase ledgers and parity obligations from the
  stronger atlas, and preserve the Phase-11 continuation state.

## 7. Seal criteria, and the bounded claim

The seal requires all of the following.

    every authority source file classified
    every active production TU has its captured compile invocation and a Clang parse or a residual
    every generated input/output has provenance
    every Doxygen entity reconciled
    every compiled object assigned to a target, every symbol and reference classified
    every installed artefact dispositioned
    every public/header entity, shared/static/module ABI surface and provider registration reconciled
    every CLI command, alias, pseudo-command and option structured
    every config directive, environment variable and default path classified
    every test / fuzz target / demo mapped to the authority it touches
    every external compatibility root has a closure
    every reachable surface has an owner phase, required parity dimensions, current status and court family
    zero UNKNOWN residuals intersect the claimed production profile
    the FRF sensitivity challenges pass
    two clean regenerations are byte-identical
    the Gemel checkpoint exists
    the Phase-11 ledger has been regenerated from the new atlas

The claim it licenses, verbatim:

> **closure-complete over the admitted OpenSSL 3.6.4 source archive, exact production build
> profile, installed distribution, enumerated runtime registries, and declared compatibility
> roots, with zero unexplained cross-plane residuals.**

Not: "proof that nothing can possibly be missing."

## 8. Dependency, and the one consequence for Phase 11

Phase 22's evidence must exist **before** Phase 11 finishes, because the verification engine is
exactly the subsystem where a missing callback, config flag, static dispatch path, error path or
policy table discovered *after* implementation is expensive.

The conservation order is therefore no longer a numeric chain. Phase 22 declares:

    requires[22] = [10]
    requires[11] = [10, 22]
    requires[12] = [11]   ...   requires[21] = [20]

Phase numbers remain as historical names; the dependency is represented by the dependency.
`phase_state.py` implements this explicitly rather than special-casing phase 22.

**The stratum-level edge is necessary and not sufficient.** `requires[11] = (10, 22)` stops Phase 11
being called `complete` while Phase 22 is open; it does not stop somebody from implementing
`X509_verify_cert`, `x509_vpm.c` and `pcy_tree.c` tomorrow, which is the thing the dependency is
*for*. The subphase-level half is `forensics/tools/phase22_x509_gate.py`, a fail-closed pipeline
gate: it reads the exports `crypto/x509/x509_vfy.c`, `x509_vpm.c` and `pcy_tree.c` define, compares
their implemented set against the frozen baseline
`forensics/phase22/x509-closure-slice-baseline.json`, and **refuses any growth while the X.509
closure slice is unsatisfied**, naming the exports that grew. The baseline is frozen rather than
zero because Phase 10's pulled-forward subphases legitimately landed part of those units before
Phase 22 existed, and a gate that fired on work already done could not be passed. The gate has its
own `--self-test`, because a gate never seen to fire is not evidence.

**The contract 22.14 must satisfy**, and the thing the gate reads:

```json
// forensics/atlas/phase22/compatibility-closure.json
"body": {
  "x509_slice": {
    "roots": [ /* X509, X509_STORE, X509_STORE_CTX, X509_VERIFY_PARAM, X509_verify_cert,
                  the policy tree, trust, purpose, CRL, name constraints, the callbacks */ ],
    "satisfied": true,
    "unknown_residuals": []
  }
}
```

`satisfied` is true exactly when no `UNKNOWN` residual intersects any of those roots. Until 22.14
lands the document the gate reports the slice unsatisfied and lists the closure as the missing
piece, so the dependency is visible from the day it exists rather than from the day it is enforced.

Phase 11 may consume a **Phase-11 POD slice** of 22.11 once that slice has zero unexplained
POD↔atlas and POD↔runtime residuals and its newly discovered obligations have propagated into
the Phase-11 ledger. That allowance does not weaken the whole-Phase-22 seal.

## 9. Process

Phase 22 inherits the project's process unchanged: a subphase lands its extractor, its court, its
raw capture and its regenerated artefacts in one commit; every artefact that a source change
moves is regenerated in the same commit; each extractor carries an FRF sensitivity challenge;
and no count is typed where it can be derived. `docs/DECISIONS.md` is append-only and this
document is a plan, not a decision record.

## 10. Non-claims

* Phase 22 does not claim the authority has no bugs; it claims the disagreements have nowhere to
  hide.
* Phase 22 does not claim the candidate is any closer to parity. It sharpens the obligation set.
* Phase 22 does not claim its own extractors are complete; 22.15 challenges them, and a failed
  challenge is a finding.
* A disposition of `INTERNAL_UNREACHABLE_PROFILE` is a statement about this profile, not about
  the source.

SPDX-License-Identifier: Apache-2.0
