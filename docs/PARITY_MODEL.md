# Parity Model

Status: **constitution** (Phase 0).

This document defines what a parity obligation *is*, the states it may occupy,
the evidence planes that must agree before it is promoted, and the prohibition on
hand-written status.

## 1. The obligation

A **parity obligation** is a machine-readable unit of compatibility contract. A
machine-readable parity obligation exists for **every externally relevant
contract item**. Obligations are generated from the atlas
(`forensics/atlas/`), never hand-typed.

An obligation is not `PARITY_VERIFIED` until every applicable dimension is
proved. Dimensions, at minimum:

```
DISCOVERED          seen in the authority atlas
ARCHAEOLOGICAL      understood, with provenance, but not implemented
SCAFFOLDED          stub present; cannot count as parity
IMPLEMENTED         code exists
ABI_PASS            binary interface/layout/symbol evidence passes
SEMANTIC_PASS       return values, outputs, state transitions pass
OWNERSHIP_PASS      allocation/ownership/refcount behaviour passes
ERROR_PASS          error queue classification and ordering pass
STATE_PASS          object/state-machine transitions pass
CONCURRENCY_PASS    thread-local/thread-safety obligations pass
SECURITY_VECTOR_PASS independent correctness/adversarial vectors pass
DOWNSTREAM_PASS     an unmodified real consumer passes
PARITY_VERIFIED     every applicable dimension above is proved
```

Also available and **never** conflated with `PARITY_VERIFIED`:

```
UNKNOWN     honest: not yet investigated, or evidence is insufficient
FAIL        investigated, evidence contradicts the claim
```

`UNKNOWN` is distinct from `FAIL`. Unknown is a research result; it is never
traded for confidence theatre.

## 2. Promotion rule

`Overall = PARITY_VERIFIED` **only** when all applicable required columns pass.
The required column set depends on the obligation's kind (for example, a pure
`#define` has no ownership column; a `get0` accessor always does). Applicability
is declared per obligation and is itself evidence.

No state may be skipped. In particular:

- `IMPLEMENTED` does not imply any `*_PASS`.
- `ABI_PASS` does not imply `SEMANTIC_PASS` (ABI is not semantics).
- `SEMANTIC_PASS` does not imply `SECURITY_VECTOR_PASS` (OpenSSL compatibility
  is not cryptographic security).
- `SEMANTIC_PASS` on one build profile does not imply another profile.

## 3. Evidence planes

OpenSSL's public contract is deliberately broader than exported functions. Each
obligation is therefore assessed across independent planes, and only promoted
when the applicable planes agree.

### 3.1 Source compatibility
headers; include topology; declarations; typedefs; public structs; opaque types;
enums; macros; constant values; feature guards; deprecation guards;
`OPENSSL_API_COMPAT`; `OPENSSL_NO_DEPRECATED`; compile-time configuration macros;
callback signatures; platform calling conventions.

### 3.2 Binary compatibility
exported symbols; presence/absence; **symbol versions**; weak/strong status; ELF
visibility; ordinals where applicable; SONAME/install name; DLL/import-library
exports; public object sizes; alignment; `offsetof`; enum representation;
calling conventions; global data symbols; runtime dependency closure; dynamic
loading.

### 3.3 Semantic compatibility
return values; output values; output bytes; object state; state-machine
transitions; protocol transcripts; filesystem artifacts; config interpretation;
environment handling; callback sequence and arguments; retry semantics; resource
limits.

### 3.4 Ownership compatibility
allocation origin; caller/callee ownership; `get0`/`get1`/`set0`/`set1`;
`up_ref`; free semantics; null semantics; duplicate semantics; lifetime
extension; callback lifetime; aliasing expectations. See `docs/OWNERSHIP_MODEL.md`.

### 3.5 Error compatibility
success/failure classification; `ERR` queue state; queue ordering; library/reason
information; additional error data; queue clearing; marks; thread-local
behaviour; interaction with `errno`; interaction with `SSL_get_error`; failure
timing.

### 3.6 Concurrency compatibility
documented thread safety; thread-local queues/state; provider/context
concurrency; refcount behaviour; initialisation; teardown; process/fork
interactions where observable. See `docs/CONCURRENCY_MODEL.md`.

## 4. Cross-plane discipline

The Phase 1 atlas already demonstrates the required discipline for symbols. Four
planes are reconciled:

```
A  util/libcrypto.num / libssl.num        the declared ABI promise
B  <build>/libcrypto.ld / libssl.ld       the build-profile-specific promise
C  the built DSO dynamic symbol table     what downstream binaries bind to
D  ELF version definitions + ABS markers  the version namespace identity
```

A symbol present in one plane and absent from another is a **residual**, not an
inconvenience. Absence is *classified*, with a specific reason, or it remains a
hard residual:

```
declared_nonexistent        .num says NOEXIST        -> correctly absent
platform_scoped             .num scopes to VMS/WIN32 -> correctly absent on ELF
excluded_by_build_profile   absent from the generated .ld -> excluded by config
unexplained_absent          expected everywhere, yet missing -> HARD residual
exported_undeclared         exported but absent from the build's own .ld -> HARD
version_mismatch            version node disagreement -> HARD
kind_mismatch               FUNCTION vs OBJECT disagreement -> HARD
```

The current result (authority `openssl-3.6.4-production`, profile
`linux-x86_64-default-shared-legacy-notests`) is **zero hard residuals** for
`libcrypto` and `libssl`; see
`forensics/atlas/openssl-3.6.4-production/symbols-*.json`.

## 5. Residual discipline

Every oracle/candidate disagreement is a residual. It is **not** immediately a
bug. It is classified by evidence:

```
candidate defect            authority version difference
build-profile difference    platform difference
intentional safe divergence harness defect
nondeterministic observation
unknown
```

Rules:

- `unknown` remains unknown until evidence changes it.
- A residual is **never** closed by editing the expected output.
- Closing a residual requires a *changed candidate* plus a *new passing court
  run*.
- **The original failure is preserved forever.** Failed approaches are durable
  knowledge, not embarrassment (`docs/SECURITY_DIVERGENCE_POLICY.md`, and the
  Gemel precedent store).

## 6. The parity matrix

The headline matrix is generated entirely from evidence:

| Obligation | Export | ABI | Semantic | Ownership | Error | State | Independent | Downstream | Overall |
|---|---|---|---|---|---|---|---|---|---|

- Handwritten status is forbidden.
- `UNKNOWN` is kept distinct from `FAIL`.
- `Overall` is computed by rule (§2), never typed.

## 7. Sensitivity requirement

A passing court is weak evidence unless it can detect the class of divergence it
claims to cover. Courts must be challenged with **seeded mutations**, and a court
blind to its declared defect class cannot supply release evidence. See
`docs/RELEASE_GATES.md` §"Phase exit rule".

## 8. Non-negotiable separations

These equations are false and must never appear in project reasoning:

```
compilation          ≠ compatibility
ABI                  ≠ semantics
standards compliance ≠ OpenSSL compatibility
OpenSSL compatibility≠ cryptographic security
behavioural FIPS parity ≠ FIPS validation
```
