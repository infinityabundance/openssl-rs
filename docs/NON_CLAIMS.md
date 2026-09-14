# Non-Claims

Status: **constitution** (Phase 0). This file is a standing, explicit list of
things `openssl-rs` does **not** claim.

## 1. No universal claims from finite evidence

The project never writes:

```
100% OpenSSL compatible
drop-in OpenSSL replacement
```

without the supported authority / version / build profile / platform scope
immediately adjacent.

## 2. What a claim looks like

Claims are generated from evidence, and name their region exactly:

```
OpenSSL 3.6.4 / linux-x86_64 / default-shared-legacy-notests profile:
N/M obligations PARITY_VERIFIED, K open residuals, J unknown obligations.
```

with links to the underlying evidence. Headline percentages are **derived from
evidence-bearing obligations** and are never typed by hand.

## 3. Specific non-claims

At all times, and regardless of how mature the repository feels:

- **Not FIPS validated.** Behavioural parity with the FIPS provider is not
  validation. See `docs/FIPS_CLAIMS.md`.
- **No cryptographic-security claim from OpenSSL parity.** Passing the OpenSSL
  oracle proves compatibility over the observed surface; it cannot prove an
  implementation is cryptographically sound. Conversely, a perfect standards
  implementation can still be OpenSSL-incompatible.
- **No constant-time claim from timing tests.** Wording is limited to
  "no statistically detectable timing class was observed under the specified test
  conditions" unless stronger formal evidence exists.
- **No platform universality.** A Linux receipt proves Linux behaviour; it proves
  nothing about Windows DLL ABI.
- **No profile universality.** Behaviour demonstrated under one configure profile
  is not claimed for another.
- **No version universality.** An OpenSSL 3.6.x receipt is not evidence for
  OpenSSL 4.x.
- **No downstream completeness.** BIND is a witness, not the specification.
  Coverage of one consumer is never generalised into coverage of OpenSSL.
- **No coverage claim from a fuzz finding.** A fuzz finding is not itself a
  parity claim; promotion requires a real court.
- **No coverage claim from a passing court that cannot detect its own defect
  class.** Sensitivity challenges are mandatory.

## 4. Unknown is stated

Where behaviour has not been investigated, or the evidence is insufficient, the
status is `UNKNOWN` — distinct from `FAIL`. Unknown is a research result and is
reported precisely, not hidden.
