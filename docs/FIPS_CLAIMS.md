# FIPS Claims

Status: **constitution** (Phase 0).

## 1. Two concepts that are never conflated

```
FIPS behavioural parity     -> implemented and courted by this project
FIPS formal validation      -> an external certification process
```

These are separate. Conflating them is prohibited.

## 2. What may be implemented and courted

The **observable** behaviour of the FIPS provider, where relevant:

```
provider loading          properties                algorithm eligibility
approved / non-approved operation indicators
self-test transitions     integrity failure behaviour
configuration             parameter restrictions    error states
```

A behavioural parity obligation may be `PARITY_VERIFIED` for these.

## 3. What may not be claimed

The candidate is labelled:

```
NOT FIPS VALIDATED
```

until an actual applicable formal validation has been completed by the relevant
scheme. Behavioural parity **is not** validation.

OpenSSL's own certification is never used to imply certification of
`openssl-rs`. A passing FIPS-behaviour court proves only that behaviour matches;
it does not confer, imply, or approximate a certificate.

## 4. Scope interaction with the parity model

- FIPS behaviour is **build-profile dependent** and must be claimed only within a
  FIPS-capable profile (`docs/AUTHORITY_POLICY.md` §3).
- Any FIPS parity claim names the authority, profile, platform and court, exactly
  as every other claim does (`docs/CUSTODIAN_CONTRACT.md` §7).
- Documentation and generated projections must render the `NOT FIPS VALIDATED`
  label wherever FIPS behaviour is discussed.
