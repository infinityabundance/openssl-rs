# Provider Model

Status: **constitution** (Phase 0). This is a **hard architectural gate**.

## 1. Why providers are not optional

OpenSSL 3.x routes modern cryptographic operations through providers,
`OSSL_LIB_CTX`, `OSSL_PARAM`, operation dispatch tables, algorithm fetches and
property queries. A compatibility layer that maps `EVP_*` directly onto bespoke
functions while *faking* provider APIs would eventually collapse under
third-party providers, alternate library contexts, property selection and
configuration.

Providers must be **real**. This is not negotiable, and it is why provider
construction (Phase 6) precedes EVP (Phase 7) and algorithms (Phase 8).

## 2. Required machinery

Implemented, not shimmed:

```
OSSL_LIB_CTX                default context          child contexts
provider registry           provider load/unload     provider reference ownership
builtin providers           dynamic providers        core/provider dispatch
OSSL_DISPATCH               operation identifiers    provider upcalls
OSSL_PARAM                  parameter descriptors    name map
algorithm registration      property definitions     property query parser
property matching           default properties       fetch
implicit fetch              fetch cache              cache invalidation
fallback / default-provider rules
```

Default, base, null and legacy provider semantics are conserved as required by
the pinned authority. Algorithm inventories are **derived automatically** from
the admitted authority, never from a handwritten list.

## 3. The third-party provider court (crown-jewel test)

A small, independently written **C** provider — implementing selected operations,
compiled separately from this project — is loaded, unchanged, into both:

```
OpenSSL 3.6.4 (authority)      openssl-rs (candidate)
```

and the following are compared:

```
init dispatch        core upcalls        parameter flow
algorithm enumeration property selection  operation calls
teardown             failure behaviour
```

This court is **mandatory**. A provider system that only supports its own
built-in providers is not OpenSSL-provider compatible. If an independently
compiled provider can be dropped into both and yields matching behaviour through
`OSSL_DISPATCH`/`OSSL_PARAM` and property-based fetches, that demonstrates vastly
more than "our `EVP_*` calls seem to work".

## 4. Integration with the rest of the model

- **Obligations**: every provider operation, algorithm and property is a
  generated obligation (`PROVIDER-LOAD`, `PROVIDER-DISPATCH`,
  `FETCH-PROPERTY` courts).
- **Registration rows are a completion input, not a report.** A provider publishes
  *algorithm registration rows* — `deflt_ciphers[]`, `deflt_digests[]`, `deflt_macs[]` and their
  siblings — and no `libcrypto.num` entry names any of them, so no symbol atlas can see one. They
  are enumerated by `forensics/atlas/provider-algorithms.json`, and since D244 a stratum cannot
  reach `complete` while any row it owns is neither implemented nor handed to a later phase. The
  row counts are carried on every phase's row in `forensics/phase-state.json` and in
  `forensics/regression-baseline.json`, so a landed row cannot be un-registered in silence.
  `deferred` is not `open`: a hand-off names the phase that will take it and a blocker.
- **Duplicated names / property selection**: the *selected* algorithm is
  observable and may differ; selection is courted, not assumed.
- **Configuration**: config-driven provider module activation and property
  defaults are part of the CONF court, because provider loading through
  configuration is externally observable.
- **FIPS**: the FIPS provider's *observable selection rules, properties,
  self-test transitions and failure behaviour* are behavioural parity targets —
  which is entirely separate from FIPS **validation**. See `docs/FIPS_CLAIMS.md`.

## 5. Phase gate

Phase 6 does not exit on "the provider APIs exist". It exits when:

1. the provider/algorithm/property inventory is generated from the authority;
2. built-in and dynamic providers load, dispatch and tear down compatibly;
3. the third-party provider court passes;
4. property-based fetch selection matches, including negative selection;
5. the FRF receipts for the above compile into a claim.

Until then, EVP work may proceed only against genuinely provider-backed
implementations.
