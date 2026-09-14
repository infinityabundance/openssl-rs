# Gemel trajectory (generated projection)

Generated from the committed `.gemel` store so the Phase 1 trajectory is
legible without checking the store out. Regenerate with:

```
bash docker/openssl-rs-frf-court.sh exec gemel log --repo /work
```

## `gemel log`

```
C2  Phase 1 foundation closure: differential atlas, completeness, FRF sensitivity-backed claim, FFI boundary
    state state.85d1e8ede88fb9f355d3d7e01f71483f9b28f0a857898a706a5fe5a3099a44f2 -> state.c86c4178c1597a82a06176665f752d3aa9107c30b5be2178f67ba5d5f4526621
C1  Phase 0 constitution and Phase 1 archaeology atlas, evidence-bound
    state (initial) -> state.85d1e8ede88fb9f355d3d7e01f71483f9b28f0a857898a706a5fe5a3099a44f2
```

## `gemel status`

```
T2  intent.fb11ed5b2ae6956c4256d2546c7d9c8e644bfef57c7090d39b98295c8e137616
state: state.c86c4178c1597a82a06176665f752d3aa9107c30b5be2178f67ba5d5f4526621
exchange: present
exchange: SOURCE_CONTEXT_DIVERGED (imported context is historical)
3 file(s) changed: +1 ~0 -2
claims: 0/3 supported
semantic: not indexed (gemel index)
residual: open [low] FRF sensitivity coverage missing for the two non-fixture-driven courts, harness disposition, blocks a sensitivity-backed claim for them
residual: open [low] Two macros added in 3.6.4, one of which (X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH) is security-fix related
readiness: READY_WITH_RESIDUALS
```
