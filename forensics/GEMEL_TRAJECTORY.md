# Gemel trajectory (generated projection)

Generated from the local `.gemel` store by
`forensics/tools/render_gemel_trajectory.sh` inside the FRF tooling
container. Gemel's store is **not** Git-tracked (Gemel ships a
`.gemel/.gitignore` containing `*`), so this projection, Gemel's own
`exchange/` namespace, and the identities quoted below are what travel
in Git. See `docs/DECISIONS.md` D17.

## `gemel log`

```
C13  Record correction: Gemel names changes by derived order, so the name C9 that Phase 3 closure (change.0321160b...) quotes in its summary is not stable. The placeholder change it means is change.e58167ada98b43af520cd6b8c39c103a30560c406cfd91e6004019fd0b75f326, currently named C11, and it is the change that carries the Phase 3 working-tree operations because it was created first. No content changed; this change exists so the durable identity is recorded in the store rather than only in prose.
    state state.fad064947e65109210abd9e4d2e1a79a9945c6dc6604c8d6c74501c1d5f1045c -> state.6fe2d6a4caa8fde4a5aed8933bcac4e4a7e403eb92165dfc85b56f54dfce9c5a
C10  Phase 3 complete: seven differential runtime courts with no residual, generated ERR reason tables and raise-site coordinates, load-gated string visibility, fail-closed obligation ledger. Supersedes C9, which was created accidentally by a command-line probe of the claim-kind enum and carries only a placeholder claim.
    state state.fad064947e65109210abd9e4d2e1a79a9945c6dc6604c8d6c74501c1d5f1045c -> state.fad064947e65109210abd9e4d2e1a79a9945c6dc6604c8d6c74501c1d5f1045c
C11  p
    state state.46cf9bcff7dad1b49b613c87d2458196666c4d2e787c76ea29702255e3913716 -> state.fad064947e65109210abd9e4d2e1a79a9945c6dc6604c8d6c74501c1d5f1045c
C6  Phase 2.1 structural closure: dynamic contract, exact symbol comparison, evidence-derived phase state
    state state.ba6b30cf8a7741640b349cf65bff4a30247994151265f119bd5f2d6a4073a42b -> state.46cf9bcff7dad1b49b613c87d2458196666c4d2e787c76ea29702255e3913716
C5  Phase 2 complete: distribution shell, ABI matrix, substitution, constants, FRF ABI court
    state state.c86c4178c1597a82a06176665f752d3aa9107c30b5be2178f67ba5d5f4526621 -> state.ba6b30cf8a7741640b349cf65bff4a30247994151265f119bd5f2d6a4073a42b
C2  Phase 1 foundation closure: differential atlas, completeness, FRF sensitivity-backed claim, FFI boundary
    state state.85d1e8ede88fb9f355d3d7e01f71483f9b28f0a857898a706a5fe5a3099a44f2 -> state.c86c4178c1597a82a06176665f752d3aa9107c30b5be2178f67ba5d5f4526621
C1  Phase 0 constitution and Phase 1 archaeology atlas, evidence-bound
    state (initial) -> state.85d1e8ede88fb9f355d3d7e01f71483f9b28f0a857898a706a5fe5a3099a44f2
```

## Checkpoints

* `K1` — `checkpoint.2a1ca2279b999e7740976a4958d6d6bb66e5312203ed9d15816d340a38073328`
* `K2` — `checkpoint.67a75f9a16d008e6e5aec0984c93dfc7549bd7a33708b909fbf6424b04fcb4a6`
* `K3` — `checkpoint.b1516eb6364ad075785911cb204a75a6e1b83b08c1a7ca39a2de6e3983dc9aed`
* `K4` — `checkpoint.1bde75b37e1ca3972037c29cbd3ba5291079544436db9176a82f097a6bf832fe`
* `K5` — `checkpoint.6b0d12f1ecf380c0808bc95675222fbed7256f99bc8e9f475a0ec2693f804a0a`
* `K6` — `checkpoint.8958092650197b473c5b00d9c0de22e075c4765efc2e8a4ab9d452ffae97cf61`

current: `checkpoint.8958092650197b473c5b00d9c0de22e075c4765efc2e8a4ab9d452ffae97cf61`

## Note: derived names are not identities

Gemel names changes by derived order, so a name quoted inside one change's
summary can be renumbered later. The Phase 3 closure change
(`change.0321160b791013c5904bb61fe65b4932da674bdbc7f1043b50e2e4369544c227`)
says it supersedes `C9`; that name no longer exists in the store. The change it
means is
`change.e58167ada98b43af520cd6b8c39c103a30560c406cfd91e6004019fd0b75f326`,
currently named `C11`: a placeholder created by a command-line probe of Gemel's
claim-kind enum, which — because it was created first — is also the change that
carries the Phase 3 working-tree operations. The correction
(`change.8423b2c8fe75201fb070e0b21df03d122c8675cde393c9b2d88d9ea1800ee5de`)
records that mapping in the store rather than only in prose. No file content
changed with it; the Git commit is the authoritative record of the diff.

## Open residuals at this boundary

```
open [low] Gemel C9 was created accidentally while probing the claim-kind enum, and Gemel is append-only so it carries a placeholder claim; C10 is the substantive record
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] the FRF runtime claim covers the first stdout line, which is a digest of the whole transcript, plus exit class; stderr is not claimed because both sides write none
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] two authority ERR raise arms (stack.c:212 and stack.c:275) need on the order of a billion elements to reach; their conditions are reproduced but no court exercises them
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] the ABI-SYMBOL court compares name, version, ELF type, binding and visibility but never C prototypes; a declaration/definition arity mismatch is invisible to it, and one was found this phase by the RT-ERR probe instead
    class: verification_gap
    persistence: 0 descendant change(s)
superseded [low] FRF sensitivity coverage missing for the two non-fixture-driven courts, harness disposition, blocks a sensitivity-backed claim for them
    class: verification_gap
    persistence: 0 descendant change(s)
open [low] candidate DSOs carry toolchain runtime dependencies the C authority does not; recorded by ABI-DYNAMIC, not removable from a Rust-linked artifact
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] Every shell symbol is SCAFFOLDED and aborts when called; Phase 2 proves structure, never semantics
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] Two macros added in 3.6.4, one of which (X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH) is security-fix related
    class: expected_mismatch
    persistence: 0 descendant change(s)
open [low] OpenSSL 3.6.3 to 3.6.4 version banner divergence, disposed as an oracle-version trajectory
    class: expected_mismatch
    persistence: 0 descendant change(s)
```
