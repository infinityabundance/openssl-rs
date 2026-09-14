# PHASE 2 DISTRIBUTION / ABI SHELL SEAL

**Authority:** `openssl-3.6.4-production` (OpenSSL 3.6.4)
**Build profile:** `linux-x86_64-default-shared-legacy-notests`
**Platform:** `linux-x86_64` (ELF)
**Scope:** the distribution shell. Structure, never semantics.

---

## 1. What this seal asserts

That a **trivial external consumer can build and load against the candidate**,
across every combination of headers and libraries, that the distribution
artifacts exist with the right names, SONAMEs, symbol versions and install
layout, and that the candidate is **binary-substitutable** for the authority
without recompilation.

## 2. What this seal does **not** assert

**Nothing about behaviour.** Every symbol in the shell is `SCAFFOLDED` and aborts
with a diagnostic when called rather than returning a plausible value
(`docs/CUSTODIAN_CONTRACT.md` §5). `SHELL_MANIFEST.json` records that for every
symbol.

Passing these courts is **not parity**. No obligation is `PARITY_VERIFIED`.

---

## 3. Artifacts

| artifact | detail |
|---|---|
| `libcrypto.so.3` / `libssl.so.3` | correct SONAME, 10 version nodes, exactly 5896 / 603 exports |
| `libcrypto.so` / `libssl.so` | development symlinks so `-lcrypto` resolves |
| `libcrypto.a` / `libssl.a` | static archives |
| `lib/ossl-modules/legacy.so` | provider module exporting `OSSL_provider_init`, declaring `NEEDED libcrypto.so.3` |
| `bin/openssl`, `bin/c_rehash` | executable names and paths present (behaviour is Phase 16) |
| `include/openssl/**` | 143-file public header shell with provenance notice |
| `lib/pkgconfig/*.pc` | pkg-config metadata |
| `install/` | the layout above, mirroring the authority's tree |

## 4. The ten courts — all pass

| court | what it establishes |
|---|---|
| `ABI-SYMBOL` | 5896/5896 and 603/603 symbols match exactly; no missing, extra, or version mismatch |
| `ABI-VERSION` | version definition nodes identical to the authority |
| `ABI-LAYOUT` | every `sizeof`/`alignof`/`offsetof` for all 158 probed aggregates matches |
| `ABI-LINK` | a trivial C consumer links against the candidate |
| `ABI-LOAD` | **5896/5896 and 603/603** resolve via `dlvsym` at their declared versions |
| `ABI-CONSTANTS` | 27 compile-time constants identical across both header sets |
| `ABI-MATRIX` | all four header×library combinations compile, link and run |
| `ABI-SUBSTITUTION` | one executable, built against the authority, runs against candidate libraries with `LD_LIBRARY_PATH` — no recompilation |
| `ABI-INSTALL-LAYOUT` | required install entries present; provider module declares its dependency |
| `libcrypto-contamination` | no non-authority OpenSSL in the dynamic closure |

## 5. FRF evidence

| item | result |
|---|---|
| court | `openssl-abi-surface` (authority `openssl-abi-3.6.4`) |
| subject | for a 500-symbol fixture, each side reports what its own library binds each symbol to |
| run | 0 residuals |
| challenge | **both** mutation operators demonstrated (exit-class and stdout-first-line) |
| receipt | emitted |
| claim | **sensitivity-backed** (`555391e9…`) |

The fixture is the query list, not decoration. That matters: `docs/DECISIONS.md`
D13 records that an FRF court whose arguments do not reference `{fixture}` cannot
be challenged, because the mutant wrapper cannot locate the reference. The ABI
court was designed fixture-driven so that its sensitivity evidence would be
obtainable rather than blocked.

## 6. Gemel

Change `C5`, trajectory `T5`, continuation checkpoint. Projection in
`forensics/GEMEL_TRAJECTORY.md`.

## 7. Recorded differences and residuals

- **`libssl.so.3` has no `NEEDED libcrypto.so.3`**, unlike the authority: the
  stubs never call libcrypto. A real ABI difference, recorded rather than hidden,
  and it will close when the implementation does.
- **The shell's static archives and provider module are scaffolds.** Their shape
  matches; their contents do not.
- **The `openssl` executable and `c_rehash` are scaffolds** that fail loudly.
- `lib/cmake/` and `lib/engines-3/` are not reproduced; reported as optional
  differences by `ABI-INSTALL-LAYOUT`.

## 8. Phase status, and why it is not `Complete`

Phase 2's work and exit criteria are satisfied. It is nevertheless recorded as
`InProgress`, and the reason is the dependency-order invariant in
`docs/RELEASE_GATES.md` §1: **Phase 1 remains open** (its FRF sensitivity gap for
the two non-fixture-driven courts is recorded, not papered over), and a later
stratum may not claim completion while an earlier one is open.

That invariant is a feature. It is what stops a tidy-looking Phase 2 from hiding
an open Phase 1. Phase 1 closes when the fixture-driven replacement courts land
and the remaining archaeology unknowns are disposed — which the user's own
instruction defers until the implementation phases make it honest.

```
PHASE 2 DISTRIBUTION SHELL: WORK COMPLETE, EXIT CRITERIA MET
CANDIDATE PARITY:           NONE CLAIMED (all symbols SCAFFOLDED)
STRATUM STATUS:             InProgress (blocked by the open Phase 1 stratum)
```

## 9. Reproduction

```bash
bash docker/openssl-rs-court.sh exec bash forensics/tools/build_phase2.sh
bash docker/openssl-rs-frf-court.sh exec sh -c 'cd /work && \
  frf --root .frf authority admit forensics/frf/refs/authority-abi-report.sh \
    --name openssl-abi --version 3.6.4 && \
  frf --root .frf court run forensics/frf/courts/openssl-abi-surface/manifest.yaml'
```
