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

## 4. The eleven courts — all pass

| court | what it establishes |
|---|---|
| `ABI-SYMBOL` | 5896/5896 and 603/603 symbols match on **name, ELF type, binding, visibility and version** |
| `ABI-VERSION` | version definition nodes identical to the authority |
| `ABI-DYNAMIC` | identical `DT_SONAME` and ELF identity; every authority `DT_NEEDED` present |
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

- **`libssl.so.3` now declares `NEEDED libcrypto.so.3`**, as the authority does.
  This was the one real ABI mismatch at the first Phase 2 seal and it is closed:
  the build uses `-Wl,--no-as-needed -lcrypto` for libssl (the same technique
  already used for `legacy.so`), because without it the linker drops a library
  nothing references. `DT_NEEDED` is part of the contract
  (`docs/CUSTODIAN_CONTRACT.md` §2): ELF symbol resolution order and transitive
  loading are observable.
- **Notable: no symbol-level court could have found that.** The FRF
  `openssl-abi-surface` court compares `symbol@version` streams and is completely
  blind to dynamic tags; its evidence is byte-identical before and after the fix
  (FRF refused to re-capture the run, quite correctly, as identical evidence).
  A defect in the dynamic contract required a court that observes the dynamic
  contract. That is the whole argument for `ABI-DYNAMIC` existing.
- **The shell's static archives and provider module are scaffolds.** Their shape
  matches; their contents do not.
- **The `openssl` executable and `c_rehash` are scaffolds** that fail loudly.
- `lib/cmake/` and `lib/engines-3/` are not reproduced; reported as optional
  differences by `ABI-INSTALL-LAYOUT`.

## 8. Phase status

Phase 2's work and exit criteria are satisfied. It was sealed as `InProgress`
rather than `complete` because the dependency-order invariant in
`docs/RELEASE_GATES.md` §1 held then: **Phase 1 was open** (its FRF sensitivity
gap for the two non-fixture-driven courts was recorded, not papered over), and a
later stratum may not claim completion while an earlier one is open.

That invariant is a feature. It is what stopped a tidy-looking Phase 2 from
hiding an open Phase 1. Phase 1 closed when the fixture-driven replacement court
landed — `openssl-cli-inventory`, described in `forensics/frf/README.md` §"The
courts" — and `forensics/phase-state.json` now derives both strata `complete`.

```
PHASE 2 DISTRIBUTION SHELL: WORK COMPLETE, EXIT CRITERIA MET
CANDIDATE PARITY:           NONE CLAIMED (all symbols SCAFFOLDED)
STRATUM STATUS:             complete (forensics/phase-state.json)
```

## 10. Phase 2.1 — structural closure

Three defects found in review, plus one stale statement, all closed.

### 10.1 `libssl.so.3 → DT_NEEDED libcrypto.so.3` (was: missing)

Restored with `-Wl,--no-as-needed -lcrypto` at link time. Verified by
`ABI-DYNAMIC`: candidate `libssl.so.3` now declares `[libcrypto.so.3, libc.so.6,
libgcc_s.so.1, ld-linux-x86-64.so.2]` against the authority's
`[libcrypto.so.3, libc.so.6]`. The toolchain runtime dependencies are recorded
as differences, not ignored, and cannot be removed from a Rust-linked artifact.

### 10.2 `ABI-DYNAMIC` court (new)

Compares `DT_SONAME`, `DT_NEEDED`, and ELF class/type/machine. Required to match:
SONAME, ELF identity, and every dependency the authority declares. Extra
dependencies are recorded with a note rather than silently dropped.

### 10.3 `ABI-SYMBOL` now compares type, binding and visibility

It previously compared only name and version, so an authority `OBJECT/WEAK`
symbol against a candidate `FUNC/GLOBAL` one would have passed. That is a real
ABI difference: taking the address of a data object and binding a function are
not interchangeable. The shell generates every scaffold as `extern "C" fn`, so
this court is specifically what proves that choice did not silently change any
symbol's ELF type. Fields compared: **name, version, type, bind, visibility**.

Two defects were found *in my own courts* while doing this, and fixed:
`candidate_export()` did not record `visibility` at all (so it compared `None`
against `DEFAULT` for all 6,499 symbols), and the contamination court flagged the
*correct* `libcrypto.so.3` dependency as contamination. The corrected
contamination court resolves the closure and requires every OpenSSL it finds to
live inside the candidate's own install tree; necessity of the dependency is
asserted by `ABI-DYNAMIC`, not conflated with contamination.

### 10.4 Phase state is derived from evidence

`forensics/tools/phase_state.py` now computes every stratum's state from
artefact existence and content and emits `forensics/phase-state.json`. The
renderer no longer contains a single typed phase status. The transition rule is
enforced in code:

> a phase may be `complete` only if every earlier phase is `complete`

which is why Phase 2 is reported `in-progress` with the reason *"blocked by the
dependency-order invariant: phase 1 is not complete"* rather than a hand-written
claim.

### 10.5 Corrected Gemel statement

The Phase 1 seal claimed `.gemel` was committed. The canonical wording is now:

> The native Gemel store is not Git-tracked. Gemel's Git-carried `exchange/`
> projection is tracked, along with the human-readable trajectory projection and
> the checkpoint identities.

### 10.6 Note on the FRF court's sensitivity

The `openssl-abi-surface` FRF court passed challenge on both operators and its
sensitivity-backed claim stands. It is deliberately retained as-is: its
limitation (blind to dynamic tags) is now documented and covered by
`ABI-DYNAMIC`, which is more useful than pretending one court observes
everything.

```
PHASE 2 DISTRIBUTION SHELL: WORK COMPLETE, EXIT CRITERIA MET (11 courts)
CANDIDATE PARITY:           NONE CLAIMED (all symbols SCAFFOLDED)
STRATUM STATUS:             complete (forensics/phase-state.json)
```

## 9. Reproduction

```bash
bash docker/openssl-rs-court.sh exec bash forensics/tools/build_phase2.sh
bash docker/openssl-rs-frf-court.sh exec sh -c 'cd /work && \
  frf --root .frf authority admit forensics/frf/refs/authority-abi-report.sh \
    --name openssl-abi --version 3.6.4 && \
  frf --root .frf court run forensics/frf/courts/openssl-abi-surface/manifest.yaml'
```
