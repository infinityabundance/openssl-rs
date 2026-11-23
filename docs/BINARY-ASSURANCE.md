# Binary-level assurance (ETP-T6)

**Status:** TCB and claim matrix recorded at `staging` = `c28ac7bb94`, 2026-11-22.
**Machine-readable:** `evidence/etp-t6/TCB.json` and
`evidence/etp-t6/CLAIM-MATRIX.json`.
**Checker:** `forensics/tools/binary_assurance.py` (`record`, `check`).
**Controls:** `forensics/tools/tests/test_binary_assurance.py` (25 tests).
**Receipt:** `evidence/etp-t6/RECEIPT.md`.

This document names the trusted computing base, binds every existing claim to a
target, a build profile, an artefact digest and a source identity, and states
the conditions under which the checker refuses a claim. It extends
`docs/CODE-GENERATION-ASSURANCE.md` (the binding and invalidation rules for
emitted code) and `docs/INSTRUMENT-QUALIFICATION.md` (what each instrument may
be cited for); it does not restate them.

## 0. What this document is not

It is not a source-to-binary correspondence argument. No row asserts, implies
or admits the claim-algebra modality `BINARY_REFINEMENT_VERIFIED`; the checker
has no status in its vocabulary for that modality, and a document containing
one is refused (`BA_FORBIDDEN_CLAIM`). `docs/REFINEMENT-ARCHITECTURE.md` §2.4
keeps edge `RFE-4` (ABI contract → machine code) at **`NONE`** after this item.
This item builds the machinery that edge will need; it does not discharge it.

It is not a safety, compatibility or cryptographic result. A row records what
was observed, on which artefact, at which target and profile, with which
instrument. Whether that observation supports a broader property is decided
elsewhere, by the relevant evidence axis (`AGENTS.md` §8).

## 1. The trusted computing base

`evidence/etp-t6/TCB.json` records 23 components from the live court toolchain.
Each carries a version or commit, a digest where one is obtainable, what it
could do to invalidate a source-level claim, and whether anything checks it.
`check.checked = true` means the identity probe ran; it does **not** mean the
component is trustworthy. A component with no probe is a stated assumption.

The canonical `tcb_digest` is SHA-256 over canonical JSON (sorted keys,
`","`/`":"` separators) of the target triple, the venue, the build profile and
the sorted component identities (`id`, `kind`, `version`, `digest`,
`check.checked`, `check.mechanism`). The recording timestamp is excluded, so a
re-record at the same toolchain is byte-identical.

### 1.1 Compiler and code generator

| component | recorded identity | digest | checked | what it can invalidate |
|---|---|---|---|---|
| `rustc` | `rustc 1.98.1 (48a229cea 2026-09-01)` | `85925497…` (sysroot `bin/rustc`) | yes | Every emitted instruction; optimisation, inlining and constant-time code shape can change between patch releases. |
| `rustc-commit` | `48a229ceaefd4985c50990b14116b6d856af0985` | identity string | yes | The same, pinned to a source commit rather than a version string. |
| `llvm` | `LLVM version: 22.1.8` | `24d5732d…` (resolved `libLLVM`) | yes | Lowering, scheduling, inlining and branch/cmov selection after Rust MIR. |
| `rustup` | `rustup 1.29.3 (edbc831ce 2026-11-02)` | `b1c8cb14…` | yes | Selects the toolchain behind the `rustc`/`cargo` shims. |
| `cargo` | `cargo 1.98.1 (797e8a9bc 2026-08-05)` | `b1c8cb14…` (resolved shim) | yes | Feature resolution, profile selection and build-script execution. |

### 1.2 Binary-producing tools

| component | recorded identity | digest | checked | what it can invalidate |
|---|---|---|---|---|
| `cc` | `cc (Debian 12.2.0-14+deb12u1) 12.2.0` | `75e997ec…` | yes | Distribution link, startup objects, PIE and linker flags. |
| `ld` | `GNU ld (GNU Binutils for Debian) 2.40` | `f6d71a1b…` | yes | Section layout, symbol-version resolution, artefact digest. |
| `as` | `GNU assembler (GNU Binutils for Debian) 2.40` | `41fe4f5a…` | yes | Encoding of compiler-emitted and inline assembly. |
| `ar` | `GNU ar (GNU Binutils for Debian) 2.40` | `3acbee27…` | yes | Archive member order and metadata; the archive digest. |
| `objdump` | `GNU objdump (GNU Binutils for Debian) 2.40` | `19717049…` | yes | The instruction stream the branch audit sees. |
| `readelf` | `GNU readelf (GNU Binutils for Debian) 2.40` | `afa25ff2…` | yes | Build-id and `NEEDED` records used to identify an artefact. |
| `python3` | `Python 3.11.2` | `9bee109d…` | yes | The checker's own JSON, hashing and comparison behaviour. |

### 1.3 C library, loader and runtime

| component | recorded identity | digest | checked | what it can invalidate |
|---|---|---|---|---|
| `libc` | `ldd (Debian GLIBC 2.36-9+deb12u14) 2.36` | `6b4a4535…` | yes | Allocation, I/O, threading and process start state. |
| `dynamic-loader` | `/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2` | `02bcda52…` | yes | Symbol resolution and relocation; which definition a call binds to. |
| `libgcc-s` | version command absent | `2bd1552c…` | yes | The unwinder behind the panic boundary. |
| `std` | as shipped with rustc 1.98.1 | `bf156342…` (`libstd` rlib) | yes | Allocation, panicking and platform abstractions. |
| `panic-unwind` | as shipped with rustc 1.98.1 | `afccbbad…` (`libpanic_unwind` rlib) | yes | Whether a panic is caught or aborts. |
| `panic-boundary` | `panic=unwind`, `guard_ffi` present | source-bound, no digest | yes | A profile change to `abort`, or a weakened guard, makes the documented failure value unreachable. |

The release profile recorded from `Cargo.toml` is `opt-level = 3`,
`codegen-units = 16`, `lto = false`, `overflow-checks = true`,
`panic = unwind`, `debug-assertions = false`, `strip = none`. The panic
boundary is `guard_ffi` in `src/ffi/mod.rs`; `catch_unwind` and
`AssertUnwindSafe` are both present.

### 1.4 CPU dispatch and the venue

| component | recorded identity | digest | checked | what it can invalidate |
|---|---|---|---|---|
| `cpu-dispatch` | compile-time `cfg(target_arch)` selection; 0 runtime feature-detection sites; no explicit `target-cpu`/`target-feature` flags | mechanism, no file digest | yes (source scan) | A runtime feature test or an explicit target flag would select code outside the audited baseline. |
| `cpu` | 13th Gen Intel Core i9-13900K; hypervisor present | `9bf94b95…` (flags string) | yes | The same instruction stream can time differently on another microarchitecture. |
| `kernel` | `7.3.5-2-cachyos` | version only | yes | Loader interface, scheduling and the timestamp counter. |
| `court-image` | `openssl-rs-court-tools:1` | **UNKNOWN** | **no** | A different image changes every tool and library in this table at once. |
| `perf-pmu` | absent: `perf stat -e cycles true` reports `<not supported>` | venue probe | yes | Without a PMU, no cycle or branch-counter claim can be made. |

### 1.5 Entries with no check

`court-image` is the only component whose identity is not probed. The container
cannot inspect its own image content id without host access; the method that
would obtain it is
`docker image inspect --format '{{.Id}}' openssl-rs-court-tools:1` on the host.
This is a **stated assumption**, not a blank: every claim in the matrix is
conditioned on the image name, and the image content id is not bound.

The kernel and the CPU microcode are recorded by version and model only; a
kernel or microcode digest is not obtained. `rustc-commit`,
`panic-boundary`, `cpu-dispatch` and `perf-pmu` have no file digest because
they are identity strings, source constructs or venue probes, not artefacts.
Their `digest.value` is `UNKNOWN` and `digest.method` names what would obtain a
byte identity if one existed.

## 2. The binding model

A claim is admissible only when all of the following agree:

1. **Target triple and ABI.** `x86_64-unknown-linux-gnu` / `sysv-amd64-elf64`
   for every bound row in this tree; `aarch64-unknown-linux-gnu` /
   `aapcs64-elf64` exists as a target with no artefact and no claim.
2. **Build profile.** The row's profile must be the build's profile; the
   matrix records `release` and `test-debug` separately.
3. **Artefact.** SHA-256 and, where the record has one, build id. A claim whose
   digest differs from the build's recorded artefact is refused.
4. **Source identity.** The build's declared source commit must equal the
   artefact's recorded build source, or the row must state an explanation.
   `UNKNOWN` without an explanation is refused.
5. **TCB.** The build's `tcb_digest` must equal the recorded TCB digest, and the
   claim's must equal the build's.
6. **Instrument.** The named instrument or proof, or `NONE`. An asserted claim
   with `NONE` is refused; an unasserted row must state why it is unbound.

Each build row also records `tcb_basis` and `tcb_basis_kind`. `PARTIAL` means
the build's own receipt names some components (typically rustc and cc) and the
rest are assumed equal to the recorded TCB. `ASSUMED` means no build record
names the toolchain and the whole match is an assumption. `NONE` means no TCB
is bound. The assumptions are listed in §7; they are not witnesses.

## 3. The matrix

`evidence/etp-t6/CLAIM-MATRIX.json` holds **7 build rows** and **13 claims**:
**9 asserted** and **4 unbound**. The seven builds are six x86-64 release
builds (ETP-2, timing, ETP-T5, two install DSOs, and a debug test build) and
one aarch64 release target with no artefact.

### 3.1 Bound claims

| claim | result | target / profile | artefact | instrument |
|---|---|---|---|---|
| `BA-CLM-001` | archive byte-identical across two builds | x86-64 / release | `641471443209…` | `build-reproducibility` |
| `BA-CLM-002` | measurement DSO byte-identical | x86-64 / release | `85395dcf7b76…` | `build-reproducibility` |
| `BA-CLM-003` | distribution DSO byte-identical | x86-64 / release | `139966033ac9…` | `build-reproducibility` |
| `BA-CLM-004` | instruction shape at 7 symbols, 0 divisions | x86-64 / release | `ee7fa27c79f5…` | `binary-branch-audit` |
| `BA-CLM-005` | dudect state 1 on four modes, state 0 on one | x86-64 / release | `ee7fa27c79f5…` | `dudect` |
| `BA-CLM-006` | 4,326 differential cases, 0 differences; 9/9 reference checks | x86-64 / release | `e071ffeebecf…` | `etp5-reference-differential` |
| `BA-CLM-007` | curl closure: 644 files, 7/7 discharged, `safe_compatible=false` | x86-64 / release | `fd25cc9e6424…` | `consumer-closure` |
| `BA-CLM-008` | ssh closure: 625 files, 290/290 discharged, `safe_compatible=false` | x86-64 / release | `06b5f3384e34…` | `consumer-closure` |
| `BA-CLM-009` | b85c adjudication `NOT ESTABLISHED` | x86-64 / release | `06b5f3384e34…` | `independent-adjudication` |

Only `build-reproducibility`, `binary-branch-audit` and `dudect` are in the
ETP-3 instrument register. The ETP-T5 harness, the consumer-closure tool and
the b85c adjudication are **not** ETP-3-qualified; the matrix records
`instrument_registered: false` and the gap is restated in §7.

### 3.2 Unbound claims

| claim | recorded status | why it cannot be bound |
|---|---|---|
| `BA-CLM-010` | `UNBINDABLE` | ctgrind ran on a debug-profile `cargo test` binary; no test-binary digest or full effective profile is recorded. |
| `BA-CLM-011` | `NONE` | No ABI-contract-to-machine-code correspondence evidence exists; `RFE-4` stays `NONE`. |
| `BA-CLM-012` | `NONE` | No aarch64 toolchain, target or artefact exists in this venue. |
| `BA-CLM-013` | `NONE` | No release result is promoted to the debug profile or the reverse. |

These are recorded gaps, not passes. The checker requires `asserted: false`,
`instrument: "NONE"`, no artefact binding and a non-empty `unbindable_reason`.
Turning any of them into an asserted claim is refused (`BA_UNBOUND_ASSERTED`,
`BA_CLAIM_TARGET_UNBOUND`).

## 4. Refusal rules and controls

`forensics/tools/binary_assurance.py check` refuses with a named code, the
claim id, the target triple and the field. Each rule has a control in
`forensics/tools/tests/test_binary_assurance.py`.

| rule | refusal code | control mutation | observed refusal |
|---|---|---|---|
| R1 no inheritance across targets | `BA_CROSS_TARGET_INHERITANCE` | claim target changed to aarch64 | `claim=BA-CLM-001 target=aarch64-unknown-linux-gnu field=claims[0].target` |
| R1 no inheritance across profiles | `BA_CROSS_PROFILE_INHERITANCE` | claim profile changed to `debug` | `claim=BA-CLM-001 field=claims[0].profile` |
| R1 target with no evidence | `BA_CLAIM_TARGET_UNBOUND` | aarch64 row asserted | `claim=BA-CLM-012 target=aarch64-unknown-linux-gnu field=claims[11].build` |
| R2 artefact digest | `BA_ARTEFACT_DIGEST_MISMATCH` | claim sha256 replaced | `claim=BA-CLM-002 field=claims[1].artefact.sha256` |
| R2 artefact identity | `BA_ARTEFACT_UNKNOWN` | artefact id not in the build | `claim=… field=claims[…].artefact.id` |
| R3 TCB | `BA_TCB_MISMATCH` | build tcb_digest replaced | `claim=BA-CLM-001 target=x86_64-unknown-linux-gnu field=builds[0].tcb_digest` |
| R3 TCB self-consistency | `BA_TCB_SELF_DIGEST` | recorded TCB digest replaced | `field=tcb_digest` |
| R4 source identity | `BA_SOURCE_IDENTITY_MISMATCH` | build source changed, no explanation | `claim=BA-CLM-001 field=builds[0].artefacts[0].built_from_source` |
| R4 source identity unknown | `BA_SOURCE_IDENTITY_UNKNOWN` | both sides `UNKNOWN`, no explanation | `claim=BA-CLM-001 field=builds[0].artefacts[0].built_from_source` |
| R5 forbidden vocabulary | `BA_FORBIDDEN_CLAIM` | status set to the refused modality | `claim=BA-CLM-001 target=x86_64-unknown-linux-gnu field=CLAIM-MATRIX:claims[0].status` |

The R4 controls include the positive case: a changed build source **with** a
non-empty explanation is accepted, and the claim's own source identity must
still match its build. The R5 scan covers every string in both documents, not
only the `status` field. The checker also refuses duplicate JSON keys
(`BA_JSON_DUPLICATE_KEY`), non-finite numbers (`BA_JSON_NON_FINITE`), an
evidence file whose digest changed (`BA_EVIDENCE_DIGEST_MISMATCH`), and a
missing evidence file (`BA_EVIDENCE_MISSING`).

Two determinism controls run the checker twice and the live TCB probe twice;
both outputs are byte-identical. A positive control runs the committed
documents unchanged (`9` asserted, `4` unbound, `0` refusals), and a
freshness control re-records the live TCB and requires the committed digest.

## 5. What a binary-level claim means here

### 5.1 Reproducibility

A byte-identical rebuild shows that two independently initialised builds agree.
It does **not** show that the bytes implement the source. It is a precondition
for treating an artefact identity as stable, and it is the reason a digest can
name a subject at all. It says nothing about memory safety, constant time or
compatibility. `BA-CLM-001`–`003` are exactly this result.

### 5.2 The branch audit

`binary_branch_audit.py` disassembles named symbols of one DSO and counts
conditional jumps, divisions and `cmov`s in the audited range. It shows
instruction shape at those symbols. It does not show that the instructions are
secret-independent, that the symbols execute on a secret-dependent path, or
that any callee, inlined caller or other target has the same shape. `BA-CLM-004`
is an instruction-shape observation, not a constant-time result.

### 5.3 ctgrind and dudect

ctgrind observes one harness on a debug-profile test binary; it is
source-level dynamic taint observation on the executed path. dudect loads a
release DSO but the venue has no PMU and no frequency/SMT control, so its
output is a statistical observation at a stated sample size. Neither is a
constant-time proof, and neither substitutes for the other
(`docs/INSTRUMENT-QUALIFICATION.md` §4). The ctgrind result is recorded as
unbindable because the test binary's digest is not recorded; the dudect result
is bound to the timing DSO (`BA-CLM-005`).

### 5.4 Differential and consumer courts

`BA-CLM-006` records agreement over a sampled population against an authority
and independent references. A differential is bounded evidence, never a proof;
it covers the declared cases only. `BA-CLM-007` and `BA-CLM-008` record
reachability closures: a discharged obligation means an existing receipt covers
a site, not that the site's precondition is established. Both closures report
`safe_compatible: false`, and `BA-CLM-009` records the independent refusal of
the ssh/sshd graduation. None of these rows establishes `Pre(c) ⇒ P`.

### 5.5 What remains trusted

The loader, the CPU dispatch mechanism, the kernel and the platform libraries
remain in the trusted computing base. The matrix binds their recorded
identities; it does not verify them. A claim about an x86-64 binary is
conditioned on this venue and this loader. Nothing here carries to aarch64, to
another image, to another toolchain, or to the debug profile.

## 6. Invalidation

Every item in §2 is an invalidation input. A change to the rustc/LLVM/rustup
identity, the linker, assembler, archiver, C library, loader, kernel, CPU
flags, build profile, target flags, an artefact digest, an evidence digest, or
the recorded TCB digest invalidates the affected rows until they are re-recorded
and re-checked. The rule is conservative: if non-impact cannot be proved, the
row is treated as invalid. `docs/CODE-GENERATION-ASSURANCE.md` governs the
code-generation half; this document governs the per-target binding half.

Re-recording is two commands:

```
python3 forensics/tools/binary_assurance.py record --out evidence/etp-t6/TCB.json
python3 forensics/tools/binary_assurance.py check
```

`record` must run in the court that produced the artefacts. `check` fails
closed if a target row or claim no longer matches the committed TCB, or if the
committed TCB's own digest does not match its content. The live re-record
comparison is a control in
the test suite (`test_live_tcb_matches_the_committed_record`), not a network or
build operation inside `check`.

## 7. Open gaps and stated assumptions

1. **The court image content id is not recorded.** `court-image` is the one
   TCB entry with no check. Every row is conditioned on the image name.
2. **Historical builds match the TCB only partially or by assumption.** ETP-2,
   the timing build and ETP-T5 name rustc and, in two cases, cc; the rest of
   the TCB is assumed. The two install DSOs have no build record at all
   (`tcb_basis_kind: ASSUMED`).
3. **The tracked install DSO's source is unknown.** It was last rebuilt before
   `S` and is not reproduced by ETP-2; the curl closure binds the consumer
   inventory to `17e45eec1`, not to the DSO's build commit.
4. **The ctgrind test binary has no recorded digest**, so that observation is
   unbound. It is not promoted.
5. **Three instruments in the matrix are not ETP-3-qualified**: the ETP-T5
   differential harness, the consumer-closure tool and the b85c adjudication.
6. **No aarch64 artefact, toolchain or claim exists.** Any aarch64 claim would
   be refused as inheritance until a build and its evidence exist.
7. **No ABI-contract-to-machine-code evidence exists.** `RFE-4` is `NONE`; no
   status in this checker can change that without an artefact and a method.
8. **Independence is not established.** The TCB and matrix were produced by the
   same campaign that will be judged by them; `ETP-T8` is the independence item.

## 8. Relationship to the claim algebra

This matrix is not a second claim algebra. `evidence/etp/claims.json` remains
the typed claim set and `forensics/tools/etp_claims.py` remains its validator.
The matrix adds the binary-side binding fields that the claim algebra does not
carry per target: artefact digest, build id, build profile, target ABI, artefact
source identity, TCB digest and the instrument-or-`NONE` field. A row here can
be cited as the binary-side witness for a claim in the algebra; it cannot
upgrade that claim's verdict.
