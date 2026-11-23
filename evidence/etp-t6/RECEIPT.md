# ETP-T6 — binary-level assurance receipt

Date: 2026-11-22 (UTC).
Item: ETP-T6 of `docs/ETP-TODO.md` — name the trusted computing base, bind
claims to exact artefacts per target, and refuse inheritance across targets or
profiles.
Branch: `staging`.
HEAD at start: `c28ac7bb94` (verified with `git rev-parse`).
Worktree at start: clean (`git status --porcelain` empty).

Deliverables:

- `docs/BINARY-ASSURANCE.md` — the TCB, the binding model, the matrix, the
  refusal rules and the non-claims.
- `evidence/etp-t6/TCB.json` — 23 live components with version/commit, digest
  or `UNKNOWN`+method, invalidating power and check state.
- `evidence/etp-t6/CLAIM-MATRIX.json` — 7 build rows, 13 claims (9 asserted,
  4 unbound), each asserted row bound to a target, ABI, profile, artefact
  digest, source identity and TCB digest.
- `forensics/tools/binary_assurance.py` — `record` and `check`, fail closed.
- `forensics/tools/tests/test_binary_assurance.py` — 25 controls.
- This receipt and the ETP-T6 row in `docs/ETP-TODO.md`.

## 1. Environment guard

Host `available` before the work: **25 GiB**, above the 24 GiB line in
`AGENTS.md` §6.1. The computed cap `min(8g, 25g − 16g)` is 8g; the batch used
the prescribed `6g`/`6g` court invocation, which is below that cap. One heavy
command ran at a time. No crate build was performed: `record` probes the live
toolchain and hashes files only. The release artefacts in the matrix are the
ones already recorded by ETP-2, ETP-T5, the timing receipt and the consumer
closures; no artefact was rebuilt for this item.

```
cd /home/user/openssl-rs
OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g \
  bash docker/openssl-rs-court.sh exec <command>
```

## 2. TCB record

`record` writes `evidence/etp-t6/TCB.json` and prints:

```
{
  "components": 23,
  "path": "/work/evidence/etp-t6/TCB.json",
  "status": "RECORDED",
  "tcb_digest": "aa8fbaea85e2fb1e8808121682f6a079ce3c0fd110e3a0750360ba690063bc83",
  "unchecked": ["court-image"]
}
```

22 of 23 components have a completed identity probe. The single unchecked
entry is `court-image`: the container cannot inspect its own image content id,
so the image name is a stated assumption. The method that would obtain the
content id is
`docker image inspect --format '{{.Id}}' openssl-rs-court-tools:1` on the host.

Recorded identities include:

- rustc `1.98.1 (48a229cea 2026-09-01)`, commit `48a229cea…`, sysroot binary
  sha256 `85925497…`, LLVM `22.1.8` with `libLLVM` sha256 `24d5732d…`;
- rustup `1.29.3`, cargo `1.98.1` (both behind the same shim, `b1c8cb14…`);
- cc/gcc `12.2.0` (`75e997ec…`), ld/as/ar/objdump/readelf `2.40`;
- libc `2.36` (`6b4a4535…`), loader `02bcda52…`, `libgcc_s` `2bd1552c…`,
  `libstd` `bf156342…`, `libpanic_unwind` `afccbbad…`;
- CPU dispatch: compile-time `cfg(target_arch)` only, **0** runtime
  feature-detection sites, no explicit `target-cpu`/`target-feature` flags;
- panic boundary: release `panic=unwind`, `guard_ffi`, `catch_unwind` and
  `AssertUnwindSafe` all present;
- venue: i9-13900K, hypervisor present, kernel `7.3.5-2-cachyos`, hardware PMU
  **absent** (`perf stat -e cycles true` prints `<not supported>`).

The canonical TCB digest covers the target triple, venue, release profile and
the sorted component identity/check fields; it excludes the recording
timestamp. Two `record` runs with a fixed `--recorded-at` are byte-identical
(control below).

## 3. Claim matrix

7 build rows, 13 claims, 9 asserted and 4 unbound.

Asserted rows, all at `x86_64-unknown-linux-gnu` / `sysv-amd64-elf64` /
`release`:

| claim | artefact | result |
|---|---|---|
| `BA-CLM-001` | archive `641471443209…` | byte-identical across two builds |
| `BA-CLM-002` | measurement DSO `85395dcf7b76…` / `77bbdedc…` | byte-identical |
| `BA-CLM-003` | distribution DSO `139966033ac9…` / `39bfc458…` | byte-identical |
| `BA-CLM-004` | timing DSO `ee7fa27c79f5…` | 7 symbols audited, 0 divisions, shape recorded |
| `BA-CLM-005` | timing DSO `ee7fa27c79f5…` | dudect state 1 on 4 modes, state 0 on `inverse_vt` |
| `BA-CLM-006` | ETP-5 DSO `e071ffeebecf…` | 4,326 cases, 0 differences; 9/9 reference checks |
| `BA-CLM-007` | install DSO `fd25cc9e6424…` | curl closure 644 files, 7/7, `safe_compatible=false` |
| `BA-CLM-008` | install DSO `06b5f3384e34…` | ssh closure 625 files, 290/290, `safe_compatible=false` |
| `BA-CLM-009` | install DSO `06b5f3384e34…` | b85c adjudication `NOT ESTABLISHED` |

Unbound rows (recorded gaps, `instrument: "NONE"`, no artefact):

- `BA-CLM-010` — ctgrind ran on a debug-profile `cargo test` binary whose
  digest and full profile are not recorded.
- `BA-CLM-011` — no ABI-contract-to-machine-code correspondence; `RFE-4`
  remains `NONE`.
- `BA-CLM-012` — no aarch64 artefact, toolchain or evidence.
- `BA-CLM-013` — no cross-profile promotion in either direction.

`aarch64-unknown-linux-gnu` exists as a build row with no artefact and no
claim; it is the target the refusal controls use to prove that inheritance is
refused.

## 4. Checker result

```
{
  "asserted_claims": 9,
  "builds": 7,
  "claims": 13,
  "refusals": [],
  "status": "PASS",
  "tcb_digest": "aa8fbaea85e2fb1e8808121682f6a079ce3c0fd110e3a0750360ba690063bc83",
  "tools_checked": 22,
  "tools_unchecked": ["court-image"],
  "unbound_claims": 4
}
```

Both JSON documents pass `python3 -m json.tool`.

## 5. Refusal controls and observed refusals

`forensics/tools/tests/test_binary_assurance.py` runs 25 controls: one per
refusal rule (including both R1 inheritance directions and both R4 source
cases), a positive control on the committed documents, a live-TCB freshness
control, two determinism controls, and strict-JSON controls. Observed lines:

```
R1 cross-target
  REFUSED BA_CROSS_TARGET_INHERITANCE claim=BA-CLM-001 target=aarch64-unknown-linux-gnu field=claims[0].target: build 'B-X86-64-RELEASE-ETP2' is for 'x86_64-unknown-linux-gnu'
R1 no-artefact
  REFUSED BA_CLAIM_TARGET_UNBOUND claim=BA-CLM-012 target=aarch64-unknown-linux-gnu field=claims[11].build: build 'B-AARCH64-RELEASE' records no artefact at this target
R2 digest
  REFUSED BA_ARTEFACT_DIGEST_MISMATCH claim=BA-CLM-002 target=x86_64-unknown-linux-gnu field=claims[1].artefact.sha256: claim records '0000…', build records '85395dcf…'
R3 build tcb
  REFUSED BA_TCB_MISMATCH claim=BA-CLM-001 target=x86_64-unknown-linux-gnu field=builds[0].tcb_digest: build records '0000…'; TCB records aa8fbaea…
R4 source
  REFUSED BA_SOURCE_IDENTITY_MISMATCH claim=BA-CLM-001 target=x86_64-unknown-linux-gnu field=builds[0].artefacts[0].built_from_source: artefact built from 'e9d492b0…', build row states '1111…', and no source_explanation is given
R5 status
  REFUSED BA_FORBIDDEN_CLAIM claim=BA-CLM-001 target=x86_64-unknown-linux-gnu field=CLAIM-MATRIX:claims[0].status: forbidden status vocabulary 'BINARY_REFINEMENT_VERIFIED' in 'BINARY_REFINEMENT_VERIFIED'; no artefact bears it
```

Test result:

```
Ran 25 tests in 0.955s
OK
```

The R4 positive control shows that a changed build source **with** a stated
explanation is accepted, provided the claim's own source identity matches its
build. The R5 scan covers every string in both documents, not only `status`.

## 6. What a binary-level claim can and cannot mean here

- **Reproducibility is agreement, not implementation.** Two byte-identical
  builds show that the build process is deterministic; they do not show that
  the bytes implement the source.
- **The branch audit is instruction shape at named symbols**, not semantic
  equivalence and not secret independence.
- **ctgrind is one harness on a debug test binary**; it is source-level dynamic
  taint observation, not release-binary timing assurance. Its row is unbound
  because the test binary has no recorded digest.
- **dudect is a statistical observation** on a venue with no PMU and no
  frequency/SMT control; state 1 is no leakage evidence, not constant time.
- **The differential court is a sampled agreement**, not equivalence, over the
  declared population.
- **The consumer closures are reachability measurements**; both report
  `safe_compatible=false`, and the independent adjudication is
  `NOT ESTABLISHED`.
- **The loader, CPU dispatch, kernel and platform libraries remain trusted.**
  Their identities are recorded; they are not verified.

No row asserts a source-to-binary correspondence, and the checker has no
status that would admit one. `docs/REFINEMENT-ARCHITECTURE.md` edge `RFE-4`
remains **`NONE`**.

## 7. Stated assumptions and residual gaps

1. The court image content id is not recorded.
2. Historical builds match the TCB partially (rustc/cc named, the rest
   assumed) or entirely by assumption (the two install DSOs have no build
   record).
3. The tracked install DSO's build source is unknown; the curl closure binds
   the consumer inventory, not the DSO's build commit.
4. The ctgrind test-binary digest is not recorded.
5. The ETP-T5 harness, the consumer-closure tool and the b85c adjudication are
   not in the ETP-3 instrument register.
6. There is no aarch64 evidence.
7. There is no ABI-contract-to-machine-code evidence.
8. Independence (`ETP-T8`) is not established: the TCB and matrix were produced
   by the same campaign that they will be used to judge.

## 8. Files changed

- `docs/BINARY-ASSURANCE.md` (new)
- `evidence/etp-t6/TCB.json` (new)
- `evidence/etp-t6/CLAIM-MATRIX.json` (new)
- `forensics/tools/binary_assurance.py` (new)
- `forensics/tools/tests/test_binary_assurance.py` (new)
- `evidence/etp-t6/RECEIPT.md` (new)
- `docs/ETP-TODO.md` (ETP-T6 row)

No file under `src/`, `docker/`, or another item's evidence directory was
modified.
