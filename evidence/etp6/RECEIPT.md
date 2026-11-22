# ETP-6 — frozen reproduction package, clean-room replay and mutation controls

**Status:** `PARTIAL` / `EXTERNAL_REVIEW_PENDING`.
**Source HEAD at session start:** `98c7b5d290a8e40a1bd4d979ed34599038733e4d`
(branch `staging`; `git status --porcelain` empty; worktree clean).
**Package candidate:** the published commit `98c7b5d29` itself. The ETP-6 tooling is
now tracked, so the builder runs its ordinary (non-provisional) mode, produces the
source tree by `git archive` from the commit, and `--refreeze` binds the manifest to
that commit hash:

| field | value |
|---|---|
| published commit | `98c7b5d290a8e40a1bd4d979ed34599038733e4d` |
| provisional | `false` |
| parent commit | `null` (a commit on `staging`, not a detached object) |
| packaged tree | `64f796e906bd7317b7f2fffbbea88bc171b3620b` |
| worktree tracked-dirty files at build | 0 |
| tracked files at commit | 14,082 |
| builder mode | `--refreeze --commit 98c7b5d29` |

The first ETP-6 package was built against a provisional `git commit-tree` object
(`b400a4e5e3a66d25d8c9e0c1012e1e7af8660741`, parent `3951f0f5e`) because the
tooling was not yet committed. The tooling is committed at `98c7b5d29`, and the
manifest and archive are rebound to that published commit. Section 7 records every
figure that changed and why; the provisional object is history, not a candidate.

**Frozen source identity of the claim set:** `9372bb28b` (from
`evidence/etp/claims.json`).

---

## 1. Frozen artifact

| field | value |
|---|---|
| archive | `openssl-rs-etp6-98c7b5d29.tar.gz` (72,070,994 bytes) |
| SHA-256 | `2a2e20e1f4f0e6e8fd6e01d6ca0957c0a7afe213ffd6821213e2e4bf13d3401a` |
| members | 1,634 (1,633 manifest inputs + `MANIFEST.json`) |
| manifest | `evidence/etp6/MANIFEST.json`, validated with `python3 -m json.tool` |
| inputs | 1,633, each with `path`, `role`, `bytes`, `sha256` |
| roles | source 897, tool 328, artefact 155, evidence 148, doc 83, object-store 22 |
| Git object store | `freeze-git/`: 91 objects, pack 9,035,329 B, SHA-256 `3268fee40e9ee54aaa0cc097a88bfd457e27a861585b12950801eddcd64777f1` |
| top-level files | `verify.sh`, `MANIFEST.json`, `TOOLCHAIN.json`, `.git` (gitfile → `freeze-git`) |

The archive is produced in `court/tmp/etp6/` and is not tracked. A second build in
the same venue, run without `--refreeze`, verified the frozen manifest and reproduced
the archive byte-for-byte (SHA-256 `2a2e20e1…` both times). The package is **not**
byte-reproducible across git versions: `freeze-git/` carries the `git init --bare`
template and a pack whose encoding is produced by the packaging git, and both differ
between the host git 2.56.1 that built the provisional package and the court git
2.39.5 used here. The object set is identical — 91 object IDs in each pack, checked
with `git verify-pack -v` — so only the encoding and the template files differ. See
section 7.

`TOOLCHAIN.json` records `rustc 1.98.1 (48a229cea 2026-09-01)`, cargo 1.98.1,
LLVM 22.1.8, `cc` (Debian 12.2.0), `ar`/`ld` 2.40, target
`x86_64-unknown-linux-gnu`, and names `evidence/etp2/reproducibility.json` as the
source of those strings (measured at `e9d492b0d`, not at this candidate).

---

## 2. Builder refusals at this commit

Invocation, inside `docker/openssl-rs-court.sh` with `OPENSSL_RS_COURT_MEM=6g` and
`OPENSSL_RS_COURT_MEMSWAP=6g`:

```
python3 forensics/tools/etp6_package.py --refreeze --commit 98c7b5d29 --out court/tmp/etp6
```

Result: `build OK`; **0 hard refusals**, **5 soft refusals**. The five are the same
paths recorded for the provisional package. A soft refusal is an input the evidence
cites but that cannot be reconstructed from the commit; it is named and omitted,
never copied in.

| path | reason | referenced by |
|---|---|---|
| `court/tmp/t20/NOTES.md` | gitignored (`.gitignore:26` `/court/`) | `ETP0-CLM-012` evidence |
| `court/tmp/t21/libcrypto.so.3` | gitignored (`.gitignore:26`) | `ETP0-CLM-014` evidence |
| `artifacts/phase2/libcrypto.so.3` | gitignored (`.gitignore:41` `/artifacts/phase2/*.so.*`) | ETP-0 RECEIPT §6 |
| `artifacts/phase2/shell/libcrypto.shell.rs` | gitignored (`.gitignore:44` `/artifacts/phase2/shell/`) | ETP-0 RECEIPT §6 |
| `forensics/phase7_courts.py` | absent at the named commit | `ETP0-CLM-004` evidence |

`court/tmp/` audit recorded in the manifest:

| quantity | value |
|---|---|
| tracked files containing `court/tmp/` | 549 |
| textual occurrences | 7,425 |
| tracked files under `court/tmp/` | 0 |
| ETP-0's count at `9372bb28b` | 1,929 references |

The published audit is 2 files and 16 occurrences above the provisional tree
(547 / 7,409). The difference is exactly the two ETP-6 evidence files that the
published commit tracks but the provisional tree did not contain, because
`evidence/etp6` is not a builder `SELECTION` path: `evidence/etp6/MANIFEST.json`
(5 occurrences) and `evidence/etp6/RECEIPT.md` (11). The previous receipt recorded
546 files / 7,399 occurrences, which was 1 file / 10 occurrences below the
provisional manifest it accompanied (547 / 7,409); the published figures are
549 / 7,425.

No `court/tmp/` path and no untracked file is placed in the package. The
`--distribution` arm of the reproducibility recipe no longer needs the ignored
shell source: ETP-2 made `phase2_shell.py --emit-shell` regenerate it from
tracked inputs. The distribution DSO named by ETP-0 remains absent and is not
substituted.

A hard refusal is produced by the same builder for an untracked, absent or
gitignored *required* selection input, for a digest that differs from the frozen
manifest, and for an input present but unnamed by it; in those cases no archive
is written and the exit status is 2. Observed control at the published commit: one
byte appended to `docs/EXTERNAL-REPRODUCTION.md`, then the builder run in
provisional mode without `--refreeze`:

```
REFUSED: the staged tree does not match the frozen manifest.
  HARD  docs/EXTERNAL-REPRODUCTION.md: digest mismatch: 467123f9… != a2308150…
  no archive written; review the drift, then --refreeze.
```

Exit status 2 and no archive written; the file was then restored and
`git diff --quiet HEAD -- docs/EXTERNAL-REPRODUCTION.md` confirmed the worktree copy
matches `HEAD`. The successful build therefore reports zero hard refusals while the
hard gate still fires on drift.

---

## 3. Clean-room replay

Venue and discipline: `openssl-rs-court-tools:1`, cap
`OPENSSL_RS_COURT_MEM=6g`, `OPENSSL_RS_COURT_MEMSWAP=6g`, fresh `HOME` and
`TMPDIR` under `/court`, one command at a time. `free -g` before the session:
`available 28 GiB` (guard met against the 24 GiB floor); computed cap
`min(8g, 28-16) = 8g`; the run used the instructed 6g cap.

```
rm -rf /court/etp6-pub && mkdir -p /court/etp6-pub/{home,tmp,unpack}
tar -xzf /work/court/tmp/etp6/openssl-rs-etp6-98c7b5d29.tar.gz -C /court/etp6-pub/unpack
cd /court/etp6-pub/unpack
HOME=/court/etp6-pub/home TMPDIR=/court/etp6-pub/tmp ./verify.sh
```

The unpacked directory is outside `/work`; no step reads the development
checkout. Observed output, verbatim:

```
ETP-6 offline verification
package  /court/etp6-pub/unpack
identity candidate 98c7b5d290a8e40a1bd4d979ed34599038733e4d (frozen source 9372bb28b); rustc rustc 1.98.1 (48a229cea 2026-09-01)
steps    digests, claims, interop, instruments, docs

[1/6] digests          PASS     (required)  1633 packaged inputs re-derived, 78 cited evidence digests re-derived from the frozen object store
      cited evidence declared absent by the claim set (not a digest re-derivation): 3
        ETP0-CLM-004: forensics/phase7_courts.py (present=false, reconstructable=True)
        ETP0-CLM-012: court/tmp/t20/NOTES.md (present=false, reconstructable=partial)
        ETP0-CLM-014: court/tmp/t21/libcrypto.so.3 (present=false, reconstructable=False)

[2/6] claims           PASS     (required)  35 claims validate with the Git-bound tree check at 9372bb28b
      {"claims":35,"document":"/court/etp6-pub/unpack/evidence/etp/claims.json","refusal_count":0,"refusals":[],"refusals_by_rule":{},"valid":true}

[3/6] interop          PASS     (required)  interop receipts and manifests satisfy R1-R5
      receipts=14 manifests=2 problems=0

[4/6] instruments      PASS     (required)  register validated: 11 instruments; 9 executable controls PASS, 2 RECORDED, 0 NOT_RUN
      valgrind-ctgrind         PASS      2 cases match the register
      dudect                   PASS      2 cases match the register
      binsec-checkct           PASS      19 cases match the register
      timecop-supercop         RECORDED  bound to courts/phase18/timing/run_timecop_supercop.sh
      perf-pmu                 PASS      3 cases match the register
      tsc-smi-fallbacks        RECORDED  bound to courts/phase18/timing/run_pmu_substitutes.sh
      binary-branch-audit      PASS      13 cases match the register
      differential-bench-court PASS      1 cases match the register
      alloc-probe              PASS      2 cases match the register
      build-reproducibility    PASS      1 cases match the register
      etp-claims               PASS      1 cases match the register

[5/6] docs             PASS     (required)  hand-written claims agree with their generated sources
      [docs-consistency] EXEMPT: docs/PHASE-7-EVP-SEAL.md: 'phase7_claim_candidate_version' is exempt -- the Phase-7 seal's claim and its measurements are bound to the 0.0.27 candidate (e4f60d8b) at which the FRF store was generated. The seal records that past moment, not the current crate version, so it legitimately contradicts Cargo.toml. Re-created when the 0.0.44/0.0.45 releases advanced the crate version; the same exemption existed before the 0.0.18 FRF regeneration made it unnecessary.
      [docs-consistency] ok: 20 hand-written claim(s) agree with their generated sources

RESULT: PASS (5/5 required steps PASS)
```

Exit status `0`. The verifier source is byte-identical to the one in the provisional
package (its digest is unchanged in the manifest diff); the `claims` JSON line and
the two `docs` lines above appear because this receipt records the full stdout,
whereas the provisional receipt printed a condensed excerpt. No step changed.

`RECORDED` is not `PASS`: the two `RECORDED` instrument controls are bound to a
tracked evidence file whose digest is re-checked, and were not re-executed here.

**Reproducibility is `NOT_RUN`.** `./verify.sh --only reproducibility` reports:

```
[6/6] reproducibility  NOT_RUN  (optional)  deferred: the two-build recipe needs a Rust toolchain (rust-toolchain.toml pins 1.98.1), the court container and two release builds; run with --full inside the court, or see docs/EXTERNAL-REPRODUCTION.md
```

It is exposed as `verify.sh --full` and was not re-run for this package. The
ETP-2 byte-identical result remains bound to `e9d492b0d` and is not a result of
this candidate.

---

## 4. Mutation controls

Each mutation was applied to a fresh extraction of the new archive; the unmodified
archive was then re-extracted (the restoration) and the full verification re-run.
Every restored package passed all five required steps with exit `0`.

| # | mutation | observed failing step | exit | restored |
|---|---|---|---|---|
| 1 | `rm evidence/etp2/RECEIPT.md` | `[1/6] digests FAIL — package integrity failed: 1 missing, 0 mismatched, 0 cited digests unresolved`; `RESULT: FAIL (4/5 required steps PASS)` | 1 | `digests PASS`, 1,633 inputs, `RESULT: PASS (5/5)`, exit 0 |
| 2 | append one byte (`printf ' ' >>`) to `evidence/etp2/RECEIPT.md` | `[1/6] digests FAIL — package integrity failed: 0 missing, 1 mismatched, 0 cited digests unresolved`; detail names `evidence/etp2/RECEIPT.md: d5a0c66c… != f6b198a5…`; `RESULT: FAIL (4/5)` | 1 | `digests PASS`, 1,633 inputs, `RESULT: PASS (5/5)`, exit 0 |
| 3 | move `courts/phase18/interop/check_receipts.py` out of the tree | `[1/6] digests PASS` (1,632 inputs; `missing tools (owning step is NOT_RUN): courts/phase18/interop/check_receipts.py`); `[3/6] interop NOT_RUN — ... is absent`; `RESULT: FAIL (4/5)` | 1 | `interop PASS`, `receipts=14 manifests=2 problems=0`, `RESULT: PASS (5/5)`, exit 0 |

In controls 1 and 2 the other four required steps still reported `PASS`; the
digest step is the one that fails. In control 3 the overall exit is nonzero
because the owning step is `NOT_RUN`, and `NOT_RUN` is never a pass. The behaviour
matches the provisional package; control 3's digest line additionally states the
reduced input count (1,632) and names the missing tool explicitly.

---

## 5. What the package establishes and does not

Established offline, from the unpacked directory:

- the packaged input set is exactly the manifest, by path and SHA-256, with no
  unnamed additions;
- 78 cited evidence digests are re-derived (77 at `S` from the frozen object
  store, one historical revision from its named commit); 3 entries the claim set
  itself marks `present: false` are reported as declared absent;
- 35 claims validate against their schema with the Git-bound tree check;
- the 14 interop receipts and 2 manifests satisfy R1–R5, including log presence,
  log digest and script counts;
- the 11-instrument register validates, with 9 executable controls passing and
  2 `RECORDED`;
- 20 registered documentation claims agree with their generated sources.

Not established offline: that any claim is true; that any interop, timing,
differential or fuzzing run can be repeated; any memory-safety, compatibility or
constant-time result; binary reproducibility (`--full` not run); the provenance
of `artifacts/phase2/install/` (built at `1e7c221f0`); any property of a
different candidate, toolchain, architecture or venue. The five soft refusals
remain unreconstructed gaps. The archive is reproducible within one git version,
not across the two versions used here.

---

## 6. Status

The builder, the offline verifier, the clean-room replay and the three mutation
controls are complete, and the package now names the published commit
`98c7b5d29` rather than a provisional tree. The row remains `PARTIAL` and reports
`EXTERNAL_REVIEW_PENDING` because the one remaining requirement is a receipt from
a party that is not this project, produced on a machine with no access to this
checkout. No external reviewer, organisation or receipt exists; the local
clean-room replay is a self-reproduction, not independent evidence.

The candidate identity `S` is `98c7b5d29`. This receipt and the regenerated
manifest are committed as a separate evidence commit `E`; adding evidence does not
change `S`, and the manifest continues to name `S` and its artefact digests.

**Files:** `forensics/tools/etp6_package.py`, `forensics/tools/etp6_verify.py`,
`forensics/etp6/verify.sh`, `docs/EXTERNAL-REPRODUCTION.md`,
`evidence/etp6/MANIFEST.json`, `evidence/etp6/RECEIPT.md`, `docs/ETP-TODO.md`
(ETP-6 row). No file under `src/`, `docker/`, or another item's evidence was
modified. The only worktree changes for this record are
`evidence/etp6/MANIFEST.json` (rewritten by `--refreeze`) and this receipt.

---

## 7. Change record: provisional (`b400a4e5e`) → published (`98c7b5d29`)

Every recorded figure that changed between the two packages, with its cause. No
figure was replaced silently.

| figure | provisional package | published package | cause |
|---|---|---|---|
| candidate commit | `b400a4e5e…` (provisional, not on a branch) | `98c7b5d29…` | tooling committed; `--refreeze` binds the published commit |
| provisional flag / parent | `true` / `3951f0f5e` | `false` / `null` | the commit is on `staging` |
| packaged tree | `a19b353e…` | `64f796e9…` | tree of the published commit |
| worktree tracked-dirty at build | 1 (`docs/ETP-TODO.md`) | 0 | the ETP-6 row is committed |
| tracked files at commit | 14,080 | 14,082 | the published commit adds `evidence/etp6/MANIFEST.json` and `evidence/etp6/RECEIPT.md`, which `SELECTION` does not stage into the provisional tree |
| archive name | `openssl-rs-etp6-b400a4e5e.tar.gz` | `openssl-rs-etp6-98c7b5d29.tar.gz` | commit hash in the name |
| archive size | 72,182,431 B | 72,070,994 B | different source tree and pack encoding |
| archive SHA-256 | `23821493…` | `2a2e20e1…` | same |
| manifest inputs | 1,635 | 1,633 | two git-version-dependent `object-store` scaffolding files |
| role counts | source 897, tool 328, artefact 155, evidence 148, doc 83, object-store 24 | … object-store 22 | same two files |
| object-store objects | 91 | 91 | unchanged object set |
| object-store pack bytes | 9,210,369 | 9,035,329 | pack encoding differs by git version |
| object-store pack SHA-256 | `e18a64a6…` | `3268fee4…` | same |
| `court/tmp/` audit files / occurrences | 547 / 7,409 | 549 / 7,425 | two ETP-6 evidence files are now tracked |
| `generated_utc` | `2026-11-22T07:40:17-05:00` | `2026-11-22T07:52:00-05:00` | committer date of the recorded HEAD (`3951f0f5e` → `98c7b5d29`) |
| replay input count | 1,635 | 1,633 | manifest input count |
| soft / hard refusals | 5 / 0 | 5 / 0 | unchanged |
| replay result | PASS 5/5, exit 0 | PASS 5/5, exit 0 | unchanged |
| mutation controls | 3/3 detect, restores pass | 3/3 detect, restores pass | unchanged |

The two missing object-store inputs are
`freeze-git/hooks/sendemail-validate.sample` and
`freeze-git/objects/pack/pack-etp6.rev`; the hook samples
(`commit-msg.sample`, `pre-commit.sample`, `fsmonitor-watchman.sample`) and
`freeze-git/HEAD` also differ in content between the two git versions. None of
these is cited evidence: they are produced by `git init --bare` and
`git index-pack`, and none is part of the frozen claim set. The 91 object IDs in
the two packs are identical. The archive digest therefore depends on the packaging
git version as well as on the source commit; a same-venue rebuild is byte-identical.
