# ETP-6 — frozen reproduction package, clean-room replay and mutation controls

**Status:** `PARTIAL` / `EXTERNAL_REVIEW_PENDING`.
**Source HEAD at session start:** `3951f0f5eef630d36fc5f8ffc3a49087ec6e3920`
(branch `staging`; `git status --porcelain` empty; worktree clean).
**Package candidate:** the ETP-6 tooling was not yet committed when the package
was built, so the builder created a real commit object from a temporary index of
`HEAD` plus the authored selection paths:

| field | value |
|---|---|
| provisional commit (`git commit-tree`, not on a branch) | `b400a4e5e3a66d25d8c9e0c1012e1e7af8660741` |
| parent | `3951f0f5e` |
| packaged tree | `a19b353e3aac96e9797e524466cb15f7356fffb2` |
| worktree tracked-dirty files at build | 1 (`docs/ETP-TODO.md`, the ETP-6 row) |

The source tree is still produced by `git archive` from that commit, not by
copying the working tree.  After the orchestrator commits these files, the
packaged selection subtree is identical; `--refreeze` then binds the published
commit hash.  Until that rebind, this replay is bound to the **tree**, and the
provisional hash is not a published candidate.

**Frozen source identity of the claim set:** `9372bb28b` (from
`evidence/etp/claims.json`).

---

## 1. Frozen artifact

| field | value |
|---|---|
| archive | `openssl-rs-etp6-b400a4e5e.tar.gz` (72,182,431 bytes) |
| SHA-256 | `238214933f0b3d39cae95f3b95e2e35785539a013e01460a431f47edbc2bf269` |
| members | 1,636 (1,635 manifest inputs + `MANIFEST.json`) |
| manifest | `evidence/etp6/MANIFEST.json`, validated with `python3 -m json.tool` |
| inputs | 1,635, each with `path`, `role`, `bytes`, `sha256` |
| roles | source 897, tool 328, artefact 155, evidence 148, doc 83, object-store 24 |
| Git object store | `freeze-git/`: 91 objects, pack 9,210,369 B, SHA-256 `e18a64a6f7ba398bd93c5388023a8c0af2eeb7197cfda969d5d7701f57e4956f` |
| top-level files | `verify.sh`, `MANIFEST.json`, `TOOLCHAIN.json`, `.git` (gitfile → `freeze-git`) |

The archive is produced in `court/tmp/etp6/` and is not tracked.  It is
reproducible from the recipe with the same commit; the manifest is the frozen
identity of its inputs.

`TOOLCHAIN.json` records `rustc 1.98.1 (48a229cea 2026-09-01)`, cargo 1.98.1,
LLVM 22.1.8, `cc` (Debian 12.2.0), `ar`/`ld` 2.40, target
`x86_64-unknown-linux-gnu`, and names `evidence/etp2/reproducibility.json` as the
source of those strings (measured at `e9d492b0d`, not at this candidate).

---

## 2. Builder refusals at this commit

Invocation:

```
python3 forensics/tools/etp6_package.py --provisional --refreeze --out court/tmp/etp6
```

Result: `build OK`; **0 hard refusals**, **5 soft refusals**.  A soft refusal is
an input the evidence cites but that cannot be reconstructed from the commit; it
is named and omitted, never copied in.

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
| tracked files containing `court/tmp/` | 546 |
| textual occurrences | 7,399 |
| tracked files under `court/tmp/` | 0 |
| ETP-0's count at `9372bb28b` | 1,929 references |

No `court/tmp/` path and no untracked file is placed in the package.  The
`--distribution` arm of the reproducibility recipe no longer needs the ignored
shell source: ETP-2 made `phase2_shell.py --emit-shell` regenerate it from
tracked inputs.  The distribution DSO named by ETP-0 remains absent and is not
substituted.

A hard refusal is produced by the same builder for an untracked, absent or
gitignored *required* selection input, for a digest that differs from the frozen
manifest, and for an input present but unnamed by it; in those cases no archive
is written and the exit status is 2.  Observed control: one byte appended to
`docs/EXTERNAL-REPRODUCTION.md`, then the builder run again without
`--refreeze`:

```
REFUSED: the staged tree does not match the frozen manifest.
  HARD  docs/EXTERNAL-REPRODUCTION.md: digest mismatch: 467123f9… != a2308150…
  no archive written; review the drift, then --refreeze.
```

Exit status 2, and the existing archive's SHA-256 was unchanged
(`23821493…`).  The file was then restored and compared byte-for-byte.  The
same run without the mutation verifies the frozen manifest and reproduces the
archive byte-for-byte: the two builds produced the same SHA-256.

---

## 3. Clean-room replay

Venue and discipline: `openssl-rs-court-tools:1`, cap
`OPENSSL_RS_COURT_MEM=6g`, `OPENSSL_RS_COURT_MEMSWAP=6g`, fresh `HOME` and
`TMPDIR` under `/court`, one command at a time.  `free -g` before the session:
`available 27 GiB` (guard met); computed cap `min(8g, 27-16) = 8g`; the run used
the instructed 6g cap.

```
rm -rf /court/etp6-final && mkdir -p /court/etp6-final/{home,tmp,unpack}
tar -xzf /work/court/tmp/etp6/openssl-rs-etp6-b400a4e5e.tar.gz -C /court/etp6-final/unpack
cd /court/etp6-final/unpack
HOME=/court/etp6-final/home TMPDIR=/court/etp6-final/tmp ./verify.sh
```

The unpacked directory is outside `/work`; no step reads the development
checkout.  Observed output:

```
ETP-6 offline verification
package  /court/etp6-final/unpack
identity candidate b400a4e5e3a66d25d8c9e0c1012e1e7af8660741 (frozen source 9372bb28b); rustc rustc 1.98.1 (48a229cea 2026-09-01)
steps    digests, claims, interop, instruments, docs

[1/6] digests          PASS     (required)  1635 packaged inputs re-derived, 78 cited evidence digests re-derived from the frozen object store
      cited evidence declared absent by the claim set (not a digest re-derivation): 3
        ETP0-CLM-004: forensics/phase7_courts.py (present=false, reconstructable=True)
        ETP0-CLM-012: court/tmp/t20/NOTES.md (present=false, reconstructable=partial)
        ETP0-CLM-014: court/tmp/t21/libcrypto.so.3 (present=false, reconstructable=False)

[2/6] claims           PASS     (required)  35 claims validate with the Git-bound tree check at 9372bb28b
[3/6] interop          PASS     (required)  interop receipts and manifests satisfy R1-R5
[4/6] instruments      PASS     (required)  register validated: 11 instruments; 9 executable controls PASS, 2 RECORDED, 0 NOT_RUN
[5/6] docs             PASS     (required)  hand-written claims agree with their generated sources

RESULT: PASS (5/5 required steps PASS)
```

Exit status `0`.  `interop` internally reported `receipts=14 manifests=2
problems=0`.  The instrument controls, each matched against the register:

```
valgrind-ctgrind          PASS      2 cases
dudect                    PASS      2 cases
binsec-checkct            PASS      19 cases
timecop-supercop          RECORDED  bound to courts/phase18/timing/run_timecop_supercop.sh
perf-pmu                  PASS      3 cases
tsc-smi-fallbacks         RECORDED  bound to courts/phase18/timing/run_pmu_substitutes.sh
binary-branch-audit       PASS      13 cases
differential-bench-court  PASS      1 case
alloc-probe               PASS      2 cases
build-reproducibility     PASS      1 case
etp-claims                PASS      1 case
```

`RECORDED` is not `PASS`: those two controls are bound to a tracked evidence
file whose digest is re-checked, and were not re-executed here.

**Reproducibility is `NOT_RUN`.**  `./verify.sh --only reproducibility` reported:

```
[6/6] reproducibility  NOT_RUN  (optional)  deferred: the two-build recipe needs a Rust toolchain (rust-toolchain.toml pins 1.98.1), the court container and two release builds; run with --full inside the court, or see docs/EXTERNAL-REPRODUCTION.md
```

It is exposed as `verify.sh --full` and was not re-run for this package.  The
ETP-2 byte-identical result remains bound to `e9d492b0d` and is not a result of
this candidate.

---

## 4. Mutation controls

Each mutation was applied to a fresh extraction of the same archive; the
unmodified archive was then re-extracted (the restoration) and the affected step
re-run.

| # | mutation | observed failing step | exit | restored |
|---|---|---|---|---|
| 1 | `rm evidence/etp2/RECEIPT.md` | `[1/6] digests FAIL — package integrity failed: 1 missing, 0 mismatched, 0 cited digests unresolved` | 1 | `digests PASS`, 1,635 inputs, exit 0 |
| 2 | append one byte (`printf ' ' >>`) to `evidence/etp2/RECEIPT.md` | `[1/6] digests FAIL — package integrity failed: 0 missing, 1 mismatched, 0 cited digests unresolved`; detail names `evidence/etp2/RECEIPT.md: d5a0c66c… != f6b198a5…` | 1 | `digests PASS`, 1,635 inputs, exit 0 |
| 3 | move `courts/phase18/interop/check_receipts.py` out of the tree | `[1/6] digests PASS` (a missing tool is not a digest match); `[3/6] interop NOT_RUN — courts/phase18/interop/check_receipts.py is absent`; `RESULT: FAIL (4/5 required steps PASS)` | 1 | `interop PASS`, `receipts=14 manifests=2 problems=0`, exit 0 |

In controls 1 and 2 the other four required steps still reported `PASS`; the
digest step is the one that fails.  In control 3 the overall exit is nonzero
because the owning step is `NOT_RUN`, and `NOT_RUN` is never a pass.

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
different candidate, toolchain, architecture or venue.  The five soft refusals
remain unreconstructed gaps.

---

## 6. Status

The builder, the offline verifier, the clean-room replay and the three mutation
controls are complete.  The row is `PARTIAL` and reports
`EXTERNAL_REVIEW_PENDING` because the one remaining requirement is a receipt
from a party that is not this project, produced on a machine with no access to
this checkout.  No external reviewer, organisation or receipt exists; the local
clean-room replay is a self-reproduction, not independent evidence.

Before the final candidate is published, the orchestrator must commit these
files, re-run `etp6_package.py --refreeze` (binding the published commit), rebuild
the archive, and repeat the clean-room replay so that the recorded identity is a
published commit rather than the provisional tree.

**Files:** `forensics/tools/etp6_package.py`, `forensics/tools/etp6_verify.py`,
`forensics/etp6/verify.sh`, `docs/EXTERNAL-REPRODUCTION.md`,
`evidence/etp6/MANIFEST.json`, `evidence/etp6/RECEIPT.md`, `docs/ETP-TODO.md`
(ETP-6 row).  No file under `src/`, `docker/`, or another item's evidence was
modified.
