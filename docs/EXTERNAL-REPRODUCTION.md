# External reproduction procedure — ETP-6

**Status:** `EXTERNAL_REVIEW_PENDING`. No party outside this project has produced
a receipt for this package. Nothing in this document records, implies or
fabricates an external review.

**Builder:** `forensics/tools/etp6_package.py`.
**Verifier:** `verify.sh` at the package root; driver
`forensics/tools/etp6_verify.py`.
**Manifest:** `evidence/etp6/MANIFEST.json`.
**Record of the local clean-room replay and the mutation controls:**
`evidence/etp6/RECEIPT.md`.

---

## 1. What the external party receives

One archive, `openssl-rs-etp6-<commit>.tar.gz`, and its SHA-256.  The archive
contains, at the unpacked root:

| content | why it is there |
|---|---|
| `src/`, `Cargo.toml`, `Cargo.lock`, `build.rs`, `rust-toolchain.toml` | the source tree at the named commit, produced by `git archive`; never a copy of a working tree |
| `README.md`, `AGENTS.md`, `docs/` | the constitution, the ETP queue, the instrument and performance methodology, and this procedure |
| `evidence/etp0`, `evidence/etp`, `evidence/etp2` … `evidence/etp5` | the claim set, the trust-gap inventory, and the ETP-2/3/4/5 records the verification reads |
| `courts/phase18/interop/` | the interop receipts, manifests and tracked logs checked by `check_receipts.py` |
| `courts/phase18/timing/`, `courts/performance-frontier/baseline/`, `artifacts/phase2/install/` | the fixtures and headers the instrument sensitivity controls compile and link |
| `forensics/tools/` | the verification tools themselves: `etp_claims.py`, `instrument_qualify.py`, `docs_consistency.py`, `build_reproducibility.sh`, `phase2_shell.py`, the interop tooling, and their test suites |
| `freeze-git/` and `.git` | a partial bare Git object store holding the frozen claim-set commit, the cited tree chains and the cited blobs; `.git` is a gitfile pointing at it |
| `TOOLCHAIN.json` | the pinned toolchain identity (`rustc`/`cargo` 1.98.1, `cc`, `ar`, `ld`) and the source of that record |
| `MANIFEST.json` | every input with path and SHA-256, and every verification step with its command, expected exit status, what it establishes and what it does not |
| `verify.sh` | the offline entry point |

The archive does **not** contain `.git` history, `court/tmp/`, any
`artifacts/phase2/libcrypto.so.3` or `artifacts/phase2/shell/` file, or any
untracked working-tree file.  Where an input is untracked or gitignored, the
builder records a refusal in `MANIFEST.json` and omits it; it does not copy the
file in to make the package look complete.

The production archive is not tracked in Git.  It is rebuilt by the recipe in
§5 and identified by the SHA-256 printed at build time, which is also recorded
in `evidence/etp6/RECEIPT.md` for the delivered candidate.

---

## 2. Environment the package assumes

| requirement | needed by | absence |
|---|---|---|
| Python 3.11 (3.11 is the tested version; the standard library only) | every step | no step runs; `verify.sh` exits 2 |
| `git` | digest and claim steps | those steps are `NOT_RUN`; the overall exit is nonzero |
| POSIX `tar` (only to unpack) | the recipient | cannot unpack |
| `cc`, `ar`, `objdump`, `valgrind`, `binsec`, `perf` | individual instrument controls | the affected control is `NOT_RUN`, never `PASS` |
| `rustc`/`cargo` 1.98.1 and the court container | `--full` reproducibility | the step is `NOT_RUN` with that reason |

No step uses the network.  `verify.sh` clears proxy variables and sets
`NO_PROXY=*`, but that is defence against an accidental attempt, not a sandbox.
The verifier is intended to be run with the network disabled.

The package was built and replayed inside `openssl-rs-court-tools:1` on Linux
x86_64.  A different venue changes what the instrument controls can establish;
the register itself records `pmu_present: false` and the toolkit is qualified for
this venue only.

---

## 3. Exact commands

```sh
# 1. Unpack into an empty directory and enter it.
mkdir -p /tmp/etp6-replay && tar -xzf openssl-rs-etp6-<commit>.tar.gz -C /tmp/etp6-replay
cd /tmp/etp6-replay

# 2. Locate the archive digest supplied with the package and compare it.
sha256sum openssl-rs-etp6-<commit>.tar.gz

# 3. Run the offline verifier.  A fresh HOME and TMPDIR are recommended.
env -i PATH=/usr/bin:/bin HOME=/tmp/etp6-replay-home TMPDIR=/tmp/etp6-replay-tmp ./verify.sh

# 4. Optional: the two-build reproducibility step (court container required).
./verify.sh --full

# 5. One step at a time, or the list of steps.
./verify.sh --only digests
./verify.sh --list
```

`verify.sh` accepts `ETP6_PYTHON` to name a Python interpreter.

### Expected output

A passing run prints one line per step and a result line:

```
ETP-6 offline verification
package  /tmp/etp6-replay
identity candidate <commit> (frozen source 9372bb28b); rustc rustc 1.98.1 (48a229cea 2026-09-01)
steps    digests, claims, interop, instruments, docs

[1/6] digests          PASS     (required)  1635 packaged inputs re-derived, 78 cited evidence digests re-derived from the frozen object store
...
[4/6] instruments      PASS     (required)  register validated: 11 instruments; 9 executable controls PASS, 2 RECORDED, 0 NOT_RUN
[5/6] docs             PASS     (required)  hand-written claims agree with their generated sources

RESULT: PASS (5/5 required steps PASS)
```

The input count and the control counts are properties of the package; the
digest, candidate and toolchain lines identify the exact package.  A recipient
must compare the `candidate`, `frozen source` and toolchain line with the
archive digest and with `MANIFEST.json`; a matching word `PASS` without those
identities is not a reproduction.

Exit status: `0` only when every required selected step is `PASS`.  A `NOT_RUN`
is never a pass.  `verify.sh` exits `2` when the manifest is absent or does not
parse.

### What a failure looks like

| mutation | observed behaviour |
|---|---|
| delete one packaged evidence file | `digests` `FAIL`: `package integrity failed: 1 missing, 0 mismatched, …`; exit 1 |
| change one byte of a receipt | `digests` `FAIL`: `package integrity failed: 0 missing, 1 mismatched, …`, naming the file and both hashes; exit 1 |
| remove one verification tool | `digests` still passes (a missing tool is not a digest match), the owning step is `NOT_RUN` with the tool named, and the overall exit is 1 |

The local receipt records these three controls on the delivered candidate, each
followed by a restored run that passes.

---

## 4. What the package can and cannot establish offline

**Establishes, from the unpacked directory alone:**

1. Every packaged input is the file recorded in `MANIFEST.json`; the input set is
   complete relative to the manifest and has no unnamed additions.
2. Every evidence digest the claim set binds to an identity is re-derived: the
   `S` entries from the frozen Git object store, the historical revision from
   its named commit, and any `E` entry from the package file.  Three evidence
   entries carry `sha256: null` and `present: false` in the claim set
   (`forensics/phase7_courts.py`, `court/tmp/t20/NOTES.md`,
   `court/tmp/t21/libcrypto.so.3`); the verifier reports them as declared
   absent, not as digest matches.
3. The typed claim set validates against its schema with the Git-bound tree
   check at the frozen source commit.
4. The interop receipts and manifests satisfy the checker's rules R1–R5,
   including that each manifest log exists at the named path with the recorded
   digest and the claimed script count.
5. The instrument register validates, and every executable control whose tool is
   installed passes and matches the register.  `RECORDED` controls are reported
   as `RECORDED`, never `PASS`; a control with a missing tool is `NOT_RUN`.
6. The registered documentation claims agree with their generated sources.

**Does not establish offline:**

- that a claim is true.  The claim algebra checks typing and law, never truth.
- that any interop, timing, differential or fuzzing execution can be repeated.
  Those runs are re-verified through their stored receipts, logs and digests;
  they are not re-executed by `verify.sh`.
- any memory-safety, compatibility or constant-time result.  A passing
  instrument control says the instrument's own control fired here; it is not a
  result about the crate.
- reproducibility.  `build_reproducibility.sh` needs a Rust toolchain, the court
  container and two release builds.  It is `NOT_RUN` unless `--full` is given in
  a venue that can run it.
- the provenance of `artifacts/phase2/install/`.  Those tracked libraries were
  built at `1e7c221f0`, 32 source-touching commits before the ETP-0 freeze, and
  are linked only by the instrument sensitivity controls, not by the candidate.
- any property of a different candidate, toolchain, architecture or venue.
  `MANIFEST.json` binds this source tree, these tool identities and this venue.

The unresolved reconstruction gaps remain gaps.  The package names them in
`MANIFEST.json` under `refusals` and never substitutes a copy for them.  In
particular, the 1,929 `court/tmp/` references ETP-0 counted (7,399 textual
occurrences in 546 tracked files at this HEAD, with zero tracked files under
`court/tmp/`) do not become reconstructable because a subset of evidence is
packaged; the audit counts are in `court_tmp_reference_audit`.

---

## 5. Rebuilding the package

From a clean checkout of the reported candidate, in the court:

```sh
OPENSSL_RS_COURT_IMAGE=openssl-rs-court-tools:1 \
OPENSSL_RS_COURT_MEM=6g OPENSSL_RS_COURT_MEMSWAP=6g \
  bash docker/openssl-rs-court.sh exec bash -c \
  'python3 forensics/tools/etp6_package.py --out /work/court/tmp/etp6'
```

The builder refuses, with a named reason and exit 2, when a required input is
untracked, absent from the commit, gitignored, or differs from the frozen
manifest.  `--refreeze` rewrites `evidence/etp6/MANIFEST.json`; it is a review
step, not a repair, and must be followed by a fresh clean-room replay and a new
external-identity record.

`--provisional` exists only for the interval before the ETP-6 tooling is
committed: it creates a real commit object from a temporary index of `HEAD` plus
the worktree selection paths and packages from that commit, so the source tree
still comes from `git archive`.  The published package must be rebuilt without
`--provisional` after the orchestrator commit; `MANIFEST.json` then names the
published commit.

---

## 6. Status and the missing step

The ETP-6 queue row remains `PARTIAL` and reports `EXTERNAL_REVIEW_PENDING`.
The package, the offline verifier, the clean-room replay and the three mutation
controls are complete and recorded.  What is missing is the only thing this
project cannot supply: a receipt from a party that is not this project, running
the procedure above on a machine with no access to this checkout.

Until such a receipt exists:

- no external review may be claimed, cited or implied;
- the local clean-room replay is a self-reproduction, not an independent one;
- `EXTERNAL_REVIEW_PENDING` is the status, never `DONE`.
