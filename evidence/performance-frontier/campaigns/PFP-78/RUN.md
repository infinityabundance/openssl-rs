# PFP-78 — re-measure the downstream corpus at one identity (status: NOT_RUN / PARTIAL)

```yaml
task:            PFP-78
subject:         downstream consumer corpus (runtime-functional-atlas)
verdict:         NOT_RUN — no family was re-measured; the run was refused fail-closed
source_identity: HEAD cb4214b6e08d715fb9833447addb7a4988b0985c (branch staging, Cargo.toml 0.0.52)
date:            2026-11-28
```

## 1. What was measured

Nothing. No family was built, linked, loaded or exercised in this pass. This is a
**reconnaissance + feasibility** record, not a corpus result. The run was not
started because starting it would have measured the wrong identity and would have
overwritten the committed atlas. Both blockers are explained below.

## 2. Reconnaissance — the harness

- **Runner:** `forensics/tools/downstream_runtime.py` (Phase-24.7). The execution
  command is
  `python3 forensics/tools/downstream_runtime.py --measure [--only <fam1,fam2,...>] [--authority <id>]`.
- **Family filter:** yes — `--only` takes a comma-separated list; families not in
  the list are "reused". A full no-reuse run (the only kind that re-measures) is
  `--measure` with **no** `--only` and **no** `--reuse-committed`.
- **Recipe count:** `forensics/downstream/build-link-atlas.json` records
  `with_recipe: 307`, `no_recipe: 693`, `p1000: 1000`; per subject `built: 253`,
  `linked: 245`, `configured: 274`, `failed: 62`, `not_attempted: 693`.
- **Where results go:** `write_outputs()` writes only to the committed
  `forensics/downstream/runtime-functional-atlas.json`. There is **no `--out` /
  scratch-output flag**. Build scratch is under `court/phase24-runtime` and
  `court/phase24-build-link` and is deleted after the run; only the small
  committed JSON persists.
- **Venue / network:** the runner calls `phase24_guard.require_admitted()` first,
  so it runs only inside the admitted court container (`container.json`:
  marker `/.dockerenv`, `PHASE24_CONTAINER=1`, image `openssl-rs-court:1`,
  platform `linux`). It fetches pristine downstream sources from the network.
- **No resume support in the harness.** There is no checkpoint/append path; a
  crash mid-run loses everything since the last `write_outputs()`.

## 3. Feasibility — memory figures

```
free -g
              total  used  free  shared  buff/cache  available
Mem:             45    20    19       0           6         25
Swap:            45    17    28
```

Hard gate: `available >= 24 GiB AND Swap free >= 16 GiB` → **MET**
(available 25, Swap free 28).

```
docker ps
openssl-rs-court              openssl-rs-court:1         Up 3 hours   6 GiB limit   (idle, 1 pid)
openssl-rs-court-pfp58-tools  openssl-rs-court-tools:1   Up 10 hours  4 GiB limit   (idle, 1 pid)
openssl-rs-court-pfp12-tools  openssl-rs-court-tools:1   Up 15 hours  4 GiB limit   (idle, 1 pid)
```

`docker stats` shows all three at 0.00% CPU and ~3.4 MiB / ~0.5 MiB memory, so no
competing heavy command was running. `/proc/pressure/io` avg10 = 0.16.

Cap derivation (operative §24.4): `cap = min(4g, available - 8g) = min(4g, 17g)
= 4g`; the §6.1 upper bound is `min(8g, available - 16g) = 8g`.

## 4. Why the run was not started (fail-closed)

1. **The candidate install is not at HEAD `cb4214b6`.** The harness measures
   against `CANDIDATE_PREFIX = artifacts/phase2/install`:
   - the committed atlas records `candidate_identity` libcrypto
     `1c03ec0a89…` / libssl `d2165444b1…`, and its carried-forward rows point at
     superseded `26ba36ff…`;
   - the **on-disk** install is libcrypto `fd25cc9e64…` / libssl `648f8cae…`
     (mtime 2026-11-28 10:17), which matches neither the atlas's recorded
     candidate nor the carried-forward identity;
   - HEAD `cb4214b6` was committed at 2026-11-28 11:08 — **after** the install
     was built — so the install is an earlier build, not `cb4214b6`.
   A faithful re-measurement therefore requires first **rebuilding the candidate
   library at `cb4214b6`** and reinstalling it, then running the corpus. That
   rebuild is a heavy Rust build and was not attempted at a 4 GiB cap in this
   session.
2. **No scratch-output path.** Running `--measure` writes the committed atlas in
   place, and the court bind-mounts the checkout read-write at `/work`. A run
   would overwrite `forensics/downstream/runtime-functional-atlas.json`, which
   the task forbids. A separate-repo-copy staging (with its own candidate build)
   was not performed.
3. **Cost.** A full re-measurement is a candidate rebuild plus 307 downstream
   fetch+configure+build+run cycles with network access — many hours, not
   bounded by this session.

Measuring any subset at the current install (`fd25cc9e64…`) would itself be a
measurement at a third, unlabeled identity, which is exactly the drift defect
PFP-78 exists to eliminate. It was therefore not done.

## 5. Counts

| metric | value |
|---|---|
| families attempted | 0 |
| reached L4-linked | 0 |
| reached L7-functional | 0 |
| failed | 0 |
| not attempted (recipe-backed) | 307 |
| no recipe (never in scope) | 693 |

Failure list: none (no run).

## 6. What must happen next (blockers)

1. Build the candidate library at `cb4214b6e08d…` and install it to
   `artifacts/phase2/install` (recording the new libcrypto/libssl digests).
2. Stage the run so it cannot overwrite the committed atlas (separate repo copy
   or a scratch-output patch to `downstream_runtime.py`).
3. Run `--measure` (full, no `--reuse-committed`), or run `--only` batches with
   an append-sidecar so a crash loses at most one batch.
4. Recompute the L7 count with the carried-forward set separated, as the PFP-78
   acceptance requires.
