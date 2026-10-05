#!/usr/bin/env bash
# openssl-rs — regenerate every derived atlas/evidence the CI freshness gates compare.
#
# The recurring failure this closes
# --------------------------------
# A substantive commit changes `src/` (or an authority input), the derived prerequisite
# atlases are not re-derived, and the `courts` job's "Re-derive the prerequisite atlases"
# step fails once with
#
#   the prerequisite atlases are stale; regenerate and commit them
#
# on the four files `forensics/atlas/{internal-symbols,macro-owners,typedef-owners,
# transcription-edges}.json`. This is the single step to run before committing; run it and
# the freshness check is satisfied.
#
# It runs **inside the court container** and in dependency order:
#
#   1. `symbol_ownership.py` — the ownership atlas `gen_prerequisite_atlas.py` reads to
#      assign each crate module a stratum. Running it first keeps the next step from reading
#      a stale map, which would make `transcription-edges.json` wrong rather than merely old.
#   2. `gen_prerequisite_atlas.py` — the five authority-derived prerequisite atlases. The CI
#      `courts` job re-derives these and requires `git diff --exit-code`; they are exactly the
#      files the freshness check compares.
#   3. `evidence_determinism.py --keep` — every other derived artefact, in dependency order:
#      the implemented surface, the provider census, the per-stratum obligation ledgers,
#      `divergence-obligations.json`, `phase-state.{json,md}`, the court-coverage and
#      ownership/prototype/dispatch atlases, `docs/SEAL-CENSUS.md` and `forensics/STATUS.md`.
#      It writes the fresh bytes and compares them with the committed ones; a first run that
#      corrects stale artefacts is re-run once so the script's exit status reflects the
#      corrected tree.
#
# Preconditions (the CI `courts` job establishes both before its re-derivation step):
#   * the authority is admitted and built:
#       python3 forensics/tools/authority_acquire.py --all
#       python3 forensics/tools/authority_build.py --all
#   * the crate is built (`bash forensics/tools/build_phase2.sh`, or `run_courts.py`), so
#     `implemented_surface.py` can read the release archive.
#
# Usage, from the repository root:
#
#   bash docker/openssl-rs-court.sh exec bash forensics/tools/regen_all.sh
#
# Then review `git status` on the derived files and commit them with the source change that
# moved them. `docs/CI.md` and `docs/REPRODUCIBILITY.md` name this as the pre-commit step.

set -eu

# Refuse the host before doing anything else; see docs/REPRODUCIBILITY.md §1.
here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=require_court.sh
. "$here/require_court.sh"

cd /work

echo "== symbol ownership (the map gen_prerequisite_atlas reads) =="
python3 forensics/tools/symbol_ownership.py

echo "== prerequisite atlases (authority-derived; the CI freshness set) =="
python3 forensics/tools/gen_prerequisite_atlas.py

echo "== every other derived artefact, in dependency order =="
if ! python3 forensics/tools/evidence_determinism.py --keep; then
  echo "== derived artefacts were stale; re-running the determinism check now they are written =="
  python3 forensics/tools/evidence_determinism.py --keep
fi

echo "REGEN OK: the derived atlases and evidence are current; commit them with the change"
