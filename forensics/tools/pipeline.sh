#!/bin/sh
# The ordered evidence pipeline, for local use inside the court.
#
# **This file is tracked, and that is the point.** The order is evidence machinery: several
# steps record the sha256 of a file another step writes, so running them in the wrong order
# records the *previous* generation's hash and `evidence_determinism.py` then fails on the
# first run and passes on the second. D96 and its neighbour found two instances of that class
# by hand. The pipeline lived in an untracked scratch path (`court/pipeline.sh`, which
# `.gitignore` excludes with the rest of `court/`) until D214, which meant no reviewer, no CI
# job and no later session could rely on the order or even see it. D214 moved it here; the
# scratch path is now a one-line forwarder so both work and there is one source of truth.
#
# The two CI jobs run the same steps between them, in this order. `.github/workflows/ci.yml`
# is the other place the order is expressed, and a change here should be reflected there.
set -eu
cd /work

echo "== fmt =="
cargo fmt --all

echo "== build =="
cargo build --release

echo "== unit tests =="
cargo test --lib -- --test-threads=1

echo "== clippy =="
cargo clippy --all-targets -- -D warnings

echo "== implemented surface =="
python3 forensics/tools/implemented_surface.py

echo "== phase 2 shell + its courts =="
bash forensics/tools/build_phase2.sh

echo "== every active stratum's courts =="
python3 forensics/tools/run_courts.py

echo "== prerequisite atlases =="
# **Before the ledgers, not after them.** The ledgers record `internal-symbols.json`'s sha256
# among their inputs, and this generator is what writes that file. Run after, and the first
# pipeline run after any source change leaves the recorded hash one generation stale --
# `evidence_determinism.py` fails, the second run passes, and the difference is invisible
# because a compared artefact's own recorded hash is normalised away. D212 found it by watching
# the hash move across two runs of the AES and RC4 commits; D214 is the reorder.
python3 forensics/tools/gen_prerequisite_atlas.py

echo "== ledgers =="
# Discovery-driven, the way `evidence_determinism.py` already is: a stratum is a file
# matching the glob, not an entry in a list somebody has to remember to extend.
for f in forensics/tools/phase*_obligations.py; do python3 "$f"; done

echo "== court coverage atlas =="
# After the ledgers and the courts, and before `phase_state.py`, which requires the
# coverage for a `complete` stratum. See docs/DECISIONS.md D199.
python3 forensics/tools/court_coverage.py

echo "== ownership audit =="
python3 forensics/tools/ownership_audit.py

echo "== prototype court =="
python3 forensics/tools/prototype_court.py

echo "== dispatch court =="
# The provider dispatch plane (D180): the `OSSL_FUNC_*` identities and callback
# signatures, which are numbers and types rather than symbols and so are invisible to
# the prototype court, the ABI courts and every runtime court alike. It sits beside the
# prototype court because it consumes the same canonicaliser, and it must run before
# `evidence_determinism.py`.
python3 forensics/tools/dispatch_court.py

echo "== probe hygiene =="
python3 forensics/tools/probe_hygiene.py

echo "== phase state =="
python3 forensics/tools/phase_state.py

echo "== prerequisite gate =="
# After `phase_state.py`, not before it: the gate both reads the phase states and records
# `phase-state.json`'s sha256 as an input, so running it first records the *previous*
# generation's hash. Same class as the reorder D214 made above.
python3 forensics/tools/prerequisite_gate.py

echo "== plan reconciliation =="
# The other half of the same question, and after `phase_state.py` for the same reason: which
# strata are claiming is what decides which plans are judged. See docs/DECISIONS.md D134.
python3 forensics/tools/plan_reconciliation.py

echo "== seal census =="
python3 forensics/tools/render_seal_census.py

echo "== status =="
python3 forensics/tools/render_status.py

echo "== docs consistency =="
# The hand-written documents against the generated evidence. It runs **after** the generators
# that move what it compares, and after `regression_guard.py --update` would have moved the
# baseline -- which is why `docs/CI.md` defers to that file rather than typing its figures
# (D205): a gate whose verdict depends on where in the pipeline it sits is not a gate.
# See docs/DECISIONS.md D203 and D208.
python3 forensics/tools/docs_consistency.py

echo "== evidence determinism =="
python3 forensics/tools/evidence_determinism.py

echo "== evidence portability =="
python3 forensics/tools/check_evidence_portability.py

echo "== frf court declarations =="
python3 forensics/tools/gen_frf_courts.py --check

echo "== regression guard (update the proposed baseline) =="
python3 forensics/tools/regression_guard.py --update

echo "== regression guard (against the branch baseline) =="
python3 forensics/tools/regression_guard.py --baseline-ref origin/main --require-current

echo "PIPELINE OK"
