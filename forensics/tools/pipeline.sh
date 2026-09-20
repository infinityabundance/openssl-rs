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

echo "== phase 8 constant tables =="
# **Before `cargo fmt`, not after it.** The two Phase 8 table generators read the authority's
# `crypto/` tree and write `src/digest/tables.rs` and `src/cipher_tables.rs` (and their atlas
# JSON). Their renderers lay the numbers out in a way `cargo fmt` rewrites, so the steps have to
# run *before* the formatting pass that normalises the working tree; running them after would
# leave two unformatted files behind on every run. They are deliberately **not** entries in
# `evidence_determinism.py`'s `GENERATORS`/`COMPARED`: that tool compares committed text with a
# fresh generation *before* any formatter runs, so a non-rustfmt-stable renderer can never match
# there. Its `cipher-tables.json`/`digest-tables.json` remain the content record. See D215.
python3 forensics/tools/gen_phase8_tables.py
python3 forensics/tools/gen_phase8_cipher_tables.py

# Phase 8.5's named-group constants (D332). Here for the same reason as the two above --
# it reads the authority's `crypto/bn/bn_dh.c` and its admitted prefix and writes a
# `cargo`-visible file, `src/bn/dh_data.rs` -- but with one difference that matters: its
# renderer **is** `rustfmt`-stable, so unlike those two it is also a `COMPARED` entry in
# `evidence_determinism.py` and a formatter pass cannot move it. It is invoked here so the
# build and the courts see the regenerated file rather than the committed one, and
# `evidence_determinism.py` re-runs it later and compares.
python3 forensics/tools/gen_bn_dh.py

# Phase 8.7's built-in curve parameters (D334). Here for the same reason as the two above -- it
# reads the authority's `crypto/ec/ec_curve.c`, links a probe against the admitted prefix and
# writes a `cargo`-visible file, `src/ec/curve_data.rs` -- and with the same property
# `gen_bn_dh.py` has: its renderer **is** `rustfmt`-stable, so it is also a `COMPARED` entry in
# `evidence_determinism.py` and the formatter pass below cannot move it. It is invoked here so
# the build and the courts see the regenerated file rather than the committed one, and
# `evidence_determinism.py` re-runs it later and compares.
python3 forensics/tools/gen_ec_curves.py

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

echo "== provider algorithm census =="
# The provider-algorithm ownership atlas (D237). It derives every algorithm *registration
# row* of the default, legacy, base and null providers from the pinned tables, with the
# profile's own `configuration.h` guards applied, and checks the crate's published rows
# against it. It sits here, beside the other authority-derived atlas and **before** the
# ledgers, for three reasons that are each about the order being evidence: it reads only the
# authority's provider tables and the crate's two provider modules, so its inputs are final
# once `cargo fmt`/`cargo build` have run and the courts have not changed a source; the
# obligation ledgers are written after it and must not record a hash of an atlas that is
# about to change under them; and `evidence_determinism.py` re-runs it later and compares, so
# a stale copy is a failure rather than a silent divergence. It is here rather than with the
# Phase 8 table generators above because those run *before* `cargo fmt` (their renderers are
# not rustfmt-stable) while this one must read the crate's final text.
python3 forensics/tools/gen_provider_algorithms.py

# Then provoke the census's own failure modes (D242). The provider context's discharge
# certificate now anchors each landed `PROV_LIBCTX_OF` acquisition **inside the crate function
# that owes it**, which is the only way the second site -- `aes_siv_newctx`, holding a NULL
# context while `ossl_cipher_generic_initkey` held the real one -- could have been caught. A
# check that fails closed is worth exactly as much as the evidence that it can fail, so each of
# the six ways to defeat it is reconstructed here and required to fire, the way
# `blocker_liveness.py --self-test` reconstructs the stale `EVP_PKEY_new_mac_key` deferral. It
# mutates copies-of-text in memory, so it leaves the tree untouched.
python3 forensics/tools/gen_provider_algorithms.py --self-test

echo "== ledgers =="
# Discovery-driven, the way `evidence_determinism.py` already is: a stratum is a file
# matching the glob, not an entry in a list somebody has to remember to extend.
for f in forensics/tools/phase*_obligations.py; do python3 "$f"; done

# The Phase 8 remainder projection (`docs/PHASE-8-REMAINING.md`), immediately after the
# loop above because it is a projection of the ledger that loop writes: run before it,
# it would render the previous generation's ledger. `evidence_determinism.py` re-runs it
# later and compares, so a stale committed copy is a failure rather than a silent
# divergence.
python3 forensics/tools/phase8_remaining.py

echo "== court coverage atlas =="
# After the ledgers and the courts, and before `phase_state.py`, which requires the
# coverage for a `complete` stratum. See docs/DECISIONS.md D199.
python3 forensics/tools/court_coverage.py

# The provider-row coverage join (D245), the same invariant one level down: every provider
# registration row the census calls `implemented` must be named by a probe of a court that
# covers its stratum. It reads the census and the probe sources, so it belongs beside the
# export atlas and before `phase_state.py`, which requires it for a `complete` stratum.
python3 forensics/tools/provider_court_coverage.py

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
