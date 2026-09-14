#!/usr/bin/env bash
# openssl-rs — build the complete Phase 1 atlas from the admitted authorities.
#
# Runs ENTIRELY inside the court container (docs/REPRODUCIBILITY.md §1): never on
# the host. Usage:
#
#     bash docker/openssl-rs-court.sh exec bash forensics/tools/build_atlas.sh
#
# The pipeline is ordered by dependency: authorities must be admitted and built
# before any surface can be mined from them.
set -euo pipefail

cd /work

echo "=== [1/7] admit authorities (verify checksums + content-address sources) ==="
python3 forensics/tools/authority_acquire.py --all

echo
echo "=== [2/7] build authorities from their verified sources ==="
python3 forensics/tools/authority_build.py --all --jobs "$(nproc)"

echo
echo "=== [3/7] symbol and symbol-version atlas ==="
python3 forensics/tools/atlas_symbols.py --all

echo
echo "=== [4/7] API surface atlas (Clang AST) ==="
python3 forensics/tools/atlas_api.py --all

echo
echo "=== [5/7] runtime surface atlas (providers, CLI, configs, corpora) ==="
python3 forensics/tools/atlas_runtime.py --all

echo
echo "=== [6/7] reconciliation, coverage and parity obligations ==="
python3 forensics/tools/atlas_parity.py --all

echo
echo "=== [7/8] atlas index and evidence receipt ==="
python3 forensics/tools/atlas_receipt.py

echo
echo "=== [8/8] status projection (rendered after the receipt so it is current) ==="
python3 forensics/tools/render_status.py

echo
echo "atlas build complete."
