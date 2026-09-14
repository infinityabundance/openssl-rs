#!/usr/bin/env bash
# openssl-rs — build the complete Phase 1 atlas from the admitted authorities.
#
# Runs ENTIRELY inside the court container (docs/REPRODUCIBILITY.md §1): never on
# the host. Usage:
#
#     bash docker/openssl-rs-court.sh exec bash forensics/tools/build_atlas.sh
#
# The pipeline is ordered by dependency: authorities must be admitted and built
# before any surface can be mined from them; the ABI probe needs the installed
# headers; reconciliation and rendering need every plane; and the receipt must
# come last so it covers everything, including the rendered projections.
set -euo pipefail

# Nothing runs on the host (docs/REPRODUCIBILITY.md §1). Enforced, not assumed.
. "$(dirname "$0")/require_court.sh"

cd /work

echo "=== [1/10] admit authorities (verify checksums + content-address sources) ==="
python3 forensics/tools/authority_acquire.py --all

echo
echo "=== [2/10] build authorities from their verified sources ==="
python3 forensics/tools/authority_build.py --all --jobs "$(nproc)"

echo
echo "=== [3/10] symbol and symbol-version atlas ==="
python3 forensics/tools/atlas_symbols.py --all

echo
echo "=== [4/10] API surface atlas (Clang AST) ==="
python3 forensics/tools/atlas_api.py --all

echo
echo "=== [5/10] runtime surface atlas (providers, CLI, configs, corpora) ==="
python3 forensics/tools/atlas_runtime.py --all

echo
echo "=== [6/10] ABI layout probes + ownership obligations ==="
python3 forensics/tools/atlas_abi.py --all

echo
echo "=== [7/12] reconciliation, coverage and parity obligations ==="
python3 forensics/tools/atlas_parity.py --all

echo
echo "=== [8/12] oracle-vs-oracle differential atlas ==="
python3 forensics/tools/atlas_differential.py

echo
echo "=== [9/12] Phase 1 completeness inventory ==="
python3 forensics/tools/atlas_phase1_completeness.py

echo
echo "=== [10/12] Markdown projections ==="
python3 forensics/tools/render_atlas.py --all

echo
echo "=== [11/12] atlas index and evidence receipt ==="
python3 forensics/tools/atlas_receipt.py

echo
echo "=== [12/12] status projection (after the receipt, so it is current) ==="
python3 forensics/tools/render_status.py

echo
echo "atlas build complete."
