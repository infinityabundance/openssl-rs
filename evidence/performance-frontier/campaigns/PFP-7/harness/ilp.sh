#!/usr/bin/env bash
# PFP-7 ILP bound: clock/width calibration and the CIOS sequential-vs-fused probe,
# built twice — baseline x86-64 (no ADX, what the crate DSO uses) and
# -march=native (ADX/BMI2 available: independent carry chains).
set -euo pipefail
ROOT=/work
DIR=/work/court/tmp/pfp7/ilp
SRC="$ROOT/evidence/performance-frontier/campaigns/PFP-7/harness/pfp7_ilp.c"
CPU="${PFP7_PIN_CPU:-1}"
mkdir -p "$DIR"

cc -O2 -Wall -Wextra "$SRC" -o "$DIR/probe-baseline"
cc -O2 -march=native -Wall -Wextra "$SRC" -o "$DIR/probe-native"
echo "=== instruction mix of the inner product loop (baseline build) ==="
objdump -d --no-show-raw-insn -M intel "$DIR/probe-baseline" | \
  awk '/<cios_mul>:/,/^$/' | grep -cE '^\s+[0-9a-f]+:' || true
objdump -d --no-show-raw-insn -M intel "$DIR/probe-baseline" | \
  awk '/<cios_mul>:/,/^$/' | grep -oE '\b(mulx|mul|adcx|adox|adc|add|setb|mov|imul)\b' | sort | uniq -c || true
echo "=== native build: mulx/adcx present? ==="
objdump -d --no-show-raw-insn -M intel "$DIR/probe-native" | grep -cE '\b(mulx|adcx|adox)\b' || true
for b in baseline native; do
    echo "=== $b ==="
    taskset -c "$CPU" "$DIR/probe-$b" calib
    for r in 1 2 3 4 5 6 7; do
        taskset -c "$CPU" "$DIR/probe-$b" cios 100000
    done
done
echo ILP_OK
