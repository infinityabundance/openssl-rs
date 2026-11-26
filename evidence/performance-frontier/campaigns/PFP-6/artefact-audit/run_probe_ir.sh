#!/bin/sh
# run_probe_ir.sh — instruction counts of the timed operation itself.
#
# The timing run measures BN_mod_exp_mont_consttime through each DSO.  This
# records how many instructions that operation executes, so the wall-time ratio
# can be read against the work ratio and the ladder's share can be stated.
#
#   bash docker/openssl-rs-court.sh exec bash \
#     evidence/performance-frontier/campaigns/PFP-6/artefact-audit/run_probe_ir.sh
set -eu
cd /work
# shellcheck source=/dev/null
. /work/forensics/tools/require_court.sh

OUT=/work/court/tmp/pfp27
EV=/work/evidence/performance-frontier/campaigns/PFP-6/artefact-audit
BIN="$OUT/instrument/pfp27_ladder_probe"
N=100

: >"$EV/timing/raw/probe-ir.tsv"
for tag in a b; do
    dso="$OUT/$tag/distribution/libcrypto.so.3"
    for i in 0 "$N"; do
        valgrind --tool=callgrind --callgrind-out-file="/tmp/pfp27-probe-$tag-$i.cglog" \
            "$BIN" --lib "$dso" --mode time --iters "$i" \
            >"$EV/timing/raw/probe-ir-$tag-$i.stdout" 2>&1
        ir=$(sed -n 's/^summary: \([0-9]*\)$/\1/p' "/tmp/pfp27-probe-$tag-$i.cglog" | tail -1)
        [ -n "$ir" ] || { echo "FATAL: no callgrind total for $tag/$i" >&2; exit 1; }
        printf '%s\t%s\t%s\n' "$tag" "$i" "$ir" >>"$EV/timing/raw/probe-ir.tsv"
    done
done

python3 - "$EV/timing/raw/probe-ir.tsv" "$N" <<'PY'
import sys
rows = {}
for line in open(sys.argv[1]):
    tag, i, ir = line.split()
    rows[(tag, int(i))] = int(ir)
n = int(sys.argv[2])
a = (rows[("a", n)] - rows[("a", 0)]) / n
b = (rows[("b", n)] - rows[("b", 0)]) / n
print("exp_ir_per_op_a=%.1f" % a)
print("exp_ir_per_op_b=%.1f" % b)
print("cios_over_sos_exp_ir=%.6f" % (b / a))
PY
