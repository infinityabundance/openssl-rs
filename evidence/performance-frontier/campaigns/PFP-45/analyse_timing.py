#!/usr/bin/env python3
"""PFP-45 timing summary: median per-arm latency and paired ratios.

Reads the `RESULT ... median_us=` line from each
`<tag>-<workload>-r<NN>.out` produced by run_timing.sh. The ratio statistic is
the median over repetitions of the paired per-repetition ratio (same
repetition, same workload), matching the campaign's earlier courts.
"""

from __future__ import annotations

import re
import statistics
import sys
from pathlib import Path

RESULT = re.compile(r"^RESULT .* median_us=([0-9.]+)", re.MULTILINE)
TAGS = ("before", "after", "auth")
WORKLOADS = ("out2400", "in225")


def load(root: Path) -> dict[tuple[str, str], list[tuple[int, float]]]:
    data: dict[tuple[str, str], list[tuple[int, float]]] = {}
    for tag in TAGS:
        for wl in WORKLOADS:
            rows = []
            for path in sorted(root.glob(f"{tag}-{wl}-r*.out")):
                rep = int(path.stem.rsplit("-r", 1)[1])
                m = RESULT.search(path.read_text())
                if m:
                    rows.append((rep, float(m.group(1))))
            data[(tag, wl)] = rows
    return data


def by_rep(rows: list[tuple[int, float]]) -> dict[int, float]:
    return dict(rows)


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    data = load(root)
    print(f"{'workload':10} {'arm':7} {'n':>3} {'median_us':>12}")
    for wl in WORKLOADS:
        for tag in TAGS:
            vals = [v for _, v in data[(tag, wl)]]
            if vals:
                print(f"{wl:10} {tag:7} {len(vals):3d} {statistics.median(vals):12.3f}")
    print()
    print(f"{'workload':10} {'ratio':20} {'median':>9} {'range':>24}")
    for wl in WORKLOADS:
        a = by_rep(data[("after", wl)])
        b = by_rep(data[("before", wl)])
        u = by_rep(data[("auth", wl)])
        for name, num, den in (
            ("after/before", a, b),
            ("auth/after", u, a),
            ("auth/before", u, b),
        ):
            reps = sorted(set(num) & set(den))
            ratios = [num[r] / den[r] for r in reps if den[r] > 0]
            if ratios:
                print(
                    f"{wl:10} {name:20} {statistics.median(ratios):9.4f} "
                    f"[{min(ratios):.4f}, {max(ratios):.4f}]"
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
