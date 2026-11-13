"""Run the re-pin controls and print every named outcome (TASK 2 evidence).

Read-only: it exercises the same control functions `--self-test` runs and
prints the per-control trace, so the observed results can be recorded without
re-deriving anything.  Inside the court:

    bash docker/openssl-rs-court.sh exec \
        python3 court/freeze-b77/run_repin_controls.py
"""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "cc", ROOT / "forensics/tools/consumer_closure.py")
cc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cc)

rows = []

fails, line = cc._e7repin_self_test()
rows.append({"group": "e7repin", "summary": line, "failures": fails})
for f in fails:
    print(f"FAIL e7repin: {f}")

cc._SELFTEST_TRACE.clear()
fails, line = cc._e7repin_search_self_test()
rows.append({"group": "e7repin-search", "summary": line, "failures": fails})
for name, got, want, ok in cc._SELFTEST_TRACE:
    print(f"{'PASS' if ok else 'FAIL'}  {name}")
    print(f"        observed={json.dumps(got, default=str)[:160]}")
for f in fails:
    print(f"FAIL e7repin-search: {f}")

rep = cc.pin_resolution_report()
print("\nmoved rows (searched, not offset-derived):")
for r in rep["moved"]:
    print(f"  {r['symbol']}+{r['pin_offset']} -> +{r['resolved_offset']} "
          f"{r['address']}: accepted={r['accepted']} "
          f"of {r['candidates']} candidate(s), rule={r['rule']}")
print("refused rows:", json.dumps(rep["refused"], default=str)[:400])
