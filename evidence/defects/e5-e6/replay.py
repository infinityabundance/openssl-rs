#!/usr/bin/env python3
"""Re-run the E5a, E5b, E6 and E7 witnesses against the repaired tools.

This is a reproducible record of the gate-4/gate-5 commands, not a new
instrument: every invocation is the consumer's own path.  It writes only to a
temporary directory and never edits a tracked record.

    python3 evidence/defects/e5-e6/replay.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
TOOLS = REPO / "forensics/tools"
sys.path.insert(0, str(TOOLS))

import sarif_adapter  # noqa: E402


def run(argv, cwd=REPO):
    return subprocess.run(
        argv, cwd=str(cwd), capture_output=True, text=True, timeout=900
    )


def report(label, result, code):
    hit = code in (result.stderr + result.stdout)
    message = (result.stderr or result.stdout).strip().splitlines()
    first = message[0] if message else ""
    print(f"{label}: exit={result.returncode} code={'yes' if hit else 'NO'}")
    print(f"    {first}")
    return hit and result.returncode != 0


def main() -> int:
    failures = 0
    tmp = Path(tempfile.mkdtemp(prefix="e5-e6-replay-"))

    empty = tmp / "empty.log"
    empty.write_bytes(b"")
    unrelated = tmp / "unrelated.log"
    unrelated.write_text(
        "==1== Memcheck, a memory error detector\n"
        "==1== Command: ./nothing-much\n"
        "==1==\n==1== HEAP SUMMARY:\n"
        "==1==   in use at exit: 0 bytes in 0 blocks\n",
        encoding="utf-8",
    )
    finding = tmp / "finding.log"
    finding.write_text(
        "==1== Conditional jump or move depends on uninitialised value(s)\n"
        "==1==    at 0x1000: mont_mul_into (fixture.S:6)\n"
        "==1==    by 0x2000: caller (fixture.S:20)\n",
        encoding="utf-8",
    )
    script = REPO / "courts/phase18/timing/summarize_ct.py"

    print("== E5a: summarize_ct.py outcome contract ==")
    for label, path, code in (
        ("empty-log", empty, "CT_SUMMARY_EMPTY_LOG"),
        ("unrelated-log", unrelated, "CT_SUMMARY_UNRELATED_LOG"),
    ):
        result = run([sys.executable, str(script), "0", str(path)])
        failures += 0 if report(label, result, code) else 1
    result = run([sys.executable, str(script), "0", str(finding)])
    print(f"log-with-a-finding: exit={result.returncode} "
          f"counts={'total contexts: 1' in result.stdout}")
    failures += 0 if result.returncode == 0 and "total contexts: 1" in result.stdout else 1

    print("\n== E5b: ctgrind binary identity ==")
    claim = {
        "id": "REPLAY-CT-1",
        "kind": "ctgrind_finding",
        "statement": "the Montgomery ladder branch is constant-time",
        "evidence": {
            "kind": "ctgrind",
            "harness": "bn::bignum::tests::ctgrind_secret_base_fold_and_ladder",
            "binary_identity": "sha256:" + "de" * 32,
            "tainted_inputs": ["secret_scalar"],
        },
        "scope": {"artefact": "release"},
        "mechanism_ref": "BN-MONT-LADDER",
    }
    claims = tmp / "claim-mismatched.json"
    claims.write_text(json.dumps({"claims": [claim]}), encoding="utf-8")
    result = run([
        sys.executable, str(TOOLS / "side_channel_erasure.py"), "check-claims",
        "--repo-root", str(REPO), "--claims", str(claims),
        "--binary-identity", "sha256:" + "ab" * 32,
    ])
    failures += 0 if report("candidate-identity-mismatch", result,
                            "CTGRIND_BINARY_IDENTITY_MISMATCH") else 1

    print("\n== E6: SARIF emission population ==")
    document = sarif_adapter.build_document(REPO)
    short = json.loads(json.dumps(document))
    del short["runs"][0]["results"][0]
    try:
        sarif_adapter.validate_emission(short)
    except sarif_adapter.Refusal as exc:
        print(f"emission-result-count-mismatch: exit=1 code=yes")
        print(f"    {exc.code}: {exc.detail}")
    else:
        print("emission-result-count-mismatch: ACCEPTED (defect)")
        failures += 1
    try:
        sarif_adapter.validate_emission(document)
        print("live-emission-accepted: exit=0")
    except sarif_adapter.Refusal as exc:  # pragma: no cover - a regression
        print(f"live-emission-accepted: REFUSED {exc.code}")
        failures += 1
    committed = json.loads((REPO / "evidence/a1/SARIF.json").read_text(encoding="utf-8"))
    try:
        sarif_adapter.validate_emission(committed)
        total = sum(len(run["results"]) for run in committed["runs"])
        print(f"evidence/a1/SARIF.json: accepted, {total} results in "
              f"{len(committed['runs'])} runs")
        failures += 0 if total == 4245 and len(committed["runs"]) == 6 else 1
    except sarif_adapter.Refusal as exc:  # pragma: no cover - a finding
        print(f"evidence/a1/SARIF.json: REFUSED {exc.code}: {exc.detail}")
        failures += 1

    print("\n== E7: duplicate-key register through both consumers ==")
    duplicate = tmp / "duplicate-register.json"
    duplicate.write_text('{"instruments": [], "instruments": []}\n', encoding="utf-8")
    result = run([
        sys.executable, str(TOOLS / "etp_t1_seed.py"),
        "--instruments", str(duplicate), "--output", str(tmp / "graph.json"),
    ])
    failures += 0 if report("etp_t1_seed duplicate-key", result,
                            "PH_REFUSED_DUPLICATE_KEY") else 1

    sys.path.insert(0, str(TOOLS))
    import freshness  # noqa: E402

    register_repo = tmp / "register-repo"
    register_repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=register_repo, check=True)
    target = register_repo / "evidence/etp3/instruments.json"
    target.parent.mkdir(parents=True)
    target.write_text('{"instruments": [], "instruments": []}\n', encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=register_repo, check=True)
    subprocess.run(
        ["git", "-c", "user.name=e5-e6", "-c", "user.email=e5-e6@example.invalid",
         "-c", "commit.gpgsign=false", "commit", "-q", "-m", "register"],
        cwd=register_repo, check=True,
    )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=register_repo, capture_output=True,
        text=True, check=True,
    ).stdout.strip()
    try:
        freshness._instrument_entries(freshness.Git(register_repo), head)
    except freshness.JsonError as exc:
        present = "PH_REFUSED_DUPLICATE_KEY" in str(exc)
        print(f"freshness duplicate-key: exit=1 code={'yes' if present else 'NO'}")
        print(f"    {exc}")
        failures += 0 if present else 1
    else:
        print("freshness duplicate-key: ACCEPTED (defect)")
        failures += 1

    print("\n== Gate 5: real records ==")
    result = run([
        sys.executable, str(TOOLS / "side_channel_erasure.py"), "validate",
        "--repo-root", str(REPO),
    ])
    print(f"ETP-T7 erasure validate: exit={result.returncode}")
    failures += 0 if result.returncode == 0 else 1
    result = run([
        sys.executable, str(TOOLS / "side_channel_erasure.py"), "--self-test",
        "--repo-root", str(REPO),
    ])
    print(f"ETP-T7 self-test: exit={result.returncode} "
          f"{'SELF-TEST PASS' if 'SELF-TEST PASS' in result.stdout else 'NO PASS'}")
    failures += 0 if result.returncode == 0 and "SELF-TEST PASS" in result.stdout else 1
    entries = freshness._instrument_entries(freshness.Git(REPO), "HEAD")
    print(f"freshness live register: {len(entries)} entries")
    failures += 0 if entries else 1
    result = run([
        sys.executable, str(TOOLS / "etp_t1_seed.py"),
        "--output", str(tmp / "TRACEABILITY.json"),
    ])
    same = False
    if result.returncode == 0:
        same = (
            (tmp / "TRACEABILITY.json").read_bytes()
            == (REPO / "evidence/etp-t1/TRACEABILITY.json").read_bytes()
        )
    print(f"etp_t1_seed live register: exit={result.returncode} reproduces={same}")
    failures += 0 if same else 1

    print(f"\nREPLAY {'PASS' if failures == 0 else 'FAIL'} failures={failures}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
