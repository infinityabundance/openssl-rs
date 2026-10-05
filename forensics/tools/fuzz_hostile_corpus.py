#!/usr/bin/env python3
"""openssl-rs — a bounded, deterministic mutational fuzz over the hostile ASN.1 / X.509 corpus.

Why this exists
---------------
`RT-HOSTILE-X509` drives a *fixed enumeration* of malformed inputs and says so; it is
not a fuzzer (`docs/PHASE-18-SUBPHASES.md` section 3.1). A fixed corpus bounds what was
tested but says nothing about inputs just beyond it. This tool mutates the committed
corpus and drives the same probe binary over the mutants, for a bounded number of cases
and a bounded wall clock, so the "not a fuzzer" non-claim is joined by an actual — if
still small — fuzz run rather than left as an admission.

It is deterministic: every mutant is a pure function of `(base entry, case index, seed)`
and the tool records the seed and per-case provenance, so a crash is reproducible. It is
**not** coverage-guided, not libFuzzer/AFL, and not a security proof; it is a bounded
mutational screen whose only claim is what it observed.

What it drives
--------------
The candidate probe `courts/phase18/rt_hostile_x509_probe.c` compiled as
`artifacts/phase18/probes/rt_hostile_x509_probe.candidate` (or `--probe`). The probe reads
`argv[1]` as a corpus directory of `<arm>__<id>.bin` files, forks once per entry, and
records each entry's class as `parse` / `crash` / `oom` / `timeout` / `probe-error`. This
tool writes its mutants into a temporary directory with the same naming, runs the probe
over them, and treats any `crash`/`oom`/`timeout` class (or a probe killed by this tool's
own wall-clock bound) as a finding.

Usage
-----
    python3 forensics/tools/fuzz_hostile_corpus.py                 # 512 cases, 120s bound
    python3 forensics/tools/fuzz_hostile_corpus.py --cases 2048 --wall-budget 600
    python3 forensics/tools/fuzz_hostile_corpus.py --out artifacts/phase18/fuzz.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import REPO_ROOT, rel  # noqa: E402

CORPUS = REPO_ROOT / "courts" / "phase18" / "fixtures" / "hostile-x509"
DEFAULT_PROBE = (REPO_ROOT / "artifacts" / "phase18" / "probes"
                 / "rt_hostile_x509_probe.candidate")
FINDING_CLASSES = ("crash", "oom", "timeout", "probe-error")


def _mutate(base: bytes, rng: random.Random) -> bytes:
    """One deterministic mutant of `base` from `rng`."""
    data = bytearray(base)
    if not data:
        return bytes(rng.randrange(256) for _ in range(rng.randrange(1, 16)))
    for _ in range(rng.randrange(1, 4)):
        op = rng.randrange(4)
        if op == 0:  # flip a bit
            i = rng.randrange(len(data))
            data[i] ^= 1 << rng.randrange(8)
        elif op == 1:  # overwrite a byte
            data[rng.randrange(len(data))] = rng.randrange(256)
        elif op == 2 and len(data) > 2:  # truncate
            del data[rng.randrange(1, len(data)):]
        else:  # insert a short run
            i = rng.randrange(len(data) + 1)
            run = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 5)))
            data[i:i] = run
        if not data:
            data = bytearray(b"\x00")
    return bytes(data)


def fuzz(corpus: Path, probe: Path, cases: int, wall_budget: float, seed: int,
         workdir: Path) -> dict:
    entries = sorted(p for p in corpus.glob("*.bin"))
    if not entries:
        raise SystemExit(f"fuzz-hostile-corpus: no `*.bin` entries under {rel(corpus)}")
    if not probe.is_file():
        raise SystemExit(
            f"fuzz-hostile-corpus: probe {rel(probe)} is absent; run the Phase 18 courts "
            f"first (it stages the probe binary)"
        )
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True)

    # One probe invocation per <=512-entry batch (the probe's MAX_ENTRIES).
    classes: dict[str, int] = {}
    findings: list[dict] = []
    drove = 0
    batch_no = 0
    started = time.monotonic()
    batch: list[tuple[str, bytes]] = []

    def run_batch(items: list[tuple[str, bytes]]) -> None:
        nonlocal drove, batch_no
        batch_dir = workdir / f"batch{batch_no:06d}"
        batch_no += 1
        batch_dir.mkdir()
        for name, data in items:
            (batch_dir / name).write_bytes(data)
        bound = max(5.0, wall_budget - (time.monotonic() - started))
        try:
            proc = subprocess.run(["timeout", f"{bound:.0f}", str(probe), str(batch_dir)],
                                  capture_output=True, text=True, check=False, timeout=bound + 5)
        except subprocess.TimeoutExpired:
            findings.append({"class": "harness-timeout", "batch": str(batch_dir),
                             "detail": "the probe outlived the wall-clock bound"})
            return
        out = proc.stdout
        seen = 0
        for line in out.splitlines():
            if not line.startswith("entry.") or "." not in line:
                continue
            key, _, value = line.partition("=")
            if key.endswith(".class"):
                seen += 1
                classes[value] = classes.get(value, 0) + 1
                if value in FINDING_CLASSES:
                    entry_id = key[len("entry."):-len(".class")]
                    findings.append({"class": value, "entry": entry_id,
                                     "batch": str(batch_dir)})
        drove += seen

    index = 0
    for case in range(cases):
        if time.monotonic() - started > wall_budget:
            break
        base = entries[case % len(entries)]
        arm = base.name.split("__", 1)[0]
        rng = random.Random((seed * 1_000_003) ^ (case * 2_654_435_761) ^ index)
        mutant = _mutate(base.read_bytes(), rng)
        batch.append((f"{arm}__fz{case:06d}.bin", mutant))
        index += 1
        if len(batch) == 512 or case == cases - 1:
            run_batch(batch)
            batch = []
    if batch:
        run_batch(batch)

    return {
        "schema": "openssl-rs/fuzz-hostile-corpus/v1",
        "tool": "forensics/tools/fuzz_hostile_corpus.py",
        "corpus": rel(corpus),
        "corpus_entries": len(entries),
        "probe": rel(probe),
        "seed": seed,
        "cases_requested": cases,
        "cases_driven": drove,
        "classes": dict(sorted(classes.items())),
        "findings": findings,
        "finding_count": len(findings),
        "wall_budget_s": wall_budget,
        "elapsed_s": round(time.monotonic() - started, 3),
        "note": (
            "a bounded, deterministic mutational screen over the committed hostile corpus, "
            "driven through the same probe the RT-HOSTILE-X509 court uses; NOT coverage-guided, "
            "NOT a fuzzing campaign, NOT a security proof"
        ),
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--corpus", type=Path, default=CORPUS)
    ap.add_argument("--probe", type=Path, default=DEFAULT_PROBE)
    ap.add_argument("--cases", type=int, default=512)
    ap.add_argument("--wall-budget", type=float, default=120.0)
    ap.add_argument("--seed", type=int, default=0x18)
    ap.add_argument("--workdir", type=Path, default=Path("/court/fuzz-hostile-x509"))
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    result = fuzz(args.corpus, args.probe, args.cases, args.wall_budget, args.seed,
                  args.workdir)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8")
        print(f"  -> {rel(args.out)}")
    print(f"[fuzz-hostile-corpus] seed={result['seed']} cases_driven={result['cases_driven']} "
          f"classes={result['classes']} findings={result['finding_count']} "
          f"({result['elapsed_s']}s)")
    for finding in result["findings"][:12]:
        print(f"  FINDING: {finding}")
    return 1 if result["finding_count"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
