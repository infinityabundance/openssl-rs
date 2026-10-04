#!/usr/bin/env python3
"""openssl-rs -- Phase 17 downstream: generate the prose FROM the records.

Each `courts/phase17/downstream/<program>/EVIDENCE.md` and the directory `README.md` are
emitted here from `courts/phase17/downstream/<program>/result.json` (the machine-owned
records the driver writes). The prose therefore cannot drift from the measurement: the
review finding was that hand-written EVIDENCE.md files still claimed HAProxy crashed and
CPython's test_ssl was red long after the fixes landed. The prose is now output, not input.

Deterministic (no timestamps): `evidence_determinism.py` re-runs it and compares.

Usage: python3 forensics/tools/gen_downstream_evidence.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROGRAMS = ["curl", "git", "haproxy", "nginx", "openssh", "python"]
REPO = Path(__file__).resolve().parents[2]
DOWN = REPO / "courts" / "phase17" / "downstream"
GENERATOR = "forensics/tools/gen_downstream_evidence.py"

ROLE = {
    "curl": "TLS client (transfers over the candidate libssl/libcrypto)",
    "nginx": "TLS server (terminates TLS 1.3 with the candidate)",
    "haproxy": "TLS terminator / load balancer in front of a plain-HTTP backend",
    "python": "CPython `ssl`/`hashlib` consumer (live TLS and its own `test_ssl`)",
    "git": "object hashing through the candidate libcrypto and HTTPS via candidate libcurl",
    "openssh": "libcrypto-only consumer (EVP/HMAC/KDF/BN/EC/RSA/Ed25519, never libssl)",
}


def load(program: str) -> dict:
    return json.loads((DOWN / program / "result.json").read_text(encoding="utf-8"))


def flag(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


def record_section(r: dict) -> str:
    out: list[str] = []
    out.append(f"# Phase 17 downstream -- unmodified {r['program']} against the candidate shell")
    out.append("")
    out.append(
        f"Status: **build/link/start/functional all "
        f"{'PROVEN' if r['functional']['ok'] and r['build']['ok'] and r['link']['ok'] and r['start']['ok'] else 'NOT all proven'}** "
        f"({flag(r['functional']['ok'])}). This file is generated from "
        f"`courts/phase17/downstream/{r['program']}/result.json` by "
        f"`{GENERATOR}`; edit the record (or re-run the driver), never this file.")
    out.append("")
    out.append("## Pinned upstream")
    out.append("")
    out.append(f"- **{r['program']} {r['version']}**, `{r['source_url']}`")
    out.append(f"  sha256 `{r['source_sha256']}` (parsed from `build.sh`).")
    out.append(f"- Candidate identity: `{r['candidate']}` (the `RT-DOWNSTREAM-CORPUS` freshness key).")
    out.append(f"- Authority: `{r['authority']}`.")
    out.append("")
    out.append("## Measured result")
    out.append("")
    out.append("| field | result | detail |")
    out.append("|---|---|---|")
    out.append(f"| build | {flag(r['build']['ok'])} | {r['build']['detail']} |")
    out.append(f"| link | {flag(r['link']['ok'])} | {r['link']['detail']} |")
    out.append(f"| start | {flag(r['start']['ok'])} | {r['start']['detail']} |")
    out.append(f"| functional | {flag(r['functional']['ok'])} | {r['functional']['detail']} |")
    out.append(f"| concurrency | {r['concurrency']['ok']}/{r['concurrency']['total']} | "
               f"parallel operations completed |")
    out.append("")
    if r["functional"]["evidence"]:
        out.append("Functional evidence (harness lines):")
        out.append("")
        for e in r["functional"]["evidence"]:
            out.append(f"- `{e}`")
        out.append("")
    if r["known_residuals"]:
        out.append("## Known residuals")
        out.append("")
        for e in r["known_residuals"]:
            out.append(f"- {e}")
        out.append("")
    else:
        out.append("## Known residuals")
        out.append("")
        out.append("None measured.")
        out.append("")
    out.append("## Historical failures")
    out.append("")
    if r["historical_failures"]:
        out.append("| exposed at | defect | fixed by |")
        out.append("|---|---|---|")
        for h in r["historical_failures"]:
            out.append(f"| `{h['commit']}` | {h['summary']} | {h['fixed_by']} |")
    else:
        out.append("None recorded.")
    out.append("")
    out.append("## How to reproduce")
    out.append("")
    out.append("```sh")
    out.append(f"bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/{r['program']}/build.sh")
    out.append("bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/run_all.sh")
    out.append("```")
    out.append("")
    out.append("`run_all.sh` runs this program's harness, rewrites `result.json` from the transcript, "
               "re-aggregates `forensics/atlas/downstream-corpus.json` and regenerates this file.")
    return "\n".join(out) + "\n"


def readme(records: list[dict]) -> str:
    out: list[str] = []
    out.append("# Phase 17 downstream -- the machine-owned corpus")
    out.append("")
    out.append(
        "Six real, unmodified downstream programs are built against the candidate distribution "
        "shell (`artifacts/phase2/install/{include,lib}`) and exercised by a harness. The result "
        f"of each is one machine-readable record, `courts/phase17/downstream/<program>/result.json`, "
        "aggregated into `forensics/atlas/downstream-corpus.json`. This README and every "
        "`EVIDENCE.md` are generated FROM those records by "
        f"`{GENERATOR}`, so prose cannot drift from measurement.")
    out.append("")
    out.append("## Records")
    out.append("")
    out.append("| program | role | version | build | link | start | functional | concurrency | residuals |")
    out.append("|---|---|---|---|---|---|---|---|---|")
    for r in records:
        out.append(
            f"| {r['program']} | {ROLE[r['program']]} | {r['version']} | "
            f"{flag(r['build']['ok'])} | {flag(r['link']['ok'])} | {flag(r['start']['ok'])} | "
            f"{flag(r['functional']['ok'])} | {r['concurrency']['ok']}/{r['concurrency']['total']} | "
            f"{len(r['known_residuals'])} |")
    out.append("")
    out.append("## Refreshing the corpus")
    out.append("")
    out.append("The records are data, not assertions: `run_all.sh` is the driver that re-runs every")
    out.append("harness and rewrites them. It does **not** run in the normal gate path -- the")
    out.append("harnesses include multi-minute builds and live TLS servers. The `RT-DOWNSTREAM-CORPUS`")
    out.append("court instead validates the recorded corpus: every program present, every required")
    out.append("field present, `functional` true, `candidate` equal to the current `Cargo.toml`")
    out.append("version, and each corpus record still equal to its per-program `result.json`.")
    out.append("")
    out.append("```sh")
    out.append("bash docker/openssl-rs-court.sh exec sh /work/courts/phase17/downstream/run_all.sh")
    out.append("python3 forensics/tools/phase17_courts.py      # RT-DOWNSTREAM-CORPUS")
    out.append("```")
    out.append("")
    return "\n".join(out) + "\n"


def main() -> int:
    records = [load(p) for p in PROGRAMS]
    for r in records:
        (DOWN / r["program"] / "EVIDENCE.md").write_text(record_section(r), encoding="utf-8")
    (DOWN / "README.md").write_text(readme(records), encoding="utf-8")
    print(f"[gen-downstream-evidence] wrote {len(records)} EVIDENCE.md + README.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
