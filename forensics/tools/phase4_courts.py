#!/usr/bin/env python3
"""openssl-rs — Phase 4 courts: BIO, CONF and the buffer object, differentially.

Each court is a C probe in `courts/phase4/` compiled **twice** — once against the
admitted authority, once against the candidate distribution shell — and run. The
two transcripts are compared line by line, and every difference is a residual.

The method is the one Phase 3 established (`phase3_courts.py`), for the same
reason: a unit test encodes what the author believes the contract is, whereas a
probe measures what the authority actually does, and the comparison is between
two *executions* of the same program, so the expectation cannot drift.

What the Phase 4 probes establish
---------------------------------
The BIO core is dispatch-heavy: most of its contract is argument checking, the
callback protocol, the `init` gate, the two different read/write return contracts,
byte accounting and the error classes. `rt_bio_probe.c` therefore drives both the
success and the failure paths of each family and records the *return value class*
and the raised reason, not just the data that moves.

Fault boundaries
----------------
A probe cannot compare a crash. Where the authority faults, the probe avoids the
call and says so; the candidate's safer behaviour is recorded in
`docs/SECURITY_DIVERGENCE_POLICY.md`. `BIO_free(BIO_new(BIO_s_core()))` is the
known case and is not exercised here because `BIO_s_core` is a Phase 6 obligation.

A probe also cannot compare a symbol the candidate has not implemented: calling a
scaffold aborts the candidate with a diagnostic. The obligation ledger
(`forensics/phase4-obligations.py`) is where that is recorded; the probes stay on
the implemented surface so that a failure here means a behavioural divergence.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    content_hash,
    envelope,
    rel,
    resolve_authority,
    run,
    write_json,
)

PROBE_DIR = REPO_ROOT / "courts" / "phase4"
PHASE2 = REPO_ROOT / "artifacts" / "phase2"
OUT = REPO_ROOT / "artifacts" / "phase4"
DETAIL = OUT / "courts"
# Compiled probes are staged beside the transcripts so the FRF runtime courts can
# re-execute exactly the same binaries in a container that has no compiler.
STAGED = OUT / "probes"

RUN_TIMEOUT_S = 60

COURTS = [
    ("RT-BIO", "rt_bio_probe.c"),
    ("RT-ERR-BIO", "rt_err_bio_probe.c"),
    ("RT-BIO-ADDR", "rt_bio_addr_probe.c"),
    ("RT-BIO-RESOLVE", "rt_bio_resolve_probe.c"),
    ("RT-BIO-SOCK", "rt_bio_sock_probe.c"),
    ("RT-BIO-COMP", "rt_bio_comp_probe.c"),
    ("RT-BIO-DEBUG", "rt_bio_debug_probe.c"),
    ("RT-BIO-PRINT", "rt_bio_print_probe.c"),
    ("RT-BIO-FILE", "rt_bio_file_probe.c"),
    ("RT-BIO-FILTER", "rt_bio_filter_probe.c"),
    ("RT-BIO-PAIR", "rt_bio_pair_probe.c"),
    ("RT-BIO-DGRAM-PAIR", "rt_bio_dgram_pair_probe.c"),
    ("RT-BIO-DGRAM", "rt_bio_dgram_probe.c"),
    ("RT-BIO-CONN", "rt_bio_conn_probe.c"),
    ("RT-OBJ-STREAM", "rt_obj_stream_probe.c"),
    ("RT-CONF", "rt_conf_probe.c"),
    ("RT-COMP", "rt_comp_probe.c"),
    # Reference basis for the BIO/CONF exports no behavioural court drives. It references,
    # it does not call; see the probe header and docs/DECISIONS.md D199.
    ("RT-BIO-CONF-REF", "rt_coverage_ref_probe.c"),
]


def compile_probe(src: Path, out: Path, include: Path, libdir: Path) -> tuple[bool, str]:
    res = run([
        "clang", "-std=c11", "-Wall", "-O1", "-D_GNU_SOURCE",
        "-I", str(include),
        "-o", str(out), str(src),
        "-L", str(libdir), "-lcrypto",
        f"-Wl,-rpath,{libdir}",
    ])
    return res.ok, res.stderr.strip()


def run_probe(binary: Path) -> tuple[str, str, int | None]:
    res = run(["timeout", str(RUN_TIMEOUT_S), str(binary)])
    code = res.returncode
    if code == 124:
        return res.stdout, res.stderr, None
    return res.stdout, res.stderr, code


def diff(authority: str, candidate: str) -> list[dict]:
    """Line-wise comparison keyed on `key=value`, so a missing or extra line
    produces exactly one residual instead of shifting every following line."""
    def parse(text: str) -> tuple[list[str], dict[str, str | None]]:
        order: list[str] = []
        values: dict[str, str | None] = {}
        for line in text.splitlines():
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            if key not in values:
                order.append(key)
            values[key] = value if key not in values else values[key] + "|" + value
        return order, values

    a_order, a = parse(authority)
    c_order, c = parse(candidate)
    residuals: list[dict] = []
    for key in a_order:
        if key not in c:
            residuals.append({"observation": key, "authority": a[key],
                              "candidate": None, "class": "missing"})
        elif a[key] != c[key]:
            residuals.append({"observation": key, "authority": a[key],
                              "candidate": c[key], "class": "value"})
    for key in c_order:
        if key not in a:
            residuals.append({"observation": key, "authority": None,
                              "candidate": c[key], "class": "extra"})
    return residuals


def court(name: str, src: Path, auth, work: Path) -> dict:
    auth_lib = auth.prefix / "lib"
    auth_inc = auth.prefix / "include"

    auth_bin = work / f"{src.stem}.authority"
    cand_bin = work / f"{src.stem}.candidate"

    ok, err = compile_probe(src, auth_bin, auth_inc, auth_lib)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-authority",
                "detail": err.splitlines()[:12]}
    ok, err = compile_probe(src, cand_bin, PHASE2 / "include", PHASE2)
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-candidate",
                "detail": err.splitlines()[:12]}

    a_out, a_err, a_code = run_probe(auth_bin)
    c_out, c_err, c_code = run_probe(cand_bin)

    staged = {}
    if not STAGED.exists():
        STAGED.mkdir(parents=True, exist_ok=True)
    for side, srcbin in (("authority", auth_bin), ("candidate", cand_bin)):
        dst = STAGED / f"{srcbin.stem}.{side}"
        if srcbin.is_file():
            shutil.copyfile(srcbin, dst)
            dst.chmod(0o755)
            staged[side] = rel(dst)

    if not a_out.strip():
        return {"court": name, "verdict": "fail", "stage": "authority-run",
                "detail": {"exit_code": a_code, "stderr": a_err.splitlines()[:12]}}

    residuals = diff(a_out, c_out)
    #
    # A probe that died on a signal compared nothing beyond the prefix it managed
    # to print, so two sides dying the same way is *not* agreement. The exit-code
    # comparison below cannot see that (`-11 == -11`), so a signal is made an
    # explicit failure. This was found by `RT-BIO-CONN`, whose probe passed a
    # `BIO_METHOD *` to `BIO_method_name` and segfaulted identically on both
    # sides.
    crashed = (
        a_code is None
        or a_code < 0
        or c_code is None
        or c_code < 0
    )
    record = {
        "court": name,
        "probe": rel(src),
        "authority_exit_code": a_code,
        "candidate_exit_code": c_code,
        "crashed": crashed,
        "authority_observations": len([l for l in a_out.splitlines() if "=" in l]),
        "candidate_observations": len([l for l in c_out.splitlines() if "=" in l]),
        "residual_count": len(residuals),
        "residuals": residuals,
        "verdict": (
            "pass"
            if not residuals and c_code == a_code and not crashed
            else "fail"
        ),
        "staged_binaries": staged,
        "candidate_stderr_tail": c_err.splitlines()[-3:],
    }
    return record


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Run the Phase 4 courts.")
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    work = REPO_ROOT / "court" / "phase4"
    work.mkdir(parents=True, exist_ok=True)
    DETAIL.mkdir(parents=True, exist_ok=True)

    print(f"[phase4-courts] authority={auth.id}")
    records = []
    for name, filename in COURTS:
        src = PROBE_DIR / filename
        if not src.is_file():
            records.append({"court": name, "verdict": "fail", "stage": "missing-probe",
                            "detail": rel(src)})
            print(f"  {name:<12} MISSING PROBE")
            continue
        rec = court(name, src, auth, work)
        records.append(rec)
        if rec["verdict"] == "pass":
            print(f"  {name:<12} pass   ({rec['authority_observations']} observations)")
        else:
            if rec.get("crashed"):
                extra = (
                    f"probe died on a signal (authority={rec['authority_exit_code']}, "
                    f"candidate={rec['candidate_exit_code']})"
                )
            else:
                extra = rec.get("stage", f"{rec.get('residual_count', '?')} residual(s)")
            print(f"  {name:<12} FAIL   {extra}")
            for r in rec.get("residuals", [])[:25]:
                print(f"      {r['observation']}: authority={r['authority']!r} "
                      f"candidate={r['candidate']!r}")
        write_json(DETAIL / f"{name}.json", rec)

    all_pass = all(r["verdict"] == "pass" for r in records)
    body = {
        "authority": auth.id,
        "courts": records,
        "summary": {
            "total": len(records),
            "pass": sum(1 for r in records if r["verdict"] == "pass"),
            "fail": sum(1 for r in records if r["verdict"] != "pass"),
        },
        "all_pass": all_pass,
        "claim": (
            "A passing court means the candidate produced the same observable "
            "transcript as the authority for the behaviours this probe exercises. "
            "It is a differential-compatibility result, NOT cryptographic or "
            "security correctness, and NOT evidence for any behaviour the probe "
            "does not touch (docs/PARITY_MODEL.md)."
        ),
    }
    doc = envelope("phase4-courts", "forensics/tools/phase4_courts.py", [],
                   body, authority=auth.id)
    doc["body_hash"] = content_hash(body)
    write_json(OUT / "COURTS.json", doc)
    print(f"  -> {rel(OUT / 'COURTS.json')} all_pass={all_pass}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
