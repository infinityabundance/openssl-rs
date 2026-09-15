#!/usr/bin/env python3
"""openssl-rs — Phase 6 courts: the parameter surface and the provider core.

Each court is a C probe in `courts/phase6/` compiled **twice** — once against the
admitted authority, once against the candidate distribution shell — and run. The two
transcripts are compared line by line, and every difference is a residual.

The method is Phases 3, 4 and 5's, for the same reason: a unit test encodes what the
author believes the contract is, whereas a probe measures what the authority actually
does, and the comparison is between two *executions* of the same program, so the
expectation cannot drift.

`RT-PARAM` is this stratum's first court and it has a specific job, because Phase 6's
subject matter is a *data* type rather than an operation. An `OSSL_PARAM` is a
descriptor whose behaviour depends on three independent axes that a caller sets:

  * its `data_type` — seven of them, and each getter and setter has a different answer
    for each;
  * the width and signedness of the *caller's* accessor, which need not match the
    parameter's;
  * whether `data` is NULL, which turns a setter into a size query that answers success.

So the probe is a matrix rather than a sequence of scenarios: the same value read back
through every accessor, and every accessor's answer recorded next to the return code and
the error queue. What is being established is not "does get_int work" but "which of the
seven-by-many combinations is a success, which is a refusal, and with which reason" —
because the refusals are where a plausible implementation and the authority disagree, and
a wrong refusal is invisible to a caller that only tests the happy path.

Fault boundaries
----------------
A probe cannot compare a crash. Where the authority faults the probe does not call, and
the candidate's safer behaviour is recorded in `docs/SECURITY_DIVERGENCE_POLICY.md`.

A probe also cannot compare a symbol the candidate has not implemented: calling a
scaffold aborts the candidate with a diagnostic. The obligation ledger
(`forensics/tools/phase6_obligations.py`) is where that is recorded; the probe stays on
the implemented surface so that a failure here means a behavioural divergence rather
than a missing symbol.

The same rule applies one level down, to `RT-LIBCTX`. `OSSL_LIB_CTX_get_data` answers a
pointer for eighteen index slots, and each slot holds an object a different stratum owns.
The probe therefore observes the *dead* indices -- which answer NULL in the authority
because its `switch` has no arm for them -- and the slots this stratum has filled, and it
prints the live/filled/deferred counts so the transcript states the scope of its own
table. Calling a slot whose owner has not landed would compare a missing subsystem, not a
divergence.

SPDX-License-Identifier: Apache-2.0
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
    InputRef,
    envelope,
    rel,
    resolve_authority,
    run,
    write_json,
)

OUT = REPO_ROOT / "artifacts" / "phase6" / "COURTS.json"
GENERATOR = "forensics/tools/phase6_courts.py"
PROBE_DIR = REPO_ROOT / "courts" / "phase6"
PHASE2 = REPO_ROOT / "artifacts" / "phase2"
STAGED = REPO_ROOT / "artifacts" / "phase6" / "probes"
RUN_TIMEOUT_S = "60"

COURTS = [
    ("RT-LIBCTX", "rt_libctx_probe.c"),
    ("RT-PARAM", "rt_param_probe.c"),
    ("RT-THREADDATA", "rt_threaddata_probe.c"),
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
    res = run(["timeout", RUN_TIMEOUT_S, str(binary)])
    code = res.returncode
    if code == 124:
        return res.stdout, res.stderr, None
    return res.stdout, res.stderr, code


def diff(authority: str, candidate: str) -> list[dict]:
    """Line-wise comparison keyed on `key=value`, so a missing or extra line
    produces exactly one residual instead of shifting every following line."""
    def parse(text: str) -> tuple[list[str], dict[str, str]]:
        order: list[str] = []
        values: dict[str, str] = {}
        for line in text.splitlines():
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            if key not in values:
                order.append(key)
                values[key] = value
            else:
                values[key] = f"{values[key]}|{value}"
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
    STAGED.mkdir(parents=True, exist_ok=True)
    for side, srcbin in (("authority", auth_bin), ("candidate", cand_bin)):
        dst = STAGED / f"{srcbin.stem}.{side}"
        if srcbin.is_file():
            shutil.copyfile(srcbin, dst)
            dst.chmod(0o755)
            staged[side] = rel(dst)

    if not a_out.strip():
        return {"court": name, "verdict": "fail", "stage": "authority-run",
                "detail": {"exit_code": a_code,
                           "stderr": a_err.splitlines()[:12]}}

    residuals = diff(a_out, c_out)
    # A probe that died on a signal compared nothing beyond the prefix it managed
    # to print, so two sides dying the same way is not agreement. The exit-code
    # comparison cannot see that (`-11 == -11`), so a signal is an explicit
    # failure. Phase 3 and 4 both learned this the hard way.
    crashed = a_code is None or a_code < 0 or c_code is None or c_code < 0
    return {
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
            "pass" if not residuals and c_code == a_code and not crashed else "fail"
        ),
        "staged_binaries": staged,
        "candidate_stderr_tail": c_err.splitlines()[-3:],
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    work = REPO_ROOT / "court" / "phase6"
    work.mkdir(parents=True, exist_ok=True)

    records = []
    for name, filename in COURTS:
        src = PROBE_DIR / filename
        if not src.is_file():
            records.append({"court": name, "verdict": "fail",
                            "stage": "probe-missing", "detail": rel(src)})
            continue
        records.append(court(name, src, auth, work))

    passed = sum(1 for r in records if r["verdict"] == "pass")
    body = {
        "all_pass": passed == len(records),
        "authority": auth.id,
        "courts": records,
        "summary": {"total": len(records), "pass": passed,
                    "fail": len(records) - passed},
        "claim": (
            "A passing court means the candidate produced the same observable "
            "transcript as the authority for the behaviours this probe exercises. "
            "It is a differential-compatibility result, NOT cryptographic or "
            "security correctness, and NOT evidence for any behaviour the probe "
            "does not touch (docs/PARITY_MODEL.md)."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols", path=REPO_ROOT / "forensics" / "atlas"
                 / auth.id / "symbols-libcrypto.json"),
    ]
    for _name, filename in COURTS:
        inputs.append(InputRef(name="probe", path=PROBE_DIR / filename))
    doc = envelope(kind="phase6-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for r in records:
        if r["verdict"] == "pass":
            print(f"  {r['court']:<12} pass   ({r['authority_observations']} observations)")
        else:
            print(f"  {r['court']:<12} FAIL   stage={r.get('stage', 'compare')}")
            detail = r.get("detail")
            if isinstance(detail, dict):
                print(f"      exit_code={detail.get('exit_code')}")
                for line in detail.get("stderr", []):
                    print(f"      {line}")
            elif isinstance(detail, list):
                for line in detail[:8]:
                    print(f"      {line}")
            for res in r.get("residuals", [])[:12]:
                print(f"      {res['observation']}: authority={res['authority']!r} "
                      f"candidate={res['candidate']!r} ({res['class']})")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']}")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
