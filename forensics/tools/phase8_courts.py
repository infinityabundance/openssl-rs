#!/usr/bin/env python3
"""openssl-rs — Phase 8 courts: the native cryptographic primitives.

Each court is a C probe in `courts/phase8/` compiled **twice** — once against the admitted
authority, once against the candidate distribution shell — and run. The two transcripts are
compared line by line, and every difference is a residual.

The method is Phases 3, 4, 5, 6 and 7's, for the same reason: a unit test encodes what the
author wrote believes the contract is, whereas a probe measures what the authority actually
does, and the comparison is between two *executions* of the same program, so the expectation
cannot drift.

What this stratum's first court has to observe, and why it can observe it at all
----------------------------------------------------------------------------------
Phase 7's first court had to *decide* what a court could see, because its subject — the
fetch store — exports nothing. This stratum's subject is the opposite: every digest, cipher
and key type here is a public function whose whole contract is a value. So the discipline is
not "what can be observed" but **"what must be observed to catch a transcription error"**,
and for a digest that list is longer than it looks:

  * the digest bytes for a message, as hex, so a wrong round constant, rotation or table
    entry is a residual rather than a plausible-looking output;
  * the empty message, because it is the padding path with a zero-length input;
  * the 55/56/64-byte boundary vectors, because that is where the length field and the
    extra-block arm of the padding diverge on a transcription error;
  * the block size and the digest size, as the authority reports them;
  * an `Update` split across two calls against the same bytes in one, because the collector's
    partial-block buffer is a second code path;
  * `Transform` on a non-multiple-of-block input, which the authority accepts and which
    advances the state without touching `num`.

The comparison is a `key=value` line diff, so a missing or extra observation is one residual
rather than a shifted transcript. Addresses are never printed: every observation is a return
code, a length, or a byte comparison the probe performs itself.

Fault boundaries
----------------
A probe cannot compare a crash. Where the authority faults the probe does not call, and the
candidate's safer behaviour is recorded in `docs/SECURITY_DIVERGENCE_POLICY.md`.

A probe also cannot compare a symbol the candidate has not implemented: calling a scaffold
aborts the candidate with a diagnostic. The obligation ledger
(`forensics/tools/phase8_obligations.py`) is where that is recorded; the probe stays on the
implemented surface so that a failure here means a behavioural divergence rather than a
missing symbol.

SPDX-License-Identifier: Apache-2.0"""

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

OUT = REPO_ROOT / "artifacts" / "phase8" / "COURTS.json"
GENERATOR = "forensics/tools/phase8_courts.py"
PROBE_DIR = REPO_ROOT / "courts" / "phase8"
PHASE2 = REPO_ROOT / "artifacts" / "phase2"
STAGED = REPO_ROOT / "artifacts" / "phase8" / "probes"
RUN_TIMEOUT_S = "60"

# The courts, in the order they landed. 8.0 lands the runner with none of them, which is
# the shape 7.0 had: the ledger and the stratum's wiring are evidence, and a court arrives
# in the subphase that gives it something to observe. `RT-DIGEST` lands with 8.1 and is
# declared here in the same commit as its probe, so a runner that names a probe which does
# not exist cannot be committed.
COURTS: list[tuple[str, str]] = []


def extra_defs(name: str, libdir: Path) -> list[str]:
    """Per-side build definitions.

    **None.** Every observation `RT-DIGEST` makes is a return code, a size, or a comparison
    between bytes the probe computed and bytes the library produced — so the probe is
    compiled identically on both sides and a difference in the transcript can only be a
    difference in behaviour. `extra_defs` is kept because the runner's shape is Phase 6's
    and a later court here may need one.
    """
    del name, libdir
    return []


def compile_probe(
    src: Path, out: Path, include: Path, libdir: Path, defs: list[str] | None = None
) -> tuple[bool, str]:
    res = run([
        # `-Werror=implicit-function-declaration` is not decoration: without a prototype, C
        # assumes a function returns `int`, so a probe that forgot an include reads a pointer
        # return as its low 32 bits and dereferences it. RT-FETCH learned that on both sides at
        # once, which the runner refused to read as agreement.
        "clang", "-std=c11", "-Wall", "-Werror=implicit-function-declaration", "-O1",
        "-D_GNU_SOURCE",
        *(defs or []),
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

    ok, err = compile_probe(src, auth_bin, auth_inc, auth_lib,
                            extra_defs(name, auth_lib))
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-authority",
                "detail": err.splitlines()[:12]}
    ok, err = compile_probe(src, cand_bin, PHASE2 / "include", PHASE2,
                            extra_defs(name, PHASE2))
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
    # to print, so two sides dying the same way is not agreement.
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
    work = REPO_ROOT / "court" / "phase8"
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
    doc = envelope(kind="phase8-courts", authority=auth.id, inputs=inputs,
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
