#!/usr/bin/env python3
"""openssl-rs — Phase 3 courts: the core runtime, differentially.

Each court is a C probe in `courts/phase3/` compiled **twice** — once against the
admitted authority, once against the candidate distribution shell — and run. The
two transcripts are compared line by line, and every difference is a residual.

Why probes rather than unit tests
---------------------------------
A unit test encodes what the author believes the contract is. A probe measures
what the authority actually does, and the comparison is between two *executions*
of the same program, so the expectation cannot drift away from the authority
without the court noticing. Several of the contract details in `src/runtime/`
were found this way and would not have survived being written from memory: the
zero-length allocation, the `CRYPTO_realloc`/`CRYPTO_clear_realloc` asymmetry, the
caller-attributed overflow error, the normalized `CRYPTO_memcmp` result, the
atomic helpers' *resulting* value, and the fact that
`CRYPTO_secure_allocated` is a range check rather than a liveness test.

Fault boundaries
----------------
A probe cannot compare a crash. Where the authority faults (a NULL
`CRYPTO_EX_DATA`, `CRYPTO_secure_used` before init, `CRYPTO_secure_actual_size`
on a released block, the `doall` family on an un-thunked table, the atomic
helpers' NULL `ret`), the probe prints a `NOT_MEASURED_AUTHORITY_FAULTS` marker
and the candidate's safer behaviour is recorded in
`docs/SECURITY_DIVERGENCE_POLICY.md`. Reproducing a fault to obtain parity is
explicitly not allowed (`docs/CUSTODIAN_CONTRACT.md`).

No probe compares memory addresses or internal allocation counts: those go to
stderr, which is captured for the human debugging a failure but never diffed.
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
    content_hash,
    envelope,
    rel,
    resolve_authority,
    run,
    write_json,
    write_text,
    REPO_ROOT,
)

PROBE_DIR = REPO_ROOT / "courts" / "phase3"
PHASE2 = REPO_ROOT / "artifacts" / "phase2"
OUT = REPO_ROOT / "artifacts" / "phase3"
DETAIL = OUT / "courts"
# The compiled probes are staged here, beside the transcripts, so the FRF runtime
# courts can re-execute exactly the same binaries at observation time instead of
# rebuilding them in a container that has no compiler. They are committed for the
# same reason the distribution shell is.
STAGED = OUT / "probes"

# Runtime budget per probe run. A probe that hangs is a finding, not a reason to
# block the suite: it is reported as `timeout`.
RUN_TIMEOUT_S = 60

# The court families this phase defines, in the order they are reported. Each
# maps to `courts/phase3/<slug>.c`.
COURTS = [
    ("RT-MEM", "rt_mem_probe.c"),
    ("RT-MEM-DEFAULT", "rt_mem_default_probe.c"),
    ("RT-MEM-INSTALL", "rt_mem_install_probe.c"),
    ("RT-EXDATA", "rt_exdata_probe.c"),
    ("RT-ERR", "rt_err_probe.c"),
    ("RT-STACK", "rt_stack_probe.c"),
    ("RT-THREAD", "rt_thread_probe.c"),
    ("RT-SECURE", "rt_secure_probe.c"),
    ("RT-LHASH", "rt_lhash_probe.c"),
    ("RT-RUNTIME-EXT", "rt_runtime_ext_probe.c"),
]

# Per-probe compile flags. An entry is a decision with a reason, never a
# convenience:
#
#   * `rt_mem_default_probe.c` interposes the four libc allocator entry points so
#     that it can observe whether `CRYPTO_realloc(p, 0)` released `p`, an effect
#     its return value hides. `-rdynamic` is what puts the executable's
#     definitions in `.dynsym`, so that `libcrypto.so.3`'s own `malloc`/`free`
#     calls resolve to them; without it the interposition silently does nothing
#     and the witness reports zero changes on both sides, which reads as
#     agreement. See the probe's header for why `__libc_*` rather than
#     `dlsym(RTLD_NEXT, ...)`.
EXTRA_CFLAGS: dict[str, list[str]] = {
    "rt_mem_default_probe.c": ["-rdynamic"],
}


def compile_probe(src: Path, out: Path, include: Path, libdir: Path) -> tuple[bool, str]:
    res = run([
        # `-D_GNU_SOURCE` is required, not optional: `rt_lhash_probe.c` captures a
        # `FILE *` report through `open_memstream`, which `<stdio.h>` only declares
        # under that macro. Without it the call is implicitly declared as returning
        # `int`, the pointer is truncated, and the probe writes through a bogus
        # `FILE *` — which crashed both sides identically and so looked like
        # agreement until the exit code was checked. The Phase 4 court already
        # passed it.
        "clang", "-std=c11", "-Wall", "-O1", "-D_GNU_SOURCE",
        *EXTRA_CFLAGS.get(src.name, ()),
        "-I", str(include),
        "-o", str(out), str(src),
        "-L", str(libdir), "-lcrypto",
        f"-Wl,-rpath,{libdir}",
    ])
    return res.ok, res.stderr.strip()


def run_probe(binary: Path) -> tuple[str, str, int | None]:
    """Return (stdout, stderr, exit_code); exit_code None on timeout."""
    res = run(["timeout", str(RUN_TIMEOUT_S), str(binary)])
    code = res.returncode
    if code == 124:
        return res.stdout, res.stderr, None
    return res.stdout, res.stderr, code


def diff(authority: str, candidate: str) -> list[dict]:
    """Line-wise comparison of the two transcripts.

    Keyed by the `key=value` shape the probes emit, so a missing or extra line
    produces exactly one residual rather than shifting every following line.
    """
    def parse(text: str) -> tuple[list[str], dict[str, str | None]]:
        order: list[str] = []
        values: dict[str, str | None] = {}
        for line in text.splitlines():
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            if key not in values:
                order.append(key)
            # A repeated key means the candidate re-emitted a line the authority
            # did not: record the duplicate rather than silently overwriting.
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

    # Stage the binaries for the FRF runtime courts. A failure to stage is not a
    # court failure -- the differential evidence above is already complete -- so
    # it is reported and the transcript comparison continues.
    staged = {}
    if not STAGED.exists():
        STAGED.mkdir(parents=True, exist_ok=True)
    for side, src in (("authority", auth_bin), ("candidate", cand_bin)):
        dst = STAGED / f"{src.stem}.{side}"
        if src.is_file():
            shutil.copyfile(src, dst)
            dst.chmod(0o755)
            staged[side] = rel(dst)

    if not a_out.strip():
        # Without an authority transcript there is nothing to compare against.
        return {"court": name, "verdict": "fail", "stage": "authority-run",
                "detail": {"exit_code": a_code, "stderr": a_err.splitlines()[:12]}}

    residuals = diff(a_out, c_out)
    crashed = a_code is None or a_code < 0 or c_code is None or c_code < 0
    record = {
        "court": name,
        "probe": rel(src),
        "authority_exit_code": a_code,
        "candidate_exit_code": c_code,
        "authority_observations": len([l for l in a_out.splitlines() if "=" in l]),
        "candidate_observations": len([l for l in c_out.splitlines() if "=" in l]),
        "residual_count": len(residuals),
        "residuals": residuals,
        # A probe that died on a signal compared nothing beyond the prefix it
        # printed, so two sides dying the same way is not agreement; see the
        # longer note in phase4_courts.py.
        "crashed": crashed,
        "verdict": (
            "pass"
            if not residuals and c_code == a_code and not crashed
            else "fail"
        ),
        "staged_binaries": staged,
        # stderr is diagnostics, not contract: it carries the internal allocation
        # counts and the tool's own warnings, which are legitimately different.
        "candidate_stderr_tail": c_err.splitlines()[-3:],
    }
    return record


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Run the Phase 3 runtime courts.")
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    work = REPO_ROOT / "court" / "phase3"
    work.mkdir(parents=True, exist_ok=True)
    DETAIL.mkdir(parents=True, exist_ok=True)

    print(f"[phase3-courts] authority={auth.id}")
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
        line = rec["verdict"]
        if rec["verdict"] == "pass":
            print(f"  {name:<12} pass   ({rec['authority_observations']} observations)")
        else:
            extra = rec.get("stage", f"{rec.get('residual_count', '?')} residual(s)")
            print(f"  {name:<12} FAIL   {extra}")
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
    doc = envelope("phase3-courts", "forensics/tools/phase3_courts.py", [],
                   body, authority=auth.id)
    doc["body_hash"] = content_hash(body)
    write_json(OUT / "COURTS.json", doc)
    print(f"  -> {rel(OUT / 'COURTS.json')} all_pass={all_pass}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
