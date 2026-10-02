#!/usr/bin/env python3
"""openssl-rs — Phase 12 courts: CMS, OCSP, CMP, CT, TS and the remaining families.

Each court is a C probe in `courts/phase12/` compiled **twice** — once against the admitted
authority, once against the candidate distribution shell — and run. The two transcripts are
compared line by line, and every difference is a residual.

The method is Phases 3-11's, for the same reason: a unit test encodes what its author believes the
contract is, whereas a probe measures what the authority actually does, and the comparison is
between two *executions* of the same program, so the expectation cannot drift.

`RT-PHASE12-REF`, and what it claims
------------------------------------
This stratum lands no behavioural court at activation, because 12.0 lands no unit of its own: the
149 exports the crate already defines were landed by earlier strata as substrate, and the five
subphases after 12.0 are what build the rest. But `court_coverage.py` refuses a stratum that has
begun while any of its implemented exports has no court edge, so those 149 names need one -- a
reference basis. `RT-PHASE12-REF`, `courts/phase12/rt_coverage_ref_probe.c`, is that basis: it
takes each into a `volatile` table, prints one `coverage_ref.N=nonnull` line per symbol, and
stops. **It does not call any of them and claims no behaviour about them.** The court coverage
atlas records every symbol covered only by it at basis `referenced`, never `called`, because the
probe's name is in that atlas's `reference_probes` table; the atlas's `claim` is the weaker, true
statement, and the atlas's phase-12 slice is the live count of the names each basis covers. See
docs/DECISIONS.md D199 and docs/PHASE-12-SUBPHASES.md section 4.3, which is where this stratum's
activation requires it.

The behavioural courts the plan gives the later subphases
---------------------------------------------------------
A court the plan names and this stratum cannot run yet is NOT registered here. It is named in
`PENDING_COURTS` with the subphase that brings it, and every name is printed on each run, so "not
run yet" cannot be read as "passed" — the contract Phase 8's `PENDING_CORRECTNESS_COURTS` and every
later activation established. `RT-PKCS7`, `RT-CMS`, `RT-CMP`, `RT-TS`, `RT-OCSP`, `RT-CRMF`,
`RT-ESS` and `RT-SRP` are the remaining subphases' own courts, and `RT-CMS-REMAINDER` is 12.9's for
the CT remainder, the shared `x_all.c` dispatch and the nine hand-offs. `RT-HTTP` was among them and
is registered by 12.1: `courts/phase12/rt_http_probe.c` drives the request/response engine over
memory BIOs (no socket, no clock). Each court not yet registered is printed with its subphase on
every run.

What the behavioural courts will compare, and what they will not
----------------------------------------------------------------
When they land, `RT-CMS`, `RT-PKCS7`, `RT-SMIME`, `RT-OCSP`, `RT-CMP`, `RT-TS`, `RT-CRMF` and
`RT-ESS` will compare the authority's *behaviour* for the container and protocol surfaces: the
DER bytes of a signed or enveloped container, the print text, the OCSP response status and
signature decision, the CMP transaction transcript and the timestamp token's `TSTInfo`. A
transcription whose writer emits bytes its own reader accepts is a different library, and
docs/PHASE-12-SUBPHASES.md section 3 records where the difference is observable. Nothing here is
a parity claim about a container's meaning.

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
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

OUT = REPO_ROOT / "artifacts" / "phase12" / "COURTS.json"
GENERATOR = "forensics/tools/phase12_courts.py"
PROBE_DIR = REPO_ROOT / "courts" / "phase12"
PHASE2 = REPO_ROOT / "artifacts" / "phase2"
STAGED = REPO_ROOT / "artifacts" / "phase12" / "probes"
RUN_TIMEOUT_S = "60"

# The differential courts, in the order they land. `(name, probe filename)`, and the probe is
# declared in the same commit as the entry, so a runner that names a probe which does not exist
# cannot be committed -- the check below fails instead.
#
# **The reference basis is the only court this activation can register.** The exports this
# stratum inherited are implemented and `court_coverage.py` requires an edge for each, and none of
# the stratum's own units is built yet, so no behavioural probe can link. The five later rows are
# the plan's own courts, named in `PENDING_COURTS` below rather than registered.
COURTS: list[tuple[str, str]] = [
    ("RT-PHASE12-REF", "rt_coverage_ref_probe.c"),
    ("RT-HTTP", "rt_http_probe.c"),
    ("RT-PKCS7", "rt_pkcs7_probe.c"),
    ("RT-CMS", "rt_cms_probe.c"),
]

# A court the plan names and this stratum cannot run yet. Not a registered court: nothing here can
# pass, and each is printed with the subphase that brings it so that "not run yet" cannot be read
# as "passed". The court names are `docs/PHASE-12-SUBPHASES.md` section 2's, one per work
# subphase; `RT-CRMF` and `RT-ESS` are the two courts of 12.7, whose two families share a
# subphase but not a court.
PENDING_COURTS: dict[str, str] = {
    "RT-CMP": "12.4 -- the CMP transaction surface (`cmp.h`, `cmp_util.h`)",
    "RT-TS": "12.5 -- the timestamping surface (`ts.h`)",
    "RT-OCSP": "12.6 -- the OCSP request/response surface (`ocsp.h`'s 94 open exports)",
    "RT-CRMF": "12.7 -- the CRMF certificate-request surface (`crmf.h`)",
    "RT-ESS": "12.7 -- the ESS signing-certificate surface (`ess.h`)",
    "RT-SRP": "12.8 -- the SRP verifier and library surface (`srp.h`)",
    "RT-CMS-REMAINDER": "12.9 -- the CT remainder, the shared `x_all.c` dispatch and the nine "
                        "hand-offs",
}


def extra_defs(name: str, libdir: Path) -> list[str]:
    """Per-side build definitions.

    **None.** `RT-PHASE12-REF` takes addresses and prints whether each is non-NULL; it is compiled
    identically on both sides, so a difference in either transcript can only be a difference in
    what the library does. `extra_defs` is kept because the runner's shape is Phase 8's through
    Phase 11's and a later court here may need one.
    """
    del name, libdir
    return []


def compile_probe(
    src: Path, out: Path, include: Path, libdir: Path, defs: list[str] | None = None
) -> tuple[bool, str]:
    res = run([
        # `-Werror=implicit-function-declaration` is not decoration: without a prototype, C
        # assumes a function returns `int`, so a probe that forgot an include reads a pointer
        # return as its low 32 bits and dereferences it. Phases 6 through 11 each paid a run to
        # learn that, so it is a compile failure here.
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
    """Line-wise comparison keyed on `key=value`, so a missing or extra line produces exactly one
    residual instead of shifting every following line."""
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
    # A probe that died on a signal compared nothing beyond the prefix it managed to print, so two
    # sides dying the same way is not agreement.
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
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    work = REPO_ROOT / "court" / "phase12"
    work.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
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
        "pending_courts": PENDING_COURTS,
        "claim": (
            "`RT-PHASE12-REF` is a **reference-basis** court: its probe takes the address of "
            "each of this stratum's 149 inherited `implemented` exports -- the `ocsp_asn.c` item "
            "group, the CT `ct_*` units, `pk7_asn1.c`/`pk7_lib.c` and `http_lib.c`'s "
            "`OSSL_parse_url` -- and prints whether each is non-NULL. A symbol covered only by it "
            "means the candidate distribution defines the name -- which the link proves -- and "
            "NOT that any arm of it was driven; the court coverage atlas records those at basis "
            "`referenced`, never `called` (docs/DECISIONS.md D199). `RT-HTTP`, landed by 12.1, is "
            "the first behavioural court here: `rt_http_probe.c` drives the `OSSL_HTTP_REQ_CTX_*` "
            "engine over memory BIOs and the high-level `OSSL_HTTP_*` path with a supplied BIO "
            "pair, comparing the two transcripts line by line. The plan's remaining courts "
            "(`pending_courts`) are each printed with the subphase that brings them, so 'not run "
            "yet' cannot be read as 'passed'. Nothing here is a parity claim: `referenced` is not "
            "`called`, and docs/PHASE-12-SUBPHASES.md section 3 records what the behavioural "
            "courts compare."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols", path=REPO_ROOT / "forensics" / "atlas"
                 / auth.id / "symbols-libcrypto.json"),
    ]
    for _name, filename in COURTS:
        inputs.append(InputRef(name="probe", path=PROBE_DIR / filename))
    doc = envelope(kind="phase12-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for r in records:
        if r["verdict"] == "pass":
            print(f"  {r['court']:<18} pass   "
                  f"({r['authority_observations']} observations)")
        else:
            print(f"  {r['court']:<18} FAIL   stage={r.get('stage', 'compare')}")
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
    for name, needs in PENDING_COURTS.items():
        print(f"  {name:<18} PENDING (not registered as passing) -- {needs}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
