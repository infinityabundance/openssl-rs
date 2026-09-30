#!/usr/bin/env python3
"""openssl-rs — Phase 11 courts: X.509 and verification.

Each court is a C probe in `courts/phase11/` compiled **twice** — once against the admitted
authority, once against the candidate distribution shell — and run. The two transcripts are
compared line by line, and every difference is a residual.

The method is Phases 3-10's, for the same reason: a unit test encodes what its author believes the
contract is, whereas a probe measures what the authority actually does, and the comparison is
between two *executions* of the same program, so the expectation cannot drift.

`RT-X509-REF` is the one court this stratum can register, and what it claims
--------------------------------------------------------------------------------
The stratum's own work has landed nothing: no store, no verification engine, no attribute
certificate, no PEM X.509 container. What it *has* is 954 exports earlier strata landed and it now
owns — the 952 atlas-owned exports of Phase 8's 8.8 chain and Phase 10's pulled-forward X.509
subphases (10.8-10.16, D442-D451), and the two `ASN1_generate_*` hand-offs of Phase 5 — and
`court_coverage.py` refuses a stratum that has begun while any of its implemented exports has no
court edge. So this runner lands `RT-X509-REF`, `courts/phase11/rt_coverage_ref_probe.c`: it takes
each of the 954's address through a `volatile` table, prints one `coverage_ref.N=nonnull` line per
symbol, and stops. **It does not call any of them and claims no behaviour about them.** The court
coverage atlas records every symbol covered only by it at basis `referenced`, never `called`,
because the probe's name is in that atlas's `reference_probes` table; the atlas's `claim` is the
weaker, true statement. See docs/DECISIONS.md D199 and docs/PHASE-11-SUBPHASES.md section 4.3,
which is where this stratum's activation requires it.

A court the plan names and this stratum cannot run yet is NOT registered here. It is named in
`PENDING_COURTS` with the subphase that brings it, and every name is printed on each run, so "not
run yet" cannot be read as "passed" — the contract Phase 8's `PENDING_CORRECTNESS_COURTS` and every
later activation established.

What the pending courts will establish, and what they will not
--------------------------------------------------------------
`RT-X509-STORE`, `RT-X509-VERIFY`, `RT-X509-ACERT`, `RT-X509-REQ`, `RT-X509-V3`, `RT-X509-PEM`
and `RT-X509` compare the authority's *behaviour* for the subphases that land them: the container
bytes and the print text for the object graphs (section 3.1), the decision, error code, depth and
callback sequence of `X509_verify_cert` (section 3.2), the lookup refusals and cache behaviour
(section 3.3), and the PEM text and malformed-input error coordinates (section 3.4). None of them
can claim that an object that round-trips is the authority's object: a transcription whose writer
emits bytes its own reader accepts is a different library, and docs/PHASE-11-SUBPHASES.md
section 3 records where the difference is observable. Nothing here is a parity claim about a
certificate's meaning (section 3.5).

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

OUT = REPO_ROOT / "artifacts" / "phase11" / "COURTS.json"
GENERATOR = "forensics/tools/phase11_courts.py"
PROBE_DIR = REPO_ROOT / "courts" / "phase11"
PHASE2 = REPO_ROOT / "artifacts" / "phase2"
STAGED = REPO_ROOT / "artifacts" / "phase11" / "probes"
RUN_TIMEOUT_S = "60"

# The differential courts, in the order they land. `(name, probe filename)`, and the probe is
# declared in the same commit as the entry, so a runner that names a probe which does not exist
# cannot be committed -- the check below fails instead.
#
# **One entry, and it is the reference basis rather than a behavioural court.** It is registered
# because the 954 exports this stratum inherited are implemented and `court_coverage.py` requires
# an edge for each; it is the only probe this stratum can link, since none of its own units is
# built. See the module doc.
COURTS: list[tuple[str, str]] = [
    ("RT-X509-REF", "rt_coverage_ref_probe.c"),
]

# A court the plan names and this stratum cannot run yet. Not a registered court: nothing here can
# pass, and each is printed with the subphase that brings it so that "not run yet" cannot be read
# as "passed". The court names are `docs/PHASE-11-SUBPHASES.md` section 2's, one per work
# subphase; `RT-X509` is 11.7's, over the units whose closure crosses into the landed strata.
PENDING_COURTS: dict[str, str] = {
    "RT-X509-STORE": "11.1 -- the `X509_STORE` object, the four `X509_LOOKUP_METHOD`s, the "
                     "`X509_OBJECT` cache and the file/`dir`/store lookups (`x509_lu.c`, "
                     "`x509_meth.c`, `x509_trust.c`, `x509_d2.c`, `by_*.c`)",
    "RT-X509-VERIFY": "11.2 -- `X509_verify_cert`, the `X509_STORE_CTX` chain builder, the "
                      "`X509_VERIFY_PARAM_*` surface and the policy tree (`x509_vfy.c`, "
                      "`x509_vpm.c`, `pcy_tree.c`)",
    "RT-X509-ACERT": "11.3 -- the `X509_ACERT` item group and its accessors, setters and "
                     "`X509_ACERT_verify` (`x509_acert.c`, `x509aset.c`, `x_ietfatt.c`, "
                     "`t_acert.c`)",
    "RT-X509-REQ": "11.4 -- `X509_REQ`, the `X509_set_*`/`X509_CRL_set_*` mutators, the "
                   "extension accessors and `X509_to_X509_REQ` (`x509_req.c`, `x509_set.c`, "
                   "`x_req.c`, `x_crl.c`, `x_exten.c`, `t_*.c`)",
    "RT-X509-V3": "11.5 -- `X509V3_EXT_nconf(_file)`, the `X509V3_EXT_*` helpers and the "
                  "`GENERAL_NAMES`/`IPAddressFamily`/`ASIdentifiers` printers (`v3_conf.c`, "
                  "`v3_utl.c`, `v3_prn.c`, `v3_addr.c`, `v3_asid.c`)",
    "RT-X509-PEM": "11.6 -- the `PEM_read[_bio]_X509*`/`PEM_write[_bio]_X509*` and "
                   "`PEM_X509_INFO_*` container surface (`pem_all.c`, `pem_pk8.c`, "
                   "`pem_info.c`, `pem_x509.c`, `pem_xaux.c`)",
    "RT-X509": "11.7 -- the remaining shared units whose closure crosses into the landed "
               "strata (`x_all.c`, `p5_scrypt.c`, `nsseq.c`, `x509_def.c`, `x_info.c`, "
               "`x_pkey.c`, `evp_lib.c`, `evp_pkey.c`, `t_spki.c`, `p12_mutl.c`, "
               "`asn_mstbl.c`)",
}


def extra_defs(name: str, libdir: Path) -> list[str]:
    """Per-side build definitions.

    **None.** The one probe this stratum registers takes addresses and prints whether each is
    non-NULL; it is compiled identically on both sides, so a difference in its transcript could
    only be a difference in what the library defines. `extra_defs` is kept because the runner's
    shape is Phase 8's through Phase 10's and a later court here may need one.
    """
    del name, libdir
    return []


def compile_probe(
    src: Path, out: Path, include: Path, libdir: Path, defs: list[str] | None = None
) -> tuple[bool, str]:
    res = run([
        # `-Werror=implicit-function-declaration` is not decoration: without a prototype, C
        # assumes a function returns `int`, so a probe that forgot an include reads a pointer
        # return as its low 32 bits and dereferences it. Phases 6 through 10 each paid a run to
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
    work = REPO_ROOT / "court" / "phase11"
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
            "`RT-X509-REF` is a **reference-basis** court: its probe takes the address of each "
            "of this stratum's 954 inherited `implemented` exports and prints whether each is "
            "non-NULL. A symbol covered only by it means the candidate distribution defines the "
            "name -- which the link proves -- and NOT that any arm of it was driven; the court "
            "coverage atlas records those at basis `referenced`, never `called` (docs/DECISIONS.md "
            "D199). **This stratum has landed no unit of its own**, so `RT-X509-REF` is the only "
            "court it can register until 11.1: none of the store, verification, attribute-"
            "certificate, request, `v3` or PEM surfaces exists, and a probe that called one would "
            "need the very object graph this stratum has not built. "
            "`pending_courts` names the courts the plan gives this stratum "
            "(docs/PHASE-11-SUBPHASES.md section 2) and the subphase that brings each, and "
            "every name is printed on each run so that 'not run yet' cannot be read as 'passed'. "
            "Nothing here is a parity claim: `referenced` is not `called`, and "
            "docs/PHASE-11-SUBPHASES.md section 3 records what the behavioural courts must "
            "compare when they land."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols", path=REPO_ROOT / "forensics" / "atlas"
                 / auth.id / "symbols-libcrypto.json"),
    ]
    for _name, filename in COURTS:
        inputs.append(InputRef(name="probe", path=PROBE_DIR / filename))
    doc = envelope(kind="phase11-courts", authority=auth.id, inputs=inputs,
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
