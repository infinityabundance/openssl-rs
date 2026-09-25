#!/usr/bin/env python3
"""openssl-rs — Phase 10 courts: key formats, PKCS#12 and STORE.

Each court is a C probe in `courts/phase10/` compiled **twice** — once against the admitted
authority, once against the candidate distribution shell — and run. The two transcripts are
compared line by line, and every difference is a residual.

The method is Phases 3-9's, for the same reason: a unit test encodes what its author believes the
contract is, whereas a probe measures what the authority actually does, and the comparison is
between two *executions* of the same program, so the expectation cannot drift.

`RT-KEYFORMAT-REF` is the one court this stratum can register, and what it claims
-------------------------------------------------------------------------------
The stratum's own work has landed nothing: no codec row, no PKCS#12 container, no STORE module,
no hand-off. What it *has* is eighty-seven exports an earlier stratum landed and it now owns —
the 38 `encoder.h` and 41 `decoder.h` exports of Phase 8's 8.8/8.9 chain (D362-D367) and the
eight `pkcs12.h` decryption and PKCS#8 names of D368 — and `court_coverage.py` refuses a
stratum that has begun while any of its implemented exports has no court edge. So this runner
lands `RT-KEYFORMAT-REF`, `courts/phase10/rt_coverage_ref_probe.c`: it takes each of the
eighty-seven's address through a `volatile` table, prints one `coverage_ref.N=nonnull` line per
symbol, and stops. **It does not call any of them and claims no behaviour about them.** The
court coverage atlas records every symbol covered only by it at basis `referenced`, never
`called`, because the probe's name is in that atlas's `reference_probes` table; the atlas's
`claim` is the weaker, true statement. See docs/DECISIONS.md D199 and
docs/PHASE-10-SUBPHASES.md section 4.3, which is where this stratum's activation requires it.

A court the plan names and this stratum cannot run yet is NOT registered here. It is named in
`PENDING_COURTS` with the subphase and the corpus or precondition that brings it, and every name
is printed on each run, so "not run yet" cannot be read as "passed" — the contract Phase 8's
`PENDING_CORRECTNESS_COURTS` and Phase 9's activation both established.

What the pending courts will establish, and what they will not
--------------------------------------------------------------
`RT-CODEC` and `RT-KEYFORMAT` compare the authority's *bytes* for the codecs and the hand-off
helpers: `OSSL_ENCODER_to_data`/`to_bio`/`to_fp`'s exact output, the error queue and coordinate
for a malformed input, the alias and selection behaviour under `set_output_type`/`set_selection`,
and the same shape for the `d2i_*`/`i2d_*`/`PEM_*` pairs. `RT-PKCS12` compares the container's
DER rather than a parsed structure, and `CT-PKCS12` checks the PKCS#12 KDF and PBE outputs
against the vectors the pinned tree already carries. None of them can claim that a codec which
round-trips is a codec: a transcription whose encoder writes and whose decoder reads back is a
different library, and docs/PHASE-10-SUBPHASES.md section 3.1 records the three joins that make
the difference observable. Nothing here is a parity claim about a key's meaning (section 3.5).

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

OUT = REPO_ROOT / "artifacts" / "phase10" / "COURTS.json"
GENERATOR = "forensics/tools/phase10_courts.py"
PROBE_DIR = REPO_ROOT / "courts" / "phase10"
PHASE2 = REPO_ROOT / "artifacts" / "phase2"
STAGED = REPO_ROOT / "artifacts" / "phase10" / "probes"
RUN_TIMEOUT_S = "60"

# The differential courts, in the order they land. `(name, probe filename)`, and the probe is
# declared in the same commit as the entry, so a runner that names a probe which does not exist
# cannot be committed -- the check below fails instead.
#
# **One entry, and it is the reference basis rather than a behavioural court.** It is registered
# because the eighty-seven exports this stratum inherited are implemented and
# `court_coverage.py` requires an edge for each; it is the only probe this stratum can link,
# since none of its own rows is implemented. See the module doc.
COURTS: list[tuple[str, str]] = [
    ("RT-KEYFORMAT-REF", "rt_coverage_ref_probe.c"),
]

# A court the plan names and this stratum cannot run yet. Not a registered court: nothing here
# can pass, and each is printed with the subphase that brings it so that "not run yet" cannot be
# read as "passed".
PENDING_COURTS: dict[str, str] = {
    "RT-CODEC": "10.1 -- the 241 `OSSL_OP_ENCODER` and 76 `OSSL_OP_DECODER` rows and the "
                "codecs behind them, driven through the public `OSSL_ENCODER_*`/"
                "`OSSL_DECODER_*` surface: the exact bytes of `to_data`/`to_bio`/`to_fp`, the "
                "error queue and coordinate for a malformed input, and the alias and selection "
                "behaviour under `set_output_type`/`set_selection`. The framework's 79 exports "
                "are already landed (8.8's D362-D367), so the probe cannot be written before "
                "the rows are, and a probe that reached an unimplemented row aborts the "
                "candidate (docs/PHASE-10-SUBPHASES.md sections 3.1 and 3.5).",
    "RT-PKCS12": "10.2-10.4 -- the `PKCS12` container and its ASN.1, compared as DER bytes and "
                 "not as a parsed structure: the `PFX` order, the `SafeBag` attribute set and "
                 "its ordering, the `MacData`'s `digestAlgorithm`/`salt`/`iterations`, and the "
                 "`PKCS12_gen_mac`/`PKCS12_verify_mac` pair. Every container symbol is open -- "
                 "the eight decryption names already landed are referenced by "
                 "`RT-KEYFORMAT-REF`, not driven -- so the court lands with 10.2-10.4 "
                 "(docs/PHASE-10-SUBPHASES.md section 3.2).",
    "CT-PKCS12": "10.4 -- the PKCS#12 KDF and PBE construction vectors, whose corpus the pinned "
                 "tree already carries: `test/recipes/30-test_evp_data/evppbe_pkcs12.txt` and "
                 "its `evppbe_pbkdf2.txt` sibling, with the `80-test_pkcs12.t` recipe data. "
                 "Candidate-only, like every `CT-*` court (docs/DECISIONS.md D201); no network "
                 "fetch is needed and none is permitted (docs/AUTHORITY_POLICY.md).",
    "RT-STORE": "10.5 -- `OSSL_STORE_open(_ex)` and the `file` loader, the `OSSL_STORE_INFO` "
                "type and its constructor/accessor family, the `OSSL_STORE_LOADER` object and "
                "its registry, and the `OSSL_STORE_SEARCH` family: the `OSSL_STORE_INFO` type "
                "and refcount surface, the `eof`/`error`/`expect` state machine, and the "
                "refusal arms (an unknown scheme, a NULL URI, a loader that answers a NULL "
                "`load`) with the error queue. The loader's sub-fetches resolve in the "
                "publishing provider's library context (D240) and the decoder arm lands after "
                "10.4's pair, so it cannot be written before then "
                "(docs/PHASE-10-SUBPHASES.md section 3.3).",
    "RT-KEYFORMAT": "10.6 -- the 26 symbols phases 5 and 7 handed forward: the PVK and PKCS#8 "
                    "container reads and writes, the four `d2i_PrivateKey*`/"
                    "`d2i_AutoPrivateKey*` and the five `i2d_*` names, and "
                    "`PEM_write_bio_PrivateKey_traditional`, compared by the exact bytes of a "
                    "fixed key and the error queue and coordinate of each malformed-input arm. "
                    "Every one is open, and the `d2i_PrivateKey*` pair is the subtle one: it "
                    "tries `d2i_PrivateKey_decoder` first and falls back to "
                    "`ossl_d2i_PrivateKey_legacy` (`crypto/asn1/d2i_pr.c:172`-`:175`, `:247`-"
                    "`:250`), so a probe that only drove the provider path would measure half "
                    "the function (docs/PHASE-10-SUBPHASES.md section 3.4).",
}


def extra_defs(name: str, libdir: Path) -> list[str]:
    """Per-side build definitions.

    **None.** The one probe this stratum registers takes addresses and prints whether each is
    non-NULL; it is compiled identically on both sides, so a difference in its transcript could
    only be a difference in what the library defines. `extra_defs` is kept because the runner's
    shape is Phase 8's and Phase 9's and a later court here may need one.
    """
    del name, libdir
    return []


def compile_probe(
    src: Path, out: Path, include: Path, libdir: Path, defs: list[str] | None = None
) -> tuple[bool, str]:
    res = run([
        # `-Werror=implicit-function-declaration` is not decoration: without a prototype, C
        # assumes a function returns `int`, so a probe that forgot an include reads a pointer
        # return as its low 32 bits and dereferences it. Phases 6 and 7 both paid a run to learn
        # that, so it is a compile failure here.
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
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    work = REPO_ROOT / "court" / "phase10"
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
            "`RT-KEYFORMAT-REF` is a **reference-basis** court: its probe takes the address "
            "of each of this stratum's eighty-seven inherited `implemented` exports and prints "
            "whether each is non-NULL. A symbol covered only by it means the candidate "
            "distribution defines the name -- which the link proves -- and NOT that any arm of "
            "it was driven; the court coverage atlas records those at basis `referenced`, never "
            "`called` (docs/DECISIONS.md D199). "
            "**No behavioural court has landed:** every one of this stratum's own rows and "
            "hand-offs is unimplemented, so nothing about the key-format layer is verified "
            "here. `pending_courts` names the courts the plan gives this stratum and the "
            "subphase that brings each, and every name is printed on each run so that 'not run "
            "yet' cannot be read as 'passed' (docs/PHASE-10-SUBPHASES.md sections 3 and 4.3)."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols", path=REPO_ROOT / "forensics" / "atlas"
                 / auth.id / "symbols-libcrypto.json"),
    ]
    for _name, filename in COURTS:
        inputs.append(InputRef(name="probe", path=PROBE_DIR / filename))
    doc = envelope(kind="phase10-courts", authority=auth.id, inputs=inputs,
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
