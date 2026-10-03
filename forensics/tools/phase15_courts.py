#!/usr/bin/env python3
"""openssl-rs — Phase 15 courts: QUIC / ECH and modern SSL surface.

Each court is a C probe in `courts/phase15/` compiled **twice** — once against the admitted
authority, once against the candidate distribution shell — and run. The two transcripts are
compared line by line, and every difference is a residual.

The method is Phases 3-14's, for the same reason: a unit test encodes what its author believes
the contract is, whereas a probe measures what the authority actually does, and the comparison
is between two *executions* of the same program, so the expectation cannot drift. The namespace
is libssl's, so every probe links `-lssl -lcrypto`.

`RT-PHASE15-REF`, and what it claims
------------------------------------
This stratum's atlas-owned universe is exactly the three `quic.h` exports 14.12 left it:
`OSSL_QUIC_client_method`, `OSSL_QUIC_client_thread_method` and `OSSL_QUIC_server_method`.
`courts/phase15/rt_coverage_ref_probe.c` takes the address of each into a `volatile` table,
prints one `coverage_ref.N=nonnull` line per symbol, and stops. **It does not call any of them
and claims no behaviour about them.** At activation the candidate distribution defined all three
through the Phase 2 ABI scaffold (`artifacts/phase2/shell/libssl.shell.rs`), which aborts when
called, so the link was the evidence that each name exists and taking an address rather than
calling was what kept the scaffold from firing. Once this stratum lands
`src/ssl/quic/quic_method.rs` the candidate defines them for real and the same probe still takes
addresses. The atlas records a symbol covered only here at basis `referenced`, never `called`
(docs/DECISIONS.md D199). See docs/PHASE-15-SUBPHASES.md section 4.2.

`RT-QUIC`, and what it claims
-----------------------------
`courts/phase15/rt_quic_probe.c` is the stratum's **behavioural** court: it drives the three
constructors the module lands. It compares each constructor's non-NULL return, the distinctness of
the three process-lifetime statics, `SSL_CTX_new`'s acceptance of each, the method identity
`SSL_CTX_get_ssl_method` reports back, the method's own `tls1_default_timeout` through
`SSL_CTX_get_timeout`, the version-inflexible protocol-bound arm (a QUIC method is neither
`TLS_ANY_VERSION` nor `DTLS_ANY_VERSION`, so `ssl_set_version_bound` ignores the bound and the
context keeps reporting its zero) and the NULL-method refusal. It does **not** drive `SSL_new`:
the QUIC connection object is not built here, so a candidate connection from these methods is an
ordinary `SSL` object and reports `SSL_is_quic == 0` where the authority reports `1`. That
divergence is recorded in `src/ssl/quic/quic_method.rs` rather than diffed as a residual.

The behavioural courts later subphases bring
--------------------------------------------
None is registered here and none is pending: this stratum's whole atlas-owned universe is the
three `quic.h` constructors, `RT-QUIC` drives all three, and the QUIC implementation object the
methods name is not this unit's. So `PENDING_COURTS` is empty, and "nothing pending" here is a
measurement rather than a court being quietly dropped.

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

OUT = REPO_ROOT / "artifacts" / "phase15" / "COURTS.json"
GENERATOR = "forensics/tools/phase15_courts.py"
PROBE_DIR = REPO_ROOT / "courts" / "phase15"
PHASE2 = REPO_ROOT / "artifacts" / "phase2"
STAGED = REPO_ROOT / "artifacts" / "phase15" / "probes"
RUN_TIMEOUT_S = "60"

# The differential courts, in the order they land. `(name, probe filename)`, and the probe is
# declared in the same commit as the entry, so a runner that names a probe which does not exist
# cannot be committed -- the check below fails instead.
COURTS: list[tuple[str, str]] = [
    ("RT-PHASE15-REF", "rt_coverage_ref_probe.c"),
    ("RT-QUIC", "rt_quic_probe.c"),
]

# A court the plan names and this stratum cannot run yet. **Empty, and here that is a
# measurement**: every court `docs/PHASE-15-SUBPHASES.md` section 2 names is registered above,
# because the stratum's whole atlas-owned universe is three constructors and one behavioural
# court covers them.
PENDING_COURTS: dict[str, str] = {}


def extra_defs(name: str, libdir: Path) -> list[str]:
    """Per-side build definitions.

    **None.** The reference probe takes addresses and prints whether each is non-NULL; `RT-QUIC`
    is compiled identically on both sides. A difference in either transcript can therefore only be
    a difference in what the library does. `extra_defs` is kept because the runner's shape is
    Phase 8's through Phase 14's and a later court here may need one.
    """
    del name, libdir
    return []


def compile_probe(
    src: Path, out: Path, include: Path, libdir: Path, defs: list[str] | None = None
) -> tuple[bool, str]:
    res = run([
        # `-Werror=implicit-function-declaration` is not decoration: without a prototype, C
        # assumes a function returns `int`, so a probe that forgot an include reads a pointer
        # return as its low 32 bits and dereferences it. Phases 6 through 14 each paid a run to
        # learn that, so it is a compile failure here.
        "clang", "-std=c11", "-Wall", "-Werror=implicit-function-declaration", "-O1",
        "-D_GNU_SOURCE",
        *(defs or []),
        "-I", str(include),
        "-o", str(out), str(src),
        # This stratum's namespace is libssl; libcrypto is named too because libssl's own
        # dynamic table depends on it and the linker resolves the pair as a unit.
        "-L", str(libdir), "-lssl", "-lcrypto",
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
    work = REPO_ROOT / "court" / "phase15"
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
            "`RT-PHASE15-REF` is the activation **reference basis**: its probe takes the address "
            "of each of the stratum's three atlas-owned `quic.h` exports and prints whether each "
            "is non-NULL. A symbol covered only by it means the candidate distribution defines "
            "the name -- which the link proves -- and NOT that any arm of it was driven; the "
            "court coverage atlas records those at basis `referenced`, never `called` "
            "(docs/DECISIONS.md D199). `RT-QUIC` is the stratum's **behavioural** court: "
            "`courts/phase15/rt_quic_probe.c` drives the three `OSSL_QUIC_*_method` constructors "
            "`src/ssl/quic/quic_method.rs` lands -- the non-NULL returns and the distinctness of "
            "the three statics, `SSL_CTX_new`'s acceptance of each and the identity "
            "`SSL_CTX_get_ssl_method` reports back, the method's `tls1_default_timeout`, the "
            "version-inflexible protocol-bound arm, and the NULL-method refusal -- and the two "
            "transcripts are compared line by line. It does not drive `SSL_new`: the QUIC "
            "connection object is not this unit's, so a candidate connection from these methods "
            "reports `SSL_is_quic == 0` where the authority reports `1`, and that divergence is "
            "recorded in the module rather than diffed. Nothing here is a parity claim about a "
            "completed handshake, which no arm drives; docs/PHASE-15-SUBPHASES.md section 3 "
            "records what the court compares."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols", path=REPO_ROOT / "forensics" / "atlas"
                 / auth.id / "symbols-libssl.json"),
    ]
    for _name, filename in COURTS:
        inputs.append(InputRef(name="probe", path=PROBE_DIR / filename))
    doc = envelope(kind="phase15-courts", authority=auth.id, inputs=inputs,
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
