#!/usr/bin/env python3
"""openssl-rs — Phase 14 courts: TLS / DTLS (libssl).

Each court is a C probe in `courts/phase14/` compiled **twice** — once against the admitted
authority, once against the candidate distribution shell — and run. The two transcripts are
compared line by line, and every difference is a residual.

The method is Phases 3-13's, for the same reason: a unit test encodes what its author believes
the contract is, whereas a probe measures what the authority actually does, and the comparison
is between two *executions* of the same program, so the expectation cannot drift. The one
difference is the namespace: every earlier stratum's probes link `-lcrypto`, and this stratum's
link `-lssl`, because libssl is the distribution's second namespace with its own export set and
its own installed `ssl.h`/`tls1.h`/`srtp.h`/`sslerr_legacy.h`.

`RT-PHASE14-REF`, and what it claims
------------------------------------
This stratum is the first whose reference basis covers an export set **none of which is
implemented at activation**: libssl's own stratum lands nothing before 14.1, so
`forensics/atlas/implemented-surface.json` records `0` implemented `libssl` symbols.
`courts/phase14/rt_coverage_ref_probe.c` takes the address of each of the stratum's 600
atlas-owned exports into a `volatile` table, prints one `coverage_ref.N=nonnull` line per
symbol, and stops. **It does not call any of them and claims no behaviour about them.** The
candidate distribution defines every one through the Phase 2 ABI scaffold
(`artifacts/phase2/shell/libssl.shell.rs`), which aborts when called, so the link is the evidence
that the name exists and taking an address rather than calling is what keeps the scaffold from
firing. The atlas records a symbol covered only here at basis `referenced`, never `called`
(docs/DECISIONS.md D199); because the stratum implements nothing yet, its phase-14 row binds no
`referenced` name at activation, and the basis is registered so the join has a probe for the
stratum from the day it begins. See docs/PHASE-14-SUBPHASES.md section 4.3.

The behavioural courts the plan gives the later subphases
---------------------------------------------------------
Every court `docs/PHASE-14-SUBPHASES.md` section 2 names is named in `PENDING_COURTS` below with
the subphase that brings it, unless that subphase has landed its court. `RT-SSL-OBJECT` (14.1),
`RT-SSL-METHODS` (14.2), `RT-SSL-CIPH` (14.3), `RT-RECORD` (14.4), `RT-STATEM` (14.5),
`RT-SSL-BIO` (14.6), `RT-DTLS` (14.8) and `RT-SSL-INIT` (14.10) are registered below;
`RT-SESSION-CERT`, `RT-SSL-EXT` and `RT-HANDOFF` remain pending, so 'not run yet' cannot be read
as 'passed'.

What the behavioural courts will compare, and what they will not
----------------------------------------------------------------
The object, method, cipher and configuration courts will compare the authority's *behaviour*: the
`SSL_CTX`/`SSL` lifecycle and refcount, the accessor and control surface, the method/version
tables each `TLS_*`/`DTLS_*` constructor returns, the cipher-list and `SSL_CONF_cmd` parsers over
fixed strings, and the certificate/session plumbing over fixed fixtures. The record-layer,
state-machine and BIO courts will drive the record framing, the handshake state transitions
read through `SSL_get_state`/`SSL_in_init`, and the BIO pair over memory BIOs, comparing what the
authority's own returns report. The DTLS court will drive `DTLSv1_listen` and the SRTP profile
extensions over fixed datagrams. Nothing here is a parity claim about the meaning of a completed
handshake: the measured surface is what each court names, and an arm that cannot be made
observable is named `pending` rather than counted as passing.

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

OUT = REPO_ROOT / "artifacts" / "phase14" / "COURTS.json"
GENERATOR = "forensics/tools/phase14_courts.py"
PROBE_DIR = REPO_ROOT / "courts" / "phase14"
PHASE2 = REPO_ROOT / "artifacts" / "phase2"
STAGED = REPO_ROOT / "artifacts" / "phase14" / "probes"
RUN_TIMEOUT_S = "60"

# The differential courts, in the order they land. `(name, probe filename)`, and the probe is
# declared in the same commit as the entry, so a runner that names a probe which does not exist
# cannot be committed -- the check below fails instead.
# Rows are appended as each subphase lands its court; a court whose probe the stratum cannot yet
# link stays in `PENDING_COURTS` below, so "not run yet" is never read as "passed".
COURTS: list[tuple[str, str]] = [
    ("RT-PHASE14-REF", "rt_coverage_ref_probe.c"),
    ("RT-SSL-OBJECT", "rt_ssl_object_probe.c"),
    ("RT-SSL-METHODS", "rt_ssl_methods_probe.c"),
    ("RT-SSL-CIPH", "rt_ssl_ciph_probe.c"),
    ("RT-RECORD", "rt_record_probe.c"),
    ("RT-STATEM", "rt_statem_probe.c"),
    ("RT-SSL-BIO", "rt_ssl_bio_probe.c"),
    ("RT-DTLS", "rt_dtls_probe.c"),
    ("RT-SSL-INIT", "rt_ssl_init_probe.c"),
]

# A court the plan names and this stratum cannot run yet. **Every one of the plan's behavioural
# courts is here at activation**, because 14.0 lands no unit of its own: the stratum's whole
# working set is open and the only court it can register is the reference basis. Each row is
# printed with the subphase that brings it so that "not run yet" cannot be read as "passed".
PENDING_COURTS: dict[str, str] = {
    "RT-SESSION-CERT": "14.7 (the session and certificate plumbing)",
    "RT-SSL-EXT": "14.9 (the TLS extension and SRP surface)",
    "RT-HANDOFF": "14.11 (the received hand-offs)",
}


def extra_defs(name: str, libdir: Path) -> list[str]:
    """Per-side build definitions.

    **None.** `RT-PHASE14-REF` takes addresses and prints whether each is non-NULL; it is compiled
    identically on both sides, so a difference in either transcript can only be a difference in
    what the library does. `extra_defs` is kept because the runner's shape is Phase 8's through
    Phase 13's and a later court here may need one.
    """
    del name, libdir
    return []


def compile_probe(
    src: Path, out: Path, include: Path, libdir: Path, defs: list[str] | None = None
) -> tuple[bool, str]:
    res = run([
        # `-Werror=implicit-function-declaration` is not decoration: without a prototype, C
        # assumes a function returns `int`, so a probe that forgot an include reads a pointer
        # return as its low 32 bits and dereferences it. Phases 6 through 13 each paid a run to
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
    work = REPO_ROOT / "court" / "phase14"
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
            "`RT-PHASE14-REF` is the activation **reference basis**: its probe takes the address "
            "of each of the stratum's 600 atlas-owned `ssl.h`/`tls1.h`/`srtp.h`/`sslerr_legacy.h` "
            "exports and prints whether each is non-NULL. A symbol covered only by it means the "
            "candidate distribution defines the name -- which the link proves -- and NOT that any "
            "arm of it was driven; the court coverage atlas records those at basis `referenced`, "
            "never `called` (docs/DECISIONS.md D199). `RT-SSL-OBJECT` (14.1) is the stratum's "
            "first **behavioural** court: `courts/phase14/rt_ssl_object_probe.c` drives the "
            "`SSL_CTX`/`SSL` object model -- allocation, refcount, ex-data, the accessor and "
            "control surface, the callback setters, `SSL_set_bio` over memory BIOs and the "
            "NULL/uninitialised arms -- against a fixed `TLS_method()`, and the two transcripts "
            "are compared line by line. `RT-SSL-METHODS` (14.2) is the second: "
            "`courts/phase14/rt_ssl_methods_probe.c` drives the 21 `TLS_*`/`DTLS_*`/`TLSv1_*` "
            "constructors and the version surface each installs (`SSL_version`, "
            "`SSL_client_version`, `SSL_get_version`, `SSL_is_dtls`, `SSL_is_server`, the "
            "the `min`/`max` protocol getters and the default timeout), `SSL_group_to_name`'s "
            "unknown-NID arms, `SSL_get0_group_name`'s NULL-connection arm and the "
            "ticket-key callback setter, and the two refusal arms. `RT-SSL-CIPH` (14.3) is the "
            "third: `courts/phase14/rt_ssl_ciph_probe.c` drives the `SSL_CIPHER_*` readers over "
            "fixed wire ids through `SSL_CIPHER_find`, the `OSSL_default_*` strings, the "
            "`SSL_CTX_set_cipher_list`/`SSL_CTX_set_ciphersuites`/`SSL_CTX_get_ciphers` / "
            "`SSL_get_ciphers`/`SSL_get_cipher_list` surface, and the `SSL_CONF_CTX_new`/"
            "`SSL_CONF_cmd`/`SSL_CONF_cmd_value_type`/`SSL_CONF_CTX_finish` parser over fixed "
            "`cmd,arg` pairs. `RT-RECORD` (14.4) is the fourth: "
            "`courts/phase14/rt_record_probe.c` drives the default read-buffer length setters, the "
            "record-state strings `SSL_rstate_string`/`_long` over a fresh connection and NULL, and "
            "`SSL_poll` over fixed in-memory `SSL_POLL_ITEM` arrays -- the zero-item, NULL-SSL, "
            "non-QUIC-SSL, socket, unknown-type, NULL-then-refused, refused-first and "
            "NO_HANDLE_EVENTS arms -- with a zero timeout so nothing blocks. `RT-STATEM` (14.5) is "
            "the fifth: `courts/phase14/rt_statem_probe.c` drives the four handshake-state readers "
            "over a fresh connection and NULL, the custom-extension add/has/supported surface, the "
            "signature-algorithm readers and `SSL_get1_builtin_sigalgs`, `SSL_check_chain`'s "
            "refusal arms, the max-fragment-length setters and "
            and "the `SSL_SESSION_get_max_fragment_length` over a zeroed session image. `RT-SSL-BIO` (14.6) "
            "is the sixth: `courts/phase14/rt_ssl_bio_probe.c` drives the `BIO_f_ssl` method over a "
            "fixed `TLS_method()` context, `BIO_new_ssl`/`BIO_new_ssl_connect`/"
            "`BIO_new_buffer_ssl_connect` and their NULL-context refusals, the `BIO_C_SSL_MODE` and "
            "renegotiation controls, `BIO_ssl_copy_session_id`'s refusal and accepted arms and "
            "`BIO_ssl_shutdown` over NULL and a BIO chain. `RT-DTLS` (14.8) is the seventh: "
            "`courts/phase14/rt_dtls_probe.c` drives `DTLSv1_listen`'s refusal arms over a fixed "
            "in-memory datagram BIO, `DTLS_get_data_mtu` and `DTLS_set_timer_cb` over NULL and a "
            "fresh DTLS connection, and the SRTP profile surface "
            "(`SSL_CTX_set_tlsext_use_srtp`/`SSL_set_tlsext_use_srtp`/`SSL_get_srtp_profiles`/"
            "`SSL_get_selected_srtp_profile`). `RT-SSL-INIT` (14.10) is the eighth: "
            "`courts/phase14/rt_ssl_init_probe.c` drives `OPENSSL_init_ssl` over fixed option words "
            "and its refusal arm, `ERR_load_SSL_strings`, and the QUIC TLS accessors' "
            "setter/refusal arms over an incomplete `OSSL_DISPATCH` table. None is a parity claim "
            "about a completed handshake, which no arm of any of them drives. `SSL_get0_group_name` "
            "on a live connection and `SSL_group_to_name`'s known-NID arm are recorded in their "
            "modules as reduced rather than driven. Every other behavioural court the plan names "
            "is named in `pending_courts` with the subphase that brings it -- "
            "`RT-SESSION-CERT`, `RT-SSL-EXT` and `RT-HANDOFF` -- and none is registered here, so "
            "'not run yet' "
            "cannot be read as 'passed'. Nothing here is a parity claim: `referenced` is not "
            "`called`, and docs/PHASE-14-SUBPHASES.md section 3 records what the behavioural "
            "courts compare."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols", path=REPO_ROOT / "forensics" / "atlas"
                 / auth.id / "symbols-libssl.json"),
    ]
    for _name, filename in COURTS:
        inputs.append(InputRef(name="probe", path=PROBE_DIR / filename))
    doc = envelope(kind="phase14-courts", authority=auth.id, inputs=inputs,
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
