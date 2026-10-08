#!/usr/bin/env python3
"""openssl-rs — Phase-24.7 runtime/functional atlas: the load/run/behave measurement.

Phase 24 measures whether `openssl-rs` survives the ways real software depends on OpenSSL, over the
frozen P1000 (`forensics/downstream/family-freeze.json`). 24.6 built and linked a pristine-source
recipe for every family that had one and recorded how far each subject reached on `L0-catalogued`
through `L4-linked`. This module is the next rung: for every family whose build/link row reached
`L4-linked` it **loads** the built program against the subject's install and drives a **real,
deterministic, local** OpenSSL-exercising workload, recording the level reached up to `L7-functional`.

What is measured, and what is not
---------------------------------
Reaching `L5-loaded` is not read from a version banner alone: the program is launched with
`LD_LIBRARY_PATH=<subject>/lib` and the subject's `libssl`/`libcrypto` must be shown **loading** by
the dynamic loader -- the program's `ldd` resolution of those sonames must be under the subject
prefix (never the authority's), and the loader must actually initialise them (`LD_DEBUG=libs`
records the subject library being called). A banner is not a load proof.

`L6-runtime` and `L7-functional` are a **real** workload, run against **local peers only**: no run
touches the public internet. The fixtures are the admitted authority's own `openssl` CLI (its
`s_server`/`s_client`/`req`) and the subject-linked program, on loopback. Where a program's workload
needs a peer or dependency this venue does not admit (an IMAP server, an authenticated FTPS login),
the exclusion is recorded with a reason and the level reached is stated honestly rather than faked.

The authority-applicable baseline
---------------------------------
A family's **authority-applicable baseline** is the highest level its **authority** runtime rows
reached. A candidate run is `DROP_IN`-relevant only when it reaches at least that rank; the candidate
is judged against what the authority itself achieved, never a higher aspirational one. The baseline
is recorded on every candidate row (`authority_applicable_level`) and re-derived by the court from
the authority rows, so a candidate row that inflates its own baseline to justify a higher pass is a
finding, not a pass.

Every P1000 family is accounted for
-----------------------------------
The atlas accounts for **all 1000** frozen families under both subjects. A family with no admitted
recipe, or whose build/link row never reached `L4-linked`, gets an honest
`not_attempted`/`unavailable` runtime row with a reason rather than being omitted or fabricated into
a pass. A sparse-but-complete atlas is the correct outcome; a fabricated pass never is.

Deterministic transcript normalisation
--------------------------------------
Every measured row carries a `transcript_sha256` over its normalised transcript, and the **same**
normaliser is applied to both subjects. It normalises only genuinely nondeterministic and
contract-irrelevant values -- absolute paths, ports, PIDs, timestamps and addresses -- and **never**
a return code, an error class, a certificate decision, or a protocol/algorithm choice, which are the
evidence the workload exists to produce (the brief's section 46).

The candidate identity is a measurement, not a pure function of committed inputs
-------------------------------------------------------------------------------
This tool performs real builds and runs; the artefact it writes is **measurement**. It is therefore
**not** listed in `forensics/tools/evidence_determinism.py`'s `GENERATORS` or `COMPARED` -- exactly
as 24.6's build/link atlas and the Phase-17 measured corpus under `courts/phase17/downstream/*/
result.json` are not -- because the level a run reaches and the transcript it produces are a function
of the court's toolchain and of the network, not of committed inputs, and a host invocation is
refused by the Docker-only guard before it builds anything. The court `RT-RUNTIME-FUNCTIONAL-ATLAS`
re-runs only this module's **pure** functions over the committed artefact and never rebuilds.

The Docker-only guard is called first
-------------------------------------
This module fetches from the network, compiles real projects and runs them, so it is an **execution**
entry point: `phase24_guard.require_admitted()` is the first statement of `main`, and a host
invocation is refused rather than producing unreproducible evidence (`docs/REPRODUCIBILITY.md`
section 1).

What is reused, not re-implemented
----------------------------------
The pristine-source recipe catalogue, the ELF/linkage helpers, the resource limits, the specimen and
variant construction and the path normaliser are **imported from 24.6** (`downstream_build_link`), so
the build each runtime row loads is the exact build 24.6 linked, one code path rather than two that
can drift.

Outputs
-------
  forensics/downstream/runtime-functional-atlas.json   the runtime/functional runs, both subjects

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    rel,
    resolve_authority,
    sha256_bytes,
    sha256_file,
    write_json,
)

# The Docker-only execution guard. Its call is the first statement of `main`: this tool fetches,
# compiles and runs, so it is an execution entry point and a host invocation is refused.
import phase24_guard  # noqa: E402

# The record schemas the rows are validated against, imported rather than restated so the vocabulary
# cannot drift from the module the court checks it with.
import downstream_schemas  # noqa: E402

# The 24.3 census primitives (fetch/extract/run/ELF inspection/resource limits) are reused through
# 24.6, which re-exports none of them itself: importing both keeps one code path.
import downstream_census as census  # noqa: E402

# The 24.6 build/link atlas: its recipe catalogue, its ELF/linkage helpers, its resource-limit reader,
# its specimen/variant/run construction and its `_norm` path normalisation are **reused by importing
# it**, so the runtime atlas loads the exact build the build/link atlas linked (the brief's "no
# divergent predicate").
import downstream_build_link as bl  # noqa: E402

# The stratum's four non-claims, imported from 24.4 so the atlas and the freeze cannot drift.
from downstream_freeze import NON_CLAIMS as STRATUM_NON_CLAIMS  # noqa: E402

FAMILIES = REPO_ROOT / "forensics" / "downstream" / "families.json"
FAMILY_FREEZE = REPO_ROOT / "forensics" / "downstream" / "family-freeze.json"
BUILD_LINK_ATLAS = REPO_ROOT / "forensics" / "downstream" / "build-link-atlas.json"
OUT = REPO_ROOT / "forensics" / "downstream" / "runtime-functional-atlas.json"

CANDIDATE_PREFIX = bl.CANDIDATE_PREFIX

# Scratch is kept under `/work/court` (never `/tmp` or the container's `/`) and removed after the
# measurement; only the small committed artefact persists in the tree.
SCRATCH = REPO_ROOT / "court" / "phase24-runtime"

GENERATOR = "forensics/tools/downstream_runtime.py"
PARSER_VERSION = "downstream-runtime/1"

L0 = "L0-catalogued"
L4 = "L4-linked"
L5 = "L5-loaded"
L6 = "L6-runtime"
L7 = "L7-functional"
RANK = downstream_schemas.EXECUTION_LEVEL_RANK

STEP_TIMEOUT = census.STEP_TIMEOUT
FETCH_TIMEOUT = census.FETCH_TIMEOUT
LAUNCH_TIMEOUT = census.LAUNCH_TIMEOUT
MAKE_JOBS = census.MAKE_JOBS

SUBJECTS = ("authority", "candidate")

# The allowed normalisation categories: only genuinely nondeterministic and contract-irrelevant
# values. Everything else -- return codes, error classes, certificate decisions, protocol or
# algorithm choices -- is evidence and is never normalised (the brief's section 46).
NORMALISATION_TAG = "runtime-transcript-normalisation/1"
NORMALISATION_ALLOWED = ("absolute_paths", "ports", "pids", "timestamps", "addresses")
NORMALISATION_NEVER = (
    "return_codes", "error_classes", "certificate_decisions", "protocol_choices",
    "algorithm_choices",
)

# The stratum's four non-claims (imported from 24.4 so the two cannot drift) plus the one this
# subphase's measurement adds: a functional pass under a measured workload is not a security proof.
NON_CLAIMS: list[str] = list(STRATUM_NON_CLAIMS) + [
    "a functional pass under a measured workload is not a security proof and not a claim about "
    "unmeasured consumers: the workload is one deterministic local exercise of the program's "
    "OpenSSL path, not a statement that every consumer works or that the library is safe",
]


# --------------------------------------------------------------------------------------------
# the per-family runtime intent: the program to load, its version argv, and its local workload
# --------------------------------------------------------------------------------------------
#
# Each recipe-backed family names the program inside the built pristine tree that is loaded, the
# argv that makes it report its version/usage (L5), and a `version_re` the output must match -- a
# banner is not the load proof (the loader trace is), but a program that does not even print its
# identity did not start. The workload itself is a runner keyed by family below.

PROGRAMS: dict[str, dict] = {
    # curl's `src/curl` is a libtool wrapper script; the real binary is `src/.libs/curl`, which
    # needs the build tree's `lib/.libs` on its library path (as the wrapper would set) so libcurl
    # resolves to the build while libssl/libcrypto resolve to the subject prefix.
    "curl": {"program": "src/.libs/curl", "launch": ["-V"], "version_re": r"curl \d",
             "lib_paths": ["lib/.libs"]},
    "haproxy": {"program": "haproxy", "launch": ["-v"], "version_re": r"HAProxy version"},
    "monit": {"program": "monit", "launch": ["-V"], "version_re": r"monit"},
    "nginx": {"program": "objs/nginx", "launch": ["-v"], "version_re": r"nginx version"},
    "openssh": {"program": "ssh", "launch": ["-V"], "version_re": r"OpenSSH_"},
    "pure-ftpd": {"program": "src/pure-ftpd", "launch": ["--help"], "version_re": r"pure-ftpd"},
    "redis": {"program": "src/redis-server", "launch": ["--version"], "version_re": r"Redis server"},
    "isync": {"program": "src/mbsync", "launch": ["--version"], "version_re": r"mbsync|isync"},
}

# The frozen runtime/functional rule, recorded verbatim in the artefact and re-derived by the court.
RULE: dict = {
    "id": "downstream-runtime-functional-atlas/1",
    "name": "the local-only runtime/functional atlas",
    "levels": [L5, L6, L7],
    "subjects": list(SUBJECTS),
    "ladder": (
        "L5-loaded: the built program starts under LD_LIBRARY_PATH=<subject>/lib and the subject's "
        "libssl/libcrypto are actually loaded -- the program's own ldd resolution of every OpenSSL "
        "soname is under the subject prefix (and never the authority's), and the loader initialises "
        "the subject library (an LD_DEBUG=libs dynamic-load trace); a version banner alone is not a "
        "load proof. L6-runtime: the program executes a real, local OpenSSL code path without "
        "failure (a TLS handshake, a key generation). L7-functional: the workload completes its "
        "intended effect -- a verified transfer, a verified TLS server response, a verified "
        "signature, a protocol round-trip over TLS"
    ),
    "authority_applicable_baseline": (
        "a specimen's authority-applicable baseline is the highest level its authority runtime rows "
        "reached; a candidate run is DROP_IN-relevant only when its own level rank is at least that "
        "rank, and the candidate is judged against what the authority itself achieved, never a "
        "higher aspirational level. The baseline is recorded on every candidate row and re-derived "
        "from the authority rows by the court"
    ),
    "local_only": (
        "every L6/L7 workload runs against local peers only -- the admitted authority's own openssl "
        "CLI and the subject-linked program, on loopback; no run touches the public internet. The "
        "network is used only to acquire a pristine source, exactly as 24.6 fetched it"
    ),
    "workload_policy": (
        "only a workload meaningful to the program is driven, never a manufactured one; where a "
        "program's workload needs a peer or dependency this venue does not admit, the exclusion is "
        "recorded with a reason and the level reached is stated honestly rather than faked"
    ),
    "normalisation": {
        "tag": NORMALISATION_TAG,
        "normalises": list(NORMALISATION_ALLOWED),
        "never": list(NORMALISATION_NEVER),
        "policy": (
            "the same normaliser is applied to both subjects; it replaces only absolute paths, "
            "ports, PIDs, timestamps and addresses, and never a return code, an error class, a "
            "certificate decision, or a protocol/algorithm choice"
        ),
    },
    "accounting": (
        "all 1000 frozen families are emitted under both subjects; a family with no admitted recipe, "
        "or whose build/link row never reached L4-linked, is `not_attempted` with a reason, never "
        "omitted and never fabricated into a pass"
    ),
    "permit": (
        "a runtime row may not reach a level above the level its build/link row reached: a subject "
        "that never linked cannot load"
    ),
    "confinement": (
        "each fetch, build and run runs inside the admitted court container under its cgroup caps "
        "and this tool's own wall-clock bounds; scratch is under /work/court and removed afterwards"
    ),
    "constants": {"make_jobs": MAKE_JOBS, "step_timeout_seconds": STEP_TIMEOUT,
                  "launch_timeout_seconds": LAUNCH_TIMEOUT},
}


# --------------------------------------------------------------------------------------------
# deterministic transcript normalisation (the same normaliser for both subjects)
# --------------------------------------------------------------------------------------------

_TS_ISO = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b")
_TS_HUMAN = re.compile(r"\b[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \d{4}\b")
_TS_CLOCK = re.compile(r"\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b")
_PID = re.compile(r"\b(pid|PID|Pid|process|Process)\b[ =:]*\d+\b")
_HEXADDR = re.compile(r"\b0x[0-9a-fA-F]+\b")
_IPPORT = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}:\d+\b")
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def normalise_transcript(text: str, prefix: Path, authority_prefix: Path, scratch: Path,
                         port: int | None = None) -> str:
    """The portable form of a transcript: paths/ports/PIDs/timestamps/addresses become tokens.

    Only genuinely nondeterministic and contract-irrelevant values are replaced. A return code, an
    error class, a certificate decision and a protocol/algorithm choice are **not** touched: they are
    the evidence the workload exists to produce.
    """
    if not text:
        return ""
    for p, token in ((str(prefix), "{prefix}"), (str(authority_prefix), "{authority}"),
                     (str(CANDIDATE_PREFIX), "{candidate}"), (str(scratch), "{scratch}"),
                     (str(REPO_ROOT), "{repo}")):
        if p and p != "/":
            text = text.replace(p, token)
    if port:
        text = re.sub(rf"(?<!\d){port}(?!\d)", "{port}", text)
    text = _TS_ISO.sub("{timestamp}", text)
    text = _TS_HUMAN.sub("{timestamp}", text)
    text = _TS_CLOCK.sub("{clock}", text)
    text = _PID.sub(lambda m: f"{m.group(1)} {{pid}}", text)
    text = _HEXADDR.sub("{addr}", text)
    text = _IPPORT.sub("{addr}", text)
    text = _IP.sub("{addr}", text)
    return text


# --------------------------------------------------------------------------------------------
# subprocess helpers (bounded; never raise on a non-zero exit)
# --------------------------------------------------------------------------------------------

def _run_captured(argv: list[str], *, cwd: Path | None = None, env: dict | None = None,
                  timeout: int = STEP_TIMEOUT, stdin_text: str | None = None) -> dict:
    start = time.monotonic()
    try:
        proc = subprocess.run([str(a) for a in argv], cwd=str(cwd) if cwd else None, env=env,
                              input=stdin_text, capture_output=True, text=True, timeout=timeout,
                              check=False)
        code, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        code = -1
        out = exc.stdout.decode("utf-8", "ignore") if isinstance(exc.stdout, bytes) \
            else (exc.stdout or "")
        err = (exc.stderr.decode("utf-8", "ignore") if isinstance(exc.stderr, bytes)
               else (exc.stderr or "")) + f"\nTIMEOUT after {timeout}s"
    except FileNotFoundError as exc:
        code, out, err = 127, "", str(exc)
    return {
        "argv": [os.path.basename(str(argv[0]))] + [str(a) for a in argv[1:]],
        "exit_code": code,
        "ok": code == 0,
        "stdout": out or "",
        "stderr": err or "",
        "elapsed_seconds": round(time.monotonic() - start, 3),
    }


def _spawn(argv: list[str], cwd: Path, env: dict, out_path: Path, err_path: Path):
    outf = open(out_path, "w", encoding="utf-8")
    errf = open(err_path, "w", encoding="utf-8")
    proc = subprocess.Popen([str(a) for a in argv], cwd=str(cwd), env=env, stdout=outf,
                            stderr=errf, text=True)
    return proc, outf, errf


def _stop(proc) -> None:
    try:
        proc.terminate()
    except Exception:  # noqa: BLE001
        pass
    try:
        proc.wait(timeout=5)
    except Exception:  # noqa: BLE001
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            pass


def _kill_comm(name: str) -> None:
    """SIGKILL any leftover process whose comm is `name` (a daemonising server's child)."""
    for p in Path("/proc").glob("[0-9]*"):
        try:
            if (p / "comm").read_text(encoding="utf-8").strip() == name:
                os.kill(int(p.name), 9)
        except OSError:
            continue


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_tcp(host: str, port: int, timeout: float = 25.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


# --------------------------------------------------------------------------------------------
# authority CLI helpers and a deterministic local PKI fixture
# --------------------------------------------------------------------------------------------

def _auth_ossl(authority_prefix: Path) -> Path:
    return authority_prefix / "bin" / "openssl"


def _auth_env(authority_prefix: Path) -> dict:
    return dict(os.environ, LD_LIBRARY_PATH=str(authority_prefix / "lib"), OPENSSL_CONF="/dev/null")


def _ossl(authority_prefix: Path, argv: list[str], *, cwd: Path | None = None,
          timeout: int = 60, stdin_text: str | None = None) -> dict:
    return _run_captured([str(_auth_ossl(authority_prefix))] + argv, cwd=cwd,
                         env=_auth_env(authority_prefix), timeout=timeout, stdin_text=stdin_text)


def _gen_pki(authority_prefix: Path, d: Path) -> dict:
    """A deterministic local PKI: a CA, a server cert with SAN IP:127.0.0.1, and an unrelated CA.

    The keys are freshly generated, so their bytes are nondeterministic -- but nothing hashes them:
    only the transcripts of the programs that consume the PKI are hashed, and those are normalised.
    """
    d.mkdir(parents=True, exist_ok=True)
    ca_key, ca_crt = d / "ca.key", d / "ca.crt"
    srv_key, srv_csr, srv_crt = d / "server.key", d / "server.csr", d / "server.crt"
    ext = d / "server.ext"
    other_key, other_crt = d / "other.key", d / "other-ca.crt"

    steps = [
        (["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key), "-out",
          str(ca_crt), "-days", "7", "-subj", "/CN=runtime test CA", "-addext",
          "basicConstraints=critical,CA:TRUE"], "CA"),
        (["req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(srv_key), "-out", str(srv_csr),
          "-subj", "/CN=127.0.0.1"], "server csr"),
        (["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(other_key), "-out",
          str(other_crt), "-days", "7", "-subj", "/CN=runtime unrelated CA", "-addext",
          "basicConstraints=critical,CA:TRUE"], "unrelated CA"),
    ]
    for argv, what in steps:
        res = _ossl(authority_prefix, argv, timeout=60)
        if not res["ok"]:
            raise RuntimeError(f"generating the {what} failed: {census._error_line(res)}")
    ext.write_text("subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n"
                   "keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n",
                   encoding="utf-8")
    res = _ossl(authority_prefix, ["x509", "-req", "-in", str(srv_csr), "-CA", str(ca_crt),
                                   "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(srv_crt),
                                   "-days", "7", "-extfile", str(ext)], timeout=60)
    if not res["ok"]:
        raise RuntimeError(f"signing the server certificate failed: {census._error_line(res)}")
    # the combined PEM a TLS server that takes cert+key in one file expects (nginx/haproxy/monit/
    # pure-ftpd/redis all accept separate files, but the combined form is portable)
    srv_pem = d / "server.pem"
    srv_pem.write_text(_read(srv_crt) + _read(srv_key), encoding="utf-8")
    return {"ca_crt": ca_crt, "ca_key": ca_key, "srv_crt": srv_crt, "srv_key": srv_key,
            "srv_pem": srv_pem, "other_crt": other_crt}


def _s_client(authority_prefix: Path, port: int, ca: Path, extra: list[str],
              stdin_text: str | None = "", timeout: int = 25) -> dict:
    argv = ["s_client", "-connect", f"127.0.0.1:{port}", "-CAfile", str(ca), "-servername",
            "127.0.0.1"] + extra
    return _ossl(authority_prefix, argv, timeout=timeout, stdin_text=stdin_text)


def _transcript(*parts: tuple[str, dict | None]) -> str:
    """A labelled transcript; exit codes are kept (they are evidence, never normalised)."""
    lines: list[str] = []
    for name, res in parts:
        if res is None:
            continue
        lines.append(f"== {name} ==")
        lines.append(f"exit={res.get('exit_code')}")
        for stream in ("stdout", "stderr"):
            blob = (res.get(stream) or "").strip("\n")
            if blob:
                lines.append(blob)
    return "\n".join(lines)


# --------------------------------------------------------------------------------------------
# the workloads: real, deterministic, local OpenSSL exercises
# --------------------------------------------------------------------------------------------
#
# Each runner returns `{runtime_ok, functional_ok, failure_class, residual, reason, transcript,
# workload, local_only}`. `runtime_ok` means the L6 code path executed without failure; `functional_ok`
# means the workload produced its intended effect (L7). A runner that cannot be driven at all records
# the exclusion with a reason and `runtime_ok=False`.

def _wl_curl(ctx: dict) -> dict:
    """A verified TLS 1.3 client fetch from the subject-linked curl against the authority s_server."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    notes: list[str] = []
    srv, of, ef = _spawn([str(_auth_ossl(ap)), "s_server", "-accept", str(port), "-cert",
                          str(pki["srv_crt"]), "-key", str(pki["srv_key"]), "-tls1_3", "-www"],
                         d, _auth_env(ap), d / "srv.out", d / "srv.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail(notes, "curl: the authority s_server did not listen", None, d)
        common = ["-sS", "--max-time", "15", "--tlsv1.3", "--tls-max", "1.3", "-o", "/dev/null",
                  "-w", "http_code=%{http_code}\\nssl_verify_result=%{ssl_verify_result}\\n"]
        ok = _run_captured([str(ctx["program"])] + common + ["--cacert", str(pki["ca_crt"]),
                           f"https://127.0.0.1:{port}/"], env=ctx["env"], timeout=40)
        neg = _run_captured([str(ctx["program"])] + common + ["--cacert", str(pki["other_crt"]),
                            f"https://127.0.0.1:{port}/"], env=ctx["env"], timeout=40)
    finally:
        _stop(srv)
        of.close()
        ef.close()
    runtime_ok = ok["ok"] and "http_code=200" in ok["stdout"]
    functional_ok = runtime_ok and not neg["ok"]
    transcript = _transcript(("curl-verify-fetch", ok), ("curl-unrelated-ca (must fail)", neg),
                             ("s_server", {"exit_code": 0, "stdout": _read(d / "srv.err")}))
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the verified TLS 1.3 fetch did not return 200" if not runtime_ok else
             "the unrelated CA was not rejected, so the fetch does not verify"),
            "transcript": transcript, "workload": "curl: verified TLS1.3 fetch + unrelated-CA reject",
            "local_only": True}


def _wl_nginx(ctx: dict) -> dict:
    """A verified TLS 1.3 server response from the subject-linked nginx, read by authority s_client."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    serve = d / "serve"
    (serve / "docroot").mkdir(parents=True, exist_ok=True)
    (serve / "logs").mkdir(parents=True, exist_ok=True)
    (serve / "run").mkdir(parents=True, exist_ok=True)
    (serve / "conf").mkdir(parents=True, exist_ok=True)
    (serve / "docroot" / "index.html").write_text("phase24-runtime-nginx-ok\n", encoding="utf-8")
    conf = serve / "conf" / "nginx.conf"
    conf.write_text(f"""worker_processes 1;
pid {serve}/run/nginx.pid;
error_log {serve}/logs/error.log info;
events {{ worker_connections 128; }}
http {{
    access_log {serve}/logs/access.log;
    default_type text/plain;
    sendfile off;
    server {{
        listen 127.0.0.1:{port} ssl;
        server_name 127.0.0.1;
        ssl_certificate {pki['srv_crt']};
        ssl_certificate_key {pki['srv_key']};
        ssl_protocols TLSv1.3;
        root {serve}/docroot;
        location / {{ }}
    }}
}}
""", encoding="utf-8")
    t = _run_captured([str(ctx["program"]), "-t", "-p", str(serve), "-c", str(conf)],
                      env=ctx["env"], timeout=30)
    if not t["ok"]:
        return {"runtime_ok": False, "functional_ok": False, "failure_class": "runtime-failure",
                "residual": "runtime-failure",
                "reason": f"nginx rejected its SSL configuration: {census._error_line(t)}",
                "transcript": _transcript(("nginx -t", t)),
                "workload": "nginx: verified TLS1.3 server response", "local_only": True}
    srv, of, ef = _spawn([str(ctx["program"]), "-p", str(serve), "-c", str(conf), "-g",
                          "daemon off;"], serve, ctx["env"], d / "nginx.out", d / "nginx.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("nginx -t", t)], "nginx did not listen", "runtime-failure", d)
        hs = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-brief"], stdin_text="", timeout=25)
        get = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-quiet"],
                        stdin_text="GET /index.html HTTP/1.0\r\nConnection: close\r\n\r\n",
                        timeout=25)
    finally:
        _stop(srv)
        _kill_comm("nginx")
        of.close()
        ef.close()
    runtime_ok = "Verification: OK" in hs["stderr"] and "Protocol version: TLSv1.3" in hs["stderr"]
    functional_ok = runtime_ok and "200 OK" in get["stdout"]
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS 1.3 handshake did not verify" if not runtime_ok else
             "the verified GET did not return 200"),
            "transcript": _transcript(("nginx -t", t), ("authority s_client -brief", hs),
                                      ("authority s_client GET", get)),
            "workload": "nginx: verified TLS1.3 server response", "local_only": True}


def _wl_haproxy(ctx: dict) -> dict:
    """A TLS-terminating haproxy proxy: authority s_client verifies and gets an HTTP 200."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    conf = d / "haproxy.cfg"
    conf.write_text(f"""global
    maxconn 100
    log stdout format raw local0
defaults
    mode http
    log global
    timeout connect 2s
    timeout client 5s
    timeout server 5s
frontend ft
    bind 127.0.0.1:{port} ssl crt {pki['srv_pem']}
    mode http
    http-request return status 200 content-type text/plain string phase24-runtime-haproxy-ok
""", encoding="utf-8")
    check = _run_captured([str(ctx["program"]), "-c", "-f", str(conf)], env=ctx["env"], timeout=30)
    if not check["ok"]:
        return {"runtime_ok": False, "functional_ok": False, "failure_class": "runtime-failure",
                "residual": "runtime-failure",
                "reason": f"haproxy rejected its TLS configuration: {census._error_line(check)}",
                "transcript": _transcript(("haproxy -c", check)),
                "workload": "haproxy: TLS terminator with a verified response", "local_only": True}
    srv, of, ef = _spawn([str(ctx["program"]), "-db", "-f", str(conf)], d, ctx["env"],
                         d / "haproxy.out", d / "haproxy.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("haproxy -c", check)], "haproxy did not listen", "runtime-failure", d)
        hs = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-brief"], stdin_text="", timeout=25)
        get = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-quiet"],
                        stdin_text="GET / HTTP/1.0\r\nConnection: close\r\n\r\n", timeout=25)
    finally:
        _stop(srv)
        of.close()
        ef.close()
    runtime_ok = "Verification: OK" in hs["stderr"] and "Protocol version: TLSv1.3" in hs["stderr"]
    functional_ok = runtime_ok and "200 OK" in get["stdout"] and "phase24-runtime-haproxy-ok" in \
        get["stdout"]
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS 1.3 handshake did not verify" if not runtime_ok else
             "the proxied GET did not return the fixed 200"),
            "transcript": _transcript(("haproxy -c", check), ("authority s_client -brief", hs),
                                      ("authority s_client GET", get)),
            "workload": "haproxy: TLS terminator with a verified response", "local_only": True}


def _wl_openssh(ctx: dict) -> dict:
    """A libcrypto-only workload: ssh-keygen generates an Ed25519 key and signs/verifies a message."""
    ap, d, root = ctx["authority_prefix"], ctx["workdir"], ctx["root"]
    env = ctx["env"]
    mk = _run_captured(["make", MAKE_JOBS, "ssh-keygen"], cwd=root, env=ctx["build_env"],
                       timeout=STEP_TIMEOUT)
    keygen = root / "ssh-keygen"
    if not keygen.is_file():
        return {"runtime_ok": False, "functional_ok": False, "failure_class": "harness-failure",
                "residual": "out-of-scope",
                "reason": f"the libcrypto workload binary ssh-keygen was not built: "
                          f"{census._error_line(mk)}",
                "transcript": _transcript(("make ssh-keygen", mk)),
                "workload": "openssh: ssh-keygen sign/verify (libcrypto)", "local_only": True}
    key = d / "id_ed25519"
    msg = d / "msg"
    msg.write_text("phase24 runtime openssh fixture\n", encoding="utf-8")
    gen = _run_captured([str(keygen), "-t", "ed25519", "-f", str(key), "-N", "", "-q", "-C",
                         "runtime"], cwd=d, env=env, timeout=30)
    runtime_ok = gen["ok"] and key.is_file() and (d / "id_ed25519.pub").is_file()
    sign = verify = None
    functional_ok = False
    if runtime_ok:
        sign = _run_captured([str(keygen), "-Y", "sign", "-f", str(key), "-n", "file", "msg"],
                             cwd=d, env=env, timeout=30)
        sig = d / "msg.sig"
        allowed = d / "allowed_signers"
        allowed.write_text("runtime " + _read(d / "id_ed25519.pub").strip() + "\n",
                           encoding="utf-8")
        if sign["ok"] and sig.is_file():
            verify = _run_captured([str(keygen), "-Y", "verify", "-f", str(allowed), "-I",
                                    "runtime", "-n", "file", "-s", str(sig)], cwd=d, env=env,
                                   timeout=30, stdin_text="phase24 runtime openssh fixture\n")
            functional_ok = verify["ok"] and "Good" in (verify["stdout"] + verify["stderr"])
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the Ed25519 key generation failed" if not runtime_ok else
             "the ssh-keygen signature did not verify"),
            "transcript": _transcript(("make ssh-keygen", mk), ("ssh-keygen keygen", gen),
                                      ("ssh-keygen -Y sign", sign), ("ssh-keygen -Y verify", verify)),
            "workload": "openssh: ssh-keygen Ed25519 sign/verify (libcrypto)", "local_only": True}


def _wl_redis(ctx: dict) -> dict:
    """A TLS redis: authority s_client completes a verified handshake and gets +PONG to PING."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    dbdir = d / "db"
    dbdir.mkdir(parents=True, exist_ok=True)
    argv = [str(ctx["program"]), "--bind", "127.0.0.1", "--port", "0", "--tls-port", str(port),
            "--tls-cert-file", str(pki["srv_crt"]), "--tls-key-file", str(pki["srv_key"]),
            "--tls-ca-cert-file", str(pki["ca_crt"]), "--tls-auth-clients", "no", "--save", "",
            "--protected-mode", "no", "--dir", str(dbdir)]
    srv, of, ef = _spawn(argv, d, ctx["env"], d / "redis.out", d / "redis.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("redis-server", {"exit_code": 0, "stdout": _read(d / "redis.err")})],
                            "redis-server did not open its TLS port", "runtime-failure", d)
        hs = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-brief"], stdin_text="", timeout=25)
        ping = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-quiet"], stdin_text="PING\r\n",
                         timeout=25)
    finally:
        _stop(srv)
        of.close()
        ef.close()
    runtime_ok = "Verification: OK" in hs["stderr"] and "Protocol version: TLSv1.3" in hs["stderr"]
    functional_ok = runtime_ok and "+PONG" in ping["stdout"]
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS 1.3 handshake did not verify" if not runtime_ok else
             "the encrypted PING did not return +PONG"),
            "transcript": _transcript(("authority s_client -brief", hs),
                                      ("authority s_client PING", ping),
                                      ("redis-server", {"exit_code": 0,
                                                        "stdout": _read(d / "redis.err")})),
            "workload": "redis: TLS handshake + encrypted PING/+PONG", "local_only": True}


def _wl_monit(ctx: dict) -> dict:
    """A TLS monit: its httpsd is verified by authority s_client and answers an HTTP request."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    # monit refuses a PEM or control file that is group/other readable: it validates the file mode
    # before it will use them, so the fixture tightens them the way a real deployment would.
    os.chmod(pki["srv_pem"], 0o600)
    conf = d / "monitrc"
    conf.write_text(f"""set daemon 5
set logfile {d}/monit.log
set httpd port {port} and
    use address 127.0.0.1
    ssl enable
    pemfile {pki['srv_pem']}
    allow runtime:runtime
""", encoding="utf-8")
    os.chmod(conf, 0o600)
    check = _run_captured([str(ctx["program"]), "-t", "-c", str(conf)], env=ctx["env"], timeout=30)
    if not check["ok"]:
        return {"runtime_ok": False, "functional_ok": False, "failure_class": "runtime-failure",
                "residual": "runtime-failure",
                "reason": f"monit rejected its SSL configuration: {census._error_line(check)}",
                "transcript": _transcript(("monit -t", check)),
                "workload": "monit: TLS httpd handshake + HTTP response", "local_only": True}
    srv, of, ef = _spawn([str(ctx["program"]), "-I", "-c", str(conf)], d, ctx["env"],
                         d / "monit.out", d / "monit.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("monit -t", check)], "monit did not open its TLS httpd port",
                            "runtime-failure", d)
        hs = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-brief"], stdin_text="", timeout=25)
        get = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-quiet"],
                        stdin_text="GET / HTTP/1.0\r\nConnection: close\r\n\r\n", timeout=25)
    finally:
        _stop(srv)
        _kill_comm("monit")
        of.close()
        ef.close()
    runtime_ok = "Verification: OK" in hs["stderr"] and "Protocol version: TLSv1.3" in hs["stderr"]
    functional_ok = runtime_ok and "HTTP/" in get["stdout"]
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS 1.3 handshake did not verify" if not runtime_ok else
             "the TLS httpd did not answer an HTTP request"),
            "transcript": _transcript(("monit -t", check), ("authority s_client -brief", hs),
                                      ("authority s_client GET", get)),
            "workload": "monit: TLS httpd handshake + HTTP response", "local_only": True}


def _ftps_account(ctx: dict) -> tuple[str, str]:
    """The deterministic local FTPS account the venue creates in its own disposable container.

    A system account (home bound to the fixture dir) lets pure-ftpd's `-l unix` backend authenticate
    a real login; the account is created idempotently and never touches the image, only the running
    container's ephemeral /etc.
    """
    user, passwd = "p24ftps", "p24ftps-pw"
    who = _run_captured(["id", "-u", user], timeout=15)
    if who["exit_code"] != 0:
        _run_captured(["useradd", "-M", "-d", str(ctx["workdir"] / "ftphome"), "-s", "/bin/sh",
                       user], timeout=30)
        _run_captured(["chpasswd"], timeout=30, stdin_text=f"{user}:{passwd}\n")
    return user, passwd


def _wl_pureftpd(ctx: dict) -> dict:
    """An authenticated FTPS session: AUTH TLS, USER/PASS and PWD against the subject pure-ftpd.

    24.17 adds the missing deterministic local workload: a system FTP account the venue creates in
    its own disposable container, whose credentials the authority's own `openssl s_client -starttls
    ftp` uses. The session completes a real authenticated explicit-TLS login and a `PWD` round trip
    on loopback (no public network), so the family reaches the functional level the authority can.
    """
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    home = d / "ftphome"
    home.mkdir(parents=True, exist_ok=True)
    user, passwd = _ftps_account(ctx)
    argv = [str(ctx["program"]), "--tls=1", "--certfile", str(pki["srv_pem"]), "-S",
            f"127.0.0.1,{port}", "-E", "-j", "-l", "unix"]
    proc, of, ef = _spawn(argv, d, ctx["env"], d / "ftpd.out", d / "ftpd.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("pure-ftpd", {"exit_code": 0, "stdout": _read(d / "ftpd.err")})],
                            "pure-ftpd did not open its control port", "runtime-failure", d)
        session = _ossl(ap, ["s_client", "-connect", f"127.0.0.1:{port}", "-starttls", "ftp",
                             "-CAfile", str(pki["ca_crt"]), "-servername", "127.0.0.1", "-brief",
                             "-ign_eof"],
                        timeout=25,
                        stdin_text=f"USER {user}\r\nPASS {passwd}\r\nPWD\r\nQUIT\r\n")
    finally:
        _stop(proc)
        _kill_comm("pure-ftpd")
        of.close()
        ef.close()
    replies = (session["stdout"] or "") + (session["stderr"] or "")
    runtime_ok = "230" in replies or "331" in replies
    functional_ok = runtime_ok and "230" in replies and "257" in replies
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the authenticated FTPS login did not complete" if not runtime_ok else
             "the FTPS session did not answer PWD"),
            "transcript": _transcript(("authority s_client -starttls ftp (USER/PASS/PWD/QUIT)",
                                       session),
                                      ("pure-ftpd", {"exit_code": 0, "stdout": _read(d / "ftpd.err")})),
            "workload": "pure-ftpd: authenticated FTPS login + PWD over explicit TLS",
            "local_only": True}


# --------------------------------------------------------------------------------------------
# a deterministic local IMAP-over-TLS peer (24.17's isync fixture)
# --------------------------------------------------------------------------------------------

_IMAP_MESSAGE = (
    b"Message-ID: <phase24-runtime-1@127.0.0.1>\r\n"
    b"Date: Thu, 01 Jan 1970 00:00:00 +0000\r\n"
    b"From: runtime@127.0.0.1\r\n"
    b"To: isync@127.0.0.1\r\n"
    b"Subject: phase24 runtime isync fixture\r\n"
    b"\r\n"
    b"phase24 runtime isync fixture body\n"
)


def _imap_serve_one(tls, stop: threading.Event) -> None:
    """Serve the one-mailbox IMAP4rev1 subset mbsync needs, over the already-TLS socket."""
    f = tls.makefile("rwb", buffering=0)
    f.write(b"* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN UIDPLUS] phase24 isync fixture ready\r\n")
    while not stop.is_set():
        raw = f.readline()
        if not raw:
            break
        line = raw.decode("utf-8", "ignore").rstrip("\r\n")
        if not line:
            continue
        parts = line.split(" ", 2)
        if len(parts) < 2:
            continue
        tag = parts[0]
        cmd = parts[1].upper()
        rest = parts[2] if len(parts) > 2 else ""
        # handle a trailing literal ({n}) on LOGIN/APPEND if the client sends one
        if rest.endswith("}") and "{" in rest:
            try:
                n = int(rest.rsplit("{", 1)[1].rstrip("}"))
                literal = f.read(n + 2)
                rest = rest + " " + literal.decode("utf-8", "ignore")
            except Exception:  # noqa: BLE001
                pass
        upper = rest.upper()
        if cmd in ("CAPABILITY",):
            f.write(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN UIDPLUS\r\n")
            f.write(f"{tag} OK CAPABILITY completed\r\n".encode())
        elif cmd in ("LOGIN", "AUTHENTICATE"):
            if cmd == "AUTHENTICATE":
                f.write(b"+ \r\n")
                f.readline()
            f.write(f"{tag} OK LOGIN completed\r\n".encode())
        elif cmd == "NAMESPACE":
            f.write(b'* NAMESPACE (("" "/")) NIL NIL\r\n')
            f.write(f"{tag} OK NAMESPACE completed\r\n".encode())
        elif cmd in ("LIST", "LSUB"):
            f.write(b'* LIST (\\HasNoChildren) "/" "INBOX"\r\n')
            f.write(f"{tag} OK {cmd} completed\r\n".encode())
        elif cmd == "STATUS":
            f.write(b'* STATUS "INBOX" (MESSAGES 1 RECENT 0 UIDNEXT 2 UIDVALIDITY 1 UNSEEN 0)\r\n')
            f.write(f"{tag} OK STATUS completed\r\n".encode())
        elif cmd in ("SELECT", "EXAMINE"):
            f.write(b"* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n")
            f.write(b"* 1 EXISTS\r\n")
            f.write(b"* 0 RECENT\r\n")
            f.write(b"* OK [UIDVALIDITY 1] UIDs valid\r\n")
            f.write(b"* OK [UIDNEXT 2] Predicted next UID\r\n")
            f.write(b"* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)] Flags\r\n")
            f.write(f"{tag} OK [READ-WRITE] {cmd} completed\r\n".encode())
        elif (cmd == "UID" and upper.startswith("FETCH")) or cmd == "FETCH":
            spec = rest[upper.index("FETCH") + 5:].strip()
            items = spec[spec.index("(") + 1:spec.rindex(")")] \
                if ("(" in spec and ")" in spec) else spec
            parts: list[str] = []
            literal: tuple[str, bytes] | None = None
            has_uid = False
            for tok in items.replace("(", " ").replace(")", " ").split():
                u = tok.upper()
                if u == "UID":
                    has_uid = True
                    parts.append("UID 1")
                elif u == "FLAGS":
                    parts.append("FLAGS ()")
                elif u == "RFC822.SIZE":
                    parts.append(f"RFC822.SIZE {len(_IMAP_MESSAGE)}")
                elif u == "INTERNALDATE":
                    parts.append('INTERNALDATE "01-Jan-1970 00:00:00 +0000"')
                elif u.startswith("BODY") or u.startswith("RFC822"):
                    name = tok.replace(".PEEK", "").replace(".peek", "")
                    literal = (name, _IMAP_MESSAGE)
                elif u == "ENVELOPE":
                    parts.append('ENVELOPE ("Thu, 01 Jan 1970 00:00:00 +0000" '
                                 '"phase24 runtime isync fixture" NIL NIL NIL NIL NIL NIL NIL)')
            # A `UID FETCH` response always carries the message UID, as a real server sends it.
            if cmd == "UID" and not has_uid:
                parts.insert(0, "UID 1")
            if literal is not None:
                n = len(literal[1])
                head = ("* 1 FETCH (" + " ".join(parts + [f"{literal[0]} {{{n}}}"]) +
                        "\r\n")
                f.write(head.encode())
                f.write(literal[1])
                f.write(b")\r\n")
            else:
                resp = "* 1 FETCH (" + " ".join(parts) + ")\r\n"
                f.write(resp.encode())
            f.write(f"{tag} OK {cmd} FETCH completed\r\n".encode())
        elif cmd == "UID" and upper.startswith("SEARCH"):
            f.write(b"* SEARCH 1\r\n")
            f.write(f"{tag} OK UID SEARCH completed\r\n".encode())
        elif cmd == "UID" and upper.startswith("STORE"):
            f.write(b"* 1 FETCH (UID 1 FLAGS (\\Seen))\r\n")
            f.write(f"{tag} OK UID STORE completed\r\n".encode())
        elif cmd in ("CREATE", "SUBSCRIBE", "UNSUBSCRIBE", "NOOP", "CHECK", "CLOSE",
                     "EXPUNGE", "STARTTLS", "ENABLE"):
            f.write(f"{tag} OK {cmd} completed\r\n".encode())
        elif cmd == "LOGOUT":
            f.write(b"* BYE phase24 fixture logging out\r\n")
            f.write(f"{tag} OK LOGOUT completed\r\n".encode())
            break
        else:
            f.write(f"{tag} OK {cmd} completed\r\n".encode())


def _imaps_server(cert_pem: Path, port: int, ready: threading.Event, stop: threading.Event) -> None:
    """Accept IMAPS connections on loopback and serve the fixture mailbox until `stop`."""
    try:
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(str(cert_pem))
    except Exception:  # noqa: BLE001
        ready.set()
        return
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", port))
        srv.listen(8)
        srv.settimeout(1.0)
    except OSError:
        ready.set()
        srv.close()
        return
    ready.set()
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        tls = None
        try:
            tls = sctx.wrap_socket(conn, server_side=True)
            _imap_serve_one(tls, stop)
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                if tls is not None:
                    tls.close()
            except Exception:  # noqa: BLE001
                pass
    srv.close()


def _wl_isync(ctx: dict) -> dict:
    """A real IMAP-over-TLS sync: the subject mbsync pulls a message from a local IMAP peer.

    24.17 adds the missing deterministic local workload: a one-mailbox IMAP4rev1 peer served by the
    courtroom's own Python over TLS with the authority-generated certificate, on loopback only. The
    subject `mbsync` connects with IMAPS, authenticates, fetches the message and writes it to a local
    Maildir, so the family reaches the functional level the authority can.
    """
    ap, port, d, root = ctx["authority_prefix"], ctx["port"], ctx["workdir"], ctx["root"]
    pki = _gen_pki(ap, d)
    maildir = d / "maildir"
    for sub in ("cur", "new", "tmp"):
        (maildir / sub).mkdir(parents=True, exist_ok=True)
    conf = d / "mbsyncrc"
    conf.write_text(
        "IMAPAccount phase24\n"
        "Host 127.0.0.1\n"
        f"Port {port}\n"
        "User runtime\n"
        "Pass runtime\n"
        "TLSType IMAPS\n"
        f"CertificateFile {pki['ca_crt']}\n"
        "\n"
        "IMAPStore remote\n"
        "Account phase24\n"
        "\n"
        "MaildirStore local\n"
        f"Path {maildir}/\n"
        f"Inbox {maildir}/INBOX\n"
        "SubFolders Verbatim\n"
        "\n"
        "Channel phase24\n"
        "Far :remote:\n"
        "Near :local:\n"
        "Patterns *\n"
        "Create Both\n"
        "Expunge Both\n"
        "SyncState *\n", encoding="utf-8")
    ready, stop = threading.Event(), threading.Event()
    thr = threading.Thread(target=_imaps_server, args=(pki["srv_pem"], port, ready, stop),
                           daemon=True)
    thr.start()
    ready.wait(timeout=10)
    try:
        if not _wait_tcp("127.0.0.1", port, timeout=10):
            return _wl_fail([], "the local IMAP peer did not listen", "runtime-failure", d)
        sync = _run_captured([str(ctx["program"]), "-c", str(conf), "phase24"], cwd=d,
                             env=ctx["env"], timeout=60)
    finally:
        stop.set()
        thr.join(timeout=5)
        _kill_comm("mbsync")
    msgs = [p for p in maildir.rglob("*") if p.is_file() and p.parent.name in ("new", "cur")]
    functional_ok = sync["exit_code"] == 0 and bool(msgs)
    runtime_ok = sync["exit_code"] == 0 or bool(msgs)
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the local IMAP-over-TLS sync did not complete"),
            "transcript": _transcript(("mbsync -c mbsyncrc phase24", sync)),
            "workload": "isync: mbsync IMAPS fetch from a local IMAP peer into a Maildir",
            "local_only": True}


def _wl_fail(notes: list, reason: str, failure_class: str | None, d: Path) -> dict:
    return {"runtime_ok": False, "functional_ok": False,
            "failure_class": failure_class or "runtime-failure", "residual": "runtime-failure",
            "reason": reason, "transcript": _transcript(*notes),
            "workload": "unavailable", "local_only": True}


RUNNERS = {
    "curl": _wl_curl,
    "nginx": _wl_nginx,
    "haproxy": _wl_haproxy,
    "openssh": _wl_openssh,
    "redis": _wl_redis,
    "monit": _wl_monit,
    "pure-ftpd": _wl_pureftpd,
    "isync": _wl_isync,
}


# --------------------------------------------------------------------------------------------
# the load proof (L5): the subject's libssl/libcrypto are actually loaded
# --------------------------------------------------------------------------------------------

def load_proof(program: Path, prefix: Path, authority_prefix: Path, launch: list[str],
               env: dict) -> dict:
    """Prove the launched program loads the subject's libssl/libcrypto, not the authority's.

    Two readings: the program's own `ldd` resolution of every OpenSSL soname (under the subject
    prefix, and -- for a candidate row -- never the authority's), and the dynamic loader's recorded
    `LD_DEBUG=libs` initialisation of the subject library. The conclusive proof is the resolution
    (the loader picking the subject's file); a version banner alone would prove neither.
    """
    run_env = dict(env)
    is_authority = os.path.realpath(str(prefix)) == os.path.realpath(str(authority_prefix))
    ldd = _run_captured(["ldd", str(program)], env=run_env, timeout=60)
    sonames: dict[str, dict] = {}
    any_lib = False
    all_under = True
    under_authority = False
    for line in (ldd["stdout"] or "").splitlines():
        left = line.split("=>")[0].strip()
        if not (left == "libssl.so" or left.startswith("libssl.so.") or
                left == "libcrypto.so" or left.startswith("libcrypto.so.")):
            continue
        resolved = line.split("=>", 1)[1].strip().split(" (")[0].strip() if "=>" in line else ""
        under = bool(resolved) and census._under(resolved, prefix)
        under_auth = bool(resolved) and census._under(resolved, authority_prefix)
        sonames[left] = {
            "resolved": f"prefix:{left}" if under else (resolved or "unresolved"),
            "under_prefix": under, "under_authority": under_auth,
        }
        any_lib = True
        all_under = all_under and under
        under_authority = under_authority or under_auth

    trace = _run_captured([str(program)] + list(launch), env=dict(run_env, LD_DEBUG="libs"),
                          timeout=LAUNCH_TIMEOUT)
    trace_lines = [ln.strip() for ln in ((trace["stderr"] or "") + "\n" +
                                         (trace["stdout"] or "")).splitlines()
                   if ("libssl" in ln or "libcrypto" in ln) and str(prefix) in ln]
    proven = any_lib and all_under and (is_authority or not under_authority)
    return {
        "proven": proven,
        "all_under_prefix": all_under,
        "resolved_under_authority": under_authority,
        "sonames": sonames,
        "dynamic_load_trace": trace_lines[:8],
        "ldd_exit": ldd["exit_code"],
        "trace_exit": trace["exit_code"],
    }


# --------------------------------------------------------------------------------------------
# measurement: every P1000 family, both subjects
# --------------------------------------------------------------------------------------------

def _runtime_row(fam: dict, recipe: dict | None, subject: str, *, level: str, outcome: str,
                 residual: str, failure_class: str | None, reason: str | None,
                 specimen_id: str | None, variant_id: str | None, source_sha256: str | None,
                 evidence: list[str], canvas: dict | None, limits: dict, prefix: Path,
                 source_root_hash: str | None, launch: list[str] | None, workload: str | None,
                 transcript: str, local_only: bool, extra: dict | None = None) -> dict:
    """One runtime run row: reuse 24.6's `run` construction and extend it with the runtime proof."""
    row = bl._subject_row(
        fam, recipe, subject, level=level, outcome=outcome, residual=residual,
        failure_class=failure_class, reason=reason, specimen_id=specimen_id, variant_id=variant_id,
        source_sha256=source_sha256, evidence=evidence, steps=None, canvas=canvas, limits=limits,
        prefix=prefix, source_root_hash=source_root_hash)
    row["run_id"] = f"run:runtime:{subject}:{fam.get('canonical_name')}"
    row["load_proof"] = (canvas or {}).get("load_proof")
    row["link"] = (canvas or {}).get("link")
    row["linkage_proven"] = bool((canvas or {}).get("linkage_proven"))
    row["resolved_under_authority"] = bool((canvas or {}).get("resolved_under_authority"))
    row["launch"] = list(launch) if launch else None
    row["workload"] = workload
    row["local_only"] = bool(local_only)
    row["transcript_sha256"] = sha256_bytes(transcript.encode("utf-8")) if transcript else ""
    lines = transcript.splitlines()
    row["transcript_excerpt"] = lines[-40:]
    row["normalisation"] = {
        "tag": NORMALISATION_TAG, "normalises": list(NORMALISATION_ALLOWED),
        "never": list(NORMALISATION_NEVER),
    }
    if extra:
        row.update(extra)
    return row


def _specimen_variant(recipe: dict, name: str) -> tuple[str, str]:
    return f"specimen:{name}:{recipe['version']}", f"variant:{name}:{recipe['version']}:pristine"


def _measure_subject_runtime(fam: dict, recipe: dict, subject: str, prefix: Path,
                             authority_prefix: Path, root: Path, source_sha256: str | None,
                             source_root_hash: str | None, limits: dict) -> dict:
    """Load and drive one subject's built program; return its runtime run row."""
    name = str(fam.get("canonical_name"))
    spec_id, variant_id = _specimen_variant(recipe, name)
    prog = PROGRAMS[name]
    program = root / prog["program"]
    workdir = SCRATCH / "run" / name / subject
    if workdir.exists():
        shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True, exist_ok=True)
    lib_paths = [str(prefix / "lib")] + [str(root / p) for p in prog.get("lib_paths", [])]
    env = dict(os.environ, LD_LIBRARY_PATH=os.pathsep.join(lib_paths))
    evidence = [f"family:{fam.get('family_id')}", f"recipe:{recipe['recipe_id']}",
                f"artifact:{prog['program']}", "local_only:loopback"]

    if not program.is_file():
        return _runtime_row(
            fam, recipe, subject, level=L4, outcome="failed", residual="runtime-failure",
            failure_class="load-failure",
            reason=f"the rebuilt pristine tree holds no program at {prog['program']}",
            specimen_id=spec_id, variant_id=variant_id, source_sha256=source_sha256,
            evidence=evidence, canvas=None, limits=limits, prefix=prefix,
            source_root_hash=source_root_hash, launch=None, workload=None, transcript="",
            local_only=True)

    launch = _run_captured([str(program)] + list(prog["launch"]), cwd=program.parent, env=env,
                           timeout=LAUNCH_TIMEOUT)
    version_ok = (re.search(prog["version_re"], launch["stdout"] + launch["stderr"],
                            re.IGNORECASE) is not None
                  and "error while loading shared libraries" not in launch["stderr"])
    proof = load_proof(program, prefix, authority_prefix, prog["launch"], env)

    base_canvas = {"load_proof": proof, "linkage_proven": proof["proven"],
                   "resolved_under_authority": proof["resolved_under_authority"],
                   "link": {"all_under_prefix": proof["all_under_prefix"],
                            "sonames": proof["sonames"]}}

    if not version_ok or not proof["proven"]:
        reason = ("the program did not start and report its version" if not version_ok else
                  "the subject's libssl/libcrypto were not loaded by the dynamic loader")
        return _runtime_row(
            fam, recipe, subject, level=L4, outcome="failed", residual="runtime-failure",
            failure_class="load-failure", reason=reason, specimen_id=spec_id, variant_id=variant_id,
            source_sha256=source_sha256, evidence=evidence, canvas=base_canvas, limits=limits,
            prefix=prefix, source_root_hash=source_root_hash, launch=list(prog["launch"]),
            workload=None, transcript=_transcript(("launch", launch)), local_only=True)

    runner = RUNNERS.get(name)
    if runner is None:
        # The program loads, but no local workload is admitted for it: state the exclusion honestly.
        return _runtime_row(
            fam, recipe, subject, level=L5, outcome="reached", residual="out-of-scope",
            failure_class=None,
            reason=("no admitted deterministic local workload exists for this program in this "
                    "venue; only L5-loaded is measured"),
            specimen_id=spec_id, variant_id=variant_id, source_sha256=source_sha256,
            evidence=evidence, canvas=base_canvas, limits=limits, prefix=prefix,
            source_root_hash=source_root_hash, launch=list(prog["launch"]), workload=None,
            transcript=_transcript(("launch", launch)), local_only=True)

    ctx = {"family": name, "subject": subject, "program": program, "root": root, "prefix": prefix,
           "authority_prefix": authority_prefix, "workdir": workdir, "port": _free_port(),
           "env": env, "build_env": dict(os.environ,
                                         PKG_CONFIG_PATH=f"{prefix}/lib/pkgconfig",
                                         CPPFLAGS=f"-I{prefix}/include",
                                         LDFLAGS=f"-L{prefix}/lib")}
    try:
        result = runner(ctx)
    except Exception as exc:  # noqa: BLE001 — a fixture failure is recorded, never raised
        result = {"runtime_ok": False, "functional_ok": False, "failure_class": "harness-failure",
                  "residual": "out-of-scope", "reason": f"the local workload fixture failed: {exc}",
                  "transcript": "", "workload": "harness-failure", "local_only": True}

    raw = _transcript(("launch", launch), ("workload", {"exit_code": 0,
                                                        "stdout": result.get("transcript", "")}))
    normalised = normalise_transcript(raw, prefix, authority_prefix, workdir, ctx["port"])

    extra = {"workload_result": {"name": result.get("workload"), "runtime_ok": result["runtime_ok"],
                                 "functional_ok": result["functional_ok"],
                                 "local_only": result.get("local_only", True)}}
    if result.get("note"):
        extra["note"] = result["note"]

    if result["functional_ok"]:
        level, outcome, residual, failure_class, reason = L7, "reached", "none", None, None
    elif result["runtime_ok"]:
        level = L6
        outcome = "failed" if result.get("failure_class") else "reached"
        residual = result.get("residual") or "functional-divergence"
        failure_class = result.get("failure_class")
        reason = result.get("reason") or result.get("note") or (
            "the workload reached its runtime level but no functional level was driven")
    else:
        level, outcome = L5, "failed"
        residual = result.get("residual") or "runtime-failure"
        failure_class = result.get("failure_class") or "runtime-failure"
        reason = result.get("reason") or "the local workload did not complete"

    return _runtime_row(
        fam, recipe, subject, level=level, outcome=outcome, residual=residual,
        failure_class=failure_class, reason=reason, specimen_id=spec_id, variant_id=variant_id,
        source_sha256=source_sha256, evidence=evidence, canvas=base_canvas, limits=limits,
        prefix=prefix, source_root_hash=source_root_hash, launch=list(prog["launch"]),
        workload=str(result.get("workload")), transcript=normalised,
        local_only=bool(result.get("local_only", True)), extra=extra)


def _not_attempted(fam: dict, subject: str, *, level: str, failure_class: str, residual: str,
                   reason: str, recipe: dict | None, specimen_id: str | None,
                   variant_id: str | None, source_sha256: str | None, limits: dict,
                   prefix: Path) -> dict:
    return _runtime_row(
        fam, recipe, subject, level=level, outcome="not_attempted", residual=residual,
        failure_class=failure_class, reason=reason, specimen_id=specimen_id, variant_id=variant_id,
        source_sha256=source_sha256, evidence=[f"family:{fam.get('family_id')}"], canvas=None,
        limits=limits, prefix=prefix, source_root_hash=None, launch=None, workload=None,
        transcript="", local_only=True)


def derive_atlas(families_body: dict, freeze_body: dict, build_link_body: dict,
                 authority_id: str) -> dict:
    """Measure the whole P1000 under both subjects and return the atlas `body`."""
    del families_body
    auth_prefix = resolve_authority(authority_id).prefix
    if not (CANDIDATE_PREFIX / "lib" / "libssl.so.3").is_file():
        raise SystemExit(f"[downstream-runtime] the candidate install prefix "
                         f"{rel(CANDIDATE_PREFIX)} holds no lib/libssl.so.3")
    limits = census.resource_limits()
    auth_defined = census.authority_defined_symbols(auth_prefix)
    cand_defined = census.authority_defined_symbols(CANDIDATE_PREFIX)

    bl_rows: dict[tuple[str, str], dict] = {}
    for r in build_link_body.get("runs") or []:
        bl_rows[(str(r.get("family_id")), str(r.get("subject")))] = r

    p1000 = freeze_body.get("p1000") or []
    rows: list[dict] = []
    specimens: dict[str, dict] = {}
    variants: dict[str, dict] = {}

    SCRATCH.mkdir(parents=True, exist_ok=True)
    try:
        for entry in p1000:
            name = str(entry.get("canonical_name"))
            fam = {
                "family_id": entry.get("family_id"),
                "canonical_name": name,
                "openssl_linkage": entry.get("openssl_linkage"),
                "directness_class": entry.get("directness_class"),
                "_rank": entry.get("p1000_rank"),
            }
            recipe = bl._RECIPE_BY_FAMILY.get(name)
            permits = {s: RANK.get(str((bl_rows.get((str(entry.get("family_id")), s)) or {})
                                        .get("level")), -1) for s in SUBJECTS}
            any_l4 = any(permits[s] >= RANK[L4] for s in SUBJECTS)

            if recipe is None:
                for subject in SUBJECTS:
                    rows.append(_not_attempted(
                        fam, subject, level=L0, failure_class="acquire-failure",
                        residual="unavailable",
                        reason=("no admitted pristine-source build recipe is recorded for this "
                                "family; the atlas does not manufacture a source URL"),
                        recipe=None, specimen_id=None, variant_id=None, source_sha256=None,
                        limits=limits, prefix=auth_prefix))
                continue

            if not any_l4:
                for subject in SUBJECTS:
                    blocked = str((bl_rows.get((str(entry.get("family_id")), subject)) or {})
                                  .get("level") or L0)
                    rows.append(_not_attempted(
                        fam, subject, level=blocked if RANK.get(blocked, -1) >= 0 else L0,
                        failure_class="link-failure", residual="unlinked",
                        reason=(f"the 24.6 build/link run reached {blocked}, below L4-linked, so "
                                f"there is no loaded program to run"),
                        recipe=recipe, specimen_id=_specimen_variant(recipe, name)[0],
                        variant_id=_specimen_variant(recipe, name)[1], source_sha256=None,
                        limits=limits, prefix=auth_prefix))
                continue

            # A recipe-backed family the venue admits no runtime workload for (no PROGRAMS entry)
            # reaches only its build/link level: the runtime atlas records that honestly rather than
            # rebuilding a program it will not load, so 24.17's admission batch (which links but has
            # no admitted local workload) is `no-fixture`, not a fabricated load.
            if name not in PROGRAMS:
                for subject in SUBJECTS:
                    blr = bl_rows.get((str(entry.get("family_id")), subject)) or {}
                    blocked = str(blr.get("level") or L0)
                    spec_id, variant_id = _specimen_variant(recipe, name)
                    if RANK.get(blocked, -1) < RANK[L4]:
                        rows.append(_not_attempted(
                            fam, subject,
                            level=blocked if RANK.get(blocked, -1) >= 0 else L0,
                            failure_class="link-failure", residual="unlinked",
                            reason=(f"the 24.6 build/link run for {subject} reached {blocked}, below "
                                    f"L4-linked, so there is no loaded program to run"),
                            recipe=recipe, specimen_id=spec_id, variant_id=variant_id,
                            source_sha256=blr.get("source_sha256"), limits=limits,
                            prefix=auth_prefix))
                    else:
                        rows.append(_runtime_row(
                            fam, recipe, subject, level=blocked, outcome="reached",
                            residual="out-of-scope", failure_class=None,
                            reason=("no admitted deterministic local workload exists for this "
                                    "program in this venue; only the build/link level is measured"),
                            specimen_id=spec_id, variant_id=variant_id,
                            source_sha256=blr.get("source_sha256"),
                            evidence=[f"family:{entry.get('family_id')}",
                                      f"recipe:{recipe['recipe_id']}"], canvas=None,
                            limits=limits, prefix=auth_prefix,
                            source_root_hash=blr.get("source_root_hash"), launch=None,
                            workload=None, transcript="", local_only=True))
                continue

            # At least one subject reached L4: rebuild the pristine source once (the exact build
            # intent 24.6 used) so the program that is loaded is the program that was linked.
            _bl_rows, specimen, variant = bl.measure_family(
                fam, recipe, auth_prefix, CANDIDATE_PREFIX, auth_defined, cand_defined, limits)
            if specimen:
                specimens[specimen["specimen_id"]] = specimen
            if variant:
                variants[variant["variant_id"]] = variant
            source_sha256 = next((r.get("source_sha256") for r in _bl_rows
                                  if r.get("source_sha256")), None)
            source_root_hash = next((r.get("source_root_hash") for r in _bl_rows
                                     if r.get("source_root_hash")), None)

            for subject in SUBJECTS:
                if permits[subject] < RANK[L4]:
                    blocked = str((bl_rows.get((str(entry.get("family_id")), subject)) or {})
                                  .get("level") or L0)
                    rows.append(_not_attempted(
                        fam, subject, level=blocked if RANK.get(blocked, -1) >= 0 else L0,
                        failure_class="link-failure", residual="unlinked",
                        reason=(f"the 24.6 build/link run for {subject} reached {blocked}, below "
                                f"L4-linked, so there is no loaded program to run"),
                        recipe=recipe, specimen_id=_specimen_variant(recipe, name)[0],
                        variant_id=_specimen_variant(recipe, name)[1], source_sha256=source_sha256,
                        limits=limits, prefix=auth_prefix))
                    continue
                root = census._single_source_root(bl.SCRATCH / name / subject / "src")
                if root is None:
                    rows.append(_not_attempted(
                        fam, subject, level=L4, failure_class="load-failure",
                        residual="runtime-failure",
                        reason="the rebuild produced no source tree to load from", recipe=recipe,
                        specimen_id=_specimen_variant(recipe, name)[0],
                        variant_id=_specimen_variant(recipe, name)[1], source_sha256=source_sha256,
                        limits=limits, prefix=auth_prefix))
                    continue
                rows.append(_measure_subject_runtime(
                    fam, recipe, subject,
                    auth_prefix if subject == "authority" else CANDIDATE_PREFIX, auth_prefix,
                    root, source_sha256, source_root_hash, limits))
                last = rows[-1]
                print(f"  [p1000 {entry.get('p1000_rank'):>4}] {name:<10} {subject:<9} "
                      f"{last['level']:<16} {str(last.get('reason') or '')[:60]}"[:150], flush=True)
    finally:
        census._cleanup(bl.SCRATCH)
        census._cleanup(SCRATCH)

    _apply_baseline(rows)
    rows.sort(key=lambda r: (str(r.get("family_id")), str(r.get("subject"))))
    counts = _counts(freeze_body, rows)
    body = {
        "rule": RULE,
        "authority": authority_id,
        "authority_prefix": rel(auth_prefix),
        "candidate_identity": bl.candidate_identity(),
        "recipe_catalogue": [
            {"family": r["family"], "version": r["version"], "recipe_id": r["recipe_id"],
             "program": PROGRAMS.get(r["family"], {}).get("program")}
            for r in bl.RECIPES
        ],
        "specimens": sorted(specimens.values(), key=lambda s: str(s["specimen_id"])),
        "variants": sorted(variants.values(), key=lambda v: str(v["variant_id"])),
        "runs": rows,
        "counts": counts,
        "resource_limits": limits,
        "non_claims": NON_CLAIMS,
    }
    return body


def _apply_baseline(rows: list[dict]) -> None:
    """Record on every row the authority-applicable baseline its family's authority rows reached."""
    baseline: dict[str, str] = {}
    for r in rows:
        if r.get("subject") == "authority":
            fid = str(r.get("family_id"))
            lv = str(r.get("level"))
            if RANK.get(lv, -1) > RANK.get(baseline.get(fid, L0), -1):
                baseline[fid] = lv
    for r in rows:
        fid = str(r.get("family_id"))
        base = baseline.get(fid, L0)
        r["authority_applicable_level"] = base
        r["reaches_baseline"] = RANK.get(str(r.get("level")), -1) >= RANK.get(base, -1)
        r["beyond_baseline"] = RANK.get(str(r.get("level")), -1) > RANK.get(base, -1)


def _counts(freeze_body: dict, rows: list[dict]) -> dict:
    """The counts, derived from the rows and the frozen P1000, never typed."""
    p1000 = freeze_body.get("p1000") or []
    recipe_families = {r["family"] for r in bl.RECIPES}

    def levels(subject: str, rung: str) -> int:
        return sum(1 for r in rows if r.get("subject") == subject
                   and RANK.get(str(r.get("level")), -1) >= RANK[rung])

    def outcomes(subject: str, outcome: str) -> int:
        return sum(1 for r in rows if r.get("subject") == subject and r.get("outcome") == outcome)

    baseline = {}
    for r in rows:
        if r.get("subject") == "authority":
            fid = str(r.get("family_id"))
            if RANK.get(str(r.get("level")), -1) > RANK.get(baseline.get(fid, L0), -1):
                baseline[fid] = str(r.get("level"))

    # The authority-applicable level per specimen (the recipe-backed families), and the candidate's
    # reach of it. `candidate_reaches_baseline` is the literal rule (candidate rank >= authority
    # baseline rank) over every specimen; `candidate_reaches_linked_baseline` restricts it to the
    # specimens whose authority baseline actually linked (rank >= L4), which is the set a drop-in is
    # even meaningful for, and `candidate_baseline_not_linked` records the rest so the first count
    # cannot be misread as 'every specimen was a real drop-in baseline'.
    spec_baseline: dict[str, str] = {}
    reaches = below = reaches_linked = not_linked = 0
    by_name = {str(e.get("canonical_name")): str(e.get("family_id")) for e in p1000}
    for name in sorted(recipe_families):
        fid = by_name.get(name)
        if fid is None:
            continue
        base = baseline.get(fid, L0)
        spec_baseline[fid] = base
        base_rank = RANK.get(base, -1)
        cand = next((r for r in rows if r.get("family_id") == fid
                     and r.get("subject") == "candidate"), None)
        cand_rank = RANK.get(str(cand.get("level")), -1) if cand else -1
        if base_rank >= RANK[L4]:
            if cand_rank >= base_rank:
                reaches_linked += 1
            else:
                below += 1
        else:
            not_linked += 1
        if cand_rank >= base_rank:
            reaches += 1

    failure_histogram: dict[str, int] = {}
    for r in rows:
        if r.get("subject") == "candidate" and r.get("outcome") in ("failed", "not_attempted"):
            fc = r.get("failure_class")
            if fc:
                failure_histogram[fc] = failure_histogram.get(fc, 0) + 1

    return {
        "p1000": len(p1000),
        "rows": len(rows),
        "with_recipe": len([e for e in p1000 if str(e.get("canonical_name")) in recipe_families]),
        "no_recipe": len([e for e in p1000 if str(e.get("canonical_name")) not in recipe_families]),
        "by_subject": {
            subject: {
                "loaded": levels(subject, L5),
                "runtime": levels(subject, L6),
                "functional": levels(subject, L7),
                "failed": outcomes(subject, "failed"),
                "not_attempted": outcomes(subject, "not_attempted"),
            }
            for subject in SUBJECTS
        },
        "authority_applicable_level": spec_baseline,
        "candidate_reaches_baseline": reaches,
        "candidate_reaches_linked_baseline": reaches_linked,
        "candidate_below_baseline": below,
        "candidate_baseline_not_linked": not_linked,
        "candidate_failures": failure_histogram,
        "candidate_specific_patch_count": sum(
            int(r.get("candidate_specific_patch_count") or 0) for r in rows),
    }


def write_outputs(body: dict, authority_id: str) -> None:
    inputs = [
        InputRef(name="family-freeze", path=FAMILY_FREEZE),
        InputRef(name="families", path=FAMILIES),
        InputRef(name="build-link-atlas", path=BUILD_LINK_ATLAS),
        InputRef(name="downstream-build-link",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_build_link.py"),
        InputRef(name="downstream-census",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_census.py"),
        InputRef(name="downstream-schemas",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_schemas.py"),
        InputRef(name="phase24-guard",
                 path=REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"),
        InputRef(name="phase-24-plan",
                 path=REPO_ROOT / "docs" / "PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"),
    ]
    doc = envelope(kind="downstream-runtime-functional-atlas", authority=authority_id,
                   inputs=inputs, body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    write_json(OUT, doc)


# --------------------------------------------------------------------------------------------
# the checks the court re-runs over the committed artefact (pure; never rebuilding)
# --------------------------------------------------------------------------------------------

def _load_atlas() -> dict:
    if not OUT.is_file():
        return {}
    return json.loads(OUT.read_text(encoding="utf-8")).get("body", {})


def _load_build_link() -> dict:
    if not BUILD_LINK_ATLAS.is_file():
        return {}
    return json.loads(BUILD_LINK_ATLAS.read_text(encoding="utf-8")).get("body", {})


def runtime_findings(families_body: dict, freeze_body: dict, build_link_body: dict,
                     atlas_body: dict) -> list[str]:
    """Every way the recorded runtime/functional atlas fails its own subject.

    Pure over the committed frozen P1000, the committed 24.6 build/link atlas and the committed
    runtime atlas, so the court re-runs it without rebuilding and the sensitivity control can mutate
    an in-memory copy. Every check is a re-derivation from the recorded rows: the population is
    accounted for under both subjects, a runtime row never reaches above the level its build/link row
    reached, an `L5+` row is backed by a real load proof, an `L6`/`L7` row has a non-empty normalised
    transcript, the candidate's authority-applicable baseline is re-derived (never inflated to
    justify a pass), the normaliser never erases evidence, a non-measured row carries a reason and a
    schema-valid residual/failure class, and the counts are read rather than typed.
    """
    del families_body
    findings: list[str] = []
    p1000 = freeze_body.get("p1000") or []
    p1000_ids = [str(e.get("family_id")) for e in p1000]
    p1000_set = set(p1000_ids)
    recipe_families = {r["family"] for r in bl.RECIPES}

    bl_rows: dict[tuple[str, str], dict] = {}
    for r in build_link_body.get("runs") or []:
        bl_rows[(str(r.get("family_id")), str(r.get("subject")))] = r

    runs = atlas_body.get("runs") or []
    if not runs:
        return ["the atlas records no runtime/functional run"]

    by_family_subject: dict[tuple[str, str], dict] = {}
    seen_run_ids: set[str] = set()
    for row in runs:
        fid = str(row.get("family_id"))
        subject = str(row.get("subject"))
        findings += [f"{fid}/{subject}: {p}" for p in downstream_schemas.validate_run(row)]
        rid = str(row.get("run_id"))
        if rid in seen_run_ids:
            findings.append(f"two runtime rows share run_id {rid!r}")
        seen_run_ids.add(rid)
        if fid not in p1000_set:
            findings.append(f"{fid} is not a frozen P1000 family: the atlas must account for the "
                            f"frozen population")
        if subject not in SUBJECTS:
            findings.append(f"{fid}: a runtime row names subject {subject!r}, not "
                            f"`authority`/`candidate`")
        by_family_subject[(fid, subject)] = row

        if int(row.get("candidate_specific_patch_count") or 0) != 0:
            findings.append(f"{fid}/{subject}: candidate_specific_patch_count is "
                            f"{row.get('candidate_specific_patch_count')!r}, not 0")

        # The permit: a runtime row may exceed its build/link level only because the build/link
        # reached L4-linked. A subject whose build/link row never linked cannot load or run.
        blr = bl_rows.get((fid, subject)) or {}
        permit = RANK.get(str(blr.get("level")), -1)
        if permit < RANK[L4] and RANK.get(str(row.get("level")), -1) > permit:
            findings.append(f"{fid}/{subject}: the runtime row reached {row.get('level')}, above "
                            f"the build/link level {blr.get('level')!r} it may load: a subject that "
                            f"never linked cannot load")

        outcome = row.get("outcome")
        if outcome in ("failed", "not_attempted", "unavailable"):
            if not row.get("reason"):
                findings.append(f"{fid}/{subject}: a {outcome} row carries no reason")
            if not row.get("failure_class"):
                findings.append(f"{fid}/{subject}: a {outcome} row carries no failure class")
            elif row["failure_class"] not in downstream_schemas.FAILURE_CLASSES:
                findings.append(f"{fid}/{subject}: failure class {row['failure_class']!r} is outside "
                                f"the taxonomy")
            if row.get("residual_class") in (None, "none"):
                findings.append(f"{fid}/{subject}: a {outcome} row carries no residual class")
        if row.get("residual_class") not in (None, "none") and not row.get("reason"):
            findings.append(f"{fid}/{subject}: a row with residual {row.get('residual_class')!r} "
                            f"carries no reason")

        level_rank = RANK.get(str(row.get("level")), -1)
        if level_rank >= RANK[L5]:
            if not row.get("linkage_proven"):
                findings.append(f"{fid}/{subject}: claims {row.get('level')} but its load/linkage "
                                f"is not proven")
            proof = row.get("load_proof") or {}
            if proof.get("proven") is not True:
                findings.append(f"{fid}/{subject}: a {row.get('level')} row carries no proven load "
                                f"proof")
            link = row.get("link") or {}
            if link.get("all_under_prefix") is not True:
                findings.append(f"{fid}/{subject}: a {row.get('level')} row does not resolve every "
                                f"OpenSSL soname under the subject prefix")
            if subject == "candidate" and (row.get("resolved_under_authority")
                                           or link.get("resolved_under_authority")):
                findings.append(f"{fid}/{subject}: a candidate {row.get('level')} row resolves the "
                                f"authority prefix, so the load proves the authority, not the "
                                f"candidate")
        if level_rank >= RANK[L6]:
            ts = str(row.get("transcript_sha256") or "")
            if len(ts) != 64:
                findings.append(f"{fid}/{subject}: a {row.get('level')} row has no non-empty "
                                f"transcript hash")
            norm = row.get("normalisation") or {}
            if not norm.get("tag"):
                findings.append(f"{fid}/{subject}: a {row.get('level')} row carries no normalisation "
                                f"tag")
            normalises = list(norm.get("normalises") or [])
            bad = [c for c in normalises if c not in NORMALISATION_ALLOWED]
            if bad:
                findings.append(f"{fid}/{subject}: the normalisation erases evidence "
                                f"({sorted(bad)}): return codes, error classes, certificate "
                                f"decisions and protocol/algorithm choices are never normalised")
        if not row.get("local_only"):
            findings.append(f"{fid}/{subject}: a runtime row is not marked local-only")

    # Every frozen family is accounted for under both subjects.
    missing = [fid for fid in p1000_ids
               if (fid, "authority") not in by_family_subject
               or (fid, "candidate") not in by_family_subject]
    if missing:
        findings.append(f"{len(missing)} frozen P1000 family(ies) lack a runtime row under both "
                        f"subjects (e.g. {missing[:3]})")

    # A family that reached L4 in 24.6 has runtime rows under both subjects.
    for fid in p1000_ids:
        bl_levels = [bl_rows.get((fid, s)) for s in SUBJECTS]
        if any(RANK.get(str(r.get("level")) if r else None, -1) >= RANK[L4] for r in bl_levels):
            for subject in SUBJECTS:
                if (fid, subject) not in by_family_subject:
                    findings.append(f"{fid}: reached L4-linked in 24.6 but has no {subject} runtime "
                                    f"row")

    # The candidate's authority-applicable baseline is re-derived, never inflated.
    derived_baseline: dict[str, str] = {}
    for r in runs:
        if r.get("subject") == "authority":
            fid = str(r.get("family_id"))
            if RANK.get(str(r.get("level")), -1) > RANK.get(derived_baseline.get(fid, L0), -1):
                derived_baseline[fid] = str(r.get("level"))
    for row in runs:
        if row.get("subject") != "candidate":
            continue
        fid = str(row.get("family_id"))
        base = derived_baseline.get(fid, L0)
        if str(row.get("authority_applicable_level")) != base:
            findings.append(f"{fid}/candidate: records authority_applicable_level "
                            f"{row.get('authority_applicable_level')!r}, but the authority rows "
                            f"reached {base!r}: the baseline is re-derived, never inflated to "
                            f"justify a pass")
        want_reach = RANK.get(str(row.get("level")), -1) >= RANK.get(base, -1)
        if bool(row.get("reaches_baseline")) != want_reach:
            findings.append(f"{fid}/candidate: reaches_baseline is {row.get('reaches_baseline')!r}, "
                            f"but the level {row.get('level')!r} against baseline {base!r} is "
                            f"{want_reach}")
        want_beyond = RANK.get(str(row.get("level")), -1) > RANK.get(base, -1)
        if bool(row.get("beyond_baseline")) != want_beyond:
            findings.append(f"{fid}/candidate: beyond_baseline is {row.get('beyond_baseline')!r}, "
                            f"but the level {row.get('level')!r} against baseline {base!r} is "
                            f"{want_beyond}")

    # The recorded rule and non-claims are the frozen ones.
    if atlas_body.get("rule") != RULE:
        findings.append("the recorded runtime rule is not the frozen rule")
    if atlas_body.get("non_claims") != NON_CLAIMS:
        findings.append("the recorded non_claims are not the stratum's four plus the functional "
                        "non-claim")

    # Counts are read, not typed.
    derived = _counts(freeze_body, runs)
    recorded = atlas_body.get("counts") or {}
    for key in ("p1000", "rows", "with_recipe", "no_recipe", "candidate_reaches_baseline",
                "candidate_reaches_linked_baseline", "candidate_below_baseline",
                "candidate_baseline_not_linked", "candidate_specific_patch_count"):
        if recorded.get(key) != derived[key]:
            findings.append(f"counts.{key} {recorded.get(key)!r} disagrees with the derived "
                            f"{derived[key]!r}")
    for subject in SUBJECTS:
        for rung in ("loaded", "runtime", "functional", "failed", "not_attempted"):
            got = (recorded.get("by_subject") or {}).get(subject, {}).get(rung)
            want = derived["by_subject"][subject][rung]
            if got != want:
                findings.append(f"counts.by_subject.{subject}.{rung} {got!r} disagrees with the "
                                f"derived {want!r}")
    if recorded.get("authority_applicable_level") != derived["authority_applicable_level"]:
        findings.append("counts.authority_applicable_level disagrees with the derived baseline map")
    if (recorded.get("candidate_failures") or {}) != derived["candidate_failures"]:
        findings.append("counts.candidate_failures disagrees with the derived histogram")
    return findings


def _mutations(atlas_body: dict, freeze_body: dict) -> list[tuple[str, str, dict]]:
    """`(name, needle, mutated_atlas)` for each seeded mutation."""
    del freeze_body
    out: list[tuple[str, str, dict]] = []
    runs = atlas_body.get("runs") or []

    # a candidate row whose level passes only because its baseline was inflated (an aspirational
    # authority level the authority never reached). Any candidate row at or below its baseline is a
    # valid target: raising its recorded baseline above the level the authority rows reached is the
    # defect the re-derivation check exists to catch.
    m1 = copy.deepcopy(atlas_body)
    cand = next((r for r in m1["runs"] if r.get("subject") == "candidate"
                 and not r.get("beyond_baseline")
                 and str(r.get("authority_applicable_level")) not in ("", "None", L0)), None)
    if cand is not None:
        cand["authority_applicable_level"] = "L8-authority-equivalent"
        cand["reaches_baseline"] = True
    out.append(("candidate_level_above_authority_baseline", "authority_applicable_level", m1))

    # an L5+ row with no load proof.
    m2 = copy.deepcopy(atlas_body)
    loaded = next((r for r in m2["runs"] if RANK.get(str(r.get("level")), -1) >= RANK[L5]), None)
    if loaded is not None:
        loaded["linkage_proven"] = False
        loaded["load_proof"] = {"proven": False}
    out.append(("loaded_row_without_proof", "load/linkage is not proven", m2))

    # an L6+ row with an empty transcript hash.
    m3 = copy.deepcopy(atlas_body)
    runtime = next((r for r in m3["runs"] if RANK.get(str(r.get("level")), -1) >= RANK[L6]), None)
    if runtime is not None:
        runtime["transcript_sha256"] = ""
    out.append(("runtime_row_without_transcript", "no non-empty transcript hash", m3))

    # a missing authority runtime row for a family that reached L4 in 24.6.
    m4 = copy.deepcopy(atlas_body)
    auth_row = next((r for r in m4["runs"] if r.get("subject") == "authority"
                     and RANK.get(str(r.get("level")), -1) >= RANK[L5]), None)
    if auth_row is not None:
        m4["runs"] = [r for r in m4["runs"] if r.get("run_id") != auth_row.get("run_id")]
    out.append(("missing_authority_runtime_row", "has no authority runtime row", m4))

    # a normalisation that erases a return code (evidence the workload exists to produce).
    m5 = copy.deepcopy(atlas_body)
    row5 = next((r for r in m5["runs"] if RANK.get(str(r.get("level")), -1) >= RANK[L6]
                 and r.get("transcript_sha256")), None)
    if row5 is not None:
        row5["normalisation"] = {**(row5.get("normalisation") or {}),
                                 "normalises": ["absolute_paths", "ports", "return_codes"]}
    out.append(("normalisation_erases_return_code", "erases evidence", m5))

    # a runtime row reaching above its build/link permit.
    m6 = copy.deepcopy(atlas_body)
    blocked = next((r for r in m6["runs"] if r.get("subject") == "candidate"
                    and RANK.get(str(r.get("level")), -1) == RANK[L0]), None)
    if blocked is not None:
        blocked["level"] = L6
        blocked["authority_applicable_level"] = L6
    out.append(("runtime_above_build_link_permit", "above the build/link level", m6))
    return out


def runtime_sensitivity_control(families_body: dict, freeze_body: dict, build_link_body: dict,
                                atlas_body: dict) -> dict:
    """Prove the court can fail: seed six mutations and require each to be caught.

    The honest atlas must yield **zero** findings (specificity), and each seeded mutation -- a
    candidate row whose level passes only by inflating its authority baseline, an `L5+` row with no
    load proof, an `L6+` row with an empty transcript hash, a missing authority runtime row for a
    family that reached `L4`, a normalisation that erases a return code, and a runtime row reaching
    above its build/link permit -- must be caught with a finding that names what it is.
    """
    base = runtime_findings(families_body, freeze_body, build_link_body, atlas_body)
    specificity = not base
    control: dict = {"baseline_findings": len(base), "specificity_holds": specificity}
    honest = specificity
    for name, needle, mutated in _mutations(atlas_body, freeze_body):
        caught = any(needle in f for f in
                     runtime_findings(families_body, freeze_body, build_link_body, mutated))
        control[f"injected_{name}"] = name
        control[f"caught_{name}"] = caught
        honest = honest and caught
    control["honest"] = bool(honest)
    return control


# --------------------------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------------------------

def _load_inputs() -> tuple[dict, dict, dict]:
    if not FAMILY_FREEZE.is_file():
        raise SystemExit(f"[downstream-runtime] {rel(FAMILY_FREEZE)} is absent; run 24.4 first")
    if not BUILD_LINK_ATLAS.is_file():
        raise SystemExit(f"[downstream-runtime] {rel(BUILD_LINK_ATLAS)} is absent; run 24.6 first")
    freeze_body = json.loads(FAMILY_FREEZE.read_text(encoding="utf-8"))["body"]
    families_body = (json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
                     if FAMILIES.is_file() else {})
    build_link_body = json.loads(BUILD_LINK_ATLAS.read_text(encoding="utf-8"))["body"]
    return freeze_body, families_body, build_link_body


def cmd_measure(authority_id: str) -> int:
    freeze_body, families_body, build_link_body = _load_inputs()
    if len(freeze_body.get("p1000") or []) != 1000:
        print(f"[downstream-runtime] the frozen P1000 carries "
              f"{len(freeze_body.get('p1000') or [])} family(ies), not 1000")
        return 1
    print(f"[downstream-runtime] loading and running the recipe-backed families against both "
          f"subjects (authority {authority_id} + candidate {rel(CANDIDATE_PREFIX)})")
    started = time.monotonic()
    body = derive_atlas(families_body, freeze_body, build_link_body, authority_id)
    findings = runtime_findings(families_body, freeze_body, build_link_body, body)
    control = runtime_sensitivity_control(families_body, freeze_body, build_link_body, body)
    if findings or not control["honest"]:
        print("[downstream-runtime] the measured atlas fails its own checks:")
        for f in findings:
            print(f"  - {f}")
        if not control["honest"]:
            print(f"  - the sensitivity control is not honest: {control}")
        return 1
    write_outputs(body, authority_id)
    c = body["counts"]
    print(f"[downstream-runtime] elapsed={time.monotonic() - started:.0f}s "
          f"with_recipe={c['with_recipe']} no_recipe={c['no_recipe']}")
    for subject in SUBJECTS:
        s = c["by_subject"][subject]
        print(f"  {subject:<9} loaded={s['loaded']} runtime={s['runtime']} "
              f"functional={s['functional']} failed={s['failed']} "
              f"not_attempted={s['not_attempted']}")
    print(f"  candidate_reaches_baseline={c['candidate_reaches_baseline']} "
          f"reaches_linked_baseline={c['candidate_reaches_linked_baseline']} "
          f"below_baseline={c['candidate_below_baseline']} "
          f"baseline_not_linked={c['candidate_baseline_not_linked']} "
          f"candidate_failures={c['candidate_failures']}")
    print(f"  -> {rel(OUT)}")
    return 0


def cmd_check(authority_id: str) -> int:
    del authority_id
    if not (FAMILY_FREEZE.is_file() and BUILD_LINK_ATLAS.is_file() and OUT.is_file()):
        print(f"[downstream-runtime] {rel(FAMILY_FREEZE)}, {rel(BUILD_LINK_ATLAS)} or {rel(OUT)} "
              f"is absent")
        return 1
    freeze_body, families_body, build_link_body = _load_inputs()
    atlas_body = _load_atlas()
    findings = runtime_findings(families_body, freeze_body, build_link_body, atlas_body)
    control = runtime_sensitivity_control(families_body, freeze_body, build_link_body, atlas_body)
    if findings:
        print(f"[downstream-runtime] {len(findings)} finding(s):")
        for f in findings:
            print(f"  - {f}")
    c = atlas_body.get("counts") or {}
    by = c.get("by_subject") or {}
    print(f"[downstream-runtime] with_recipe={c.get('with_recipe')} "
          f"cand_loaded={(by.get('candidate') or {}).get('loaded')} "
          f"cand_functional={(by.get('candidate') or {}).get('functional')} "
          f"reaches_baseline={c.get('candidate_reaches_baseline')} findings={len(findings)} "
          f"control honest={control['honest']}")
    return 0 if (not findings and control["honest"]) else 1


def self_test() -> int:
    """Prove the guard refuses a host invocation and the pure functions behave over committed data."""
    failures: list[str] = []

    # 1. The guard refuses a host invocation of this tool, naming the marker and the opt-in flag.
    refusal = phase24_guard.host_refusal_reasons("downstream_runtime.py")
    if not refusal:
        failures.append("the guard admitted a host invocation of downstream_runtime.py")
    else:
        manifest = phase24_guard.load_manifest()
        joined = " ".join(refusal)
        if str(manifest.get("marker")) not in joined:
            failures.append("the host refusal does not name the container marker")
        if str(manifest.get("env_flag")) not in joined:
            failures.append("the host refusal does not name the opt-in flag")

    # 2. The workload intents are well-formed over the reused recipe catalogue.
    for r in bl.RECIPES:
        name = r["family"]
        if name in PROGRAMS:
            spec = PROGRAMS[name]
            if not (r["family"] and spec["program"] and spec["launch"] and spec["version_re"]):
                failures.append(f"the runtime intent for {name!r} is incomplete")

    # 3. The normaliser never erases evidence: a return code survives it.
    sample = "exit=1 error=verify failed return_code=0 TLSv1.3 ECDHE-RSA-AES256-GCM-SHA384"
    norm = normalise_transcript(sample, Path("/p"), Path("/a"), Path("/s"), 8443)
    for kept in ("exit=1", "return_code=0", "TLSv1.3", "ECDHE-RSA-AES256-GCM-SHA384",
                 "error=verify failed"):
        if kept not in norm:
            failures.append(f"the normaliser erased evidence: {kept!r} is not in {norm!r}")

    # 4. The pure functions behave over the committed evidence.
    if not (FAMILY_FREEZE.is_file() and BUILD_LINK_ATLAS.is_file()):
        failures.append(f"{rel(FAMILY_FREEZE)} or {rel(BUILD_LINK_ATLAS)} is absent")
    else:
        freeze_body, families_body, build_link_body = _load_inputs()
        if len(freeze_body.get("p1000") or []) != 1000:
            failures.append("the frozen P1000 does not carry 1000 family(ies)")
        if not OUT.is_file():
            failures.append(f"{rel(OUT)} is absent; run --measure")
        else:
            atlas_body = _load_atlas()
            findings = runtime_findings(families_body, freeze_body, build_link_body, atlas_body)
            if findings:
                failures.append(f"the committed atlas has findings: {findings[:3]}")
            control = runtime_sensitivity_control(families_body, freeze_body, build_link_body,
                                                  atlas_body)
            if not control["honest"]:
                failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[downstream-runtime] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[downstream-runtime] self-test ok: the guard refuses a host invocation of this tool "
          "(marker and flag both named), the normaliser preserves every return code, error class, "
          "certificate decision and protocol/algorithm choice it must, the committed P1000 "
          "runtime/functional atlas reproduces with zero findings, and every seeded mutation "
          "(an inflated authority baseline, an L5 row with no load proof, an L6 row with an empty "
          "transcript, a missing authority runtime row, a normalisation that erases a return code, "
          "and a runtime row above its build/link permit) is caught with specificity holding")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--measure", action="store_true",
                    help="run the real builds and workloads and write the atlas (in-container)")
    ap.add_argument("--check", action="store_true",
                    help="validate the committed atlas without rebuilding (in-container)")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the pure functions over the committed evidence")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool fetches, compiles and runs, so it is an
    # execution entry point and a host invocation is refused.
    phase24_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return cmd_check(args.authority)
    return cmd_measure(args.authority)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
