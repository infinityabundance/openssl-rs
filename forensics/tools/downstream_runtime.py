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
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import struct
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
    # The 24.20 L7-expansion batch: four executable consumers and one DNSSEC tool set whose
    # functional level is a real local TLS/crypto operation rather than a banner.
    "fossil": {"program": "fossil", "launch": ["version"],
               "version_re": r"fossil version"},
    "ldns": {"program": "examples/.libs/ldns-signzone", "launch": ["-h"],
             "version_re": r"ldns-signzone", "lib_paths": [".libs"],
             "make_targets": ["examples"],
             # `make -j8 examples` races on libtool's .loT temporary names (observed:
             # `mv: cannot stat examples/ldns-*.loT`); the workload target is built serially.
             "make_jobs": ["-j1"]},
    "rsync": {"program": "rsync", "launch": ["--version"],
              "version_re": r"rsync\s+version"},
    "socat": {"program": "socat", "launch": ["-V"], "version_re": r"socat version"},
    "squid": {"program": "src/squid", "launch": ["-v"],
              "version_re": r"Squid Cache: Version"},
    # The 24.21 L7-expansion batch: two TLS servers (stunnel/openvpn), a TLS scanner (sslscan), a
    # VPN key-exchange daemon (tinc) and a TLS Redis client (hiredis-ssl).
    "stunnel": {"program": "src/stunnel", "launch": ["-version"],
                "version_re": r"stunnel 5"},
    "sslscan": {"program": "sslscan", "launch": ["--version"],
                "version_re": r"OpenSSL \d"},
    "openvpn": {"program": "src/openvpn/openvpn", "launch": ["--version"],
                "version_re": r"OpenVPN 2"},
    "tinc": {"program": "src/tincd", "launch": ["--version"],
             "version_re": r"tinc version 1\.0"},
    # hiredis ships no TLS CLI; its own upstream example is the admitted program. The default
    # recipe make builds the libraries and the unit test but not the example, so the example target
    # is built here with the recipe's own OpenSSL environment (`USE_SSL=1`, `OPENSSL_PREFIX`).
    "hiredis-ssl": {"program": "examples/hiredis-example-ssl", "launch": ["--help"],
                    "version_re": r"Usage:",
                    "make_targets": ["hiredis-example-ssl"],
                    "make_env": {"OPENSSL_PREFIX": "{prefix}", "USE_SSL": "1"}},
    # The 24.22 L7-expansion batch: a CONNECT-tunnel client and a health checker whose TLS evidence
    # is a fetched-page digest rather than a banner.
    "proxytunnel": {"program": "proxytunnel", "launch": ["-h"],
                    "version_re": r"proxytunnel \d"},
    "keepalived": {"program": "keepalived/keepalived", "launch": ["-v"],
                   "version_re": r"Keepalived v\d"},
    # The 24.23 L7-expansion batch: an SMTP submitter that speaks STARTTLS and an FTP/HTTP client
    # whose HTTPS fetch path is its libssl consumer path.
    "ssmtp": {"program": "ssmtp", "launch": ["-V"],
              "version_re": r"sSMTP 2\.64"},
    "tnftp": {"program": "src/tnftp", "launch": ["-?"],
              "version_re": r"usage: tnftp"},
    # The Phase-25 L7-expansion batch: an IMAPS client (fetchmail), an RSA/SHA-256 authenticated
    # throughput tool (iperf3) and a module-signature parser (kmod). Each asserts the family's own
    # OpenSSL consumer path, not a banner.
    "fetchmail": {"program": "fetchmail", "launch": ["--version"],
                  "version_re": r"fetchmail release 6\.5"},
    # iperf3's recipe artifact is the shared library, but configure also links `src/iperf3`; the
    # libtool target binary under `.libs` is what the loader trace can resolve.
    "iperf3": {"program": "src/.libs/iperf3", "launch": ["--version"],
               "version_re": r"iperf 3", "lib_paths": ["src/.libs"]},
    # kmod dispatches its tools on argv[0]; `tools/modinfo` is the build tree's own symlink to the
    # single kmod binary, so launching it selects the modinfo command (and keeps the loader proof
    # on the ELF that libkmod links).
    "kmod": {"program": "tools/modinfo", "launch": ["--version"],
             "version_re": r"kmod version"},
    # The 24.24 L7-expansion batch: three LIBRARY-only families. They ship no executable of their
    # own, so the admitted workload is a small harness under forensics/tools/ built against the
    # rebuilt library and the subject prefix. `harness` compiles it into the source tree before the
    # launch/load proof, exactly as `make_targets` builds a workload target for an upstream tree.
    "libevent": {
        "program": ".l7-libevent-harness", "launch": ["--version"],
        "version_re": r"libevent-l7-harness", "lib_paths": [".libs"],
        "harness": {
            "source": "forensics/tools/l7_libevent.c",
            "cflags": ["-I{root}/include", "-I{prefix}/include"],
            "ldflags": ["-L{root}/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-levent_openssl", "-levent", "-lssl", "-lcrypto", "-pthread"],
        },
        "note": ("libevent's own libevent_openssl consumer path: two bufferevents over a "
                 "socketpair negotiate TLS1.3, verify the peer against the fixture CA and carry "
                 "a payload round trip; an unrelated CA is rejected"),
    },
    "libretls": {
        # Known candidate blocker (2026-10-21): every libtls context calls
        # SSL_CTX_set_tlsext_status_cb, whose macro reaches
        # SSL_CTX_callback_ctrl(SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB); the candidate falls through to
        # `_ => 0` (src/ssl/ssl_lib.rs:5022), so tls_configure fails before the handshake. The
        # workload is recorded honestly at L5 until that control arm lands.
        "program": ".l7-libretls-harness", "launch": ["--version"],
        "version_re": r"libretls-l7-harness", "lib_paths": [".libs"],
        "harness": {
            "source": "forensics/tools/l7_libretls.c",
            "cflags": ["-I{root}/include", "-I{prefix}/include"],
            "ldflags": ["-L{root}/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-ltls", "-lssl", "-lcrypto"],
        },
        "note": ("libtls (libretls) consumer path: client+server over a socketpair complete a "
                 "verified TLS1.3 handshake and a payload round trip; an unrelated CA is "
                 "rejected"),
    },
    "libarchive": {
        "program": ".l7-libarchive-harness", "launch": ["--version"],
        "version_re": r"libarchive-l7-harness", "lib_paths": [".libs"],
        "harness": {
            "source": "forensics/tools/l7_libarchive.c",
            "cflags": ["-I{root}/libarchive", "-I{prefix}/include"],
            "ldflags": ["-L{root}/.libs", "-L{prefix}/lib",
                        "-Wl,-rpath,{root}/.libs", "-Wl,-rpath,{prefix}/lib",
                        "-larchive", "-lcrypto", "-lz"],
        },
        "note": ("libarchive's own create/read path: an in-memory tar carries a payload and its "
                 "libcrypto SHA-256 digest, the read-back verifies it, and a tampered payload "
                 "byte is rejected"),
    },
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


def _wait_log(path: Path, needle: str, timeout: float = 25.0) -> bool:
    """Wait for a literal line/marker in a spawned program's log; the workload's own evidence."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if needle in _read(path):
            return True
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
    # A client certificate from the same CA, for the workloads whose client authenticates to the
    # server with a certificate (hiredis-ssl's example, openvpn's client). It is an extra fixture
    # file only: it changes no workload that does not read it.
    cli_key, cli_csr, cli_crt = d / "client.key", d / "client.csr", d / "client.crt"
    cli_ext = d / "client.ext"
    res = _ossl(authority_prefix, ["req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(cli_key),
                                   "-out", str(cli_csr), "-subj", "/CN=127.0.0.1"], timeout=60)
    if not res["ok"]:
        raise RuntimeError(f"generating the client csr failed: {census._error_line(res)}")
    cli_ext.write_text("subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n"
                       "extendedKeyUsage=clientAuth\n", encoding="utf-8")
    res = _ossl(authority_prefix, ["x509", "-req", "-in", str(cli_csr), "-CA", str(ca_crt),
                                   "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(cli_crt),
                                   "-days", "7", "-extfile", str(cli_ext)], timeout=60)
    if not res["ok"]:
        raise RuntimeError(f"signing the client certificate failed: {census._error_line(res)}")
    return {"ca_crt": ca_crt, "ca_key": ca_key, "srv_crt": srv_crt, "srv_key": srv_key,
            "srv_pem": srv_pem, "other_crt": other_crt,
            "client_crt": cli_crt, "client_key": cli_key}


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


def _http_connect_proxy(port: int, stop: threading.Event) -> threading.Thread:
    """A minimal loopback HTTP CONNECT proxy on `port`, relaying bytes both ways.

    It answers `CONNECT host:port HTTP/1.x` with `200 Connection established` and then pipes the
    client and the origin until either side closes, exactly the one hop a CONNECT-tunnel workload
    needs. Every connection is handled on its own thread so a rejected tunnel cannot stall the next.
    """
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(8)
    listener.settimeout(0.5)

    def relay(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                dst.sendall(chunk)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def handle(client: socket.socket) -> None:
        with client:
            client.settimeout(15.0)
            head = b""
            try:
                while b"\r\n\r\n" not in head:
                    chunk = client.recv(4096)
                    if not chunk:
                        return
                    head += chunk
                target = head.split(b"\r\n", 1)[0].decode("utf-8", "ignore").split()[1]
                host, _, num = target.rpartition(":")
                origin = socket.create_connection((host, int(num)), timeout=5.0)
            except (OSError, IndexError, ValueError):
                return
            with origin:
                client.sendall(b"HTTP/1.0 200 Connection established\r\n\r\n")
                upstream = threading.Thread(target=relay, args=(client, origin), daemon=True)
                upstream.start()
                relay(origin, client)
                upstream.join(timeout=2)

    def serve() -> None:
        while not stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=handle, args=(client,), daemon=True).start()
        listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


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
    """A TLS redis: a verified handshake plus two independent encrypted paths.

    The PING path exercises a single command over TLS; the SET/GET path exercises two further
    record-layer round trips and asserts the returned value, so a broken record layer or a broken
    key space is distinguishable from a broken handshake. A client trusting only the unrelated CA
    must be rejected, so an unverifiable server certificate is a recorded failure rather than a
    silent pass.
    """
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
        kv = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-quiet"],
                       stdin_text="SET phase24:probe phase24-value\r\nGET phase24:probe\r\n",
                       timeout=25)
        neg = _s_client(ap, port, pki["other_crt"],
                        ["-tls1_3", "-brief", "-verify_return_error"], stdin_text="", timeout=25)
    finally:
        _stop(srv)
        of.close()
        ef.close()
    runtime_ok = "Verification: OK" in hs["stderr"] and "Protocol version: TLSv1.3" in hs["stderr"]
    ping_ok = "+PONG" in ping["stdout"]
    kv_ok = "+OK" in kv["stdout"] and "phase24-value" in kv["stdout"]
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    functional_ok = runtime_ok and ping_ok and kv_ok and neg_rejected
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS 1.3 handshake did not verify" if not runtime_ok else
             "the encrypted PING did not return +PONG" if not ping_ok else
             "the SET/GET round trip did not return the stored value" if not kv_ok else
             "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(("authority s_client -brief", hs),
                                      ("authority s_client PING", ping),
                                      ("authority s_client SET/GET", kv),
                                      ("authority s_client unrelated-ca (must fail)", neg),
                                      ("redis-server", {"exit_code": 0,
                                                        "stdout": _read(d / "redis.err")})),
            "workload": ("redis: TLS handshake + encrypted PING/+PONG + SET/GET round trip + "
                         "unrelated-CA reject"), "local_only": True}


def _wl_monit(ctx: dict) -> dict:
    """A TLS monit: verified TLS 1.3 and TLS 1.2 paths, each answering an HTTP request.

    TLS 1.2 and TLS 1.3 are separate handshake/record paths in the server's libssl, so both being
    exercised makes a version-specific regression visible. A client trusting only the unrelated CA
    must be rejected, so an unverifiable certificate is a recorded failure.
    """
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
        hs12 = _s_client(ap, port, pki["ca_crt"], ["-tls1_2", "-brief"], stdin_text="",
                         timeout=25)
        get12 = _s_client(ap, port, pki["ca_crt"], ["-tls1_2", "-quiet"],
                          stdin_text="GET / HTTP/1.0\r\nConnection: close\r\n\r\n", timeout=25)
        neg = _s_client(ap, port, pki["other_crt"],
                        ["-tls1_3", "-brief", "-verify_return_error"], stdin_text="", timeout=25)
    finally:
        _stop(srv)
        _kill_comm("monit")
        of.close()
        ef.close()
    runtime_ok = "Verification: OK" in hs["stderr"] and "Protocol version: TLSv1.3" in hs["stderr"]
    get_ok = "HTTP/" in get["stdout"]
    tls12_ok = ("Verification: OK" in hs12["stderr"]
                and "Protocol version: TLSv1.2" in hs12["stderr"]
                and "HTTP/" in get12["stdout"])
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    functional_ok = runtime_ok and get_ok and tls12_ok and neg_rejected
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS 1.3 handshake did not verify" if not runtime_ok else
             "the TLS httpd did not answer an HTTP request" if not get_ok else
             "the TLS 1.2 handshake or HTTP response failed" if not tls12_ok else
             "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(("monit -t", check), ("authority s_client -brief", hs),
                                      ("authority s_client GET", get),
                                      ("authority s_client -brief tls1_2", hs12),
                                      ("authority s_client GET tls1_2", get12),
                                      ("authority s_client unrelated-ca (must fail)", neg)),
            "workload": ("monit: TLS httpd handshake + HTTP response over TLS 1.3 and TLS 1.2 + "
                         "unrelated-CA reject"), "local_only": True}


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

    The second harness repeats the login over TLS 1.2 (a different handshake/record path from the
    default TLS 1.3 session) and a client trusting only the unrelated CA must be rejected, so a
    version-specific or certificate-chain defect is not masked by the single successful session.
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
        session12 = _ossl(ap, ["s_client", "-connect", f"127.0.0.1:{port}", "-starttls", "ftp",
                               "-CAfile", str(pki["ca_crt"]), "-servername", "127.0.0.1",
                               "-tls1_2", "-ign_eof"],
                          timeout=25,
                          stdin_text=f"USER {user}\r\nPASS {passwd}\r\nPWD\r\nQUIT\r\n")
        neg = _ossl(ap, ["s_client", "-connect", f"127.0.0.1:{port}", "-starttls", "ftp",
                         "-CAfile", str(pki["other_crt"]), "-servername", "127.0.0.1",
                         "-verify_return_error", "-brief", "-ign_eof"],
                    timeout=25, stdin_text="")
    finally:
        _stop(proc)
        _kill_comm("pure-ftpd")
        of.close()
        ef.close()
    replies = (session["stdout"] or "") + (session["stderr"] or "")
    replies12 = (session12["stdout"] or "") + (session12["stderr"] or "")
    runtime_ok = "230" in replies or "331" in replies
    login_ok = runtime_ok and "230" in replies and "257" in replies
    tls12_ok = "230" in replies12 and "257" in replies12 and "TLSv1.2" in replies12
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    functional_ok = login_ok and tls12_ok and neg_rejected
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the authenticated FTPS login did not complete" if not runtime_ok else
             "the FTPS session did not answer PWD" if not login_ok else
             "the FTPS login over TLS 1.2 did not complete" if not tls12_ok else
             "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(("authority s_client -starttls ftp (USER/PASS/PWD/QUIT)",
                                       session),
                                      ("authority s_client -starttls ftp tls1_2", session12),
                                      ("authority s_client unrelated-ca (must fail)", neg),
                                      ("pure-ftpd", {"exit_code": 0, "stdout": _read(d / "ftpd.err")})),
            "workload": ("pure-ftpd: authenticated FTPS login + PWD over explicit TLS 1.3 and "
                         "TLS 1.2 + unrelated-CA reject"),
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


def _imap_plain_readline(conn) -> bytes:
    """Read one CRLF-terminated line from the plaintext socket without over-reading into TLS."""
    buf = bytearray()
    while True:
        try:
            ch = conn.recv(1)
        except OSError:
            return bytes(buf)
        if not ch:
            return bytes(buf)
        buf += ch
        if ch == b"\n":
            return bytes(buf)


def _imap_serve_starttls(conn, sctx, stop: threading.Event) -> None:
    """Serve the plaintext greeting/CAPABILITY/STARTTLS exchange, then hand off to the TLS peer.

    A STARTTLS IMAP session is a different client path in mbsync from implicit IMAPS: the client
    reads the plaintext capability list, issues STARTTLS and upgrades the same connection. The
    plaintext reads are byte-at-a-time so no part of the following TLS ClientHello is consumed, and
    the same socket is wrapped in place so the handshake continues on that stream.
    """
    wrapped = False
    try:
        conn.sendall(b"* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN UIDPLUS STARTTLS] phase24 isync "
                     b"fixture ready\r\n")
        while not stop.is_set():
            raw = _imap_plain_readline(conn)
            if not raw:
                break
            line = raw.decode("utf-8", "ignore").rstrip("\r\n")
            if not line:
                continue
            parts = line.split(" ", 2)
            if len(parts) < 2:
                continue
            tag, cmd = parts[0], parts[1].upper()
            if cmd == "CAPABILITY":
                conn.sendall(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN UIDPLUS STARTTLS\r\n")
                conn.sendall(f"{tag} OK CAPABILITY completed\r\n".encode())
            elif cmd == "STARTTLS":
                conn.sendall(f"{tag} OK Begin TLS negotiation now\r\n".encode())
                tls = sctx.wrap_socket(conn, server_side=True)
                wrapped = True
                try:
                    _imap_serve_one(tls, stop)
                finally:
                    tls.close()
                break
            else:
                conn.sendall(f"{tag} BAD CAPABILITY or STARTTLS expected\r\n".encode())
    finally:
        if not wrapped:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


def _imaps_server(cert_pem: Path, port: int, ready: threading.Event, stop: threading.Event,
                  starttls: bool = False) -> None:
    """Accept IMAPS (or STARTTLS-upgraded IMAP) on loopback and serve the fixture until `stop`."""
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
            if starttls:
                _imap_serve_starttls(conn, sctx, stop)
            else:
                tls = sctx.wrap_socket(conn, server_side=True)
                _imap_serve_one(tls, stop)
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                if tls is not None:
                    tls.close()
                elif starttls:
                    conn.close()
            except Exception:  # noqa: BLE001
                pass
    srv.close()


def _write_mbsync_conf(path: Path, port: int, cacert: Path, maildir: Path,
                       tlstype: str) -> None:
    """Write one mbsync channel over `port`, verifying against `cacert` and syncing `maildir`."""
    path.write_text(
        "IMAPAccount phase24\n"
        "Host 127.0.0.1\n"
        f"Port {port}\n"
        "User runtime\n"
        "Pass runtime\n"
        f"TLSType {tlstype}\n"
        f"CertificateFile {cacert}\n"
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


def _wl_isync(ctx: dict) -> dict:
    """A real IMAP-over-TLS sync: the subject mbsync pulls a message from a local IMAP peer.

    24.17 adds the missing deterministic local workload: a one-mailbox IMAP4rev1 peer served by the
    courtroom's own Python over TLS with the authority-generated certificate, on loopback only. The
    subject `mbsync` connects with IMAPS, authenticates, fetches the message and writes it to a local
    Maildir, so the family reaches the functional level the authority can.

    The second harness drives the STARTTLS upgrade path (a different client code path from implicit
    IMAPS) into a second Maildir, and a config trusting only the unrelated CA must abort the fetch
    with a non-zero exit and no delivered message. A certificate-verification or upgrade-path
    defect is therefore visible independently of the single successful IMAPS fetch.
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
    stport = _free_port()
    negdir, stmdir = d / "maildir-neg", d / "maildir-starttls"
    for target in (negdir, stmdir):
        for sub in ("cur", "new", "tmp"):
            (target / sub).mkdir(parents=True, exist_ok=True)
    negconf, stconf = d / "mbsyncrc-neg", d / "mbsyncrc-starttls"
    _write_mbsync_conf(negconf, port, pki["other_crt"], negdir, "IMAPS")
    _write_mbsync_conf(stconf, stport, pki["ca_crt"], stmdir, "STARTTLS")
    ready, stop = threading.Event(), threading.Event()
    thr = threading.Thread(target=_imaps_server, args=(pki["srv_pem"], port, ready, stop),
                           daemon=True)
    thr.start()
    ready.wait(timeout=10)
    ready2, stop2 = threading.Event(), threading.Event()
    thr2 = threading.Thread(target=_imaps_server,
                            args=(pki["srv_pem"], stport, ready2, stop2, True), daemon=True)
    thr2.start()
    ready2.wait(timeout=10)
    try:
        if (not _wait_tcp("127.0.0.1", port, timeout=10)
                or not _wait_tcp("127.0.0.1", stport, timeout=10)):
            return _wl_fail([], "the local IMAP peer did not listen", "runtime-failure", d)
        sync = _run_captured([str(ctx["program"]), "-c", str(conf), "phase24"], cwd=d,
                             env=ctx["env"], timeout=60)
        negsync = _run_captured([str(ctx["program"]), "-c", str(negconf), "phase24"], cwd=d,
                                env=ctx["env"], timeout=60)
        stsync = _run_captured([str(ctx["program"]), "-c", str(stconf), "phase24"], cwd=d,
                               env=ctx["env"], timeout=60)
    finally:
        stop.set()
        stop2.set()
        thr.join(timeout=5)
        thr2.join(timeout=5)
        _kill_comm("mbsync")
    msgs = [p for p in maildir.rglob("*") if p.is_file() and p.parent.name in ("new", "cur")]
    negmsgs = [p for p in negdir.rglob("*") if p.is_file() and p.parent.name in ("new", "cur")]
    stmsgs = [p for p in stmdir.rglob("*") if p.is_file() and p.parent.name in ("new", "cur")]
    sync_ok = sync["exit_code"] == 0 and bool(msgs)
    neg_rejected = negsync["exit_code"] != 0 and not negmsgs
    starttls_ok = stsync["exit_code"] == 0 and bool(stmsgs)
    functional_ok = sync_ok and neg_rejected and starttls_ok
    runtime_ok = sync["exit_code"] == 0 or bool(msgs)
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the local IMAP-over-TLS sync did not complete" if not runtime_ok else
             "the IMAPS sync did not deliver the fixture message" if not sync_ok else
             "the unrelated CA did not abort the IMAPS fetch" if not neg_rejected else
             "the STARTTLS sync did not deliver the fixture message"),
            "transcript": _transcript(("mbsync -c mbsyncrc phase24", sync),
                                      ("mbsync unrelated-ca (must abort)", negsync),
                                      ("mbsync -c mbsyncrc-starttls phase24", stsync)),
            "workload": ("isync: mbsync IMAPS fetch + STARTTLS fetch from a local IMAP peer + "
                         "unrelated-CA abort"),
            "local_only": True}


def _wl_socat(ctx: dict) -> dict:
    """A TLS socat: a verified TLS 1.3 session carries a round trip to an EXEC peer.

    `OPENSSL-LISTEN` is socat's own libssl server path; the authority's `s_client` verifies the
    certificate and sends a line that a one-shot shell peer answers. A client trusting only the
    unrelated CA must be rejected, so an unverifiable server certificate is a recorded failure.
    """
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    echo = d / "echo.sh"
    echo.write_text("#!/bin/sh\nread line\nprintf 'socat-echo:%s\\n' \"$line\"\n",
                    encoding="utf-8")
    os.chmod(echo, 0o755)
    argv = [str(ctx["program"]),
            (f"OPENSSL-LISTEN:{port},reuseaddr,fork,cert={pki['srv_crt']},"
             f"key={pki['srv_key']},verify=0"),
            f"EXEC:{echo}"]
    srv, of, ef = _spawn(argv, d, ctx["env"], d / "socat.out", d / "socat.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([], "socat did not open its TLS port", "runtime-failure", d)
        echo_res = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-quiet"],
                             stdin_text="phase24-socat\n", timeout=25)
        neg = _s_client(ap, port, pki["other_crt"],
                        ["-tls1_3", "-brief", "-verify_return_error"], stdin_text="", timeout=25)
    finally:
        _stop(srv)
        of.close()
        ef.close()
    runtime_ok = "socat-echo:phase24-socat" in echo_res["stdout"]
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    functional_ok = runtime_ok and neg_rejected
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS session did not carry the peer's echo" if not runtime_ok else
             "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(("authority s_client echo", echo_res),
                                      ("authority s_client unrelated-ca (must fail)", neg),
                                      ("socat", {"exit_code": 0,
                                                 "stdout": _read(d / "socat.err")})),
            "workload": ("socat: verified TLS1.3 session + encrypted echo round trip + "
                         "unrelated-CA reject"),
            "local_only": True}


def _wl_rsync(ctx: dict) -> dict:
    """A local rsync: a verified copy plus the checksum path (`-c`) that consumes OpenSSL MD5.

    `rsync -ac` compares file digests instead of sizes/mtimes. A same-content file whose mtime
    alone moved must not be transferred, while changed content must be. The pair distinguishes a
    working digest path from a copy that silently ignores it.
    """
    d, rs = ctx["workdir"], ctx["program"]
    src, dst = d / "src", d / "dst"
    src.mkdir(parents=True, exist_ok=True)
    dst.mkdir(parents=True, exist_ok=True)
    probe = src / "probe.txt"
    probe.write_text("phase24-rsync-payload\n", encoding="utf-8")
    copy = _run_captured([str(rs), "-a", f"{src}/", f"{dst}/"], env=ctx["env"], timeout=30)
    copied = (dst / "probe.txt").is_file() and (
        (dst / "probe.txt").read_text(encoding="utf-8") == probe.read_text(encoding="utf-8"))
    # Move only the mtime: a checksum comparison must see identical content and skip the file.
    stamp = time.time() + 300
    os.utime(probe, (stamp, stamp))
    skip = _run_captured([str(rs), "-ac", "--itemize-changes", f"{src}/", f"{dst}/"],
                         env=ctx["env"], timeout=30)
    skip_ok = skip["ok"] and not any(line.startswith(">f")
                                     for line in skip["stdout"].splitlines())
    # Change the content: the same checksum path must now transfer the file.
    probe.write_text("phase24-rsync-payload-changed\n", encoding="utf-8")
    changed = _run_captured([str(rs), "-ac", "--itemize-changes", f"{src}/", f"{dst}/"],
                            env=ctx["env"], timeout=30)
    change_ok = (changed["ok"]
                 and any(line.startswith(">f") for line in changed["stdout"].splitlines())
                 and (dst / "probe.txt").read_text(encoding="utf-8")
                 == probe.read_text(encoding="utf-8"))
    runtime_ok = copy["ok"] and copied
    functional_ok = runtime_ok and skip_ok and change_ok
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the local copy did not complete" if not runtime_ok else
             "the checksum path transferred an unchanged file" if not skip_ok else
             "the checksum path did not transfer changed content"),
            "transcript": _transcript(("rsync -a copy", copy), ("rsync -ac unchanged", skip),
                                      ("rsync -ac changed", changed)),
            "workload": "rsync: local copy + OpenSSL-MD5 checksum skip/transfer",
            "local_only": True}


def _wl_fossil(ctx: dict) -> dict:
    """A TLS fossil server: a verified TLS 1.3 handshake and a real HTTP 200 from the SCM UI."""
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    env = dict(ctx["env"], USER="fossil", LOGNAME="fossil", HOME=str(d))
    repo = d / "repo.fossil"
    init = _run_captured([str(ctx["program"]), "init", "-A", "fossil", str(repo)], cwd=d,
                         env=env, timeout=30)
    if not init["ok"] or not repo.is_file():
        return _wl_fail([("fossil init", {"exit_code": init["exit_code"],
                                        "stdout": "repository created" if repo.is_file() else ""})],
                        f"fossil could not create its repository: {census._error_line(init)}",
                        "runtime-failure", d)
    srv, of, ef = _spawn([str(ctx["program"]), "server", "--localhost", "--nojail", "--port",
                          str(port), "--cert", str(pki["srv_crt"]), "--pkey",
                          str(pki["srv_key"]), str(repo)], d, env, d / "fossil.out",
                         d / "fossil.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("fossil init", {"exit_code": init["exit_code"],
                                            "stdout": "repository created" if repo.is_file()
                                            else ""})],
                            "fossil did not open its TLS port", "runtime-failure", d)
        hs = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-brief"], stdin_text="",
                       timeout=25)
        get = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-quiet"],
                        stdin_text="GET /home HTTP/1.0\r\nHost: 127.0.0.1\r\n"
                                   "Connection: close\r\n\r\n", timeout=25)
        neg = _s_client(ap, port, pki["other_crt"],
                        ["-tls1_3", "-brief", "-verify_return_error"], stdin_text="", timeout=25)
    finally:
        _stop(srv)
        _kill_comm("fossil")
        of.close()
        ef.close()
    runtime_ok = ("Verification: OK" in hs["stderr"]
                  and "Protocol version: TLSv1.3" in hs["stderr"])
    page_ok = "HTTP/1.0 200 OK" in get["stdout"] and "Fossil" in get["stdout"]
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    functional_ok = runtime_ok and page_ok and neg_rejected
    # The SCM page carries server timestamps and generated identifiers; only the status and the
    # functional marker are evidence, so the transcript keeps exactly those.
    get_note = {"exit_code": get["exit_code"],
                "stdout": "\n".join(line for line in get["stdout"].splitlines()
                                     if line.startswith("HTTP/") or "Fossil" in line)[:400]}
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS 1.3 handshake did not verify" if not runtime_ok else
             "the SCM UI did not answer an HTTP request" if not page_ok else
             "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(("fossil init", {"exit_code": init["exit_code"],
                                                       "stdout": "repository created"
                                                       if repo.is_file() else ""}),
                                      ("authority s_client -brief", hs),
                                      ("authority s_client GET /home", get_note),
                                      ("authority s_client unrelated-ca (must fail)", neg)),
            "workload": "fossil: verified TLS1.3 server + HTTP 200 + unrelated-CA reject",
            "local_only": True}


def _wl_squid(ctx: dict) -> dict:
    """A TLS squid: the authority client fetches through squid's `https_port` proxy.

    The proxy terminates TLS with its own libssl, forwards a plain HTTP request to a local origin,
    and returns the origin's body. A client trusting only the unrelated CA must be rejected.
    """
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    for stale in Path("/dev/shm").glob("squid-*"):
        try:
            stale.unlink()
        except OSError:
            pass
    docroot = d / "docroot"
    docroot.mkdir(parents=True, exist_ok=True)
    (docroot / "index.html").write_text("phase24-squid-ok\n", encoding="utf-8")
    origin_port = _free_port()
    origin, oof, oef = _spawn([sys.executable, "-m", "http.server", str(origin_port), "--bind",
                              "127.0.0.1"], docroot, ctx["env"], d / "origin.out",
                             d / "origin.err")
    srv = of = ef = None
    try:
        if not _wait_tcp("127.0.0.1", origin_port):
            return _wl_fail([], "the local HTTP origin did not listen", "runtime-failure", d)
        icons = d / "icons"
        icons.mkdir(parents=True, exist_ok=True)
        mime = d / "mime.conf"
        mime.write_text("text/plain txt\n", encoding="utf-8")
        for writable in (d, docroot, icons):
            os.chmod(writable, 0o777)
        for readable in (pki["srv_crt"], pki["srv_key"], mime):
            os.chmod(readable, 0o644)
        conf = d / "squid.conf"
        conf.write_text(
            f"http_port 127.0.0.1:{_free_port()}\n"
            f"https_port 127.0.0.1:{port} tls-cert={pki['srv_crt']} "
            f"tls-key={pki['srv_key']}\n"
            "acl all src all\n"
            "http_access allow all\n"
            "cache deny all\n"
            "cache_replacement_policy heap\n"
            "memory_replacement_policy heap\n"
            "unlinkd_program /bin/true\n"
            "cache_effective_user nobody\n"
            "cache_effective_group nogroup\n"
            f"pid_filename {d}/squid.pid\n"
            f"coredump_dir {d}\n"
            f"access_log stdio:{d}/access.log\n"
            f"cache_log {d}/cache.log\n"
            "cache_store_log none\n"
            f"mime_table {mime}\n"
            f"icon_directory {icons}\n"
            "visible_hostname phase24\n", encoding="utf-8")
        srv, of, ef = _spawn([str(ctx["program"]), "-N", "-f", str(conf)], d, ctx["env"],
                             d / "squid.out", d / "squid.err")
        if not _wait_tcp("127.0.0.1", port, timeout=25):
            return _wl_fail([], "squid did not open its TLS proxy port", "runtime-failure", d)
        get = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-quiet"],
                        stdin_text=(f"GET http://127.0.0.1:{origin_port}/index.html HTTP/1.0\r\n"
                                    "Host: 127.0.0.1\r\nConnection: close\r\n\r\n"),
                        timeout=25)
        neg = _s_client(ap, port, pki["other_crt"],
                        ["-tls1_3", "-brief", "-verify_return_error"], stdin_text="", timeout=25)
    finally:
        if srv is not None:
            _stop(srv)
        _kill_comm("squid")
        _stop(origin)
        for handle in (of, ef, oof, oef):
            if handle is not None:
                handle.close()
    runtime_ok = "HTTP/1.1 200 OK" in get["stdout"] and "phase24-squid-ok" in get["stdout"]
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    functional_ok = runtime_ok and neg_rejected
    # Keep the status line and the origin's marker; the origin's Date/Last-Modified are not evidence.
    get_note = {"exit_code": get["exit_code"],
                "stdout": "\n".join(line for line in get["stdout"].splitlines()
                                     if line.startswith("HTTP/") or "phase24-squid-ok" in line)}
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the proxied fetch did not return the origin's payload" if not runtime_ok else
             "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(("authority s_client GET via https_port", get_note),
                                      ("authority s_client unrelated-ca (must fail)", neg)),
            "workload": "squid: verified TLS1.3 https_port proxy fetch + unrelated-CA reject",
            "local_only": True}


def _wl_ldns(ctx: dict) -> dict:
    """A DNSSEC workload: ldns generates a key, signs a zone, and verifies the signature.

    `ldns-keygen` and `ldns-signzone` consume the subject's libcrypto for RSA/SHA-256,
    `ldns-verify-zone` validates the RRSIGs, and a one-record tamper must be reported as a bogus
    signature. The random key tag is evidence only of key generation, so it is not transcribed.
    """
    d, root = ctx["workdir"], ctx["root"]
    keygen = root / "examples" / ".libs" / "ldns-keygen"
    verify = root / "examples" / ".libs" / "ldns-verify-zone"
    if not keygen.is_file() or not verify.is_file():
        return _wl_fail([], "the ldns tools were not built by the examples target",
                        "runtime-failure", d)
    zone = d / "example.com.zone"
    zone.write_text(
        "example.com. 3600 IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 3600\n"
        "example.com. 3600 IN NS ns.example.com.\n"
        "ns.example.com. 3600 IN A 127.0.0.1\n"
        "www.example.com. 3600 IN A 127.0.0.1\n", encoding="utf-8")
    gen = _run_captured([str(keygen), "-a", "RSASHA256", "-b", "2048", "example.com"], cwd=d,
                        env=ctx["env"], timeout=60)
    names = [line.strip() for line in gen["stdout"].splitlines() if line.strip().startswith("K")]
    base = names[-1] if names else ""
    signed = d / "signed.zone"
    sign = _run_captured([str(ctx["program"]), "-n", "-f", str(signed), str(zone), base], cwd=d,
                         env=ctx["env"], timeout=60) if base else None
    checked = _run_captured([str(verify), str(signed)], cwd=d, env=ctx["env"], timeout=60) \
        if signed.is_file() else None
    tampered = d / "tampered.zone"
    tamper_rejected = False
    tamper = None
    if signed.is_file():
        tampered.write_text(
            re.sub(r"(www\.example\.com\.\s+3600\s+IN\s+A\s+)127\.0\.0\.1", r"\g<1>127.0.0.2",
                   signed.read_text(encoding="utf-8"), count=1), encoding="utf-8")
        tamper = _run_captured([str(verify), str(tampered)], cwd=d, env=ctx["env"], timeout=60)
        tamper_rejected = (tamper["exit_code"] != 0
                           and "Bogus DNSSEC signature" in (tamper["stdout"] + tamper["stderr"]))
    runtime_ok = bool(gen["ok"] and base and sign and sign["ok"] and checked and checked["ok"])
    functional_ok = (runtime_ok and "verified" in (checked["stdout"] + checked["stderr"])
                     and tamper_rejected)
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the zone could not be keyed and signed" if not runtime_ok else
             "the signed zone did not verify" if "verified" not in
             (checked["stdout"] + checked["stderr"]) else
             "a tampered record was not reported as a bogus signature"),
            "transcript": _transcript(
                ("ldns-keygen", {"exit_code": gen["exit_code"],
                                 "stdout": "key generated" if base else "no key"}),
                ("ldns-signzone", sign), ("ldns-verify-zone", checked),
                ("ldns-verify-zone tampered (must fail)", tamper)),
            "workload": ("ldns: DNSSEC RSASHA256 keygen + zone signing + verify + tamper reject"),
            "local_only": True}


def _wl_stunnel(ctx: dict) -> dict:
    """A TLS stunnel: a verified TLS 1.3 accept-forward round trip to a local plain peer.

    stunnel's `accept`/`connect` service is its own libssl server path: the authority's `s_client`
    verifies the certificate and sends a line that a one-shot loopback peer answers, so a broken
    accept path, record layer or forwarding path is distinguishable from a broken handshake. A
    client trusting only the unrelated CA must be rejected.
    """
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    back = _free_port()
    peer = socket.socket()
    peer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    peer.bind(("127.0.0.1", back))
    peer.listen(5)
    done = threading.Event()

    def echo() -> None:
        while not done.is_set():
            try:
                conn, _ = peer.accept()
            except OSError:
                return
            with conn:
                data = conn.recv(4096)
                conn.sendall(b"stunnel-echo:" + data.strip() + b"\n")

    thread = threading.Thread(target=echo, daemon=True)
    thread.start()
    conf = d / "stunnel.conf"
    conf.write_text(
        "foreground = yes\n"
        f"pid = {d}/stunnel.pid\n"
        "debug = 4\n"
        "[probe]\n"
        f"accept = 127.0.0.1:{port}\n"
        f"connect = 127.0.0.1:{back}\n"
        f"cert = {pki['srv_crt']}\n"
        f"key = {pki['srv_key']}\n"
        "sslVersionMin = TLSv1.3\n", encoding="utf-8")
    srv, of, ef = _spawn([str(ctx["program"]), str(conf)], d, ctx["env"], d / "stunnel.out",
                         d / "stunnel.err")
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("stunnel", {"exit_code": 0, "stdout": _read(d / "stunnel.err")})],
                            "stunnel did not open its accept port", "runtime-failure", d)
        echo_res = _s_client(ap, port, pki["ca_crt"], ["-tls1_3", "-quiet"],
                             stdin_text="phase24-stunnel\n", timeout=25)
        neg = _s_client(ap, port, pki["other_crt"],
                        ["-tls1_3", "-brief", "-verify_return_error"], stdin_text="", timeout=25)
    finally:
        _stop(srv)
        done.set()
        peer.close()
        thread.join(timeout=2)
        of.close()
        ef.close()
    runtime_ok = "stunnel-echo:phase24-stunnel" in echo_res["stdout"]
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stderr"] + neg["stdout"]))
    functional_ok = runtime_ok and neg_rejected
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS session did not carry the peer's echo" if not runtime_ok else
             "the unrelated CA was not rejected, so the server certificate does not verify"),
            "transcript": _transcript(("authority s_client echo", echo_res),
                                      ("authority s_client unrelated-ca (must fail)", neg),
                                      ("stunnel", {"exit_code": 0, "stdout": _read(
                                          d / "stunnel.err")})),
            "workload": ("stunnel: verified TLS1.3 accept-forward round trip + unrelated-CA reject"),
            "local_only": True}


def _wl_sslscan(ctx: dict) -> dict:
    """A TLS scan of a local candidate server: the reported protocol and cipher are the evidence.

    sslscan's own libssl client probes the authority's `s_server` on loopback and must report the
    negotiated TLS 1.3 protocol and an accepted TLS 1.3 cipher. The negative control is a server
    with TLS 1.3 disabled: `--tls13` must then report `TLSv1.3 disabled` rather than a fabricated
    result. sslscan performs no certificate-chain verification of its own (its verify mode is NONE,
    so every private chain reports a missing issuer), so an unrelated-CA rejection is not a
    discriminating negative control for this program and is deliberately not claimed.
    """
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    neg_port = _free_port()
    srv, of, ef = _spawn([str(_auth_ossl(ap)), "s_server", "-accept", str(port), "-cert",
                          str(pki["srv_crt"]), "-key", str(pki["srv_key"]), "-tls1_3", "-www"],
                         d, _auth_env(ap), d / "srv.out", d / "srv.err")
    neg, nof, nef = _spawn([str(_auth_ossl(ap)), "s_server", "-accept", str(neg_port), "-cert",
                            str(pki["srv_crt"]), "-key", str(pki["srv_key"]), "-tls1_2", "-www"],
                           d, _auth_env(ap), d / "neg.out", d / "neg.err")
    try:
        if not (_wait_tcp("127.0.0.1", port) and _wait_tcp("127.0.0.1", neg_port)):
            return _wl_fail([], "a local authority TLS server did not listen", "runtime-failure", d)
        scan = _run_captured([str(ctx["program"]), "--tls13", "--no-colour",
                              f"127.0.0.1:{port}"], env=ctx["env"], timeout=90)
        neg_scan = _run_captured([str(ctx["program"]), "--tls13", "--no-colour",
                                  f"127.0.0.1:{neg_port}"], env=ctx["env"], timeout=90)
    finally:
        _stop(srv)
        _stop(neg)
        of.close()
        ef.close()
        nof.close()
        nef.close()
    runtime_ok = ("TLSv1.3   enabled" in scan["stdout"]
                  and "TLS_AES_256_GCM_SHA384" in scan["stdout"])
    neg_ok = ("TLSv1.3   disabled" in neg_scan["stdout"]
              and "TLSv1.3   enabled" not in neg_scan["stdout"])
    functional_ok = runtime_ok and neg_ok
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("sslscan did not report the local server's TLS1.3 protocol and cipher"
             if not runtime_ok else
             "sslscan did not report TLSv1.3 as disabled on a TLS1.2-only server"),
            "transcript": _transcript(("sslscan --tls13", scan),
                                      ("sslscan --tls13 tls1.2-only (must be disabled)", neg_scan)),
            "workload": ("sslscan: TLS1.3 protocol/cipher scan of a local server + TLS1.2-only "
                         "negative control"),
            "local_only": True}


def _wl_openvpn(ctx: dict) -> dict:
    """A local OpenVPN TLS session: peer certificate verification and a completed handshake.

    Two subject-linked daemons run point-to-point over TCP with `--dev null` (no kernel device is
    created or configured): the client verifies the server certificate against the CA, the control
    channel negotiates TLS 1.3, and both sides reach `Initialization Sequence Completed`. A client
    trusting only the unrelated CA must fail verification, so an unverifiable peer certificate is a
    recorded failure rather than a silent pass.
    """
    ap, port, d = ctx["authority_prefix"], ctx["port"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    common = ["--dev", "null", "--dev-type", "null", "--ifconfig-noexec", "--route-noexec",
              "--dh", "none", "--verb", "4", "--cipher", "AES-256-GCM",
              "--data-ciphers", "AES-256-GCM:AES-128-GCM", "--data-ciphers-fallback",
              "AES-256-GCM"]
    srv_log, cli_log, neg_log = d / "srv.log", d / "cli.log", d / "neg.log"
    srv, of, ef = _spawn([prog, "--tls-server", "--ifconfig", "10.8.0.1", "10.8.0.2", "--proto",
                          "tcp-server", "--local", "127.0.0.1", "--port", str(port), "--ca",
                          str(pki["ca_crt"]), "--cert", str(pki["srv_crt"]), "--key",
                          str(pki["srv_key"])] + common, d, ctx["env"], srv_log,
                         d / "srv.err")
    cli = neg = None
    cf = nf = cfe = nfe = None
    try:
        if not _wait_tcp("127.0.0.1", port):
            return _wl_fail([("openvpn server", {"exit_code": 0, "stdout": _read(srv_log)})],
                            "the openvpn server did not open its TCP port", "runtime-failure", d)
        cli, cf, cfe = _spawn([prog, "--tls-client", "--ifconfig", "10.8.0.2", "10.8.0.1",
                               "--proto", "tcp-client", "--remote", "127.0.0.1", str(port),
                               "--nobind", "--ca", str(pki["ca_crt"]), "--cert",
                               str(pki["client_crt"]), "--key", str(pki["client_key"]),
                               "--remote-cert-tls", "server"] + common, d, ctx["env"], cli_log,
                              d / "cli.err")
        connected = _wait_log(cli_log, "Initialization Sequence Completed", timeout=25)
        _stop(cli)
        time.sleep(1.0)
        neg, nf, nfe = _spawn([prog, "--tls-client", "--ifconfig", "10.8.0.2", "10.8.0.1",
                               "--proto", "tcp-client", "--remote", "127.0.0.1", str(port),
                               "--nobind", "--ca", str(pki["other_crt"]), "--cert",
                               str(pki["client_crt"]), "--key", str(pki["client_key"]),
                               "--remote-cert-tls", "server"] + common, d, ctx["env"], neg_log,
                              d / "neg.err")
        _wait_log(neg_log, "VERIFY ERROR", timeout=15)
    finally:
        for proc in (cli, neg, srv):
            if proc is not None:
                _stop(proc)
        for handle in (of, ef, cf, cfe, nf, nfe):
            if handle is not None:
                handle.close()
    cli_text, neg_text = _read(cli_log), _read(neg_log)
    runtime_ok = ("Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384" in cli_text
                  and "Initialization Sequence Completed" in cli_text)
    neg_rejected = ("VERIFY ERROR" in neg_text
                    and "Initialization Sequence Completed" not in neg_text)
    functional_ok = runtime_ok and neg_rejected
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the local TLS control channel did not verify and initialise" if not runtime_ok else
             "the unrelated CA was not rejected, so the peer certificate does not verify"),
            "transcript": _transcript(("openvpn client", {"exit_code": 0, "stdout": cli_text}),
                                      ("openvpn client unrelated-ca (must fail)",
                                       {"exit_code": 0, "stdout": neg_text}),
                                      ("openvpn server", {"exit_code": 0, "stdout": _read(
                                          srv_log)})),
            "workload": ("openvpn: mutual certificate verify + TLS1.3 control channel + "
                         "Initialization Sequence + unrelated-CA reject"),
            "local_only": True}


def _wl_tinc(ctx: dict) -> dict:
    """A two-node tinc meta connection: RSA key generation, key exchange and a data packet.

    Both subject-linked `tincd` daemons use `DeviceType = dummy` (no kernel device), generate their
    RSA keys through the subject's libcrypto, authenticate the meta connection with those keys and
    complete the symmetric key exchange; the peer then sends a data packet over the established
    connection. A tinc without a reachable peer must not report an exchange, so the negative control
    runs the same node with its peer absent.
    """
    d = ctx["workdir"]
    prog = str(ctx["program"])
    ports = {"n1": ctx["port"], "n2": _free_port()}
    subnets = {"n1": 1, "n2": 2}
    conf: dict[str, Path] = {}
    keys: dict[str, str] = {}
    for node in ("n1", "n2"):
        conf[node] = d / node
        (conf[node] / "hosts").mkdir(parents=True, exist_ok=True)
        text = (f"Name = {node}\nDeviceType = dummy\nAddressFamily = ipv4\n"
                f"ListenAddress = 127.0.0.1\nPort = {ports[node]}\n")
        if node == "n1":
            text += "ConnectTo = n2\n"
        (conf[node] / "tinc.conf").write_text(text, encoding="utf-8")
        keygen = _run_captured([prog, "-c", str(conf[node]), "-K", "2048"], env=ctx["env"],
                               timeout=60)
        if not keygen["ok"]:
            return _wl_fail([("tincd -K", keygen)],
                            f"tincd could not generate an RSA key: {census._error_line(keygen)}",
                            "runtime-failure", d)
        keys[node] = _read(conf[node] / "hosts" / node)
    if not all(keys.values()):
        return _wl_fail([], "tincd generated no public key", "runtime-failure", d)

    def address(node: str) -> str:
        return (f"Address = 127.0.0.1\nPort = {ports[node]}\n"
                f"Subnet = 10.9.0.{subnets[node]}/32\n")

    for node in ("n1", "n2"):
        for peer in ("n1", "n2"):
            (conf[node] / "hosts" / peer).write_text(keys[peer] + address(peer), encoding="utf-8")
    logs = {node: d / f"{node}.log" for node in ("n1", "n2")}
    procs: dict[str, subprocess.Popen] = {}
    handles: dict[str, list] = {}

    def start(node: str, log: Path) -> None:
        out = open(log, "w", encoding="utf-8")
        procs[node] = subprocess.Popen(
            [prog, "-c", str(conf[node]), "-D", "-d", "3", "--pidfile", str(d / f"{node}.pid")],
            cwd=str(d), env=ctx["env"], stdout=out, stderr=subprocess.STDOUT, text=True)
        handles[node] = [out]

    try:
        start("n2", logs["n2"])
        time.sleep(1.0)
        start("n1", logs["n1"])
        exchanged = _wait_log(logs["n1"], "Got ANS_KEY from n2", timeout=25)
        _wait_log(logs["n1"], "Got PACKET from n2", timeout=5)
        _stop(procs["n1"])
        _stop(procs["n2"])
        neg_log = d / "n1-absent-peer.log"
        start("n1", neg_log)
        _wait_log(neg_log, "Could not set up a meta connection", timeout=20)
    finally:
        for proc in procs.values():
            _stop(proc)
        for opened in handles.values():
            for handle in opened:
                handle.close()
    text = _read(logs["n1"])
    runtime_ok = exchanged and "Got PACKET from n2" in text
    neg_text = _read(d / "n1-absent-peer.log")
    neg_rejected = ("Could not set up a meta connection" in neg_text
                    and "ANS_KEY" not in neg_text)
    functional_ok = runtime_ok and neg_rejected
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the two tinc nodes did not exchange keys and a data packet" if not runtime_ok else
             "a tinc without a reachable peer still reported an exchange"),
            "transcript": _transcript(("tincd n1 (peer n2)", {"exit_code": 0, "stdout": text}),
                                      ("tincd n1 absent-peer (must fail)",
                                       {"exit_code": 0, "stdout": neg_text})),
            "workload": ("tinc: RSA keygen + authenticated meta connection + key exchange + "
                         "data packet + absent-peer negative control"),
            "local_only": True}


def _wl_hiredis(ctx: dict) -> dict:
    """A TLS Redis session through hiredis: PING, SET and GET over a verified record layer.

    hiredis ships no TLS CLI, so its own upstream `example-ssl` is the admitted program. The local
    peer is the subject-linked `redis-server` the preceding redis family built in this same run
    (deterministically earlier in the frozen P1000 order), started with TLS on loopback; the example
    completes a verified TLS handshake and the PING/SET/GET round trips. A client trusting only the
    unrelated CA must be rejected.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    peer_src = bl.SCRATCH / "redis" / ctx["subject"] / "src"
    peer_root = census._single_source_root(peer_src) if peer_src.is_dir() else None
    peer = (peer_root / "src" / "redis-server") if peer_root else None
    if peer is None or not peer.is_file():
        return _wl_fail([], "the subject-linked redis-server peer was not built by this run",
                        "runtime-failure", d)
    dbdir = d / "db"
    dbdir.mkdir(parents=True, exist_ok=True)
    srv, of, ef = _spawn([str(peer), "--port", "0", "--tls-port", str(ctx["port"]),
                          "--tls-cert-file", str(pki["srv_crt"]), "--tls-key-file",
                          str(pki["srv_key"]), "--tls-ca-cert-file", str(pki["ca_crt"]),
                          "--tls-auth-clients", "no", "--save", "", "--protected-mode", "no",
                          "--dir", str(dbdir)], d, ctx["env"], d / "redis.out",
                         d / "redis.err")
    try:
        if not _wait_tcp("127.0.0.1", ctx["port"]):
            return _wl_fail([("redis-server", {"exit_code": 0, "stdout": _read(
                d / "redis.err")})], "the redis TLS peer did not open its port", "runtime-failure",
                            d)
        args = [str(ctx["program"]), "127.0.0.1", str(ctx["port"]), str(pki["client_crt"]),
                str(pki["client_key"])]
        good = _run_captured(args + [str(pki["ca_crt"])], env=ctx["env"], timeout=40)
        neg = _run_captured(args + [str(pki["other_crt"])], env=ctx["env"], timeout=40)
    finally:
        _stop(srv)
        of.close()
        ef.close()
    runtime_ok = "PING: PONG" in good["stdout"]
    kv_ok = ("SET: OK" in good["stdout"] and "GET foo: hello world" in good["stdout"])
    neg_rejected = (neg["exit_code"] != 0
                    and "certificate verify failed" in (neg["stdout"] + neg["stderr"]))
    functional_ok = runtime_ok and kv_ok and neg_rejected
    return {"runtime_ok": runtime_ok, "functional_ok": functional_ok,
            "failure_class": None if functional_ok else ("functional-failure" if runtime_ok else
                                                         "runtime-failure"),
            "residual": "none" if functional_ok else ("functional-divergence" if runtime_ok else
                                                      "runtime-failure"),
            "reason": None if functional_ok else
            ("the TLS PING did not return PONG" if not runtime_ok else
             "the SET/GET round trip did not return the stored value" if not kv_ok else
             "the unrelated CA was not rejected, so the peer certificate does not verify"),
            "transcript": _transcript(("hiredis-example-ssl PING/SET/GET", good),
                                      ("hiredis-example-ssl unrelated-ca (must fail)", neg)),
            "workload": ("hiredis-ssl: verified TLS connect + PING + SET/GET + unrelated-CA reject"),
            "local_only": True}


def _wl_proxytunnel(ctx: dict) -> dict:
    """A CONNECT tunnel through a local HTTP proxy whose destination leg is TLS.

    proxytunnel's documented ProxyCommand mode is driven over a socketpair: it CONNECTs to a local
    proxy, wraps the tunnelled stream in TLS to the authority's `s_server` (`-e`) and forwards a
    real HTTP GET whose fixed page comes back through the tunnel. A destination certificate whose
    SAN names a different address must not tunnel. proxytunnel 1.12.2 never calls
    `SSL_CTX_set_verify`, so an unrelated CA would not be rejected by this build; the certificate
    decision it does enforce is the host/SAN match, and that is the control driven here.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    prog = str(ctx["program"])
    pki = _gen_pki(ap, d)
    body = b"phase24-proxytunnel-tls-probe\n"
    (d / "probe.txt").write_bytes(body)

    bad_key, bad_csr, bad_crt = d / "bad.key", d / "bad.csr", d / "bad.crt"
    bad_ext = d / "bad.ext"
    csr = _ossl(ap, ["req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(bad_key), "-out",
                     str(bad_csr), "-subj", "/CN=127.0.0.2"], timeout=60)
    bad_ext.write_text("subjectAltName=IP:127.0.0.2\nbasicConstraints=CA:FALSE\n"
                       "keyUsage=digitalSignature,keyEncipherment\n"
                       "extendedKeyUsage=serverAuth\n", encoding="utf-8")
    signed = _ossl(ap, ["x509", "-req", "-in", str(bad_csr), "-CA", str(pki["ca_crt"]),
                        "-CAkey", str(pki["ca_key"]), "-CAcreateserial", "-out", str(bad_crt),
                        "-days", "7", "-extfile", str(bad_ext)], timeout=60)
    if not (csr["ok"] and signed["ok"]):
        return _wl_fail([("mismatched-SAN certificate", signed if not signed["ok"] else csr)],
                        "the mismatched-SAN certificate fixture could not be generated",
                        "runtime-failure", d)

    tls_port, bad_port, proxy_port = _free_port(), _free_port(), _free_port()
    servers = []
    for port, crt, key, tag in ((tls_port, pki["srv_crt"], pki["srv_key"], "tls"),
                                (bad_port, bad_crt, bad_key, "mismatch")):
        servers.append(_spawn([str(_auth_ossl(ap)), "s_server", "-accept", str(port), "-cert",
                               str(crt), "-key", str(key), "-WWW", "-quiet"], d,
                              _auth_env(ap), d / f"{tag}.out", d / f"{tag}.err"))
    stop = threading.Event()
    proxy = _http_connect_proxy(proxy_port, stop)

    def tunnel(dest_port: int, tag: str) -> tuple[bytes, dict]:
        """Drive one proxytunnel worker over a socketpair and return its bytes and transcript."""
        local, peer = socket.socketpair()
        log = d / f"proxytunnel-{tag}.err"
        with open(log, "w", encoding="utf-8") as handle:
            proc = subprocess.Popen(
                [prog, "-p", f"127.0.0.1:{proxy_port}", "-d", f"127.0.0.1:{dest_port}",
                 "-e", "-C", str(pki["ca_crt"]), "-v"],
                stdin=peer.fileno(), stdout=peer.fileno(), stderr=handle,
                cwd=str(d), env=ctx["env"], text=True)
            peer.close()
            try:
                local.settimeout(20.0)
                local.sendall(b"GET /probe.txt HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
                data = b""
                while True:
                    chunk = local.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                data = b""
            finally:
                local.close()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    _stop(proc)
        return data, {"exit_code": proc.returncode or 0, "stdout": _read(log)}

    try:
        if not (_wait_tcp("127.0.0.1", tls_port) and _wait_tcp("127.0.0.1", bad_port)):
            return _wl_fail([("s_server", {"exit_code": 0, "stdout": _read(d / "tls.err")})],
                            "the TLS destinations did not open their ports",
                            "runtime-failure", d)
        good, good_log = tunnel(tls_port, "tunnel")
        bad, bad_log = tunnel(bad_port, "mismatched-san")
    finally:
        stop.set()
        proxy.join(timeout=2)
        for proc, out, err in servers:
            _stop(proc)
            out.close()
            err.close()

    tunnelled = body.strip() in good
    neg_rejected = (body.strip() not in bad
                    and "does not match certificate subject alternative names" in bad_log["stdout"])
    functional_ok = tunnelled and neg_rejected
    return {
        "runtime_ok": tunnelled,
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else ("functional-failure" if tunnelled else
                                                     "runtime-failure"),
        "residual": "none" if functional_ok else ("functional-divergence" if tunnelled else
                                                  "runtime-failure"),
        "reason": None if functional_ok else
        ("the GET did not come back through the CONNECT tunnel" if not tunnelled else
         "a destination certificate naming another address was still tunnelled to"),
        "transcript": _transcript(("proxytunnel CONNECT + TLS destination", good_log),
                                  ("proxytunnel mismatched-SAN destination (must fail)", bad_log)),
        "workload": ("proxytunnel: HTTP CONNECT through a local proxy + TLS 1.3 to the destination "
                     "+ GET round trip + mismatched-SAN reject"),
        "local_only": True}


def _wl_keepalived(ctx: dict) -> dict:
    """keepalived's HTTP/SSL check path against a local TLS server, in `-T` genhash mode.

    The daemon's IPVS virtual-server checkers cannot start in this venue (there is no
    `/proc/net/ip_vs`), so the admitted workload drives the same check implementation the checker
    uses: `-T` genhash fetches a fixed page over TLS through keepalived's own libssl client and
    prints the MD5 of the body, which must equal the served file's digest. A plaintext server
    serving the same bytes must not satisfy the SSL request. keepalived 2.3.1 sets no verify mode
    (`SSL_VERIFY_NONE`), so an unrelated CA is not a discriminator this build can be held to.

    The two legs must be provably distinct: `_free_port` closes its probe socket, so the kernel can
    return the same port twice, and a shared port would point the "plaintext" control at the TLS
    listener, whose correct digest then reads as "a plaintext server satisfied the SSL request".
    The plaintext listener therefore binds an ephemeral port *first* and holds it, and only then is
    the TLS port chosen -- the kernel cannot hand out a port that is already in LISTEN. Both
    endpoints are probed for their actual payload before either leg launches, and the negative leg
    is judged on content alone: any body digest returned for the SSL request aimed at the plaintext
    peer means cleartext was accepted, while the error text the TLS client prints is transcribed
    and never used as the predicate.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    prog = str(ctx["program"])
    pki = _gen_pki(ap, d)
    body = b"phase24-keepalived-tls-probe\n"
    (d / "probe.txt").write_bytes(body)
    expected = hashlib.md5(body).hexdigest()

    plain_state: dict = {"ready": threading.Event(), "error": None, "port": None}
    stop = threading.Event()

    def plain() -> None:
        """Serve the same bytes without TLS: the SSL request must not be satisfied by it."""
        listener = socket.socket()
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            listener.settimeout(0.5)
        except OSError as exc:
            listener.close()
            plain_state["error"] = exc
            plain_state["ready"].set()
            return
        plain_state["port"] = int(listener.getsockname()[1])
        plain_state["ready"].set()
        while not stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with client:
                # Drain the request first. A TLS client sends a ClientHello this listener will not
                # understand; closing with those bytes still unread turns the close into a reset,
                # which makes the client's own error text depend on a race rather than on the
                # protocol. The close below is therefore preceded by a bounded drain and followed
                # by a half-close, so the peer's interpretation is not timing-dependent.
                deadline = time.monotonic() + 0.5
                client.settimeout(0.3)
                while time.monotonic() < deadline:
                    try:
                        if not client.recv(4096):
                            break
                    except OSError:
                        break
                try:
                    client.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: "
                                   + str(len(body)).encode() + b"\r\n\r\n" + body)
                    client.shutdown(socket.SHUT_WR)
                    client.settimeout(0.3)
                    while client.recv(4096):
                        pass
                except OSError:
                    pass
        listener.close()

    def plain_fetch(port: int) -> bytes:
        """A plaintext GET against `port`, returning its body (empty when the peer is not HTTP)."""
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5.0) as client:
                client.settimeout(5.0)
                client.sendall(b"GET /probe.txt HTTP/1.0\r\n\r\n")
                chunks = []
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
        except OSError:
            return b""
        raw = b"".join(chunks)
        return raw.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in raw else b""

    thread = threading.Thread(target=plain, daemon=True)
    thread.start()
    server = out = err = None
    try:
        if not plain_state["ready"].wait(timeout=10.0) or plain_state["error"] is not None:
            return _wl_fail([("plaintext control", {"exit_code": 0, "stdout": str(
                                plain_state["error"])})],
                            "the plaintext control could not bind its port",
                            "runtime-failure", d)
        plain_port = int(plain_state["port"])
        # Chosen only now, with the plaintext listener already in LISTEN, so the kernel cannot return
        # the same port and the two legs cannot silently become one endpoint.
        tls_port = _free_port()
        if tls_port == plain_port:
            return _wl_fail([("plaintext control", {"exit_code": 0,
                                                    "stdout": f"bound {plain_port}"})],
                            "the TLS and plaintext legs were not provably distinct",
                            "runtime-failure", d)
        server, out, err = _spawn([str(_auth_ossl(ap)), "s_server", "-accept", str(tls_port),
                                   "-cert", str(pki["srv_crt"]), "-key", str(pki["srv_key"]),
                                   "-WWW", "-quiet"], d, _auth_env(ap), d / "tls.out",
                                  d / "tls.err")
        if not _wait_tcp("127.0.0.1", tls_port):
            return _wl_fail([("s_server", {"exit_code": 0, "stdout": _read(d / "tls.err")})],
                            "the TLS destination did not open its port",
                            "runtime-failure", d)
        # Fixture integrity, asserted on content rather than on a connection: the plaintext leg
        # really serves the page over plain HTTP, and the TLS listener does not serve it in the
        # clear. A port collision or a dead plaintext listener fails here loudly instead of being
        # reported as a subject divergence.
        plain_body = plain_fetch(plain_port)
        tls_cleartext_body = plain_fetch(tls_port)
        if not (tls_port != plain_port and plain_body == body
                and tls_cleartext_body != body):
            return _wl_fail([("plaintext control", {
                                 "exit_code": 0,
                                 "stdout": plain_body.decode("utf-8", "replace")}),
                             ("tls listener cleartext probe", {
                                 "exit_code": 0,
                                 "stdout": tls_cleartext_body.decode("utf-8", "replace")})],
                            "the TLS and plaintext legs were not provably distinct",
                            "runtime-failure", d)
        base = [prog, "-T", "-S", "-s", "127.0.0.1", "-u", "/probe.txt", "-t", "5", "-p"]
        good = _run_captured(base + [str(tls_port)], env=ctx["env"], timeout=40)
        neg = _run_captured(base + [str(plain_port)], env=ctx["env"], timeout=40)
    finally:
        stop.set()
        thread.join(timeout=2)
        if server is not None:
            _stop(server)
        if out is not None:
            out.close()
        if err is not None:
            err.close()

    digest = good["stdout"].strip()
    fetched = re.fullmatch(r"[0-9a-f]{32}", digest) is not None
    # The control asserts on content, not on a connection or an error string: the plaintext peer is
    # proven alive and serving this exact payload above, so any body digest from the SSL request
    # aimed at it is a real acceptance of cleartext. Which error message the TLS client prints while
    # rejecting the peer is its own choice (a reset and a TLS alert are both rejections), so the
    # message is transcribed and never used as the predicate.
    neg_rejected = re.fullmatch(r"[0-9a-f]{32}", neg["stdout"].strip()) is None
    functional_ok = fetched and digest == expected and neg_rejected
    return {
        "runtime_ok": fetched,
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else ("functional-failure" if fetched else
                                                     "runtime-failure"),
        "residual": "none" if functional_ok else ("functional-divergence" if fetched else
                                                  "runtime-failure"),
        "reason": None if functional_ok else
        ("the TLS page fetch returned no body digest" if not fetched else
         "the fetched body digest did not match the served page" if digest != expected else
         "a plaintext server satisfied the SSL request"),
        "transcript": _transcript(("genhash TLS fetch", good),
                                  ("genhash SSL request to a plaintext server (must fail)", neg)),
        "workload": ("keepalived: TLS page fetch + body-digest match + plaintext-peer reject"),
        "local_only": True}


def _wl_ssmtp(ctx: dict) -> dict:
    """An end-to-end message submission over SMTP STARTTLS to a local stub.

    `s_server -starttls smtp` does not exist, so the stub is a tiny loopback SMTP server: `220`,
    `250-STARTTLS` on EHLO, then it answers STARTTLS and hands the accepted socket to a TLS server
    context using the fixture certificate. The message must be accepted (`250` after DATA) and its
    body must arrive intact over the TLS leg.

    ssmtp 2.64 calls no `SSL_CTX_set_verify` and only checks that `SSL_get_peer_certificate`
    returned a certificate, so the TLS leg is confidentiality without authentication. The fixture
    CA is freshly generated and is not in any default trust store; the accepted submission records
    that limitation explicitly (it is not claimed as certificate verification).
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    prog = str(ctx["program"])
    pki = _gen_pki(ap, d)
    body = b"phase24-ssmtp-starttls-payload\n"
    port = _free_port()
    conf = d / "ssmtp.conf"
    conf.write_text(f"mailhub=127.0.0.1:{port}\nUseSTARTTLS=YES\nFromLineOverride=YES\n"
                    f"hostname=localhost\nroot=root@example.test\n", encoding="utf-8")
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(pki["srv_pem"]))
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(1)
    listener.settimeout(40.0)
    peer: list[str] = []
    messages: list[bytes] = []
    tls_versions: list[str] = []

    def serve() -> None:
        """One SMTP submission: greeting, EHLO/STARTTLS, TLS handoff, DATA, QUIT."""
        try:
            client, _ = listener.accept()
        except OSError:
            return
        conn = client
        buffer = bytearray()

        def read_line() -> bytes | None:
            while b"\n" not in buffer:
                try:
                    chunk = conn.recv(4096)
                except OSError:
                    return None
                if not chunk:
                    return None
                buffer.extend(chunk)
            raw, _, rest = buffer.partition(b"\n")
            buffer[:] = rest
            return bytes(raw).rstrip(b"\r")

        def send(payload: bytes) -> None:
            peer.append("S: " + payload.decode("utf-8", "replace").strip())
            conn.sendall(payload)

        with client:
            client.settimeout(20.0)
            send(b"220 smtp-fixture ESMTP\r\n")
            while True:
                line = read_line()
                if line is None:
                    return
                peer.append("C: " + line.decode("utf-8", "replace"))
                verb = line.split(b" ", 1)[0].upper()
                if verb == b"EHLO":
                    send(b"250-smtp-fixture\r\n250 STARTTLS\r\n")
                elif verb == b"STARTTLS":
                    send(b"220 Ready to start TLS\r\n")
                    try:
                        conn = server_ctx.wrap_socket(client, server_side=True)
                    except ssl.SSLError as exc:
                        peer.append(f"TLS-FAILED {exc}")
                        return
                    tls_versions.append(conn.version() or "")
                    peer.append("TLS-ESTABLISHED " + (conn.version() or ""))
                    buffer.clear()
                elif verb == b"DATA":
                    send(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    data = bytearray()
                    while True:
                        entry = read_line()
                        if entry is None:
                            return
                        if entry == b".":
                            break
                        data.extend(entry + b"\n")
                    messages.append(bytes(data))
                    send(b"250 OK queued\r\n")
                elif verb == b"QUIT":
                    send(b"221 Bye\r\n")
                    return
                else:
                    send(b"250 OK\r\n")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        # No SSL_CERT_FILE/SSL_CERT_DIR is injected: the default trust store must be the one the
        # program uses, so acceptance records ssmtp's missing verification rather than assuming it.
        sent = _run_captured([prog, "-v", "root@example.test", "-C", str(conf)], cwd=d,
                             env=dict(ctx["env"]), timeout=60,
                             stdin_text="Subject: phase24 ssmtp probe\n\n" + body.decode())
    finally:
        thread.join(timeout=5)
        listener.close()

    delivered = bool(messages) and body.strip() in messages[0]
    starttls = any(line.startswith("C: STARTTLS") for line in peer) and bool(tls_versions)
    functional_ok = bool(delivered and starttls and sent["ok"])
    return {
        "runtime_ok": bool(delivered or (sent["ok"] and starttls)),
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if delivered else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if delivered else "runtime-failure"),
        "reason": None if functional_ok else (
            "the message was not accepted end to end" if not delivered else
            "the submission was accepted without a negotiated STARTTLS/TLS leg" if not starttls else
            "the submitting client exited non-zero"),
        "transcript": _transcript(("ssmtp submission", sent),
                                  ("SMTP STARTTLS stub", {"exit_code": 0,
                                                          "stdout": "\n".join(peer)})),
        "workload": ("ssmtp: SMTP submission through a local STARTTLS stub + TLS handoff + "
                     "end-to-end message acceptance"),
        "note": ("ssmtp 2.64 performs no certificate verification (no SSL_CTX_set_verify; only a "
                 "presence check on SSL_get_peer_certificate). The fixture CA is untrusted, so "
                 "acceptance records the upstream TODO; it is not a verification result."),
        "local_only": True,
    }


def _wl_tnftp(ctx: dict) -> dict:
    """tnftp's HTTPS fetch path against a local TLS server, with a plaintext negative control.

    tnftp is an FTP client that also fetches `http://`/`https://` URLs through its libssl client.
    A local `s_server -WWW` serves a fixed payload, tnftp is told to trust only the fixture CA (its
    `SSL_CTX_set_default_verify_paths` honours `SSL_CERT_FILE`), and the saved file must be
    byte-identical. The same `https://` URL aimed at a plaintext server must not yield the payload.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    prog = str(ctx["program"])
    pki = _gen_pki(ap, d)
    body = b"phase24-tnftp-https-payload\n"
    (d / "probe.txt").write_bytes(body)
    tls_port = _free_port()
    plain_port = _free_port()
    # `_free_port` closes the probe socket, so the kernel may hand the same port back for the next
    # call; a shared port would silently point the "plaintext" control at the TLS server.
    while plain_port == tls_port:
        plain_port = _free_port()
    server, out, err = _spawn([str(_auth_ossl(ap)), "s_server", "-accept", str(tls_port),
                               "-cert", str(pki["srv_crt"]), "-key", str(pki["srv_key"]),
                               "-WWW", "-quiet"], d, _auth_env(ap), d / "tls.out", d / "tls.err")
    stop = threading.Event()

    def plain() -> None:
        """Accept and drop: a TLS client must not be satisfied by this plaintext peer."""
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", plain_port))
        listener.listen(4)
        listener.settimeout(0.5)
        while not stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with client:
                client.settimeout(5.0)
                try:
                    client.recv(4096)
                except OSError:
                    pass
        listener.close()

    thread = threading.Thread(target=plain, daemon=True)
    thread.start()
    env = dict(ctx["env"], SSL_CERT_FILE=str(pki["ca_crt"]))
    fetched, rejected = d / "fetched.txt", d / "plain-fetched.txt"
    try:
        if not _wait_tcp("127.0.0.1", tls_port):
            return _wl_fail([("s_server", {"exit_code": 0, "stdout": _read(d / "tls.err")})],
                            "the TLS destination did not open its port", "runtime-failure", d)
        good = _run_captured([prog, "-V", "-o", str(fetched),
                              f"https://127.0.0.1:{tls_port}/probe.txt"], cwd=d, env=env,
                             timeout=60)
        neg = _run_captured([prog, "-V", "-o", str(rejected),
                             f"https://127.0.0.1:{plain_port}/probe.txt"], cwd=d, env=env,
                            timeout=60)
    finally:
        stop.set()
        thread.join(timeout=2)
        _stop(server)
        out.close()
        err.close()

    payload_ok = fetched.is_file() and fetched.read_bytes() == body
    neg_rejected = not rejected.is_file() or rejected.read_bytes() != body
    functional_ok = bool(good["ok"] and payload_ok and neg_rejected)
    return {
        "runtime_ok": payload_ok,
        "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if payload_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if payload_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the HTTPS fetch returned no saved payload" if not payload_ok else
            "a plaintext peer satisfied the HTTPS request"),
        "transcript": _transcript(("tnftp https fetch", good),
                                  ("tnftp https fetch from a plaintext peer (must fail)", neg)),
        "workload": ("tnftp: HTTPS GET over TLS to a local server + byte-identical payload match "
                     "+ plaintext-peer reject"),
        "note": ("tnftp verifies the peer against the default verify paths, narrowed here to the "
                 "fixture CA through SSL_CERT_FILE, and matches the URL host against the SAN."),
        "local_only": True,
    }


def _wl_fail(notes: list, reason: str, failure_class: str | None, d: Path) -> dict:
    return {"runtime_ok": False, "functional_ok": False,
            "failure_class": failure_class or "runtime-failure", "residual": "runtime-failure",
            "reason": reason, "transcript": _transcript(*notes),
            "workload": "unavailable", "local_only": True}


def _wl_libevent(ctx: dict) -> dict:
    """A libevent_openssl socketpair session: TLS1.3, verified peer, byte round trip.

    Both endpoints are bufferevents created with `bufferevent_openssl_socket_new`; the client
    verifies the server certificate against the fixture CA and the payload must return unchanged.
    A session whose client trusts only the unrelated CA must fail the handshake.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    common = ["--cert", str(pki["srv_crt"]), "--key", str(pki["srv_key"])]
    good = _run_captured([prog] + common + ["--ca", str(pki["ca_crt"])], cwd=d,
                         env=ctx["env"], timeout=60)
    neg = _run_captured([prog, "--negative"] + common + ["--ca", str(pki["other_crt"])],
                        cwd=d, env=ctx["env"], timeout=60)
    text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    verified = "handshake=TLSv1.3" in text and "peer_verify=ok" in text
    runtime_ok = bool(good["ok"] and verified)
    payload_ok = "payload=ok" in text
    neg_rejected = bool(neg["ok"] and "negative=rejected" in neg_text)
    functional_ok = runtime_ok and payload_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the bufferevent socketpair did not complete a verified TLS1.3 handshake"
            if not runtime_ok else
            "the encrypted round trip did not return the payload" if not payload_ok else
            "the unrelated CA was not rejected, so the peer certificate does not verify"),
        "transcript": _transcript(("libevent bufferevent TLS1.3 round trip", good),
                                  ("libevent unrelated-ca (must fail)", neg)),
        "workload": ("libevent: bufferevent_openssl client+server over a socketpair + TLS1.3 + "
                     "peer-certificate verify + payload round trip + unrelated-CA reject"),
        "local_only": True,
    }


def _wl_libretls(ctx: dict) -> dict:
    """A libtls (libretls) client/server session over a socketpair.

    The client configures the fixture CA, completes a TLS1.3 handshake, asserts the peer
    certificate was provided and verifies it, then exchanges a payload with a libtls server. A
    client configured with only the unrelated CA must fail the handshake.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    pki = _gen_pki(ap, d)
    prog = str(ctx["program"])
    common = ["--cert", str(pki["srv_crt"]), "--key", str(pki["srv_key"])]
    good = _run_captured([prog] + common + ["--ca", str(pki["ca_crt"])], cwd=d,
                         env=ctx["env"], timeout=60)
    neg = _run_captured([prog, "--negative"] + common + ["--ca", str(pki["other_crt"])],
                        cwd=d, env=ctx["env"], timeout=60)
    text = good["stdout"] + good["stderr"]
    neg_text = neg["stdout"] + neg["stderr"]
    verified = "handshake=TLSv1.3" in text and "peer_verify=ok" in text
    runtime_ok = bool(good["ok"] and verified)
    payload_ok = "payload=ok" in text
    neg_rejected = bool(neg["ok"] and "negative=rejected" in neg_text)
    functional_ok = runtime_ok and payload_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the libtls socketpair session did not complete a verified TLS1.3 handshake"
            if not runtime_ok else
            "the libtls round trip did not return the payload" if not payload_ok else
            "the unrelated CA was not rejected, so the peer certificate does not verify"),
        "transcript": _transcript(("libtls client/server TLS1.3 round trip", good),
                                  ("libtls unrelated-ca (must fail)", neg)),
        "workload": ("libretls: libtls client+server over a socketpair + TLS1.3 + peer-certificate "
                     "verify + payload round trip + unrelated-CA reject"),
        "local_only": True,
    }


def _wl_libarchive(ctx: dict) -> dict:
    """A libarchive create/read cycle whose integrity is a libcrypto SHA-256 digest.

    The archive holds a payload and its SHA-256 digest (computed through EVP); reading it back
    must reproduce the payload and verify the digest. One payload byte flipped inside the archive
    must be rejected by the digest check, so a reader that ignores integrity is a recorded failure.
    """
    d = ctx["workdir"]
    prog = str(ctx["program"])
    good = _run_captured([prog], cwd=d, env=ctx["env"], timeout=60)
    tamper = _run_captured([prog, "--tamper"], cwd=d, env=ctx["env"], timeout=60)
    text = good["stdout"] + good["stderr"]
    tamper_text = tamper["stdout"] + tamper["stderr"]
    runtime_ok = bool(good["ok"] and "archive=read" in text and "digest=ok" in text)
    tamper_rejected = bool(tamper["ok"] and "tampered=rejected" in tamper_text)
    functional_ok = runtime_ok and tamper_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "libarchive did not create and read back the archive with a matching SHA-256 digest"
            if not runtime_ok else
            "the tampered payload byte was not rejected by the digest check"),
        "transcript": _transcript(("libarchive create/read + SHA-256", good),
                                  ("libarchive tampered payload (must reject)", tamper)),
        "workload": ("libarchive: in-memory tar create/read + libcrypto SHA-256 digest verify + "
                     "tampered-byte reject"),
        "local_only": True,
    }


def _wl_fetchmail(ctx: dict) -> dict:
    """fetchmail's IMAPS retrieve path against a local IMAP stub, with a trust negative control.

    fetchmail's IMAP client wraps the mailbox socket with libssl (`ssl` in the rc), verifies the
    peer chain against the fixture CA through `sslcertfile`, and hands the fetched message to its
    MDA. The stub speaks the minimum IMAP4rev1 needed for a one-message retrieve; the MDA appends
    what it receives, so the message body is the functional assertion. A second poll whose trust
    store holds only the unrelated CA must fail certificate verification before any IMAP command.

    fetchmail's reader calls `SSL_peek` before every `SSL_read` (`socket.c:SockRead`). A subject
    whose `SSL_peek` is unimplemented therefore completes the TLS handshake and then aborts the
    poll; that is recorded as L6 with the blocker named, never masked as a fixture failure.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    prog = str(ctx["program"])
    pki = _gen_pki(ap, d)
    body = b"L7-FETCHMAIL-BODY-MARKER"
    message = (b"From: l7@example.test\r\nTo: l7@example.test\r\nSubject: l7-fetchmail\r\n"
               b"Date: Tue, 21 Oct 2026 00:00:00 +0000\r\nMessage-ID: <l7@example.test>\r\n"
               b"\r\n" + body + b"\r\n")
    port = ctx["port"]
    events: list[str] = []
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(str(pki["srv_crt"]), str(pki["srv_key"]))
    stop = threading.Event()
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(4)
    listener.settimeout(0.5)

    def session(raw: socket.socket) -> None:
        """One IMAPS session: greeting, LOGIN, SELECT, FETCH, STORE, LOGOUT."""
        try:
            conn = tls.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            events.append(f"tls=failed ({exc.__class__.__name__})")
            raw.close()
            return
        events.append(f"handshake={conn.version()}")
        stream = conn.makefile("rwb")

        def reply(line: bytes) -> None:
            stream.write(line)
            stream.flush()

        try:
            reply(b"* OK [CAPABILITY IMAP4rev1] l7 stub ready\r\n")
            while True:
                line = stream.readline()
                if not line:
                    break
                text = line.decode("utf-8", "replace").rstrip("\r\n")
                tag, _, rest = text.partition(" ")
                upper = rest.upper()
                events.append("imap: " + rest)
                if upper.startswith("CAPABILITY"):
                    reply(b"* CAPABILITY IMAP4rev1\r\n" + tag.encode() + b" OK done\r\n")
                elif upper.startswith("LOGIN"):
                    reply(tag.encode() + b" OK LOGIN done\r\n")
                elif upper.startswith(("SELECT", "EXAMINE")):
                    reply(b"* 1 EXISTS\r\n* 0 RECENT\r\n* FLAGS (\\Seen)\r\n"
                          + tag.encode() + b" OK [READ-WRITE] done\r\n")
                elif upper.startswith("SEARCH"):
                    reply(b"* SEARCH 1\r\n" + tag.encode() + b" OK done\r\n")
                elif upper.startswith(("FETCH", "UID FETCH")):
                    bits = rest.split(None, 2)
                    items = (bits[1] if len(bits) > 1 else "") + (
                        " " + bits[2] if len(bits) > 2 else "")
                    spec = items.upper()
                    if "RFC822.SIZE" in spec and "BODY" not in spec and "HEADER" not in spec:
                        reply(b"* 1 FETCH (RFC822.SIZE " + str(len(message)).encode() + b")\r\n")
                    else:
                        if "HEADER" in spec:
                            data = message.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
                            item = b"RFC822.HEADER"
                        elif "TEXT" in spec:
                            data = message.split(b"\r\n\r\n", 1)[1]
                            item = b"RFC822.TEXT"
                        else:
                            data, item = message, b"BODY[]"
                        if "UID" in spec and "BODY" not in spec:
                            item = b"UID 1 " + item
                        reply(b"* 1 FETCH (" + item + b" {" + str(len(data)).encode() + b"}\r\n"
                              + data + b")\r\n")
                    reply(tag.encode() + b" OK done\r\n")
                elif upper.startswith("LOGOUT"):
                    reply(b"* BYE bye\r\n" + tag.encode() + b" OK done\r\n")
                    break
                else:
                    reply(tag.encode() + b" OK done\r\n")
        except (ssl.SSLError, OSError):
            events.append("imap: session ended by peer")
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def serve() -> None:
        while not stop.is_set():
            try:
                raw, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=session, args=(raw,), daemon=True).start()
        listener.close()

    def poll(tag: str, ca: Path) -> dict:
        """One fetchmail run: an appending MDA and a one-message IMAP poll over implicit TLS."""
        out = d / f"{tag}.mbox"
        mda = d / f"{tag}-mda.sh"
        mda.write_text("#!/bin/sh\nexec cat >> " + str(out) + "\n", encoding="utf-8")
        mda.chmod(0o755)
        rc = d / f"{tag}.rc"
        rc.write_text(
            "set no syslog\nset daemon 0\nset postmaster l7\n"
            f"poll 127.0.0.1 protocol IMAP port {port}\n"
            '  user "l7" password "secret"\n'
            f'  ssl sslcertck sslcertfile "{ca}"\n'
            f'  keep fetchall\n  mda "{mda}"\n', encoding="utf-8")
        rc.chmod(0o600)
        return _run_captured([prog, "-f", str(rc), "-v", "--nosyslog"], cwd=d, env=ctx["env"],
                             timeout=60)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        good = poll("good", pki["ca_crt"])
        neg = poll("neg", pki["other_crt"])
    finally:
        stop.set()
        try:
            listener.close()
        except OSError:
            pass
        thread.join(timeout=2)

    delivered = d / "good.mbox"
    rejected = d / "neg.mbox"
    text = good["stdout"] + good["stderr"]
    tls_line = next((ln for ln in text.splitlines() if "SSL/TLS: using protocol" in ln), "")
    neg_text = neg["stdout"] + neg["stderr"]
    runtime_ok = bool(tls_line)
    payload_ok = delivered.is_file() and body in delivered.read_bytes()
    neg_rejected = not rejected.is_file() or body not in rejected.read_bytes()
    functional_ok = runtime_ok and payload_ok and neg_rejected
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "fetchmail did not complete the TLS handshake with the local IMAPS stub"
            if not runtime_ok else
            "fetchmail completed the verified TLS session but delivered no message body: its "
            "IMAP reader calls SSL_peek before every SSL_read, and ssl_peek_internal returns -1 "
            "for every call (src/ssl/ssl_lib.rs), which fetchmail reports as a socket error"
            if not payload_ok else
            "the poll trusting only the unrelated CA was not rejected"),
        "transcript": _transcript(
            ("fetchmail IMAPS poll", {"exit_code": good["exit_code"], "stdout": tls_line}),
            ("imap stub", {"exit_code": 0, "stdout": "\n".join(events)}),
            ("fetchmail unrelated-ca poll (must fail)", {
                "exit_code": neg["exit_code"],
                "stderr": "\n".join(ln for ln in neg_text.splitlines()
                                     if "verification error" in ln
                                     or "OpenSSL reported" in ln
                                     or "SSL connection failed" in ln)})),
        "workload": ("fetchmail: IMAPS poll to a local IMAP/TLS stub + message-body delivery "
                     "through the MDA + unrelated-CA reject"),
        "note": ("fetchmail verifies the peer against the fixture CA through sslcertfile and "
                 "checks the SAN IP; the IMAP exchange runs over TLSv1.3 / TLSv1.2 as negotiated"),
        "local_only": True,
    }


def _wl_iperf3(ctx: dict) -> dict:
    """iperf3's completed test plus its OpenSSL SHA-256/authorization decision.

    iperf3 3.17.1's authenticated mode encrypts the salted credentials with OpenSSL's RSA. Its
    `encrypt_rsa_message` passes an output length of 0 to `EVP_PKEY_encrypt`, so every OpenSSL 3
    build answers "output buffer too small" and the token is empty; the authority and the candidate
    fail identically, which is recorded as a venue/upstream limitation rather than a divergence.
    The assertions are therefore (a) a completed server/client throughput test and (b) the part of
    the same libiperf auth code that does work on both subjects: `sha256()` over the salted
    credential and `check_authentication()`'s authorized-users decision, driven by a small harness
    linked against the family's rebuilt libiperf and the subject's libcrypto.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    root, prefix = ctx["root"], ctx["prefix"]
    prog = str(ctx["program"])
    pki = _gen_pki(ap, d)
    pub = d / "auth-pub.pem"
    keygen = _ossl(ap, ["pkey", "-in", str(pki["srv_key"]), "-pubout", "-out", str(pub)],
                   timeout=60)
    if not keygen["ok"]:
        return _wl_fail([("openssl pkey -pubout", keygen)],
                        "the authentication public key could not be derived", "harness-failure", d)
    users = d / "users.csv"
    users.write_text("l7," + hashlib.sha256(b"{l7}secret").hexdigest() + "\n", encoding="utf-8")

    def test(extra_server: list[str], extra_client: list[str], env_extra: dict,
             tag: str, port: int | None = None) -> tuple[dict, dict]:
        """Run one server and its client; the server stays up for the client's real test."""
        port = port or _free_port()
        server, out, err = _spawn([prog, "-s", "-p", str(port), *extra_server], d,
                                  ctx["env"], d / f"{tag}-server.out",
                                  d / f"{tag}-server.err")
        try:
            if not _wait_tcp("127.0.0.1", port):
                return ({"exit_code": -1, "ok": False, "stdout": "", "stderr": ""},
                        {"exit_code": -1, "ok": False, "stdout": "", "stderr": ""})
            client = _run_captured([prog, "-c", "127.0.0.1", "-p", str(port), "-t", "1",
                                    *extra_client], cwd=d,
                                   env=dict(ctx["env"], **env_extra), timeout=90)
        finally:
            _stop(server)
            out.close()
            err.close()
        srv = {"exit_code": server.returncode, "ok": server.returncode == 0,
               "stdout": _read(d / f"{tag}-server.out"),
               "stderr": _read(d / f"{tag}-server.err")}
        return client, srv

    plain, plain_srv = test([], [], {}, "plain", ctx["port"])
    auth, auth_srv = test(
        [f"--rsa-private-key-path={pki['srv_key']}", f"--authorized-users-path={users}"],
        ["--username", "l7", "--rsa-public-key-path", str(pub)], {"IPERF3_PASSWORD": "secret"},
        "auth")

    harness = d / "l7-iperf3-harness"
    build = census._run(
        ["cc", str(REPO_ROOT / "forensics/tools/l7_iperf3.c"), "-o", str(harness), "-O2",
         "-Wall", "-Wextra", f"-I{prefix / 'include'}", f"-L{root / 'src/.libs'}",
         f"-L{prefix / 'lib'}", f"-Wl,-rpath,{root / 'src/.libs'}",
         f"-Wl,-rpath,{prefix / 'lib'}", "-liperf", "-lssl", "-lcrypto"],
        cwd=root, env=ctx["build_env"])
    if not build["ok"]:
        return _wl_fail([("cc l7_iperf3.c", build)],
                        f"the iperf3 digest/auth harness did not compile: "
                        f"{census._error_line(build)}", "harness-failure", d)
    digest = _run_captured([str(harness), str(users)], cwd=d, env=ctx["env"], timeout=60)

    plain_text = plain["stdout"] + plain["stderr"]
    plain_ok = bool(plain["ok"] and "iperf Done." in plain_text
                    and "Server listening on" in (plain_srv["stdout"] + plain_srv["stderr"]))
    digest_text = digest["stdout"] + digest["stderr"]
    expected = "65e9c904a7f6c8e173a48c57a67ac6e25cf991a79ff87b53591b3f1c26616dcf"
    digest_ok = bool(
        digest["ok"] and f"sha256={expected}" in digest_text
        and "auth_ok=accepted" in digest_text and "auth_wrong=rejected" in digest_text
        and "auth_stale=rejected" in digest_text)
    auth_text = auth["stdout"] + auth["stderr"]
    runtime_ok = plain_ok
    functional_ok = plain_ok and digest_ok
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "the local iperf3 server/client test did not complete" if not plain_ok else
            "libiperf's SHA-256/authorized-users decision did not match the fixture"),
        "transcript": _transcript(
            ("iperf3 test", {"exit_code": plain["exit_code"], "stdout": "\n".join(
                ln for ln in plain_text.splitlines()
                if "Connecting to host" in ln or "iperf Done." in ln)}),
            ("iperf3 server", {"exit_code": plain_srv["exit_code"], "stdout": "\n".join(
                ln for ln in (plain_srv["stdout"] + plain_srv["stderr"]).splitlines()
                if "Server listening on" in ln)}),
            ("iperf3 digest/auth harness", digest),
            ("iperf3 rsa-auth attempt (same upstream OpenSSL 3 failure on both subjects)", {
                "exit_code": auth["exit_code"], "stderr": "\n".join(
                    ln for ln in auth_text.splitlines()
                    if "output buffer too small" in ln or "authorization failed" in ln)})),
        "workload": ("iperf3: local server/client throughput test + libiperf SHA-256 of the "
                     "salted credential + authorized-users accept/reject/stale decisions"),
        "note": ("iperf3 3.17.1's RSA auth transport cannot complete with OpenSSL 3 (it passes a "
                 "zero output length to EVP_PKEY_encrypt; the authority fails identically), so "
                 "the digest and authorization decision are the asserted OpenSSL observable"),
        "local_only": True,
    }


def _wl_kmod(ctx: dict) -> dict:
    """kmod's module-signature path: libkmod parses an appended PKCS#7 with libcrypto.

    kmod 33 is built `--with-openssl` (its version banner reports `+LIBCRYPTO`), and `modinfo`
    reads a module's appended signature through `kmod_module_signature_info`. For the PKCS#7 id
    type that runs `d2i_PKCS7_bio`, `PKCS7_get_signer_info`, `X509_NAME_*`, `ASN1_INTEGER_to_BN`
    and `OBJ_obj2txt` from the subject's libcrypto, and reports the signer, key id, digest name and
    id type. The fixture is an ELF relocatable with a `.modinfo` section plus a PKCS#7 produced by
    the authority's `smime -sign`, laid out exactly as the kernel's sign-file does (module,
    signature, the 12-byte module_signature, the magic). The certificate serial is fixed so the
    reported key id is deterministic. A flipped signature byte must yield no signature metadata
    while the module's own `.modinfo` fields still parse.
    """
    ap, d = ctx["authority_prefix"], ctx["workdir"]
    prog = str(ctx["program"])
    source = d / "module.c"
    source.write_text(
        'const char __modinfo[] __attribute__((section(".modinfo"),used)) =\n'
        '    "license=GPL\\0description=kmod l7 fixture\\0";\n', encoding="utf-8")
    module = d / "module.ko"
    compiled = census._run(["cc", "-c", "-o", str(module), "-x", "c", str(source)], cwd=d,
                           env=ctx["build_env"])
    if not compiled["ok"]:
        return _wl_fail([("cc module.c", compiled)],
                        f"the kmod module fixture did not compile: {census._error_line(compiled)}",
                        "harness-failure", d)
    signer_key, signer_crt = d / "signer.key", d / "signer.crt"
    der, tampered = d / "signature.der", d / "tampered.ko"
    steps = [
        (["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(signer_key),
          "-out", str(signer_crt), "-days", "7", "-subj", "/CN=kmod-l7-signer",
          "-set_serial", "0x6b6d6f64"], "signer certificate"),
        (["smime", "-sign", "-nocerts", "-noattr", "-binary", "-md", "sha256", "-in",
          str(module), "-signer", str(signer_crt), "-inkey", str(signer_key), "-outform",
          "DER", "-out", str(der)], "module signature"),
    ]
    for argv, what in steps:
        res = _ossl(ap, argv, cwd=d, timeout=60)
        if not res["ok"]:
            return _wl_fail([(f"openssl {argv[0]}", res)],
                            f"generating the {what} failed: {census._error_line(res)}",
                            "harness-failure", d)

    module_bytes, der_bytes = module.read_bytes(), der.read_bytes()
    magic = b"~Module signature appended~\n"
    # struct module_signature: algo=RSA(1), hash=SHA256(4), id_type=PKCS7(2), signer/key id
    # carried by the PKCS#7, sig_len big-endian.
    header = struct.pack(">BBBBBBBBI", 1, 4, 2, 0, 0, 0, 0, 0, len(der_bytes))
    (d / "signed.ko").write_bytes(module_bytes + der_bytes + header + magic)
    flipped = bytes([der_bytes[0] ^ 0xFF]) + der_bytes[1:]
    tampered.write_bytes(module_bytes + flipped + header + magic)

    def field(name: str, path: Path) -> dict:
        return _run_captured([prog, "-F", name, str(path)], cwd=d, env=ctx["env"], timeout=60)

    description = field("description", module)
    signer = field("signer", d / "signed.ko")
    key_id = field("sig_key", d / "signed.ko")
    hash_algo = field("sig_hashalgo", d / "signed.ko")
    id_type = field("sig_id", d / "signed.ko")
    unsigned_signer = field("signer", module)
    tampered_signer = field("signer", tampered)

    def text(res: dict) -> str:
        return (res["stdout"] + res["stderr"]).strip()
    runtime_ok = bool(description["ok"] and text(description) == "kmod l7 fixture"
                      and unsigned_signer["ok"] and text(unsigned_signer) == "")
    functional_ok = bool(
        runtime_ok and text(signer) == "kmod-l7-signer" and text(key_id) == "6B:6D:6F:64"
        and text(hash_algo) == "sha256" and text(id_type) == "PKCS#7"
        and tampered_signer["ok"] and text(tampered_signer) == "")
    return {
        "runtime_ok": runtime_ok, "functional_ok": functional_ok,
        "failure_class": None if functional_ok else (
            "functional-failure" if runtime_ok else "runtime-failure"),
        "residual": "none" if functional_ok else (
            "functional-divergence" if runtime_ok else "runtime-failure"),
        "reason": None if functional_ok else (
            "modinfo did not read the fixture's .modinfo section" if not runtime_ok else
            "libkmod did not report the PKCS#7 signer/key-id/digest the fixture carries, or "
            "reported it for a corrupted signature"),
        "transcript": _transcript(
            ("modinfo -F description module.ko", description),
            ("modinfo -F signer module.ko (unsigned)", unsigned_signer),
            ("modinfo -F signer signed.ko", signer),
            ("modinfo -F sig_key signed.ko", key_id),
            ("modinfo -F sig_hashalgo signed.ko", hash_algo),
            ("modinfo -F sig_id signed.ko", id_type),
            ("modinfo -F signer tampered.ko (must report nothing)", tampered_signer)),
        "workload": ("kmod: modinfo parses a signed module fixture's appended PKCS#7 through "
                     "libcrypto (signer, key id, digest name, id type) + corrupted-signature "
                     "reject"),
        "note": ("kmod 33 is built --with-openssl and reports +LIBCRYPTO; libkmod's signature "
                 "path uses d2i_PKCS7/PKCS7_get_signer_info/X509_NAME/OBJ_obj2txt"),
        "local_only": True,
    }


RUNNERS = {
    "curl": _wl_curl,
    "nginx": _wl_nginx,
    "haproxy": _wl_haproxy,
    "openssh": _wl_openssh,
    "redis": _wl_redis,
    "monit": _wl_monit,
    "pure-ftpd": _wl_pureftpd,
    "isync": _wl_isync,
    "fossil": _wl_fossil,
    "ldns": _wl_ldns,
    "rsync": _wl_rsync,
    "socat": _wl_socat,
    "squid": _wl_squid,
    "stunnel": _wl_stunnel,
    "sslscan": _wl_sslscan,
    "openvpn": _wl_openvpn,
    "tinc": _wl_tinc,
    "hiredis-ssl": _wl_hiredis,
    "proxytunnel": _wl_proxytunnel,
    "keepalived": _wl_keepalived,
    "ssmtp": _wl_ssmtp,
    "tnftp": _wl_tnftp,
    "libevent": _wl_libevent,
    "libretls": _wl_libretls,
    "libarchive": _wl_libarchive,
    "fetchmail": _wl_fetchmail,
    "iperf3": _wl_iperf3,
    "kmod": _wl_kmod,
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


def _build_harness(prog: dict, root: Path, prefix: Path, out: Path,
                   build_env: dict) -> dict:
    """Compile a library-only family's admitted workload harness against the rebuilt library.

    The harness is a test-only consumer of the family library (which was itself built against the
    subject prefix by the shared recipe), so the program the load proof resolves links both the
    rebuilt family library and the subject's libssl/libcrypto.
    """
    spec = prog["harness"]
    source = REPO_ROOT / str(spec["source"])
    argv = ["cc", str(source), "-o", str(out), "-O2", "-Wall", "-Wextra"]
    argv += [str(a).format(root=root, prefix=prefix) for a in spec.get("cflags") or []]
    argv += [str(a).format(root=root, prefix=prefix) for a in spec.get("ldflags") or []]
    return census._run(argv, cwd=root, env=build_env)


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
    build_env = dict(os.environ, PKG_CONFIG_PATH=f"{prefix}/lib/pkgconfig",
                     CPPFLAGS=f"-I{prefix}/include", LDFLAGS=f"-L{prefix}/lib")

    # A few admitted programs live behind an upstream target the shared recipe's `make` does not
    # build (ldns's tools are `make examples`). The workload's own target is built here with the
    # identical prefix environment, so the program loaded is the program built against the subject.
    targets = list(prog.get("make_targets") or [])
    if targets:
        target_env = dict(build_env)
        for key, value in (prog.get("make_env") or {}).items():
            target_env[str(key)] = str(value).format(prefix=prefix)
        prep = census._run(["make", *(prog.get("make_jobs") or [MAKE_JOBS]), *targets], cwd=root,
                           env=target_env)
        if not prep["ok"]:
            return _runtime_row(
                fam, recipe, subject, level=L4, outcome="failed", residual="runtime-failure",
                failure_class="load-failure",
                reason=(f"the workload target {targets} did not build: "
                        f"{census._error_line(prep)}"),
                specimen_id=spec_id, variant_id=variant_id, source_sha256=source_sha256,
                evidence=evidence + [f"build:{','.join(targets)}"], canvas=None, limits=limits,
                prefix=prefix, source_root_hash=source_root_hash, launch=None, workload=None,
                transcript=_transcript(("make " + " ".join(targets), prep)), local_only=True)

    # A library-only family has no program of its own: compile the admitted workload harness
    # against the library rebuilt in this source tree and the subject prefix. The harness is the
    # program the load proof then resolves, so the L5 evidence is the library's own load, not a
    # fabricated banner.
    if prog.get("harness"):
        built = _build_harness(prog, root, prefix, program, build_env)
        if not built["ok"]:
            return _runtime_row(
                fam, recipe, subject, level=L4, outcome="failed", residual="runtime-failure",
                failure_class="load-failure",
                reason=(f"the L7 workload harness did not compile: {census._error_line(built)}"),
                specimen_id=spec_id, variant_id=variant_id, source_sha256=source_sha256,
                evidence=evidence + ["build:l7-harness"], canvas=None, limits=limits,
                prefix=prefix, source_root_hash=source_root_hash, launch=None, workload=None,
                transcript=_transcript(("cc " + prog["harness"]["source"], built)),
                local_only=True)

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
           "env": env, "build_env": build_env}
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
