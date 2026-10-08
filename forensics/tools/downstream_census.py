#!/usr/bin/env python3
"""openssl-rs — Phase-24.3 authority-baseline census: what the authority itself reaches.

Phase 24 measures whether `openssl-rs` survives the ways real software depends on OpenSSL, by
normalising every candidate run against **what the admitted authority itself achieved** for the
same pristine source. Before a candidate is run (24.4 freezes the population; 24.12 runs it), this
module takes the **authority baseline**: for a bounded, precommitted **census cohort** of the
committed candidate families it acquires each family's pristine upstream source, builds it against
the admitted authority in the resource-capped court container, and records the level the build
reached on the `L0`-`L8` ladder together with the family's **direct OpenSSL use** -- the imported
OpenSSL symbols and the headers it includes -- and a **linkage proof** that the authority's own
`libssl`/`libcrypto` resolved, never a system one.

This is **authority-side only**
-----------------------------
Candidate execution is forbidden until the P1000 freezes (24.4), so the census records no
`subject: candidate` row and its rows carry `candidate_executed: false`. A family the *authority*
cannot build is classified `AUTHORITY_BASELINE_FAIL` with the precise reason (an acquisition, a
configure, a build or a link failure, or a build that simply never links OpenSSL) and is **never**
counted as a candidate failure: the census is what makes a later `DROP_IN_PASS` baseline-normalized
(`docs/PHASE-24-DOWNSTREAM-1000-SUBPHASES.md` sections 0, 2 and 3.2).

The cohort is precommitted and provisional
------------------------------------------
The real P1000 freeze is 24.4 and does not exist yet, so the cohort is a **bounded, provisional,
reproducible** census cohort: the families carried by at least `COHORT_MIN_SOURCES` independent
frozen 24.1 ranking sources, ranked by a provisional consensus signal derived **only** from the
committed families (source breadth, distro breadth, popularity). The rule is recorded in the
artefact and re-derived by the court `RT-AUTHORITY-CENSUS`; it is provisional and changes nothing
about the eventual P1000 selection.

Where a family has no pristine-source recipe
--------------------------------------------
The census does not manufacture a source URL: a cohort family whose upstream source this instrument
does not have a recipe for is recorded `AUTHORITY_BASELINE_FAIL` with the reason that no recipe is
recorded, so a missing recipe is a stated fact rather than a silent drop. Every network-derived
artefact is hashed with its URL and retrieval timestamp.

The Docker-only guard is called first
-------------------------------------
This module fetches from the network and builds real projects, so it is an **execution** entry
point: `phase24_guard.require_admitted()` is the first statement of `main`, and a host invocation is
refused rather than producing unreproducible evidence (`docs/REPRODUCIBILITY.md` section 1). The
court re-runs only the pure functions on the committed artefacts and never rebuilds.

Outputs
-------
  forensics/downstream/authority-baselines.jsonl  one `run` row per cohort member (kind `run`)
  forensics/downstream/usage-fingerprints.json    the specimens, variants, link surface and proof

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import glob as globmod
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    envelope,
    rel,
    resolve_authority,
    sha256_file,
    write_json,
)

# The Docker-only execution guard. Its call is the first statement of `main`: this tool fetches and
# compiles, so it is an execution entry point and a host invocation is refused.
import phase24_guard  # noqa: E402

# The record schemas the rows are validated against, imported rather than restated so the vocabulary
# cannot drift from the module the court checks it with.
import downstream_schemas  # noqa: E402

FAMILIES = REPO_ROOT / "forensics" / "downstream" / "families.json"
OUTCOMES = REPO_ROOT / "forensics" / "downstream" / "authority-baselines.jsonl"
FINGERPRINTS = REPO_ROOT / "forensics" / "downstream" / "usage-fingerprints.json"
# Scratch is kept under `/work` (never `/tmp` or the container's `/`), per the census rule, and
# deleted after each build; only the small committed artefacts persist in the tree.
SCRATCH = REPO_ROOT / "court" / "phase24-census"

GENERATOR = "forensics/tools/downstream_census.py"
USER_AGENT = "openssl-rs-forensics/1"
PARSER_VERSION = "downstream-census/1"

# The provisional consensus rule. The cohort is every family carried by at least this many
# independent frozen ranking sources -- the natural consensus tier of the frozen evidence -- ranked
# by the provisional signal below. Provisional, because the real P1000 selection is 24.4.
COHORT_MIN_SOURCES = 4

# The classification a cohort member's authority baseline carries. A `..._FAIL` is a failure of the
# *authority*, never of the candidate, and the court refuses a `..._FAIL` classified as a candidate
# failure.
CLASS_PASS = "AUTHORITY_BASELINE_PASS"
CLASS_FAIL = "AUTHORITY_BASELINE_FAIL"

# The failure classes (brief section 31) an authority baseline may carry. A class outside this set
# names a candidate-side failure, which an authority baseline can never be.
AUTHORITY_FAILURE_CLASSES = frozenset({
    "acquire-failure", "configure-failure", "authority-build-failure", "link-failure",
    "load-failure",
})

# The execution levels this census can reach, by rank.
L0 = "L0-catalogued"
L1 = "L1-admitted-source"
L2 = "L2-configured"
L3 = "L3-built"
L4 = "L4-linked"
L5 = "L5-loaded"
RANK = downstream_schemas.EXECUTION_LEVEL_RANK
PASS_RANK = RANK[L4]

# The OpenSSL soname bases a direct consumer links, matched against a DT_NEEDED soname.
OPENSSL_SONAMES = ("libssl.so", "libcrypto.so")


def _is_openssl_soname(soname: str) -> bool:
    """Whether a DT_NEEDED soname names libssl/libcrypto (any era: `libssl.so.3`, `libssl.so`)."""
    return any(soname == base or soname.startswith(base + ".") for base in OPENSSL_SONAMES)

# Per-step wall-clock bound and a whole-family bound, so a runaway build cannot hold the venue.
STEP_TIMEOUT = 900
FETCH_TIMEOUT = 300
LAUNCH_TIMEOUT = 60
MAKE_JOBS = "-j8"

_INCLUDE = re.compile(r'#\s*include\s*[<"](openssl/[A-Za-z0-9_./+-]+\.h)[">]')
_NEEDED = re.compile(r"\(NEEDED\)\s+Shared library: \[(?P<soname>[^\]]+)\]")
_RUNPATH = re.compile(r"\((?:RPATH|RUNPATH)\)\s+Library (?:rpath|runpath): \[(?P<path>[^\]]+)\]")
_UNDEF = re.compile(r"\bUND\b\s+(?P<name>[^\s@]+)")
_NM_DEFINED = re.compile(
    r"^[0-9a-fA-F]+\s+\S\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:@@?[A-Za-z0-9_.]+)?\s*$",
    re.MULTILINE)


# --------------------------------------------------------------------------------------------
# the precommitted, provisional cohort rule (pure; re-derived by the court)
# --------------------------------------------------------------------------------------------

def consensus_signal(fam: dict) -> dict:
    """The provisional consensus signal of one family, derived only from the committed record.

    Three frozen-signal components, in priority order: how many independent 24.1 ranking sources
    carry the family (`source_breadth`), how many distro ecosystems list it (`distro_breadth`), and
    the summed popularity value of its Popcon / Homebrew-analytics / crates rows (`popularity`).
    Nothing here reads a candidate result; the rule is provisional, because the P1000 freeze is
    24.4.
    """
    sources = {str(p.get("source_id")) for p in fam.get("selection_provenance") or []}
    distros = {str(p.get("ecosystem")) for p in fam.get("distro_packages") or []}
    popularity = sum(int(p.get("value") or 0) for p in fam.get("popularity_signals") or [])
    return {
        "source_breadth": len(sources),
        "distro_breadth": len(distros),
        "popularity": popularity,
    }


def cohort_rank_key(fam: dict) -> tuple:
    """The deterministic sort the provisional consensus signal induces."""
    sig = consensus_signal(fam)
    return (-sig["source_breadth"], -sig["distro_breadth"], -sig["popularity"],
            str(fam.get("canonical_name")))


def select_cohort(families_body: dict) -> list[dict]:
    """The provisional census cohort: the consensus tier, ranked.

    Every family carried by at least `COHORT_MIN_SOURCES` independent frozen ranking sources, in
    the order the provisional consensus signal induces. Returned as `(rank, family, signal)` rows so
    the artefact records exactly what was selected and why.
    """
    families = families_body.get("families") or []
    tier = [f for f in families if consensus_signal(f)["source_breadth"] >= COHORT_MIN_SOURCES]
    tier.sort(key=cohort_rank_key)
    return [
        {
            "rank": i,
            "family_id": str(f.get("family_id")),
            "canonical_name": str(f.get("canonical_name")),
            "openssl_linkage": f.get("openssl_linkage"),
            "directness_class": f.get("directness_class"),
            **consensus_signal(f),
        }
        for i, f in enumerate(tier, 1)
    ]


def cohort_findings(families_body: dict, cohort: list[dict]) -> list[str]:
    """Every way the recorded cohort fails to reproduce from the frozen families."""
    findings: list[str] = []
    derived = select_cohort(families_body)
    if not derived:
        return ["the provisional cohort rule selects no family from the committed families"]
    got = [(c.get("family_id"), c.get("canonical_name")) for c in cohort]
    want = [(c["family_id"], c["canonical_name"]) for c in derived]
    if got != want:
        findings.append(
            "the recorded cohort does not reproduce from the frozen families by the provisional "
            f"consensus rule (recorded {len(got)}, derived {len(want)})"
        )
    for i, c in enumerate(cohort, 1):
        if c.get("rank") != i:
            findings.append(f"cohort member {c.get('family_id')!r} records rank "
                            f"{c.get('rank')!r}, not its position {i}")
        if int(c.get("source_breadth") or 0) < COHORT_MIN_SOURCES:
            findings.append(f"cohort member {c.get('family_id')!r} is carried by only "
                            f"{c.get('source_breadth')} source(s), below the consensus tier "
                            f"{COHORT_MIN_SOURCES}")
    return findings


# --------------------------------------------------------------------------------------------
# the pristine-source recipes (authored evidence, like 24.1's SOURCE_SPECS; a missing recipe is
# recorded, never invented). `{prefix}` is the admitted authority prefix.
# --------------------------------------------------------------------------------------------

SPECS: tuple[dict, ...] = (
    {
        "family": "libssh", "version": "0.10.6",
        "url": "https://www.libssh.org/files/0.10/libssh-0.10.6.tar.xz", "archive": "tar.xz",
        "build_system": "autotools",
        "configure": ["--with-openssl={prefix}", "--without-gssapi", "--without-libgcrypt",
                      "--without-pcap", "--without-socket-wrapper", "--silent"],
        "make": [MAKE_JOBS], "artifact": "src/libssh.so*", "launch": None,
        "note": ("libssh 0.10.6 ships a CMake build and a source tree with no pre-generated "
                 "`configure`; the census records that as an unsupported build system rather than "
                 "installing a toolchain"),
    },
    {
        "family": "curl", "version": "8.10.1",
        "url": "https://curl.se/download/curl-8.10.1.tar.gz", "archive": "tar.gz",
        "build_system": "autotools",
        "configure": ["--with-openssl={prefix}", "--without-libpsl", "--without-zstd",
                      "--without-brotli", "--disable-ldap", "--disable-ldaps", "--without-libidn2",
                      "--without-nghttp2", "--silent"],
        "make": [MAKE_JOBS], "artifact": "lib/.libs/libcurl.so*", "launch": None,
        "note": "curl 8.10.1's libcurl is the direct OpenSSL consumer; the census fingerprints it",
    },
    {
        "family": "haproxy", "version": "3.0.6",
        "url": "https://www.haproxy.org/download/3.0/src/haproxy-3.0.6.tar.gz",
        "archive": "tar.gz", "build_system": "make",
        "configure": None,
        "make": [MAKE_JOBS, "TARGET=linux-glibc", "USE_OPENSSL=1", "SSL_INC={prefix}/include",
                 "SSL_LIB={prefix}/lib"],
        "artifact": "haproxy", "launch": ["-v"],
        "note": "haproxy 3.0.6's Makefile takes the authority prefix through SSL_INC/SSL_LIB",
    },
    {
        "family": "monit", "version": "5.34.3",
        "url": "https://mmonit.com/monit/dist/monit-5.34.3.tar.gz", "archive": "tar.gz",
        "build_system": "autotools",
        "configure": ["--without-pam", "--with-ssl-dir={prefix}", "--silent"],
        "make": [MAKE_JOBS], "artifact": "monit", "launch": ["-V"],
        "note": "monit 5.34.3 links libssl/libcrypto directly (the HTTP/SSL check)",
    },
    {
        "family": "openssh", "version": "9.9p1",
        "url": "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-9.9p1.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "configure": ["--with-ssl-dir={prefix}", "--without-openssl-header-check", "--without-pam",
                      "--without-selinux", "--without-libedit", "--without-ldns", "--silent"],
        "make": [MAKE_JOBS, "ssh"], "artifact": "ssh", "launch": ["-V"],
        "note": ("openssh 9.9p1's `ssh` links the authority's libcrypto directly; its header-version "
                 "check is disabled so a newer authority is not mistaken for a mismatch"),
    },
    {
        "family": "pure-ftpd", "version": "1.0.52",
        "url": "https://download.pureftpd.org/pub/pure-ftpd/releases/pure-ftpd-1.0.52.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "configure": ["--with-tls", "--without-inetd", "--silent"],
        "make": [MAKE_JOBS], "artifact": "src/pure-ftpd", "launch": ["--help"],
        "note": "pure-ftpd 1.0.52 links OpenSSL through --with-tls",
    },
    {
        "family": "redis", "version": "7.4.1",
        "url": "https://download.redis.io/releases/redis-7.4.1.tar.gz", "archive": "tar.gz",
        "build_system": "make",
        "configure": None,
        "make": [MAKE_JOBS, "BUILD_TLS=yes", "OPENSSL_PREFIX={prefix}"],
        "artifact": "src/redis-server", "launch": ["--version"],
        "note": "redis 7.4.1 builds TLS support against the authority through OPENSSL_PREFIX",
    },
    {
        "family": "kmod", "version": "33",
        "url": "https://cdn.kernel.org/pub/linux/utils/kernel/kmod/kmod-33.tar.xz",
        "archive": "tar.xz", "build_system": "autotools",
        "configure": ["--with-openssl", "--silent"],
        "make": [MAKE_JOBS], "artifact": "tools/.libs/kmod", "launch": None,
        "note": "kmod 33 is attempted with its OpenSSL signature support enabled",
    },
    {
        "family": "lighttpd", "version": "1.4.76",
        "url": "https://download.lighttpd.net/lighttpd/releases-1.4.x/lighttpd-1.4.76.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "configure": ["--with-openssl", "--silent"],
        "make": [MAKE_JOBS], "artifact": "src/lighttpd", "launch": ["-v"],
        "note": "lighttpd 1.4.76 is attempted with its TLS module enabled",
    },
    {
        "family": "openvpn", "version": "2.6.12",
        "url": "https://swupdate.openvpn.net/community/releases/openvpn-2.6.12.tar.gz",
        "archive": "tar.gz", "build_system": "autotools",
        "configure": ["--with-crypto-library=openssl", "--disable-lzo", "--disable-lz4",
                      "--disable-plugin-auth-pam", "--silent"],
        "make": [MAKE_JOBS], "artifact": "src/openvpn/openvpn", "launch": ["--version"],
        "note": "openvpn 2.6.12 is attempted against the authority's OpenSSL",
    },
    {
        "family": "isync", "version": "1.5.0",
        "url": ("https://downloads.sourceforge.net/project/isync/isync/1.5.0/"
                "isync-1.5.0.tar.gz"),
        "archive": "tar.gz", "build_system": "autotools",
        "configure": ["--with-ssl={prefix}", "--without-sasl", "--without-zlib", "--silent"],
        "make": [MAKE_JOBS], "artifact": "src/mbsync", "launch": None,
        "note": "isync 1.5.0's mbsync is attempted against the authority's OpenSSL",
    },
)

_SPEC_BY_FAMILY = {s["family"]: s for s in SPECS}


# --------------------------------------------------------------------------------------------
# subprocess helpers
# --------------------------------------------------------------------------------------------

def _norm(text: str, prefix: Path) -> str:
    """Portable text: the ephemeral authority/scratch absolute paths become tokens."""
    if text is None:
        return ""
    text = text.replace(str(prefix), "{authority}")
    text = text.replace(str(SCRATCH), "{scratch}")
    return text


def _run(argv: list[str], *, cwd: Path | None = None, env: dict | None = None,
         timeout: int = STEP_TIMEOUT) -> dict:
    """Run one bounded step, capturing output; never raises on a non-zero exit."""
    start = time.monotonic()
    try:
        proc = subprocess.run(argv, cwd=str(cwd) if cwd else None, env=env,
                              capture_output=True, text=True, timeout=timeout, check=False)
        code, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        code = -1
        out = (exc.stdout or b"").decode("utf-8", "ignore") if isinstance(exc.stdout, bytes) \
            else (exc.stdout or "")
        err = f"TIMEOUT after {timeout}s"
    except FileNotFoundError as exc:
        code, out, err = 127, "", str(exc)
    return {
        "argv": [os.path.basename(argv[0])] + argv[1:],
        "exit_code": code,
        "ok": code == 0,
        "stdout": out,
        "stderr": err,
        "elapsed_seconds": round(time.monotonic() - start, 3),
    }


def _tail(text: str, lines: int = 15) -> str:
    return "\n".join((text or "").strip().splitlines()[-lines:])


def _error_line(step: dict) -> str:
    """The most informative error line of a failed step, for the failure reason."""
    blob = ((step.get("stderr") or "") + "\n" + (step.get("stdout") or "")).strip()
    for line in reversed(blob.splitlines()):
        low = line.lower()
        if any(k in low for k in ("error", "no such file", "not found", "cannot", "failed",
                                  "required", "unable")):
            return line.strip()[:300]
    return _tail(blob, 1)[:300] or "the step failed with no diagnostic output"


# --------------------------------------------------------------------------------------------
# ELF / linkage inspection
# --------------------------------------------------------------------------------------------

def _readelf(path: Path, *flags: str) -> str:
    res = _run(["readelf", *flags, str(path)], timeout=60)
    return res["stdout"] if res["ok"] else ""


def dt_needed(path: Path) -> list[str]:
    return sorted({m.group("soname") for m in _NEEDED.finditer(_readelf(path, "-d", "--wide"))})


def runpaths(path: Path) -> list[str]:
    return sorted({m.group("path") for m in _RUNPATH.finditer(_readelf(path, "-d", "--wide"))})


def undefined_symbols(path: Path) -> set[str]:
    text = _readelf(path, "--dyn-syms", "--wide")
    return {m.group("name") for m in _UNDEF.finditer(text)}


def authority_defined_symbols(prefix: Path) -> set[str]:
    """The symbols the authority's libssl/libcrypto export, so an import can be attributed."""
    out: set[str] = set()
    for soname in OPENSSL_SONAMES:
        for lib in sorted(prefix.glob(f"lib/{soname}.3")) + sorted(prefix.glob(f"lib/{soname}")):
            res = _run(["nm", "-D", "--defined-only", str(lib)], timeout=60)
            if res["ok"]:
                out |= {m.group("name") for m in _NM_DEFINED.finditer(res["stdout"])}
    return out


def _resolve_sonames(artifact: Path, prefix: Path) -> dict:
    """The linkage proof: where each OpenSSL soname resolves, under the authority and by default.

    `authority:` values mean the resolved object is under the admitted prefix; anything else is the
    absolute path a system loader would pick. The default resolution (no `LD_LIBRARY_PATH`) is
    recorded so the proof is visibly load-bearing rather than vacuous.
    """
    needed = [s for s in dt_needed(artifact) if _is_openssl_soname(s)]
    proof: dict = {
        "authority_prefix": rel(prefix),
        "sonames": {},
        "all_under_authority": bool(needed),
        "default_resolution": {},
    }
    env_auth = dict(os.environ, LD_LIBRARY_PATH=str(prefix / "lib"))
    for soname in needed:
        auth = _resolved_path(artifact, soname, env_auth)
        dflt = _resolved_path(artifact, soname, dict(os.environ))
        under = bool(auth) and _under(auth, prefix)
        proof["sonames"][soname] = {
            "resolved": f"authority:{soname}" if under else (auth or "unresolved"),
            "under_authority": under,
        }
        proof["default_resolution"][soname] = dflt or "unresolved"
        proof["all_under_authority"] = proof["all_under_authority"] and under
    return proof


def _resolved_path(artifact: Path, soname: str, env: dict) -> str | None:
    res = _run(["ldd", str(artifact)], env=env, timeout=60)
    for line in (res["stdout"] or "").splitlines():
        parts = line.split("=>")
        if len(parts) == 2 and parts[0].strip().startswith(soname):
            path = parts[1].strip().split(" (")[0].strip()
            return path or None
    return None


def _under(path: str, prefix: Path) -> bool:
    try:
        return os.path.realpath(path).startswith(os.path.realpath(str(prefix)) + os.sep)
    except OSError:
        return False


def source_headers(src_root: Path) -> list[str]:
    """The `openssl/*.h` headers the pristine source includes, from the source tree itself."""
    found: set[str] = set()
    for path in src_root.rglob("*"):
        if not path.is_file() or path.stat().st_size > 1 << 20:
            continue
        if path.suffix.lower() not in (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".in", ".ac"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        found |= {m.group(1) for m in _INCLUDE.finditer(text)}
    return sorted(found)


# --------------------------------------------------------------------------------------------
# resource limits + venue
# --------------------------------------------------------------------------------------------

def resource_limits() -> dict:
    """The container's cgroup limits, read rather than asserted; `unknown` when unreadable."""
    def read(p: str) -> str:
        try:
            return Path(p).read_text(encoding="utf-8").strip()
        except OSError:
            return "unknown"

    man = phase24_guard.load_manifest()
    return {
        "memory_max": read("/sys/fs/cgroup/memory.max"),
        "memory_swap_max": read("/sys/fs/cgroup/memory.swap.max"),
        "pids_max": read("/sys/fs/cgroup/pids.max"),
        "cpu_max": read("/sys/fs/cgroup/cpu.max"),
        "image": man.get("image"),
        "platform": man.get("platform"),
        "entry_point": man.get("env_flag"),
        "note": ("the census runs inside the admitted court container, which docker/"
                 "openssl-rs-court.sh starts with --memory/--memory-swap/--cpus/--pids-limit, "
                 "--restart=no and no-new-privileges; each step is bounded by this tool's own "
                 "timeout and the network is used only for acquisition"),
    }


# --------------------------------------------------------------------------------------------
# measurement: one family, one pristine source, one authority build
# --------------------------------------------------------------------------------------------

def _fetch(url: str, dest: Path) -> dict:
    dest.parent.mkdir(parents=True, exist_ok=True)
    return _run(["curl", "-sSL", "--fail", "--retry", "2", "--retry-delay", "2", "-A", USER_AGENT,
                 "--max-time", str(FETCH_TIMEOUT), "-o", str(dest), url], timeout=FETCH_TIMEOUT + 30)


def _extract(archive: Path, dest: Path) -> dict:
    dest.mkdir(parents=True, exist_ok=True)
    return _run(["tar", "xf", str(archive), "-C", str(dest)], timeout=STEP_TIMEOUT)


def _single_source_root(dest: Path) -> Path | None:
    entries = [p for p in sorted(dest.iterdir()) if p.is_dir()]
    return entries[0] if len(entries) == 1 else (dest if entries else None)


def _row(fam: dict, spec: dict | None, *, level: str, outcome: str, residual: str,
         classification: str, failure_class: str | None, failure_reason: str | None,
         source_sha256: str | None, elapsed: float, steps: list[dict] | None = None,
         fingerprint: dict | None = None, prefix: Path | None = None) -> dict:
    """One authority-baseline run row: a schema-valid `run` record plus the census extension."""
    name = str(fam.get("canonical_name"))
    version = spec.get("version") if spec else None
    specimen_id = f"specimen:{name}:{version}" if version else None
    variant_id = f"variant:{name}:pristine-build" if version else None
    fp = fingerprint or {}
    evidence = [f"family:{fam.get('family_id')}"]
    if spec:
        evidence.append(f"spec:{spec['url']}")
    if source_sha256:
        evidence.append(f"source:{source_sha256}")
    if fp.get("artifact_rel"):
        evidence.append(f"artifact:{fp['artifact_rel']}")
    return {
        # the `run` schema fields (kind `run`)
        "run_id": f"run:authority-census:{name}",
        "specimen_id": specimen_id,
        "variant_id": variant_id,
        "subject": "authority",
        "level": level,
        "outcome": outcome,
        "residual_class": residual,
        "evidence": evidence,
        # the census extension
        "family_id": fam.get("family_id"),
        "canonical_name": name,
        "rank": fam.get("_rank"),
        "openssl_linkage": fam.get("openssl_linkage"),
        "directness_class": fam.get("directness_class"),
        "classification": classification,
        "max_level": level,
        "failure_class": failure_class,
        "failure_reason": failure_reason,
        "source_sha256": source_sha256,
        "source_url": spec["url"] if spec else None,
        "retrieved_at": (spec or {}).get("_retrieved_at"),
        "candidate_executed": False,
        "elapsed_seconds": round(elapsed, 3),
        "dt_needed": fp.get("dt_needed", []),
        "imported_openssl_symbols_count": len(fp.get("imported_openssl_symbols", [])),
        "openssl_headers": fp.get("openssl_headers", []),
        "linkage_authority_resolved": bool(fp.get("linkage_proof", {}).get(
            "all_under_authority")),
        "steps": [
            {"name": s["name"], "ok": s["ok"], "exit_code": s["exit_code"],
             "elapsed_seconds": s["elapsed_seconds"],
             "argv": [_norm(a, prefix) for a in s["argv"]] if prefix else s["argv"]}
            for s in (steps or [])
        ],
        "log_tail": _tail((steps or [{}])[-1].get("stderr", "") or
                          (steps or [{}])[-1].get("stdout", "")) if steps else "",
    }


def _no_recipe_row(fam: dict, prefix: Path) -> dict:
    return _row(
        fam, None, level=L0, outcome="unavailable", residual="unavailable",
        classification=CLASS_FAIL, failure_class="acquire-failure",
        failure_reason=("no pristine-source acquisition recipe is recorded for this family; the "
                        "census does not manufacture a source URL"),
        source_sha256=None, elapsed=0.0, prefix=prefix,
    )


def measure_family(fam: dict, prefix: Path, auth_defined: set[str],
                   limits: dict) -> tuple[dict, dict | None, dict | None, dict | None]:
    """Acquire and build one cohort family against the authority; return `(row, specimen, variant,
    fingerprint)`.

    Pure of any candidate: the subject is always `authority`. A failure at any rung is classified
    `AUTHORITY_BASELINE_FAIL` with the rung's failure class and the step's own diagnostic.
    """
    name = str(fam.get("canonical_name"))
    spec = _SPEC_BY_FAMILY.get(name)
    if spec is None:
        return _no_recipe_row(fam, prefix), None, None, None

    spec = dict(spec)
    spec["_retrieved_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    work = SCRATCH / name
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    steps: list[dict] = []

    def stage(label: str, res: dict) -> dict:
        res = dict(res, name=label)
        steps.append(res)
        return res

    # L1 -- acquisition, content-addressed with URL and timestamp.
    archive = work / f"source.{spec['archive']}"
    fetch = stage("fetch", _fetch(spec["url"], archive))
    if not fetch["ok"] or not archive.is_file():
        _cleanup(work)
        return (_row(fam, spec, level=L0, outcome="failed", residual="unavailable",
                     classification=CLASS_FAIL, failure_class="acquire-failure",
                     failure_reason=f"fetching the pristine source failed: {_error_line(fetch)}",
                     source_sha256=None, elapsed=time.monotonic() - started, steps=steps,
                     prefix=prefix), None, None, None)
    source_sha256 = sha256_file(archive)
    source_bytes = archive.stat().st_size
    spec["_source_bytes"] = source_bytes

    extract = stage("extract", _extract(archive, work / "src"))
    root = _single_source_root(work / "src")
    if not extract["ok"] or root is None:
        _cleanup(work)
        return (_row(fam, spec, level=L1, outcome="failed", residual="unavailable",
                     classification=CLASS_FAIL, failure_class="acquire-failure",
                     failure_reason=f"extracting the source archive failed: {_error_line(extract)}",
                     source_sha256=source_sha256, elapsed=time.monotonic() - started,
                     steps=steps, prefix=prefix), None, None, None)

    env = dict(os.environ,
               PKG_CONFIG_PATH=f"{prefix}/lib/pkgconfig",
               CPPFLAGS=f"-I{prefix}/include",
               LDFLAGS=f"-L{prefix}/lib")

    # L2 -- configure (autotools), where the spec has one.
    level = L1
    if spec["build_system"] == "autotools":
        argv = ["./configure"] + [a.format(prefix=prefix) for a in spec["configure"]]
        conf = stage("configure", _run(argv, cwd=root, env=env))
        if not conf["ok"]:
            _cleanup(work)
            return (_row(fam, spec, level=L1, outcome="failed", residual="unbuildable",
                         classification=CLASS_FAIL, failure_class="configure-failure",
                         failure_reason=f"configure failed: {_error_line(conf)}",
                         source_sha256=source_sha256, elapsed=time.monotonic() - started,
                         steps=steps, prefix=prefix), None, None, None)
        level = L2

    # L3 -- compile.
    make_argv = ["make"] + [a.format(prefix=prefix) for a in spec["make"]]
    build = stage("make", _run(make_argv, cwd=root, env=env))
    if not build["ok"]:
        _cleanup(work)
        return (_row(fam, spec, level=level, outcome="failed", residual="unbuildable",
                     classification=CLASS_FAIL, failure_class="authority-build-failure",
                     failure_reason=f"the build failed: {_error_line(build)}",
                     source_sha256=source_sha256, elapsed=time.monotonic() - started,
                     steps=steps, prefix=prefix), None, None, None)
    level = L3

    artifact = _pick_artifact(root, spec["artifact"])
    if artifact is None:
        _cleanup(work)
        return (_row(fam, spec, level=L3, outcome="failed", residual="unbuildable",
                     classification=CLASS_FAIL, failure_class="authority-build-failure",
                     failure_reason=f"the build produced no artifact matching {spec['artifact']!r}",
                     source_sha256=source_sha256, elapsed=time.monotonic() - started,
                     steps=steps, prefix=prefix), None, None, None)

    imported = sorted(undefined_symbols(artifact) & auth_defined)
    proof = _resolve_sonames(artifact, prefix)
    fp = {
        "artifact_rel": os.path.relpath(artifact, root),
        "artifact_sha256": sha256_file(artifact),
        "dt_needed": dt_needed(artifact),
        "runpath": runpaths(artifact),
        "imported_openssl_symbols": imported,
        "openssl_headers": source_headers(root),
        "linkage_proof": proof,
    }

    # L4 -- link: DT_NEEDED names an OpenSSL soname and it resolves to the authority.
    openssl_needed = [s for s in fp["dt_needed"] if _is_openssl_soname(s)]
    if not openssl_needed:
        _cleanup(work)
        return (_row(fam, spec, level=L3, outcome="failed", residual="unlinked",
                     classification=CLASS_FAIL, failure_class="link-failure",
                     failure_reason=("the built artifact declares no libssl/libcrypto dependency, "
                                     "so the authority was not consumed"),
                     source_sha256=source_sha256, elapsed=time.monotonic() - started,
                     steps=steps, fingerprint=fp, prefix=prefix), None, None, None)
    if not proof["all_under_authority"] or not imported:
        _cleanup(work)
        reason = ("the built artifact declares " + ", ".join(openssl_needed) +
                  " but it did not resolve to the admitted authority")
        if not imported:
            reason = ("the built artifact links " + ", ".join(openssl_needed) +
                      " but imports no OpenSSL symbol")
        return (_row(fam, spec, level=L3, outcome="failed", residual="unlinked",
                     classification=CLASS_FAIL, failure_class="link-failure",
                     failure_reason=reason, source_sha256=source_sha256,
                     elapsed=time.monotonic() - started, steps=steps, fingerprint=fp,
                     prefix=prefix), None, None, None)
    level = L4

    # L5 -- launch, where the spec is a program and names a launch.
    launch = spec.get("launch")
    launch_ok = None
    if launch:
        run_env = dict(env, LD_LIBRARY_PATH=f"{prefix}/lib")
        res = stage("launch", _run([str(artifact)] + list(launch), cwd=artifact.parent,
                                   env=run_env, timeout=LAUNCH_TIMEOUT))
        launch_ok = res["ok"] or ("error while loading shared libraries" not in res["stderr"])
        if launch_ok:
            level = L5

    specimen = {
        "specimen_id": f"specimen:{name}:{spec['version']}",
        "family_id": fam.get("family_id"),
        "version": spec["version"],
        "upstream_ref": spec["url"],
        "pristine_source_sha256": source_sha256,
        "licence": "unknown",
        "evidence": [f"source:{spec['url']}#{source_sha256}",
                     f"retrieved_at:{spec['_retrieved_at']}",
                     f"bytes:{source_bytes}"],
    }
    variant = {
        "variant_id": f"variant:{name}:pristine-build",
        "specimen_id": specimen["specimen_id"],
        "build_profile": f"{spec['build_system']}-pristine",
        "platform": "linux",
        "arch": "x86_64",
        "patch_set": "pristine",
        "evidence": [f"authority:{prefix.name}", f"build_system:{spec['build_system']}"],
    }
    fp.update({
        "family_id": fam.get("family_id"),
        "canonical_name": name,
        "specimen_id": specimen["specimen_id"],
        "variant_id": variant["variant_id"],
        "classification": CLASS_PASS,
        "max_level": level,
        "launch_attempted": bool(launch),
        "launch_ok": launch_ok,
    })
    row = _row(fam, spec, level=level, outcome="reached", residual="none",
               classification=CLASS_PASS, failure_class=None, failure_reason=None,
               source_sha256=source_sha256, elapsed=time.monotonic() - started, steps=steps,
               fingerprint=fp, prefix=prefix)
    _cleanup(work)
    return row, specimen, variant, fp


def _pick_artifact(root: Path, pattern: str) -> Path | None:
    """The first built artifact matching the spec's pattern, preferring a direct OpenSSL linker."""
    matches = [Path(p) for p in sorted(globmod.glob(str(root / pattern)))]
    matches = [p for p in matches if p.is_file() and not p.is_symlink()]
    for p in matches:
        if any(_is_openssl_soname(s) for s in dt_needed(p)):
            return p
    return matches[0] if matches else None


def _cleanup(work: Path) -> None:
    shutil.rmtree(work, ignore_errors=True)


# --------------------------------------------------------------------------------------------
# the census: every cohort member, then the two artefacts
# --------------------------------------------------------------------------------------------

def derive_census(families_body: dict, authority_id: str) -> tuple[list[dict], dict]:
    """Measure the whole cohort and return `(rows, fingerprints_body)`."""
    prefix = resolve_authority(authority_id).prefix
    auth_defined = authority_defined_symbols(prefix)
    limits = resource_limits()
    cohort = select_cohort(families_body)
    by_id = {str(f.get("family_id")): f for f in families_body.get("families") or []}

    rows: list[dict] = []
    specimens: list[dict] = []
    variants: list[dict] = []
    fingerprints: list[dict] = []
    for entry in cohort:
        fam = dict(by_id[str(entry["family_id"])])
        fam["_rank"] = entry["rank"]
        row, specimen, variant, fp = measure_family(fam, prefix, auth_defined, limits)
        rows.append(row)
        if specimen:
            specimens.append(specimen)
            variants.append(variant)
        if fp:
            fingerprints.append(fp)
        mark = "PASS" if row["classification"] == CLASS_PASS else "FAIL"
        print(f"  [{entry['rank']:>2}] {entry['canonical_name']:<22} {mark} "
              f"{row['level']:<18} {row['failure_reason'] or ''}"[:150])

    counts = {
        "cohort": len(cohort),
        "passed": sum(1 for r in rows if r["classification"] == CLASS_PASS),
        "failed": sum(1 for r in rows if r["classification"] == CLASS_FAIL),
        "acquired": sum(1 for r in rows if r["source_sha256"]),
        "linked_to_authority": sum(1 for r in rows if r["linkage_authority_resolved"]),
        "launched": sum(1 for r in rows if RANK[r["max_level"]] >= RANK[L5]),
        "no_recipe": sum(1 for r in rows if r["failure_class"] == "acquire-failure"
                         and not r["source_url"]),
        "with_recipe": len(SPECS),
    }
    body = {
        "rule": (
            "the cohort is the families carried by at least "
            f"{COHORT_MIN_SOURCES} independent frozen 24.1 ranking sources (the consensus tier), "
            "ranked by the provisional consensus signal (source breadth, then distro breadth, then "
            "popularity, then canonical name). The rule is provisional: the real P1000 selection is "
            "24.4, and this cohort changes nothing about it. Every row is authority-side; a family "
            "the authority cannot build is `AUTHORITY_BASELINE_FAIL`, never a candidate failure, "
            "and its reason is preserved."
        ),
        "authority": authority_id,
        "authority_prefix": rel(prefix),
        "cohort_min_sources": COHORT_MIN_SOURCES,
        "cohort": cohort,
        "cohort_size": len(cohort),
        "source_specs": [
            {"family": s["family"], "version": s["version"], "url": s["url"],
             "archive": s["archive"], "build_system": s["build_system"], "note": s["note"]}
            for s in SPECS
        ],
        "specimens": sorted(specimens, key=lambda s: s["specimen_id"]),
        "variants": sorted(variants, key=lambda v: v["variant_id"]),
        "fingerprints": sorted(fingerprints, key=lambda f: str(f["family_id"])),
        "counts": counts,
        "resource_limits": limits,
        "non_claims": [
            "an authority baseline is not a candidate result: no candidate was executed (24.4 "
            "freezes the population first)",
            "reaching L4-linked is not a functional proof: a build is not behaving",
            "the cohort is provisional and bounded, not the P1000: it is a census, not the stratum's "
            "population",
            "a family with no recorded source recipe is a stated gap, not an absence of a consumer",
        ],
    }
    return rows, body


def write_outputs(rows: list[dict], body: dict) -> None:
    """Write the JSONL census and the JSON usage-fingerprint envelope, deterministically."""
    OUTCOMES.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in rows)
    OUTCOMES.write_text(text, encoding="utf-8")

    inputs = [
        InputRef(name="families", path=FAMILIES),
        InputRef(name="phase-24-plan", path=REPO_ROOT / "docs"
                 / "PHASE-24-DOWNSTREAM-1000-SUBPHASES.md"),
        InputRef(name="downstream-schemas",
                 path=REPO_ROOT / "forensics" / "tools" / "downstream_schemas.py"),
        InputRef(name="phase24-guard",
                 path=REPO_ROOT / "forensics" / "tools" / "phase24_guard.py"),
    ]
    doc = envelope(kind="downstream-usage-fingerprints", authority=body["authority"],
                   inputs=inputs, body=body, generator=GENERATOR)
    write_json(FINGERPRINTS, doc)


def cmd_measure(authority_id: str) -> int:
    if not FAMILIES.is_file():
        print(f"[downstream-census] {rel(FAMILIES)} is absent; run 24.2 first")
        return 1
    families_body = json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
    SCRATCH.mkdir(parents=True, exist_ok=True)
    print(f"[downstream-census] measuring the provisional cohort against {authority_id}")
    rows, body = derive_census(families_body, authority_id)
    _cleanup(SCRATCH)
    findings = census_findings(families_body, rows, body)
    control = census_sensitivity_control(families_body, rows, body)
    if findings or not control["honest"]:
        print("[downstream-census] the measured census fails its own checks:")
        for f in findings:
            print(f"  - {f}")
        if not control["honest"]:
            print(f"  - the sensitivity control is not honest: {control}")
        return 1
    write_outputs(rows, body)
    c = body["counts"]
    print(f"[downstream-census] cohort={c['cohort']} passed={c['passed']} failed={c['failed']} "
          f"linked={c['linked_to_authority']} launched={c['launched']} "
          f"no_recipe={c['no_recipe']} with_recipe={c['with_recipe']}")
    print(f"  -> {rel(OUTCOMES)}")
    print(f"  -> {rel(FINGERPRINTS)}")
    return 0


# --------------------------------------------------------------------------------------------
# the checks the court re-runs over the committed artefacts (pure; never rebuilding)
# --------------------------------------------------------------------------------------------

def _load_outcomes() -> list[dict]:
    if not OUTCOMES.is_file():
        return []
    return [json.loads(line) for line in OUTCOMES.read_text(encoding="utf-8").splitlines() if line]


def _load_fingerprints() -> dict:
    if not FINGERPRINTS.is_file():
        return {}
    doc = json.loads(FINGERPRINTS.read_text(encoding="utf-8"))
    return doc.get("body", doc)


def census_findings(families_body: dict, rows: list[dict], body: dict) -> list[str]:
    """Every way the committed authority-baseline census fails its own subject.

    Pure over the committed rows, the fingerprint envelope and the frozen families, so the court
    re-runs it without rebuilding and the sensitivity control can mutate it.
    """
    findings: list[str] = []
    families = {str(f.get("family_id")): f for f in families_body.get("families") or []}
    cohort = body.get("cohort") or []
    findings += cohort_findings(families_body, cohort)

    if not rows:
        return findings + ["the census records no authority-baseline row"]

    spec_families = {str(s["family"]) for s in SPECS}
    cohort_names = {str(c.get("canonical_name")) for c in cohort}
    for name in sorted(spec_families - cohort_names):
        findings.append(f"the source recipe for {name!r} names a family outside the cohort: the "
                        f"census would select its cohort by recipe rather than by the rule")

    seen: set[str] = set()
    by_family: dict[str, dict] = {}
    for row in rows:
        fid = str(row.get("family_id"))
        if fid in seen:
            findings.append(f"{fid}: two authority-baseline rows for one cohort member")
        seen.add(fid)
        by_family[fid] = row
        # A census row is a `run` record, and it is always the authority's.
        findings += [f"{fid}: {p}" for p in downstream_schemas.validate_run(row)]
        if row.get("subject") != "authority":
            findings.append(f"{fid}: an authority census row names subject "
                            f"{row.get('subject')!r}, not `authority`")
        if row.get("candidate_executed"):
            findings.append(f"{fid}: an authority census row claims candidate execution, but "
                            f"candidate execution is forbidden until the P1000 freezes")

        classification = row.get("classification")
        if classification not in (CLASS_PASS, CLASS_FAIL):
            findings.append(f"{fid}: classification {classification!r} is neither "
                            f"{CLASS_PASS!r} nor {CLASS_FAIL!r}")
            continue

        if classification == CLASS_FAIL:
            if not row.get("failure_reason"):
                findings.append(f"{fid}: an {CLASS_FAIL} carries no reason")
            fc = row.get("failure_class")
            if fc not in AUTHORITY_FAILURE_CLASSES:
                findings.append(f"{fid}: an {CLASS_FAIL} is classified {fc!r}, which counts an "
                                f"authority baseline failure as a candidate failure; only "
                                f"{sorted(AUTHORITY_FAILURE_CLASSES)} are authority failures")
            # A build-level failure must still have reached a source if it got past L0.
            if RANK.get(row.get("level"), 0) >= RANK[L1] and not row.get("source_sha256"):
                findings.append(f"{fid}: reaches {row.get('level')} with no source hash")
            continue

        # A PASS: the highest rung, the source hash, the linkage proof and the fingerprint.
        if RANK.get(row.get("level"), -1) < PASS_RANK:
            findings.append(f"{fid}: is {CLASS_PASS} but reached only {row.get('level')!r}")
        if not row.get("source_sha256"):
            findings.append(f"{fid}: is {CLASS_PASS} with no source hash")
        if row.get("linkage_authority_resolved") is not True:
            findings.append(f"{fid}: is {CLASS_PASS} but its linkage did not resolve to the "
                            f"authority")

    # The fingerprints: every PASS names one, and it proves authority linkage with real imports.
    fp_by_family = {str(f.get("family_id")): f for f in body.get("fingerprints") or []}
    for fid, row in sorted(by_family.items()):
        if row.get("classification") != CLASS_PASS:
            continue
        fp = fp_by_family.get(fid)
        if fp is None:
            findings.append(f"{fid}: is {CLASS_PASS} but carries no usage fingerprint")
            continue
        symbols = fp.get("imported_openssl_symbols") or []
        if not symbols:
            findings.append(f"{fid}: a fingerprint with no imported OpenSSL symbols is claimed "
                            f"{CLASS_PASS}")
        openssl_needed = [s for s in (fp.get("dt_needed") or [])
                          if _is_openssl_soname(s)]
        if not openssl_needed:
            findings.append(f"{fid}: a {CLASS_PASS} fingerprint declares no libssl/libcrypto "
                            f"dependency")
        proof = fp.get("linkage_proof") or {}
        if proof.get("all_under_authority") is not True:
            findings.append(f"{fid}: a {CLASS_PASS} fingerprint does not prove the authority's "
                            f"libssl/libcrypto resolved")
        for soname, resolved in sorted((proof.get("sonames") or {}).items()):
            value = str(resolved.get("resolved"))
            if not value.startswith("authority:"):
                findings.append(f"{fid}: claims authority linkage but resolves a system library "
                                f"{soname} -> {value}")

    # Counts are read, not typed.
    c = body.get("counts") or {}
    if c.get("cohort") not in (None, len(cohort)):
        findings.append(f"counts.cohort {c.get('cohort')!r} disagrees with the {len(cohort)} "
                        f"cohort member(s)")
    if c.get("passed") not in (None, sum(1 for r in rows if r.get("classification") == CLASS_PASS)):
        findings.append("counts.passed disagrees with the classified rows")
    if c.get("failed") not in (None, sum(1 for r in rows if r.get("classification") == CLASS_FAIL)):
        findings.append("counts.failed disagrees with the classified rows")
    return findings


def _mutations(rows: list[dict], body: dict) -> list[tuple[str, str, list[dict], dict]]:
    """`(name, needle, mutated_rows, mutated_body)` for each seeded mutation."""
    out: list[tuple[str, str, list[dict], dict]] = []
    pass_row = next((r for r in rows if r.get("classification") == CLASS_PASS), None)
    fail_row = next((r for r in rows if r.get("classification") == CLASS_FAIL), None)

    # (a) a build claiming authority linkage while resolving a system libssl.
    m1, b1 = copy.deepcopy(rows), copy.deepcopy(body)
    if pass_row is not None:
        for fp in b1.get("fingerprints") or []:
            if str(fp.get("family_id")) == str(pass_row.get("family_id")):
                for soname in list((fp.get("linkage_proof") or {}).get("sonames") or {}):
                    fp["linkage_proof"]["sonames"][soname]["resolved"] = \
                        f"/usr/lib/x86_64-linux-gnu/{soname}"
                break
    out.append(("authority_linkage_but_system", "resolves a system library", m1, b1))

    # (b) an AUTHORITY_BASELINE_FAIL counted as a candidate failure.
    m2, b2 = copy.deepcopy(rows), copy.deepcopy(body)
    for row in m2:
        if row.get("classification") == CLASS_FAIL:
            row["failure_class"] = "candidate-build-failure"
            break
    out.append(("authority_fail_as_candidate_failure", "candidate failure", m2, b2))

    # (c) a cohort member with no source hash, still classified a pass.
    m3, b3 = copy.deepcopy(rows), copy.deepcopy(body)
    for row in m3:
        if row.get("classification") == CLASS_PASS:
            row["source_sha256"] = None
            break
    out.append(("cohort_member_without_source_hash", "no source hash", m3, b3))

    # (d) a fingerprint with no imported symbols claimed as PASS.
    m4, b4 = copy.deepcopy(rows), copy.deepcopy(body)
    for fp in b4.get("fingerprints") or []:
        if fp.get("classification") == CLASS_PASS:
            fp["imported_openssl_symbols"] = []
            break
    out.append(("fingerprint_without_symbols_claimed_pass", "no imported OpenSSL symbols", m4, b4))
    return out


def census_sensitivity_control(families_body: dict, rows: list[dict], body: dict) -> dict:
    """Prove the court can fail: seed four mutations and require each to be caught.

    The honest census must yield **zero** findings (specificity), and each seeded mutation -- an
    authority-linkage claim that resolves a system library, an authority failure classified as a
    candidate failure, a cohort member with no source hash, and a fingerprint with no imported
    symbols claimed as a pass -- must be caught with a finding that names what it is.
    """
    base = census_findings(families_body, rows, body)
    specificity = not base
    control: dict = {"baseline_findings": len(base), "specificity_holds": specificity}
    honest = specificity
    for name, needle, mrows, mbody in _mutations(rows, body):
        caught = any(needle in f for f in census_findings(families_body, mrows, mbody))
        control[f"injected_{name}"] = name
        control[f"caught_{name}"] = caught
        honest = honest and caught
    control["honest"] = bool(honest)
    return control


# --------------------------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------------------------

def self_test() -> int:
    """Prove the pure functions of this module behave, over the committed evidence."""
    failures: list[str] = []
    if not FAMILIES.is_file():
        failures.append(f"{rel(FAMILIES)} is absent")
    else:
        families_body = json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
        cohort = select_cohort(families_body)
        if not cohort:
            failures.append("the provisional cohort rule selects no family")
        if not OUTCOMES.is_file() or not FINGERPRINTS.is_file():
            failures.append("the committed census artefacts are absent; run --measure")
        else:
            rows = _load_outcomes()
            body = _load_fingerprints()
            findings = census_findings(families_body, rows, body)
            if findings:
                failures.append(f"the committed census has findings: {findings[:3]}")
            control = census_sensitivity_control(families_body, rows, body)
            if not control["honest"]:
                failures.append(f"the sensitivity control is not honest: {control}")
    if failures:
        print("[downstream-census] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[downstream-census] self-test ok: the provisional cohort reproduces, the committed "
          "census yields zero findings, and every seeded mutation (system-linkage, authority-fail-"
          "as-candidate-failure, no-source-hash, no-imported-symbols) is caught with specificity "
          "holding")
    return 0


def cmd_check(authority_id: str) -> int:
    del authority_id
    if not FAMILIES.is_file():
        print(f"[downstream-census] {rel(FAMILIES)} is absent")
        return 1
    families_body = json.loads(FAMILIES.read_text(encoding="utf-8"))["body"]
    rows = _load_outcomes()
    body = _load_fingerprints()
    findings = census_findings(families_body, rows, body)
    control = census_sensitivity_control(families_body, rows, body)
    if findings:
        print(f"[downstream-census] {len(findings)} finding(s):")
        for f in findings:
            print(f"  - {f}")
    c = body.get("counts") or {}
    print(f"[downstream-census] cohort={c.get('cohort')} passed={c.get('passed')} "
          f"failed={c.get('failed')} findings={len(findings)} control honest={control['honest']}")
    return 0 if (not findings and control["honest"]) else 1


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--check", action="store_true",
                    help="validate the committed census without rebuilding (in-container)")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the pure functions over the committed evidence")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool fetches and compiles, so it is an
    # execution entry point and a host invocation is refused.
    phase24_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return cmd_check(args.authority)
    return cmd_measure(args.authority)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
