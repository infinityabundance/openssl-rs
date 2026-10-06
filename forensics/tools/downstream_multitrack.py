#!/usr/bin/env python3
"""openssl-rs — the downstream multitrack court's evidence (Phase 23.11).

Phase 23.11 is the **downstream multitrack court** (`docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 2,
row 23.11). At least one **meaningful unmodified real downstream consumer per major compatibility
epoch** is exercised against the corresponding **built authority's** headers and libraries, and its
real workload is run. Historical support is only useful when real software can consume it, so a real
consumer built against an authority is far stronger evidence than a symbol census, and no downstream
source is patched to make a build succeed.

What this tool does, in two tiers
---------------------------------
  * **`--measure`** runs only in a venue container (`openssl-rs-historical` for the pre-1.1.0 era,
    `openssl-rs-court` for the 3.6 cohort). It downloads the pinned upstream consumer release,
    verifies its sha256, configures and builds it **unmodified** against the authority's installed
    prefix (`-I <prefix>/include -L <prefix>/lib`, rpath), starts the authority's own `s_server` with
    a self-signed certificate, issues a real TLS request with the just-built consumer, and captures
    the **raw outputs** (the configure transcript and exit, the make tail, `curl -V`, `ldd` and the
    TLS run transcript). The raw outputs are stored *in* the artefact, so the record can be re-derived
    and a claim can never drift from the bytes it was read from. A trial of the other venue is carried
    forward from the committed artefact, so the two venues land one record between them.

  * **the default run** is what the court and `regen_all.sh` drive: it reads the committed artefact,
    re-derives every record from the **preserved raw outputs** through the same code, and rewrites the
    artefact. It needs no compiler, no network and no authority prefix, so the committed record cannot
    drift from the raw evidence it carries and the court is re-runnable.

The epochs, the consumers, and honest unavailability
---------------------------------------------------
The five major ABI/architecture epochs the historical population carries (`pre-1.0`, `1.0.x`, `1.1.x`,
`3.x`, `3.6+/4.x`) each have a **primary** consumer contemporary with the epoch -- the newest curl that
still supports that epoch's OpenSSL -- built against that epoch's built representative authority
(0.9.8zh, 1.0.2u, 1.1.1w, 3.0.0 and 3.6.4). A pair that cannot honestly be built is recorded
`not_run` with its reason and the raw configure evidence rather than counted as passing: the
**maintained** consumer (the current curl, 8.22.0) refuses every pre-3.0 authority at configure time
("OpenSSL 3.0.0 or greater required"), so those three pairs are recorded not_run while the epoch stays
covered by its contemporary consumer. A skipped court is not a passing court.

This plane is also the `downstream-evidenced` support rung's evidence: the historical population
`forensics/multitrack/historical-population.json` reads `records[]` and marks the authority a real
consumer exercised. Only a record that actually built and ran (outcome `passed`) is a `records[]`
entry, so a `not_run` pair never advances a rung.

Outputs
-------
  forensics/multitrack/downstream-multitrack.json   the per-epoch unmodified downstream consumer
                                                    results, the honest not-run set, and the raw
                                                    build/run outputs they were derived from

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
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
    content_hash,
    envelope,
    rel,
    resolve_authority,
    sha256_file,
    write_json,
)

GENERATOR = "forensics/tools/downstream_multitrack.py"
OUT = REPO_ROOT / "forensics" / "multitrack" / "downstream-multitrack.json"
PLAN = REPO_ROOT / "docs" / "PHASE-23-MULTITRACK-SUBPHASES.md"
AUTHORITY_NODES = REPO_ROOT / "forensics" / "authority-nodes.json"
HIST_RECEIPTS = REPO_ROOT / "forensics" / "multitrack" / "historical-build-receipts.json"
BUILD_RECORDS = REPO_ROOT / "forensics" / "atlas" / "BUILD_RECORDS.json"
PHASE17_CORPUS = REPO_ROOT / "forensics" / "atlas" / "downstream-corpus.json"
SCRATCH = REPO_ROOT / "court" / "phase23" / "downstream"

# The venue markers. The historical venue creates `/historical/toolchain.txt`; the forensic court
# does not. Both have `/.dockerenv`, so the historical marker is what separates them.
HISTORICAL_MARKER = Path("/historical/toolchain.txt")
DOCKER_MARKER = Path("/.dockerenv")

# The five major ABI/architecture epochs the population covers (historical_population.MAJOR_EPOCHS).
# The court cross-checks the two definitions cannot drift.
MAJOR_EPOCHS: tuple[str, ...] = ("pre-1.0", "1.0.x", "1.1.x", "3.x", "3.6+/4.x")

# The configure flags every trial shares: a static libcurl built into the tool, so `ldd` shows only
# the authority's libssl/libcrypto (plus libc), and the optional protocols/deps the venue does not
# carry are removed so the build is small and self-contained. The flags only ever remove options; no
# downstream source is edited.
COMMON_CONFIGURE = [
    "--disable-shared", "--without-zlib", "--disable-ldap", "--disable-ldaps",
    "--disable-rtsp", "--disable-dict", "--disable-telnet", "--disable-tftp",
    "--disable-pop3", "--disable-imap", "--disable-smtp", "--disable-gopher",
    "--disable-manual", "--disable-threaded-resolver",
]

# The maintained consumer the 3.6+ epoch's primary trial uses and the pre-3.0 epochs cannot reach.
CURL_MAINTAINED = {
    "version": "8.22.0",
    "url": "https://curl.se/download/curl-8.22.0.tar.gz",
    "sha256": "d54dd598bf05927a726deb38df31c6a255ba83ff1de57c5d1464dac3ed8f44a1",
    "extra": ["--without-libpsl", "--without-brotli", "--without-zstd", "--without-nghttp2",
              "--without-libidn2", "--without-librtmp", "--without-libssh2"],
}


def _trial(trial_id: str, epoch: str, role: str, version: str, url: str, sha256: str,
           authority_id: str, release_id: str, measure_venue: str, configure_style: str,
           extra: list[str]) -> dict:
    return {
        "trial_id": trial_id, "epoch": epoch, "role": role,
        "consumer": "curl", "consumer_version": version,
        "source": {"url": url, "sha256": sha256,
                   "artifact": url.rsplit("/", 1)[-1]},
        "authority_id": authority_id, "release_id": release_id,
        "measure_venue": measure_venue, "configure_style": configure_style,
        "extra": extra,
    }


# The attempted consumer/authority pairs. Each has a `trial_id`, the epoch it is about, the role it
# plays, the consumer release it pins (URL + sha256) and the authority it is built against. The
# primary trials cover the five epochs; the maintained trials are the honest unavailability attempts
# (the current curl against the pre-3.0 authorities) that are recorded `not_run` with their measured
# configure reason.
TRIALS: list[dict] = [
    _trial("pre-1.0--curl-7.46.0", "pre-1.0", "primary", "7.46.0",
           "https://curl.se/download/curl-7.46.0.tar.gz",
           "df9e7d4883abdd2703ee758fe0e3ae74cec759b26ec2b70e5d1c40239eea06ec",
           "openssl-0.9.8zh-historical", "openssl-0.9.8zh", "historical", "with-ssl", []),
    _trial("1.0.x--curl-7.67.0", "1.0.x", "primary", "7.67.0",
           "https://curl.se/download/curl-7.67.0.tar.gz",
           "52af3361cf806330b88b4fe6f483b6844209d47ae196ac46da4de59bb361ab02",
           "openssl-1.0.2u-historical", "openssl-1.0.2u", "historical", "with-ssl", []),
    _trial("1.1.x--curl-8.3.0", "1.1.x", "primary", "8.3.0",
           "https://curl.se/download/curl-8.3.0.tar.gz",
           "d3a19aeea301085a56c32bc0f7d924a818a7893af253e41505d1e26d7db8e95a",
           "openssl-1.1.1w-historical", "openssl-1.1.1w", "historical", "with-openssl",
           ["--disable-mqtt"]),
    _trial("3.x--curl-7.79.0", "3.x", "primary", "7.79.0",
           "https://curl.se/download/curl-7.79.0.tar.gz",
           "aff0c7c4a526d7ecc429d2f96263a85fa73e709877054d593d8af3d136858074",
           "openssl-3.0.0-historical", "openssl-3.0.0", "historical", "with-openssl",
           ["--disable-mqtt"]),
    _trial("3.6+/4.x--curl-8.22.0", "3.6+/4.x", "primary", CURL_MAINTAINED["version"],
           CURL_MAINTAINED["url"], CURL_MAINTAINED["sha256"],
           "openssl-3.6.4-production", "openssl-3.6.4", "court", "with-openssl",
           CURL_MAINTAINED["extra"]),
    _trial("pre-1.0--curl-8.22.0-maintained", "pre-1.0", "maintained", CURL_MAINTAINED["version"],
           CURL_MAINTAINED["url"], CURL_MAINTAINED["sha256"],
           "openssl-0.9.8zh-historical", "openssl-0.9.8zh", "historical", "with-openssl",
           CURL_MAINTAINED["extra"]),
    _trial("1.0.x--curl-8.22.0-maintained", "1.0.x", "maintained", CURL_MAINTAINED["version"],
           CURL_MAINTAINED["url"], CURL_MAINTAINED["sha256"],
           "openssl-1.0.2u-historical", "openssl-1.0.2u", "historical", "with-openssl",
           CURL_MAINTAINED["extra"]),
    _trial("1.1.x--curl-8.22.0-maintained", "1.1.x", "maintained", CURL_MAINTAINED["version"],
           CURL_MAINTAINED["url"], CURL_MAINTAINED["sha256"],
           "openssl-1.1.1w-historical", "openssl-1.1.1w", "historical", "with-openssl",
           CURL_MAINTAINED["extra"]),
]


# --------------------------------------------------------------------------------------------
# the pure derivation: the whole record from the preserved raw outputs
# --------------------------------------------------------------------------------------------

def read_json(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"downstream-multitrack: {rel(path)} is absent")
    return json.loads(path.read_text(encoding="utf-8"))


def authority_nodes() -> dict[str, dict]:
    """The authority-node registry by authority id, the identity each record is bounded to."""
    body = read_json(AUTHORITY_NODES).get("body") or {}
    return {n["authority_id"]: n for n in body.get("nodes") or []}


def _search(pattern: str, text: str) -> str | None:
    m = re.search(pattern, text or "")
    return m.group(1) if m else None


def _int_or_none(text: str | None) -> int | None:
    try:
        return int(text) if text is not None else None
    except ValueError:
        return None


def _linked_from_ldd(ldd_output: str) -> list[str]:
    """The shared-object names `ldd` resolved, sorted (the linker name, not the path)."""
    names = []
    for line in (ldd_output or "").splitlines():
        m = re.match(r"\s*(\S+\.so\S*)\s+=>", line)
        if m:
            names.append(m.group(1))
    return sorted(set(names))


def _configure_reason(spec: dict, node: dict, raw: dict) -> str:
    """The measured reason a configure refused the authority, read from the raw transcript."""
    err = _search(r"configure: error: (.*)", raw.get("configure_log") or "")
    detail = err.strip() if err else "configure did not complete"
    return (f"{spec['consumer']} {spec['consumer_version']}'s configure refuses "
            f"{spec['release_id']} (OpenSSL {node.get('release_id', '').removeprefix('openssl-')}): "
            f"{detail}")


def derive_record(spec: dict, raw: dict, node: dict) -> dict:
    """One downstream record, a pure function of the trial's spec, the authority node and raw bytes.

    The outcome is read from the raw outputs, never typed: a configure that did not complete is
    `not_run` with the measured reason; a build that did not produce the tool is `failed`; a built
    consumer that did not complete its TLS workload is `failed`; and `passed` requires a genuine
    built artifact, `ldd` linking the authority's own shared objects (and not the candidate shell),
    a version banner naming the authority, and a completed HTTPS GET.
    """
    cfg_exit = raw.get("configure_exit")
    make_exit = raw.get("make_exit")
    version_output = raw.get("version_output") or ""
    ldd_output = raw.get("ldd_output") or ""
    run_transcript = raw.get("run_transcript") or ""

    linked = _linked_from_ldd(ldd_output)
    prefix_frag = f"forensics/authorities/prefix/{node['authority_id']}/"
    authority_libs = sorted(node.get("binary_hashes") or {})
    link_ok = (bool(authority_libs)
               and all(name in linked for name in authority_libs)
               and prefix_frag in ldd_output
               and "artifacts/phase2/install" not in ldd_output)
    openssl_token = _search(r"OpenSSL/(\S+)", version_output)
    version_ok = bool(openssl_token) and openssl_token == spec["release_id"].removeprefix("openssl-")
    version_line = (version_output.splitlines() or [""])[0]
    build_ok = cfg_exit == 0 and make_exit == 0 and bool(version_output.strip()) \
        and link_ok and version_ok

    http_code = _int_or_none(_search(r"HTTPCODE=(-?\d+)", run_transcript))
    run_exit = _int_or_none(_search(r"CURL_EXIT=(-?\d+)", run_transcript))
    tls = _search(r"SSL connection using (\S+)", run_transcript)
    run_ok = bool(build_ok and http_code == 200)

    if cfg_exit is None:
        outcome, reason = "not_run", "the authority prefix was not present in the measurement venue"
    elif cfg_exit != 0:
        outcome, reason = "not_run", _configure_reason(spec, node, raw)
    elif not build_ok:
        outcome, reason = ("failed",
                           "the consumer configured but did not produce a tool linked to the "
                           "authority")
    elif run_ok:
        outcome, reason = "passed", "built unmodified against the authority's headers and libraries "\
                                    "and run against its own s_server"
    else:
        outcome, reason = ("failed",
                           f"the consumer built but its TLS workload did not complete "
                           f"(http_code={http_code}, exit={run_exit})")

    build = {
        "ok": outcome == "passed",
        "configure_argv": raw.get("configure_argv") or [],
        "configure_exit": cfg_exit,
        "make_exit": make_exit,
        "linked": linked,
        "version_line": version_line,
    }
    run = {
        "ok": outcome == "passed",
        "server": "the authority's own bin/openssl s_server" if build_ok else None,
        "command": raw.get("run_command") if build_ok else None,
        "http_code": http_code if build_ok else None,
        "tls": tls if build_ok else None,
        "exit_code": run_exit if build_ok else None,
    }
    if outcome == "passed":
        observation = (f"{spec['consumer']} {spec['consumer_version']} linked OpenSSL/{openssl_token} "
                       f"from {node['authority_id']} and completed a {tls or 'TLS'} HTTPS GET of the "
                       f"authority's own s_server (HTTP {http_code}).")
    elif outcome == "not_run":
        observation = f"not run: {reason}"
    else:
        observation = ""

    return {
        "trial_id": spec["trial_id"],
        "epoch": spec["epoch"],
        "role": spec["role"],
        "consumer": spec["consumer"],
        "consumer_version": spec["consumer_version"],
        "source": dict(spec["source"]),
        "authority_id": node["authority_id"],
        "release_id": node["release_id"],
        "authority": {
            "authority_id": node["authority_id"],
            "release_id": node["release_id"],
            "build_profile": node["build_profile"],
            "platform": node["platform"],
            "arch": node["arch"],
            "venue": (node.get("build_environment") or {}).get("venue"),
            "chain": (node.get("build_environment") or {}).get("chain")
                     or (node.get("build_environment") or {}).get("base"),
        },
        "outcome": outcome,
        "build": build,
        "run": run,
        "observation": observation,
        "reason": reason,
        "evidence": [f"forensics/multitrack/downstream-multitrack.json#raw/{spec['trial_id']}"],
        "raw": raw,
    }


def _epoch_rows(records: list[dict]) -> list[dict]:
    """One row per major epoch, read from the passed records (never typed)."""
    rows = []
    for name in MAJOR_EPOCHS:
        members = sorted((r for r in records if r["epoch"] == name), key=lambda r: r["trial_id"])
        primary = [r for r in members if r["role"] == "primary"]
        rows.append({
            "epoch": name,
            "covered": len(primary) == 1,
            "records": [r["trial_id"] for r in members],
            "authority_id": primary[0]["authority_id"] if len(primary) == 1 else None,
            "release_id": primary[0]["release_id"] if len(primary) == 1 else None,
            "consumer": primary[0]["consumer"] if len(primary) == 1 else None,
            "consumer_version": primary[0]["consumer_version"] if len(primary) == 1 else None,
        })
    return rows


def counts_of(records: list[dict], not_run: list[dict], failed: list[dict],
             epochs: list[dict]) -> dict:
    """The body counts, recomputed from the records (never read from the body)."""
    return {
        "trials": len(records) + len(not_run) + len(failed),
        "passed": len(records),
        "not_run": len(not_run),
        "failed": len(failed),
        "epochs": len(MAJOR_EPOCHS),
        "epochs_covered": sum(1 for e in epochs if e["covered"]),
        "consumers": sorted({r["consumer"] for r in records + not_run + failed}),
        "consumer_versions": sorted({f"{r['consumer']}-{r['consumer_version']}"
                                     for r in records + not_run + failed}),
        "authorities": sorted({r["authority_id"] for r in records + not_run + failed}),
    }


def body_hash(records: list[dict], not_run: list[dict], failed: list[dict],
              epochs: list[dict]) -> str:
    """The body's content hash, a function of the committed records and their coverage."""
    return content_hash({"records": records, "not_run": not_run, "failed": failed, "epochs": epochs})


def derive_body(raw_by_id: dict[str, dict]) -> dict:
    """The whole body from the raw outputs: pure, so the default run reproduces it exactly.

    A trial with no raw output is omitted (an intermediate state while the two venues land the
    record between them); the court requires every major epoch covered, so a partial record cannot
    pass.
    """
    nodes = authority_nodes()
    records: list[dict] = []
    not_run: list[dict] = []
    failed: list[dict] = []
    for spec in TRIALS:
        raw = raw_by_id.get(spec["trial_id"])
        if raw is None:
            continue
        node = nodes.get(spec["authority_id"])
        if node is None:
            raise SystemExit(f"downstream-multitrack: {spec['authority_id']} is not an authority "
                             f"node, so trial {spec['trial_id']} has no authority to be about")
        rec = derive_record(spec, raw, node)
        if rec["outcome"] == "passed":
            records.append(rec)
        elif rec["outcome"] == "not_run":
            not_run.append(rec)
        else:
            failed.append(rec)
    records.sort(key=lambda r: (r["epoch"], r["trial_id"]))
    not_run.sort(key=lambda r: (r["epoch"], r["trial_id"]))
    failed.sort(key=lambda r: (r["epoch"], r["trial_id"]))
    epochs = _epoch_rows(records)
    counts = counts_of(records, not_run, failed, epochs)
    return {
        "rule": (
            "one record per major ABI/architecture epoch (pre-1.0, 1.0.x, 1.1.x, 3.x, 3.6+/4.x), "
            "each an unmodified real downstream consumer built against that epoch's built "
            "representative authority and exercised against the authority's own s_server; the "
            "outcome, the build result, the linkage and the workload observation are read from the "
            "raw outputs the record carries, never typed. A pair whose consumer cannot honestly be "
            "built is recorded `not_run` with its measured reason and its raw configure evidence, "
            "and is never counted as passing"
        ),
        "scope": (
            "unmodified upstream curl releases: a primary consumer contemporary with each epoch "
            "(7.46.0 for pre-1.0, 7.67.0 for 1.0.x, 8.3.0 for 1.1.x, 7.79.0 for 3.x, 8.22.0 for "
            "3.6+/4.x) and the maintained consumer (8.22.0) attempted against the pre-3.0 "
            "authorities. No downstream source is patched; only the build flags differ, and the "
            "linked authority is proven by `ldd` naming the authority's prefix and its own "
            "libssl/libcrypto sonames"
        ),
        "epochs": epochs,
        "records": records,
        "not_run": not_run,
        "failed": failed,
        "counts": counts,
        "content_hash": body_hash(records, not_run, failed, epochs),
        "boundary": (
            "the court is bounded to the linux/x86_64 authorities the historical and forensic "
            "venues build, and to the curl releases named here; a pass is a real consumer consuming "
            "a named authority on one platform/profile and is not a compatibility claim about any "
            "other platform, profile or release. The five epochs are covered by their primary "
            "consumers; the maintained consumer's pre-3.0 pairs are recorded not_run, so a skipped "
            "build is never read as a pass"
        ),
    }


def rederive_body(body: dict) -> dict:
    """Re-derive a committed body from the raw outputs it carries (the default, pure run)."""
    raw_by_id: dict[str, dict] = {}
    for r in (body.get("records") or []) + (body.get("not_run") or []) + (body.get("failed") or []):
        raw = r.get("raw")
        if raw is None:
            raise SystemExit(f"downstream-multitrack: record {r.get('trial_id')!r} carries no raw "
                             f"outputs; run --measure in the venue first")
        raw_by_id[r["trial_id"]] = raw
    return derive_body(raw_by_id)


def _inputs() -> list[InputRef]:
    return [
        InputRef(name="phase-23-plan", path=PLAN),
        InputRef(name="authority-nodes", path=AUTHORITY_NODES),
        InputRef(name="historical-build-receipts", path=HIST_RECEIPTS),
        InputRef(name="build-records", path=BUILD_RECORDS),
        InputRef(name="phase17-downstream-corpus", path=PHASE17_CORPUS),
    ]


def _write(body: dict) -> None:
    doc = envelope("downstream-multitrack", GENERATOR, _inputs(), body,
                   authority=PRODUCTION_AUTHORITY)
    write_json(OUT, doc)


# --------------------------------------------------------------------------------------------
# the measurement: build and run each consumer against its authority, in a venue container only
# --------------------------------------------------------------------------------------------

def current_venue() -> str:
    if HISTORICAL_MARKER.is_file():
        return "historical"
    if DOCKER_MARKER.is_file():
        return "court"
    return "host"


def _sh(argv: list[str], *, cwd: Path, env: dict, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run([str(a) for a in argv], cwd=str(cwd), env=env, timeout=timeout,
                          capture_output=True, text=True, check=False)


def _combined(proc: subprocess.CompletedProcess) -> str:
    return (proc.stdout or "") + (proc.stderr or "")


def _fetch(spec: dict) -> Path:
    dl = SCRATCH / "dl"
    dl.mkdir(parents=True, exist_ok=True)
    dest = dl / spec["source"]["artifact"]
    if not dest.is_file():
        proc = subprocess.run(["curl", "-fsSL", "-o", str(dest), spec["source"]["url"]],
                              capture_output=True, text=True, check=False, timeout=300)
        if proc.returncode != 0:
            raise SystemExit(f"downstream-multitrack: could not fetch {spec['source']['url']}: "
                             f"{proc.stderr}")
    if sha256_file(dest) != spec["source"]["sha256"]:
        raise SystemExit(f"downstream-multitrack: sha256 mismatch for {dest.name}")
    return dest


def _build_and_run(spec: dict) -> dict:
    node = authority_nodes().get(spec["authority_id"])
    if node is None:
        raise SystemExit(f"downstream-multitrack: {spec['authority_id']} is not an authority node")
    authority = resolve_authority(spec["authority_id"])
    prefix = authority.prefix
    if not (prefix / "include").is_dir():
        raise SystemExit(f"downstream-multitrack: the authority prefix {rel(prefix)} is absent; "
                         f"build the authority before measuring")
    tarball = _fetch(spec)

    src = SCRATCH / "src" / spec["trial_id"]
    if src.exists():
        shutil.rmtree(src)
    src.mkdir(parents=True)
    subprocess.run(["tar", "xf", str(tarball), "-C", str(src), "--strip-components=1"],
                   check=True)

    env = dict(os.environ, LC_ALL="C.UTF-8", LANG="C.UTF-8",
               CPPFLAGS=f"-I{prefix}/include",
               LDFLAGS=f"-L{prefix}/lib -Wl,-rpath,{prefix}/lib")
    style = "--with-ssl=" if spec["configure_style"] == "with-ssl" else "--with-openssl="
    configure_argv = ["./configure", f"{style}{prefix}", "--prefix", str(SCRATCH / "install"),
                      *COMMON_CONFIGURE, *spec["extra"]]

    cfg = _sh(configure_argv, cwd=src, env=env, timeout=900)
    raw: dict = {
        "configure_argv": configure_argv,
        "configure_exit": cfg.returncode,
        "configure_log": _combined(cfg)[-40000:],
    }
    if cfg.returncode != 0:
        return raw

    make = _sh(["make", f"-j{os.cpu_count() or 1}"], cwd=src, env=env, timeout=1800)
    raw["make_exit"] = make.returncode
    raw["make_log_tail"] = _combined(make)[-4000:]
    if make.returncode != 0:
        return raw

    curl = src / "src" / "curl"
    raw["version_output"] = _combined(_sh([curl, "-V"], cwd=src, env=env, timeout=60))
    raw["ldd_output"] = _combined(_sh(["ldd", curl], cwd=src, env=env, timeout=60))
    raw.update(_tls_run(spec, prefix, curl, env))
    return raw


def _tls_run(spec: dict, prefix: Path, curl: Path, env: dict) -> dict:
    """Start the authority's own `s_server` and issue one real TLS request with the built curl."""
    work = SCRATCH / "run" / spec["trial_id"]
    work.mkdir(parents=True, exist_ok=True)
    cert, key = work / "cert.pem", work / "key.pem"
    # The environment differs by authority era, because the same setting means opposite things twice:
    # a 3.x authority has no shipped `openssl.cnf` and so needs `OPENSSL_CONF=/dev/null` (and its
    # module dir) to generate a certificate, while a pre-3.0 `req -x509` needs the *default* config
    # and fails its self-signing step against `/dev/null`. So the override is applied only to the
    # 3.x-plus authorities.
    major = int(str(spec["release_id"]).removeprefix("openssl-").split(".", 1)[0])
    ssl_env = dict(env, LD_LIBRARY_PATH=str(prefix / "lib"))
    if major >= 3:
        ssl_env["OPENSSL_CONF"] = "/dev/null"
        ssl_env["OPENSSL_MODULES"] = str(prefix / "lib" / "ossl-modules")
    openssl_bin = prefix / "bin" / "openssl"
    req = _sh([openssl_bin, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
               "-out", cert, "-days", "1", "-subj", "/CN=localhost"],
              cwd=work, env=ssl_env, timeout=120)
    if req.returncode != 0 or not cert.is_file():
        return {"run_command": None, "run_transcript": "", "run_exit": None,
                "tls_server_log_tail": None,
                "cert_error": _combined(req)[-2000:]}

    port = 9600 + [t["trial_id"] for t in TRIALS].index(spec["trial_id"])
    server_log = work / "s_server.log"
    server = subprocess.Popen(
        [str(openssl_bin), "s_server", "-accept", str(port), "-cert", str(cert), "-key", str(key),
         "-www"], cwd=str(work), env=ssl_env,
        stdout=open(server_log, "w"), stderr=subprocess.STDOUT)
    time.sleep(2)
    command = (f"curl -skv -m 15 -o /dev/null -w '\\nHTTPCODE=%{{http_code}}\\n' "
               f"https://127.0.0.1:{port}/")
    run = subprocess.run(
        [str(curl), "-skv", "-m", "15", "-o", "/dev/null", "-w", "\nHTTPCODE=%{http_code}\n",
         f"https://127.0.0.1:{port}/"], cwd=str(work), env=ssl_env,
        capture_output=True, text=True, check=False, timeout=60)
    try:
        server.terminate()
        server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        server.kill()
    time.sleep(0.2)
    tail = ""
    try:
        tail = server_log.read_text(encoding="utf-8", errors="replace")[-2000:]
    except OSError:
        pass
    return {
        "run_command": command,
        "run_transcript": _combined(run) + f"\nCURL_EXIT={run.returncode}\n",
        "run_exit": run.returncode,
        "tls_server_log_tail": tail,
    }


def measure() -> int:
    venue = current_venue()
    if venue == "host":
        raise SystemExit(
            "downstream-multitrack: --measure builds and runs real consumers against authority "
            "prefixes, so it refuses the host; run it in the venue that builds that authority "
            "(`bash docker/openssl-rs-historical.sh exec python3 "
            "forensics/tools/downstream_multitrack.py --measure` and "
            "`bash docker/openssl-rs-court.sh exec python3 "
            "forensics/tools/downstream_multitrack.py --measure`)"
        )
    raw_by_id: dict[str, dict] = {}
    if OUT.is_file():
        committed = read_json(OUT).get("body") or {}
        for r in (committed.get("records") or []) + (committed.get("not_run") or []) \
                + (committed.get("failed") or []):
            if r.get("raw") is not None:
                raw_by_id[r["trial_id"]] = r["raw"]
    measured = 0
    for spec in TRIALS:
        if spec["measure_venue"] != venue:
            continue
        print(f"[downstream-multitrack] measuring {spec['trial_id']} against {spec['authority_id']}")
        raw_by_id[spec["trial_id"]] = _build_and_run(spec)
        measured += 1
    body = derive_body(raw_by_id)
    _write(body)
    print(f"[downstream-multitrack] venue={venue}: measured {measured} trial(s); "
          f"{body['counts']['passed']} passing, {body['counts']['not_run']} not_run, "
          f"{body['counts']['epochs_covered']}/{body['counts']['epochs']} epoch(s) covered")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="build and run the consumer trials of this venue against the built "
                         "authority prefixes, then write the artefact")
    args = ap.parse_args(argv)
    if args.measure:
        return measure()
    if not OUT.is_file():
        raise SystemExit(f"downstream-multitrack: {rel(OUT)} is absent; run --measure in both "
                         f"venues first")
    body = rederive_body(read_json(OUT).get("body") or {})
    _write(body)
    print(f"[downstream-multitrack] re-derived {body['counts']['passed']} passing, "
          f"{body['counts']['not_run']} not_run, "
          f"{body['counts']['epochs_covered']}/{body['counts']['epochs']} epoch(s) covered")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
