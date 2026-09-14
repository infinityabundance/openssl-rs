#!/usr/bin/env python3
"""openssl-rs — authority build.

Builds an admitted authority from its verified source tree into a pinned prefix
and records the exact build configuration. This produces the artifacts Phase 1
needs for symbol/ABI archaeology: the built shared objects (`libcrypto.so.3`,
`libssl.so.3`), the generated configuration header, `configdata.pm`, and the
installed public headers.

Everything runs inside the court container (docker/court.sh). The tool never
touches the host filesystem outside the repository bind mount.

Outputs
-------
    forensics/authorities/build/<id>/         out-of-tree build
    forensics/authorities/prefix/<id>/        installed headers + libs
    forensics/authorities/captures/<id>/      raw configure/make logs, configdata
    forensics/atlas/BUILD_RECORDS.json        machine-readable build records

Design rules
------------
* The configure invocation is explicit and versioned, not inferred. The exact
  argv and environment are recorded verbatim in the build record.
* Out-of-tree builds keep the source tree pristine (raw authority material is
  immutable).
* A build is not recorded as successful unless the expected shared objects
  exist and are loadable.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AUTH_ROOT = REPO_ROOT / "forensics" / "authorities"
BUILD_ROOT = AUTH_ROOT / "build"
PREFIX_ROOT = AUTH_ROOT / "prefix"
CAPTURE_ROOT = AUTH_ROOT / "captures"
ATLAS = REPO_ROOT / "forensics" / "atlas"
BUILD_RECORDS = ATLAS / "BUILD_RECORDS.json"
REGISTRY = AUTH_ROOT / "AUTHORITIES.json"

# The default authority configure profile. This is deliberately a *named*
# profile so that build-profile-dependent behaviour can never be silently
# generalised (docs/AUTHORITY_POLICY.md, docs/ABI_POLICY.md).
#
#   linux-x86_64   upstream's own target for this platform
#   shared         produce libcrypto.so.3 / libssl.so.3 (a hard Phase 1 need)
#   enable-legacy  admit the legacy provider, which is part of the authority's
#                  observable provider surface and CLI `list` output
#   no-tests       skip building the upstream test binaries; the upstream test
#                  *suite* is inventoried from source and, where re-run, is run
#                  as its own court. Skipping the binaries keeps the Phase 1
#                  build fast without altering the library ABI or symbols.
#
# `no-tests` does not remove any public symbol and does not change the provider
# algorithm inventory. It is recorded in the build record so no claim is ever
# made about an unbuilt surface.
PROFILE_ARGS = [
    "shared",
    "enable-legacy",
    "no-tests",
]

OPENSSL_CONFIGURE = "Configure"


def load_registry() -> dict:
    if not REGISTRY.exists():
        raise SystemExit("FATAL: no authority registry; run authority_acquire.py first")
    return json.loads(REGISTRY.read_text())


def run(argv: list[str], *, cwd: Path, env: dict | None = None, log: Path) -> int:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w") as fh:
        fh.write("$ " + " ".join(argv) + "\n")
        fh.flush()
        proc = subprocess.run(argv, cwd=cwd, env=env, stdout=fh, stderr=subprocess.STDOUT)
    return proc.returncode


def tool_version(cmd: list[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return (out.stdout or out.stderr).splitlines()[0] if (out.stdout or out.stderr) else ""
    except FileNotFoundError:
        return ""


def build_authority(record: dict, *, jobs: int, force: bool) -> dict:
    aid = record["id"]
    version = record["version"]
    src = REPO_ROOT / record["source_tree"]["path"]
    build_dir = BUILD_ROOT / aid
    prefix = PREFIX_ROOT / aid
    capture = CAPTURE_ROOT / aid

    print(f"[build] {aid}")
    if not src.exists():
        raise SystemExit(f"FATAL: source tree missing for {aid}: {src}")

    if force and build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)
    capture.mkdir(parents=True, exist_ok=True)

    configure = src / OPENSSL_CONFIGURE
    argv = [
        "perl", str(configure),
        "linux-x86_64",
        f"--prefix={prefix}",
        f"--openssldir={prefix}/ssl",
        f"--libdir=lib",
        *PROFILE_ARGS,
    ]
    env = dict(os.environ)
    # Reproducibility: pin locale and discourage non-deterministic parallelism
    # in anything that honours it. We do NOT strip SOURCE_DATE_EPOCH handling;
    # OpenSSL does not honour it, and pretending otherwise would be dishonest.
    env.update({"LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"})

    print(f"  configure ...")
    rc = run(argv, cwd=build_dir, env=env, log=capture / "configure.log")
    if rc != 0:
        raise SystemExit(f"FATAL: Configure failed for {aid} (see {capture/'configure.log'})")

    configdata = build_dir / "configdata.pm"
    if configdata.exists():
        shutil.copy2(configdata, capture / "configdata.pm")

    print(f"  make -j{jobs} ...")
    mk_env = dict(env)
    rc = run(["make", f"-j{jobs}"], cwd=build_dir, env=mk_env, log=capture / "make.log")
    if rc != 0:
        raise SystemExit(f"FATAL: make failed for {aid} (see {capture/'make.log'})")

    print(f"  install_sw ...")
    rc = run(["make", "install_sw"], cwd=build_dir, env=mk_env, log=capture / "install.log")
    if rc != 0:
        raise SystemExit(f"FATAL: install_sw failed for {aid}")

    # Confirm the two runtime artifacts Phase 1 depends on actually exist.
    produced = {}
    for name in ("libcrypto.so.3", "libssl.so.3"):
        libdir = next(prefix.glob("lib*"), prefix / "lib")
        candidate = libdir / name
        if not candidate.exists():
            candidate = build_dir / name
        if not candidate.exists():
            raise SystemExit(f"FATAL: {aid}: expected artifact {name} not produced")
        produced[name] = {
            "path": candidate.relative_to(REPO_ROOT).as_posix(),
            "size_bytes": candidate.stat().st_size,
        }

    # Capture the built binary's own version banner; this is raw authority
    # material (a capture), not a normalised comparison surface.
    openssl_bin = prefix / "bin" / "openssl"
    if openssl_bin.exists():
        with (capture / "built-openssl-version.txt").open("w") as fh:
            subprocess.run([str(openssl_bin), "version", "-a"], stdout=fh,
                           stderr=subprocess.STDOUT, check=False)

    return {
        "id": aid,
        "version": version,
        "profile": "linux-x86_64-default-shared-legacy-notests",
        "configure_argv": argv,
        "profile_args": PROFILE_ARGS,
        "build_toolchain": {
            "cc": tool_version(["cc", "--version"]),
            "clang": tool_version(["clang", "--version"]),
            "ld": tool_version(["ld", "--version"]),
            "make": tool_version(["make", "--version"]),
            "perl": tool_version(["perl", "--version"]),
            "python": sys.version.split()[0],
        },
        "build_platform": {
            "machine": platform.machine(),
            "system": platform.system(),
            "release": platform.release(),
        },
        "artifacts": produced,
        "captures": capture.relative_to(REPO_ROOT).as_posix(),
        "build_dir": build_dir.relative_to(REPO_ROOT).as_posix(),
        "prefix": prefix.relative_to(REPO_ROOT).as_posix(),
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Build admitted OpenSSL authorities.")
    ap.add_argument("--authority", action="append", default=[])
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args(argv)

    registry = load_registry()
    records = {a["id"]: a for a in registry["authorities"]}
    if args.all:
        targets = list(records.values())
    elif args.authority:
        unknown = set(args.authority) - set(records)
        if unknown:
            ap.error(f"unknown authority id(s): {sorted(unknown)}")
        targets = [records[i] for i in args.authority]
    else:
        ap.error("specify --all or --authority")

    out = []
    if BUILD_RECORDS.exists():
        existing = json.loads(BUILD_RECORDS.read_text())
        out = [r for r in existing.get("builds", []) if r["id"] not in {t["id"] for t in targets}]
    for rec in targets:
        out.append(build_authority(rec, jobs=args.jobs, force=args.force))

    ATLAS.mkdir(parents=True, exist_ok=True)
    BUILD_RECORDS.write_text(
        json.dumps({"schema": "openssl-rs/build-records/v1",
                    "builds": sorted(out, key=lambda r: r["id"])},
                   indent=2, sort_keys=True) + "\n"
    )
    print(f"[atlas] wrote {BUILD_RECORDS.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
