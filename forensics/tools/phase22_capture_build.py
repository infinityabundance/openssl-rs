#!/usr/bin/env python3
"""openssl-rs -- Phase 22.1 raw build-command capture.

Re-runs the admitted production authority's own build with a transparent compiler
wrapper in `CC`, so the *exact* compiler invocations the build makes are recorded
rather than reconstructed.

Why a capture and not a reconstruction
---------------------------------------
`docs/PHASE-22-SUBPHASES.md` section 6 is explicit: 22.1 "must capture the compiler
invocations the authority build actually made. It may not reconstruct flags from
`Configure`." A compilation database synthesised from the `Configure` profile is a
guess about what the build would do; the wrapper records what it did. The two
differ wherever the generated `Makefile` adds a per-object flag -- the x86_64
perlasm objects carry `-DAES_ASM -DBSHA...` that no top-level profile mentions --
so a reconstructed database would be silently wrong exactly where Phase 22's later
planes (22.3's AST, 22.4's conditional graph) lean on it.

The profile is `forensics/tools/authority_build.py`'s, verbatim: target
`linux-x86_64`, `--prefix=...`, `--openssldir=.../ssl`, `--libdir=lib`, then
`shared enable-legacy no-tests` (`authority_build.py` lines 66-70 and 116-123), with
`LC_ALL=C.UTF-8` / `LANG=C.UTF-8` (line 128). The one deliberate addition is
`CC=<wrapper>`: the authority's own `Configure`-baked compiler is `gcc` (read from
the pinned `configdata.pm`), and `linux-x86_64` is a GCC target, so the wrapper is
transparent -- it `exec`s the real compiler unchanged and only appends the argv to
a log first.

The pinned authority is immutable evidence. This tool therefore builds in a
scratch directory (`/tmp/phase22-recapture` by default, outside the repository) and
never invokes `make` in `forensics/authorities/build/openssl-3.6.4-production`,
whose `Makefile`/`configdata.pm` a re-run there would rewrite.

Output
------
    forensics/atlas/phase22/raw/compile-commands.jsonl

One JSON object per line: a leading `record="configure"` header carrying the exact
`configure` argv, then one `record="compile"` line per compiler invocation that
carries `-c`. Each compile line has `argv` (the full argument vector, minus the
compiler's own argv[0]), `directory` (the build directory the command ran in),
`source` (the `-c` input), `output` (the `-o` value) and `wrapper_version`.

Everything runs inside the court container; the repository is bind-mounted at
`/work`. `forensics/tools/phase22_build_commands.py` normalises this raw log.

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

REPO_ROOT = Path(__file__).resolve().parents[2]

SRC_REL = "forensics/authorities/src/openssl-3.6.4"
CAPTURE_REL = "forensics/atlas/phase22/raw/compile-commands.jsonl"
BUILD_DIR_REL = "forensics/authorities/build/openssl-3.6.4-production"

SCRATCH_DEFAULT = "/tmp/phase22-recapture"
WRAPPER_VERSION = "phase22-cc-wrapper/1"

# authority_build.py's profile, restated here so this tool is a standalone record of it.
TARGET = "linux-x86_64"
PROFILE_ARGS = ["shared", "enable-legacy", "no-tests"]

# The transparent wrapper. It reads `PHASE22_CC_LOG`; when that is unset it only
# `exec`s the real compiler, so the `Configure`-time feature probes are not logged
# and the raw log holds exactly the build's translation-unit invocations. It never
# changes argv, environment or exit status of the compiler it wraps.
WRAPPER_SOURCE = '''#!/usr/bin/env python3
"""Phase 22.1 transparent compiler wrapper (generated; do not edit by hand).

Appends one JSON object per `-c` invocation to $PHASE22_CC_LOG and then `exec`s
the real compiler ($PHASE22_REAL_CC, default "gcc") with argv unchanged.
"""
import json
import os
import sys

WRAPPER_VERSION = "''' + WRAPPER_VERSION + '''"
_SOURCE_SUFFIXES = (".c", ".s", ".S", ".cc", ".cpp", ".cxx", ".m")


def _source_and_output(argv):
    source = None
    output = None
    i = 0
    n = len(argv)
    while i < n:
        a = argv[i]
        if a == "-o" and i + 1 < n:
            output = argv[i + 1]
            i += 2
            continue
        if a == "-MF" and i + 1 < n:  # a dependency file, never the source
            i += 2
            continue
        if not a.startswith("-") and a.endswith(_SOURCE_SUFFIXES):
            source = a
        i += 1
    return source, output


def main():
    argv = sys.argv[1:]
    log = os.environ.get("PHASE22_CC_LOG")
    real = os.environ.get("PHASE22_REAL_CC") or "gcc"
    if log and "-c" in argv:
        source, output = _source_and_output(argv)
        record = {
            "record": "compile",
            "argv": argv,
            "directory": os.getcwd(),
            "source": source,
            "output": output,
            "wrapper_version": WRAPPER_VERSION,
        }
        line = (json.dumps(record, ensure_ascii=False) + "\\n").encode("utf-8")
        fd = os.open(log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            os.write(fd, line)
        finally:
            os.close(fd)
    os.execvp(real, [real] + argv)


if __name__ == "__main__":
    main()
'''


def read_configdata_cc(path: Path) -> str:
    """The authority's own compiler, from its pinned `configdata.pm` (`"CC" => "..."`)."""
    if not path.is_file():
        return "gcc"
    m = re.search(r'^\s*"CC"\s*=>\s*"([^"]*)"', path.read_text(encoding="utf-8", errors="replace"),
                  re.MULTILINE)
    return m.group(1) if m and m.group(1) else "gcc"


def configure_argv(configure: Path, scratch: Path, wrapper: Path) -> list[str]:
    prefix = scratch / "prefix"
    return [
        "perl", str(configure), TARGET,
        f"--prefix={prefix}",
        f"--openssldir={prefix}/ssl",
        "--libdir=lib",
        f"CC={wrapper}",
        *PROFILE_ARGS,
    ]


def run(argv: list[str], *, cwd: Path, env: dict, log: Path, timeout: int) -> int:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w") as fh:
        fh.write("$ " + " ".join(argv) + "\n")
        fh.flush()
        try:
            proc = subprocess.run(argv, cwd=cwd, env=env, stdout=fh,
                                  stderr=subprocess.STDOUT, timeout=timeout)
        except subprocess.TimeoutExpired:
            fh.write(f"\n[phase22] TIMEOUT after {timeout}s\n")
            return 124
    return proc.returncode


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scratch", default=SCRATCH_DEFAULT,
                    help="out-of-tree build directory (default: %(default)s)")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--target", default=None,
                    help="build only this make target (a feasibility/subset run)")
    ap.add_argument("--configure-timeout", type=int, default=900)
    ap.add_argument("--make-timeout", type=int, default=1800)
    ap.add_argument("--keep", action="store_true",
                    help="reuse an existing scratch directory instead of wiping it")
    args = ap.parse_args(argv)

    src = REPO_ROOT / SRC_REL
    configure = src / "Configure"
    if not configure.is_file():
        print(f"[phase22-capture] FATAL: no Configure at {configure}", file=sys.stderr)
        return 2

    build_dir = REPO_ROOT / BUILD_DIR_REL
    producer = read_configdata_cc(build_dir / "configdata.pm")
    real_cc = shutil.which(producer) or producer

    scratch = Path(args.scratch)
    if not args.keep and scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True, exist_ok=True)

    wrapper = scratch / "cc-logger"
    wrapper.write_text(WRAPPER_SOURCE, encoding="utf-8")
    wrapper.chmod(0o755)

    raw = REPO_ROOT / CAPTURE_REL
    raw.parent.mkdir(parents=True, exist_ok=True)

    env = dict(os.environ)
    env.update({"LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"})

    cargv = configure_argv(configure, scratch, wrapper)
    print(f"[phase22-capture] scratch={scratch}")
    print(f"[phase22-capture] producer={producer!r} real_cc={real_cc!r}")
    print("[phase22-capture] configure ...")
    rc = run(cargv, cwd=scratch, env=env, log=scratch / "configure.log",
             timeout=args.configure_timeout)
    if rc != 0:
        print(f"[phase22-capture] FATAL: Configure failed (rc={rc}); "
              f"see {scratch / 'configure.log'}", file=sys.stderr)
        return 1

    # The raw log starts with the exact configure argv, then the wrapper appends compiles.
    with raw.open("w") as fh:
        fh.write(json.dumps({
            "record": "configure",
            "argv": cargv,
            "directory": str(scratch),
            "producer": producer,
            "wrapper_version": WRAPPER_VERSION,
        }, ensure_ascii=False) + "\n")

    mk_env = dict(env)
    mk_env["PHASE22_CC_LOG"] = str(raw)
    mk_env["PHASE22_REAL_CC"] = real_cc

    mk_argv = ["make", f"-j{args.jobs}"] + ([args.target] if args.target else [])
    print(f"[phase22-capture] {' '.join(mk_argv)} ...")
    started = time.monotonic()
    rc = run(mk_argv, cwd=scratch, env=mk_env, log=scratch / "make.log",
             timeout=args.make_timeout)
    elapsed = time.monotonic() - started
    if rc != 0:
        print(f"[phase22-capture] FATAL: make failed (rc={rc}) after {elapsed:.0f}s; "
              f"see {scratch / 'make.log'}", file=sys.stderr)
        return 1

    compiles = sum(1 for line in raw.read_text(encoding="utf-8").splitlines()
                   if '"record": "compile"' in line)
    print(f"[phase22-capture] make finished in {elapsed:.0f}s; "
          f"{compiles} compile invocation(s) captured")
    print(f"[phase22-capture] -> {raw}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
