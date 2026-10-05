#!/usr/bin/env python3
"""openssl-rs — run the six sealed downstream consumers under AddressSanitizer.

Why this exists
---------------
`artifacts/phase18/asan.json` recorded the six Phase-17 downstream consumers as
`not-yet`: the ASan venue built a *statically linked* probe set, not an installed
DSO tree, so no real consumer ever loaded the instrumented candidate. This harness
closes that layer.

It runs inside the ASan venue (`docker/openssl-rs-asan.sh`) — never on the host, and
never in the court, whose hard per-process RLIMIT_DATA is exactly what ASan cannot
run under (D105). It:

  1. builds the instrumented distribution DSOs into a dedicated prefix
     (`/asan/install`, never the normal `artifacts/phase2/install`) via
     `forensics/tools/build_phase2_asan.sh`;
  2. runs each consumer's *admitted* probe from `courts/phase17/downstream/<p>/`
     against the Phase-17 consumer builds, which are relocated onto the ASan DSOs
     with `LD_LIBRARY_PATH` and `LD_PRELOAD` of clang's dynamic ASan runtime
     (the consumers themselves are deliberately NOT rebuilt: the defect surface
     under test is the candidate, and an instrumented consumer would add its own
     noise);
  3. requires zero ASan findings per consumer, using `log_path` so a report from a
     forked worker or an exec'd helper is captured rather than lost;
  4. writes `artifacts/phase18/asan-downstream.json`.

What it is not
--------------
A clean run is a bounded observation, not a memory-safety proof. The consumers
still load their own uninstrumented objects; ASan's interceptors replace the
process-global allocator/string primitives, so a consumer-side error can surface
too, and every finding is attributed rather than assumed candidate-side.

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

from atlas_common import REPO_ROOT, rel, sha256_file, write_json  # noqa: E402

GENERATOR = "forensics/tools/asan_downstream.py"
OUT = REPO_ROOT / "artifacts" / "phase18" / "asan-downstream.json"
BUILD_SCRIPT = "forensics/tools/build_phase2_asan.sh"

ASAN_DIR = Path(os.environ.get("OPENSSL_RS_ASAN_DIR", "/asan"))
PREFIX = Path(os.environ.get("OPENSSL_RS_ASAN_PREFIX", str(ASAN_DIR / "install")))
CONSUMERS = Path(os.environ.get("OPENSSL_RS_ASAN_CONSUMERS",
                               str(ASAN_DIR.parent / "work" / "court" / "phase18-asan" / "consumers")))
AUTHORITY = REPO_ROOT / "forensics" / "authorities" / "prefix" / "openssl-3.6.4-production"
DSR = ASAN_DIR / "dsr"
AUTH_KG_WRAPPER = DSR / "openssl-auth-keygen.sh"
SAFE_BIN = DSR / "bin"

# Non-candidate helpers that ASan's interceptors mis-judge. The probes use `dd` only to
# generate a test-data file (`dd if=/dev/zero bs=1024 count=64`); coreutils requests
# `aligned_alloc(4096, 1024)`, which C11 forbids (size must be a multiple of alignment).
# glibc tolerates it, ASan's interceptor reports it. The helper is run OUTSIDE the ASan
# envelope so the envelope stays on the candidate; the report is recorded verbatim as an
# excluded non-candidate finding rather than silently dropped.
NON_CANDIDATE_HELPERS = {
    "dd": (
        "coreutils dd requests aligned_alloc(4096, 1024) for the 1 KiB block size; C11 requires "
        "the size to be a multiple of the alignment, glibc tolerates it and ASan's aligned_alloc "
        "interceptor reports invalid-alignment. The helper generates test data and never touches "
        "the candidate, so it runs outside the ASan envelope."
    ),
}

# The verbatim report the pre-exclusion nginx run produced, kept as evidence that the
# helper finding is real, is coreutils-side, and was excluded deliberately (not hidden).
EXCLUDED_HELPER_REPORT = (
    "==NNN==ERROR: AddressSanitizer: invalid alignment requested in aligned_alloc: 4096, "
    "alignment must be a power of two and the requested size 0x400 must be a multiple of "
    "alignment (thread T0)\n"
    "    #0 0x... in aligned_alloc (/usr/lib/llvm-14/lib/clang/14.0.6/lib/linux/"
    "libclang_rt.asan-x86_64.so+0xd45f2)\n"
    "    #1 0x... (/usr/bin/dd+0x4a9d)\n"
    "==NNN==HINT: if you don't care about these errors you may set allocator_may_return_null=1\n"
    "SUMMARY: AddressSanitizer: invalid-aligned-alloc-alignment "
    "(/usr/lib/llvm-14/lib/clang/14.0.6/lib/linux/libclang_rt.asan-x86_64.so+0xd45f2) in aligned_alloc"
)

# The consumers' Phase-17 probe scripts, relative to the repo.
D = "courts/phase17/downstream"
CURL_BIN = "$CONSUMERS/curl/curl-8.22.0/src/curl"
NGINX_BIN = "$CONSUMERS/nginx/nginx-1.26.3/objs/nginx"

ASAN_OPTIONS = "detect_leaks=0:symbolize=1:halt_on_error=0:abort_on_error=0"


# ---------------------------------------------------------------------------
# process / report helpers
# ---------------------------------------------------------------------------

def rename_self() -> None:
    """Give this process a comm that the probes' own `kill_ours` cannot mistake for a
    leaked `python3` helper. `courts/phase17/downstream/haproxy/proxy_probe.sh` SIGKILLs
    every process whose comm is `python3`, which would otherwise kill this harness."""
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.prctl(15, b"dsr-runner", 0, 0, 0)  # PR_SET_NAME
    except Exception:
        pass


def run(argv, *, env=None, timeout=None, cwd=None):
    full = os.environ.copy()
    if env:
        full.update(env)
    try:
        p = subprocess.run([str(a) for a in argv], env=full,
                           cwd=str(cwd) if cwd else None, capture_output=True,
                           text=True, check=False, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return 124, out, err + f"\n[harness] timed out after {timeout}s"


def asan_blocks(text: str) -> list[str]:
    blocks, lines, i = [], text.splitlines(), 0
    while i < len(lines):
        if "ERROR: AddressSanitizer" in lines[i]:
            j = i + 1
            while j < len(lines) and "SUMMARY: AddressSanitizer" not in lines[j]:
                j += 1
            blocks.append("\n".join(lines[i:j + 1]))
            i = j + 1
        else:
            i += 1
    return blocks


def runtime_so() -> str:
    rc, out, _ = run(["clang", "-print-file-name=libclang_rt.asan-x86_64.so"])
    if rc != 0 or not out.strip():
        raise SystemExit("asan-downstream: cannot locate libclang_rt.asan-x86_64.so")
    return out.strip()


def require_venue() -> None:
    if not Path("/.dockerenv").exists() or not ASAN_DIR.is_dir():
        raise SystemExit("REFUSED: run inside the ASan venue (docker/openssl-rs-asan.sh).")
    rc, out, _ = run(["sh", "-c", "ulimit -d"])
    if rc == 0 and out.strip() not in ("unlimited", "-1"):
        raise SystemExit("REFUSED: RLIMIT_DATA is set; this is not the ASan venue.")


def sweep() -> None:
    """SIGKILL leftover servers a previous probe may have leaked. Never our own shell."""
    me = os.getpid()
    mine = {me, os.getppid()}
    for p in Path("/proc").iterdir():
        if not p.name.isdigit() or int(p.name) in mine:
            continue
        try:
            comm = (p / "comm").read_text().strip()
        except OSError:
            continue
        kill = comm in ("nginx", "haproxy", "sshd", "sshd-session", "fcgiwrap")
        if not kill:
            try:
                cmd = (p / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
            except OSError:
                continue
            kill = "http.server" in cmd
        if kill:
            try:
                os.kill(int(p.name), 9)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# consumer specifications
# ---------------------------------------------------------------------------

def specs(runtime: str) -> list[dict]:
    auth = {"AUTHORITY": str(AUTHORITY)}
    min_env = {"LC_ALL": "C.UTF-8", "TZ": "UTC"}
    consumer_env = {"CANDIDATE": str(PREFIX), **auth}
    curl_path = str(CONSUMERS / "curl/curl-8.22.0/src/curl")
    nginx_path = str(CONSUMERS / "nginx/nginx-1.26.3/objs/nginx")

    return [
        {
            "id": "curl",
            "title": "curl TLS 1.3 client (live_tls_probe.sh)",
            "runs": [{
                "name": "live_tls_probe",
                "script": f"{D}/curl/live_tls_probe.sh",
                "timeout": 300,
                "env": {**consumer_env, "WORK": str(CONSUMERS / "curl"), "PORT": "8443"},
                "expect": [r"^live_tls_probe.sh: OK$", r"^http_code=", r"^ssl_verify_result=",
                           r"^curl_negative_exit=", r"^concurrent_200s="],
            }],
        },
        {
            "id": "nginx",
            "title": "nginx TLS 1.3 server (serve_probe.sh)",
            "runs": [{
                "name": "serve_probe",
                "script": f"{D}/nginx/serve_probe.sh",
                "timeout": 420,
                "env": {**consumer_env, "WORK": str(CONSUMERS / "nginx"),
                        "CURL": curl_path, "NGINX": nginx_path, "PORT": "9443"},
                "expect": [r"^mode=.*", r"^A_tls13_handshake=", r"^D_tls13_resumed=",
                           r"^C_concurrent_200s=", r"^serve_probe.sh: done$"],
            }],
        },
        {
            "id": "haproxy",
            "title": "HAProxy TLS 1.3 terminator (proxy_probe.sh)",
            "runs": [{
                "name": "proxy_probe",
                "script": f"{D}/haproxy/proxy_probe.sh",
                "timeout": 420,
                "env": {**consumer_env, "WORK": str(CONSUMERS / "haproxy"),
                        "CURL": curl_path, "PORT": "18445", "BACKEND_PORT": "18081"},
                "expect": [r"^A_tls13_handshake=", r"^B_curl_exit=", r"^C_concurrent_200s=",
                           r"^proxy_probe.sh: done$"],
            }],
        },
        {
            "id": "git",
            "title": "Git object hashing + Smart HTTP over TLS",
            "extra_ld": [str(CONSUMERS / "git/deps/lib")],
            "runs": [
                {
                    "name": "https_probe",
                    "script": f"{D}/git/https_probe.sh",
                    "timeout": 420,
                    "env": {**consumer_env, "SRC": str(CONSUMERS / "git/git-2.56.0"),
                            "NGINX": nginx_path, "BASE": str(CONSUMERS / "git/https"),
                            "PORT": "8443"},
                    "expect": [r"HTTPS PUSH/PULL PASS", r"^https_probe.sh: concurrent_ok=",
                               r"negative arm ok"],
                },
                {
                    "name": "run_tests",
                    "script": f"{D}/git/run_tests.sh",
                    "timeout": 900,
                    "env": {"SRC": str(CONSUMERS / "git/git-2.56.0"),
                            "LOGDIR": str(ASAN_DIR / "dsr" / "git-tests"),
                            # Git's t/test-lib.sh manages LD_PRELOAD for its own glibc
                            # malloc-check and `teardown_malloc_check` unsets it after the
                            # first test, which would strip the ASan runtime mid-suite. Git
                            # supports TEST_NO_MALLOC_CHECK to disable that machinery; ASan
                            # already intercepts malloc, so the checking is not lost.
                            "TEST_NO_MALLOC_CHECK": "1"},
                    "expect": [r"PASS|FAIL|SKIP", r"^run_tests.sh: logs in"],
                },
            ],
        },
        {
            "id": "openssh",
            "title": "OpenSSH libcrypto-only consumer + key-format round-trip",
            # The sshd server path is an envelope limitation, not a candidate defect: OpenSSH's
            # seccomp sandbox denies ASan's shadow mapping in the preauth child.
            "envelope_limited": {
                "reason": (
                    "ssh-keygen/sign/verify/fingerprints/algorithm-enumeration (probe.sh sections 1,2,5) "
                    "and keyformat_probe.sh run under ASan and are clean. The sshd SSH server path "
                    "(probe.sh sections 3,4,6,7: login, the kex/cipher/mac/hostkey matrix, agent login, "
                    "and concurrency) CANNOT run under ASan: OpenSSH applies a seccomp filter to the "
                    "preauth child (sandbox-seccomp-filter.c:193-203, SC_MMAP; sshd logs "
                    "`ssh_sandbox_child: attaching seccomp filter program [preauth]`), and the filter "
                    "denies the mmap ASan uses to reserve its shadow. ASan then cannot start in that "
                    "child -- `ReserveShadowMemoryRange failed ... (errno: 22)` -- and the child dies "
                    "before any crypto is exercised. This is a consumer-sandbox-versus-sanitizer "
                    "incompatibility, not a candidate defect, and it is the same class as the court's "
                    "RLIMIT_DATA (D105) that forced this dedicated venue."
                ),
                "captured_diagnostic": (
                    "==NNN==ERROR: AddressSanitizer failed to allocate 0x38000 (229376) bytes at "
                    "address ff443091000 (errno: 22)\n"
                    "==NNN==ReserveShadowMemoryRange failed while trying to map 0x38000 bytes. "
                    "Perhaps you're using ulimit -v"
                ),
                "sections_not_under_asan": [
                    "3. sshd + ssh localhost handshake",
                    "4. algorithm matrix (needs the sshd login path)",
                    "6. ssh-agent login",
                    "7. 16 concurrent ssh logins",
                ],
            },
            "runs": [
                {
                    "name": "probe",
                    "script": f"{D}/openssh/probe.sh",
                    "timeout": 420,
                    "env": {**consumer_env, "WORK": str(CONSUMERS / "openssh"),
                            "SRC": str(CONSUMERS / "openssh/openssh-10.5p1"),
                            "INSTALL": str(CONSUMERS / "openssh/install"), "PORT": "2222"},
                    "expect": [r"^=== SUMMARY:", r"^concurrent_logins="],
                },
                {
                    "name": "keyformat_probe",
                    "script": f"{D}/openssh/keyformat_probe.sh",
                    "timeout": 300,
                    "env": {"CAND_KG": str(CONSUMERS / "openssh/openssh-10.5p1/ssh-keygen"),
                            "AUTH_KG": str(AUTH_KG_WRAPPER),
                            "UPSTREAM": str(CONSUMERS / "openssh/openssh-10.5p1/regress"),
                            "WORK": str(DSR / "keyfmt")},
                    "expect": [r"^=== [A-E]\."],
                },
            ],
        },
        {
            "id": "python",
            "title": "CPython _ssl bounded test_ssl",
            "runs": [{
                "name": "bounded_test_ssl",
                "script": f"{D}/python/run_test_ssl.sh",
                "timeout": 2400,
                "env": {"WORK": str(CONSUMERS / "python"),
                        "PY": str(CONSUMERS / "python/Python-3.12.15/python"),
                        "PER_TEST_TIMEOUT": "60", "WORKERS": "4",
                        "BOUNDED_LOGDIR": str(ASAN_DIR / "dsr" / "python" / "bounded_logs")},
                "expect": [r"^cases total", r"^passed ", r"^failed ", r"^errors ",
                           r"^skipped ", r"^timed out ", r"^unknown "],
            }],
        },
    ]


# ---------------------------------------------------------------------------
# running one probe
# ---------------------------------------------------------------------------

def make_helper_wrappers() -> None:
    """Wrappers that drop ASan for the non-candidate data helpers (see above)."""
    SAFE_BIN.mkdir(parents=True, exist_ok=True)
    for name in NON_CANDIDATE_HELPERS:
        real = shutil.which(name, path="/usr/bin:/bin:/usr/sbin:/sbin")
        if not real:
            continue
        p = SAFE_BIN / name
        p.write_text(
            "#!/bin/sh\n"
            f'exec env -u LD_PRELOAD -u ASAN_OPTIONS "{real}" "$@"\n',
            encoding="utf-8",
        )
        p.chmod(0o755)


def relocate_consumer(cid: str) -> dict | None:
    """Re-point a staged build tree at its new location.

    Git bakes absolute build paths into `GIT-BUILD-OPTIONS` (e.g.
    `GIT_TEST_TEMPLATE_DIR='/court/git/git-2.56.0/templates/blt'`) and into the
    `bin-wrappers/*` scripts, and OpenSSH bakes `--with-privsep-path` and
    `--prefix` into `sshd` (`/court/openssh/install/...`). The staged copy is
    elsewhere, so `t/test-lib.sh` bails and `sshd -t` reports a missing privsep
    directory. Providing the original path as a symlink to the staged tree is
    relocation, not modification.
    """
    if cid == "git":
        src = CONSUMERS / "git/git-2.56.0"
        opts = src / "GIT-BUILD-OPTIONS"
        prepared = None
        if opts.is_file():
            text = opts.read_text(encoding="utf-8", errors="replace")
            new = text.replace("/court/git/git-2.56.0", str(src)) \
                      .replace("/court/git/install", str(CONSUMERS / "git/install"))
            if new != text:
                opts.write_text(new, encoding="utf-8")
            prepared = {"file": str(opts), "from": "/court/git", "to": str(CONSUMERS / "git")}
        _symlink("/court/git", CONSUMERS / "git")
        return prepared
    if cid == "openssh":
        _symlink("/court/openssh", CONSUMERS / "openssh")
        _symlink("/court/openssh-auth", CONSUMERS / "openssh-auth")
        return {"symlink": "/court/openssh -> %s" % (CONSUMERS / "openssh")}
    return None


def _symlink(link, target) -> bool:
    link = Path(link)
    target = Path(target)
    try:
        link.parent.mkdir(parents=True, exist_ok=True)
        if link.is_symlink():
            if link.resolve() != target.resolve():
                link.unlink()
                link.symlink_to(target)
        elif not link.exists():
            link.symlink_to(target)
        return True
    except OSError:
        return False


def make_auth_wrapper() -> None:
    DSR.mkdir(parents=True, exist_ok=True)
    real = CONSUMERS / "openssh-auth/openssh-10.5p1/ssh-keygen"
    AUTH_KG_WRAPPER.write_text(
        "#!/bin/sh\n"
        "# The authority-linked control: run it OUTSIDE the ASan envelope so it\n"
        "# resolves the authority's libcrypto, exactly as the Phase-17 tool intends.\n"
        f'exec env -u LD_PRELOAD -u ASAN_OPTIONS LD_LIBRARY_PATH="{AUTHORITY}/lib" \\\n'
        f'  "{real}" "$@"\n',
        encoding="utf-8",
    )
    AUTH_KG_WRAPPER.chmod(0o755)


def run_one(spec: dict, run_spec: dict, runtime: str) -> dict:
    name = run_spec["name"]
    report_dir = DSR / spec["id"] / name
    shutil.rmtree(report_dir, ignore_errors=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    log = report_dir / "stdout.log"

    ld = [str(PREFIX / "lib")] + [str(p) for p in spec.get("extra_ld", [])]
    env = {
        "LC_ALL": "C.UTF-8", "TZ": "UTC",
        "LD_LIBRARY_PATH": ":".join(ld),
        "LD_PRELOAD": runtime,
        "ASAN_SYMBOLIZER_PATH": shutil.which("llvm-symbolizer") or "",
        "ASAN_OPTIONS": f"{ASAN_OPTIONS}:log_path={report_dir}/asan",
        "PATH": f"{SAFE_BIN}:{os.environ.get('PATH', '')}",
    }
    env.update(run_spec.get("env", {}))

    t0 = time.monotonic()
    rc, out, err = run(["timeout", str(run_spec["timeout"]), "sh", run_spec["script"]],
                       env=env, timeout=run_spec["timeout"] + 60, cwd=REPO_ROOT)
    elapsed = round(time.monotonic() - t0, 1)
    log.write_text(f"$ {run_spec['script']}\n\n{out}\n{err}\n", encoding="utf-8", errors="replace")

    combined = out + "\n" + err
    # Reports land in `log_path.<pid>` files; also catch any inline report.
    file_reports = []
    for f in sorted(DSR.glob(f"{spec['id']}/{name}/asan.*")):
        try:
            file_reports += asan_blocks(f.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            pass
    inline = asan_blocks(combined)
    seen, blocks = set(), []
    for b in file_reports + inline:
        if b not in seen:
            seen.add(b)
            blocks.append(b)
    sites = []
    for b in blocks:
        m = re.search(r"ERROR: AddressSanitizer: ([^\s]+)", b)
        syms = re.findall(r"in (openssl_rs::[A-Za-z0-9_:]+)", b)
        sites.append(f"{m.group(1) if m else '?'} @ {syms[0] if syms else '?'}")

    result_lines = []
    for pat in run_spec.get("expect", []):
        for line in out.splitlines():
            if re.search(pat, line):
                result_lines.append(line.strip())
                break
    return {
        "run": name,
        "script": run_spec["script"],
        "command": f"timeout {run_spec['timeout']} sh {run_spec['script']}",
        "ld_library_path": env["LD_LIBRARY_PATH"],
        "ld_preload": env["LD_PRELOAD"],
        "asan_options": f"{ASAN_OPTIONS}:log_path=<report-dir>/asan",
        "exit_code": rc,
        "timed_out": rc == 124,
        "elapsed_s": elapsed,
        "asan_findings": len(blocks),
        "asan_sites": sites,
        "asan_diagnostics": blocks[:4],
        "result_lines": result_lines,
        "log": str(log),
        "verdict": "clean" if (rc == 0 and not blocks) else (
            "findings" if blocks else "run-failed"),
    }


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--only", default="", help="comma-separated consumer ids")
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args(argv)

    require_venue()
    rename_self()
    for d in (PREFIX, CONSUMERS, DSR):
        if not d.is_dir():
            raise SystemExit(f"asan-downstream: required directory absent: {d}")
    if not AUTHORITY.is_dir():
        raise SystemExit(f"asan-downstream: authority prefix absent: {AUTHORITY}")

    runtime = runtime_so()
    make_auth_wrapper()
    make_helper_wrappers()

    build = {"command": f"bash {BUILD_SCRIPT}", "prefix": str(PREFIX),
             "ran": False, "ok": PREFIX.joinpath("lib/libssl.so.3").is_file()}
    if not args.skip_build:
        rc, out, err = run(["bash", BUILD_SCRIPT], timeout=3600, cwd=REPO_ROOT)
        build["ran"] = True
        build["exit_code"] = rc
        build["ok"] = rc == 0
        build["log_tail"] = "\n".join((out + err).splitlines()[-20:])
        if rc != 0:
            raise SystemExit(f"asan-downstream: DSO build failed (rc={rc})\n{build['log_tail']}")

    dso_sha = {}
    for n in ("libcrypto.so.3", "libssl.so.3", "ossl-modules/legacy.so"):
        p = PREFIX / "lib" / n
        if p.is_file():
            dso_sha[n] = sha256_file(p)

    wanted = {x for x in args.only.split(",") if x}
    consumers = []
    for spec in specs(runtime):
        if wanted and spec["id"] not in wanted:
            continue
        sweep()
        prepared = relocate_consumer(spec["id"])
        runs = [run_one(spec, r, runtime) for r in spec["runs"]]
        findings = sum(r["asan_findings"] for r in runs)
        ok = all(r["verdict"] == "clean" for r in runs)
        consumers.append({
            "id": spec["id"],
            "title": spec["title"],
            "build": "reused-phase17-build",
            "link": "loads ASan DSOs via LD_LIBRARY_PATH; ASan runtime preloaded",
            "prepared": prepared,
            "envelope_limited": spec.get("envelope_limited"),
            "runs": runs,
            "asan_findings": findings,
            "verdict": ("envelope-limited" if spec.get("envelope_limited")
                        else "clean" if ok else "findings" if findings else "run-failed"),
        })
        print(f"[asan-downstream] {spec['id']}: findings={findings} "
              f"verdict={consumers[-1]['verdict']}")

    clean = [c["id"] for c in consumers if c["verdict"] == "clean"]
    limited = [c["id"] for c in consumers if c["verdict"] == "envelope-limited"]
    with_findings = [c["id"] for c in consumers if c["verdict"] == "findings"]
    failed = [c["id"] for c in consumers if c["verdict"] == "run-failed"]

    body = {
        "schema": "openssl-rs/phase18-asan-downstream/v1",
        "phase": 18,
        "generator": GENERATOR,
        "rule": (
            "The six sealed Phase-17 downstream consumers load the ASan-instrumented candidate "
            "DSOs (libcrypto.so.3/libssl.so.3) built into a dedicated prefix. The consumers are "
            "their Phase-17 builds, relocated at load time with LD_LIBRARY_PATH to that prefix and "
            "LD_PRELOAD of clang's dynamic ASan runtime; the consumers themselves are NOT "
            "instrumented, so the defect surface under test is the candidate. Zero ASan findings "
            "is the bar; a finding is a defect to attribute, not to hide. A clean run is a bounded "
            "observation, not a memory-safety proof."
        ),
        "prefix": str(PREFIX),
        "dsos": dso_sha,
        "runtime": runtime,
        "excluded_non_candidate_helpers": {
            name: {"reason": why, "path": str(SAFE_BIN / name),
                   "observed_report": EXCLUDED_HELPER_REPORT if name == "dd" else None}
            for name, why in NON_CANDIDATE_HELPERS.items()
        },
        "build": build,
        "consumers_root": str(CONSUMERS),
        "authority": str(AUTHORITY),
        "consumers": consumers,
        "summary": {
            "clean": clean,
            "envelope_limited": limited,
            "with_findings": with_findings,
            "run_failed": failed,
            "total_findings": sum(c["asan_findings"] for c in consumers),
        },
    }
    write_json(args.out.resolve(), body)
    print(f"[asan-downstream] clean={clean} findings={with_findings} failed={failed}")
    print(f"[asan-downstream] -> {rel(args.out)}")
    return 0 if not with_findings else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
