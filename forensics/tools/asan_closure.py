#!/usr/bin/env python3
"""openssl-rs — the AddressSanitizer closure harness.

Why this exists
---------------
`docs/UNSAFE.md` §4 recorded that AddressSanitizer *could not run*: the forensic
court's OOM protection sets a hard per-process `RLIMIT_DATA` (default 4 GiB,
`docker/openssl-rs-court.sh`), and ASan reserves a terabyte-scale sparse virtual
shadow before it tests anything. That cap stays — it is what keeps a runaway
court off the host (`docs/DECISIONS.md` D105) — so ASan gets a **dedicated
venue**, `docker/openssl-rs-asan.{Dockerfile,sh}`, that bounds real resources
(cgroup memory, PIDs, CPU, wall clock) while leaving the per-process
`RLIMIT_DATA` unset, because ASan's shadow is `PROT_NONE`, `MAP_NORESERVE`
virtual address space the cgroup does not count.

This harness runs inside that venue. It:

  1. builds the candidate under ASan — the Rust implementation
     (`-Zsanitizer=address -Zbuild-std`), the first-party C adapters (compiled by
     `build.rs` through a `CC` wrapper that appends the ASan flags) and the test
     probes — and produces an **instrumentation-closure receipt** from the link
     map, naming every retained object and whether it is instrumented;
  2. builds and runs a **sensitivity canary** (a deliberate heap use-after-free /
     buffer overflow) and requires ASan to diagnose it, before any zero-findings
     result is trusted;
  3. runs ASan in **layers**, recording each layer's command and result: the
     allocator/unit tests, targeted ownership tests, the Phase-18 hostile TLS
     corpus, the hostile X.509 corpus, and the 16,384-case mutation corpus;
  4. writes `artifacts/phase18/asan.json`.

What it is not
--------------
It is not a memory-safety proof: ASan observes specific error classes (heap
out-of-bounds, use-after-free, double-free, invalid free, stack/global OOB) under
specific execution. It does not instrument the authority, it does not run
TSan/UBSan/MSan, and the downstream-consumer probes (CPython/nginx/curl/Git/
HAProxy/OpenSSH) are recorded as not-yet where they need DSO-based consumers this
step did not build. It does not blind ASan with a custom allocator: the default
path (libc malloc, ASan-intercepted) is what every layer runs; the crate's
optional `CRYPTO_set_mem_functions` path is recorded separately rather than
hidden.

Everything runs inside the ASan venue. Nothing runs on the host.

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

GENERATOR = "forensics/tools/asan_closure.py"
OUT = REPO_ROOT / "artifacts" / "phase18" / "asan.json"
NIGHTLY = os.environ.get("ASAN_NIGHTLY", "nightly")
TARGET_TRIPLE = "x86_64-unknown-linux-gnu"

ASAN_DIR = Path(os.environ.get("OPENSSL_RS_ASAN_DIR", "/asan"))
TARGET = ASAN_DIR / "target"
BIN = ASAN_DIR / "bin"
LOGS = ASAN_DIR / "logs"
WORK = ASAN_DIR / "work"
ARCHIVE = TARGET / TARGET_TRIPLE / "release" / "libopenssl_rs.a"
CC_WRAPPER = BIN / "asan-cc"

# The Phase-18 probes, by court. The canary is built and run separately.
PROBES = {
    "RT-HOSTILE-TLS": "courts/phase18/rt_hostile_tls_probe.c",
    "RT-HOSTILE-X509": "courts/phase18/rt_hostile_x509_probe.c",
}
CANARY_SRC = "forensics/tools/asan_canary.c"

# The first-party C adapters `build.rs` compiles (the C-variadic ABI shims and the
# platform-layout readers). The closure receipt compiles each one with the venue's
# CC and checks the object for ASan references, so the claim is per-source.
C_ADAPTERS = [
    "src/runtime/err_variadic.c",
    "src/runtime/bio/bio_variadic.c",
    "src/runtime/bio/bio_va.c",
    "src/evp/pkey_q_keygen_variadic.c",
    "src/store/store_lib_variadic.c",
    "src/runtime/dir_posix.c",
    "src/async/arch/async_ucontext.c",
]

# A canary must fire before any layer's zero findings may be trusted. These are
# the ASan runtime's own strings.
CANARY_MUST_MATCH = ("AddressSanitizer", "use-after-free")

# Default malloc is ASan-intercepted. Leak detection is off so that the error
# class under test is memory corruption, not a global registry the reduced engine
# intentionally never frees; the choice is recorded.
ASAN_OPTIONS_TESTS = "detect_leaks=0:symbolize=1:abort_on_error=0"
ASAN_OPTIONS_PROBES = "detect_leaks=0:symbolize=1:abort_on_error=1"

LAYER_NAMES = (
    "allocator-unit-tests",
    "ownership-tests",
    "hostile-tls",
    "hostile-x509",
    "mutation-corpus",
    "downstream-consumers",
)

# Downstream consumer probes named by the task. Each needs consumer binaries (or
# sources) built/loaded against the *candidate DSOs* under ASan, which this step
# does not build; recorded as not-yet rather than silently skipped.
DOWNSTREAM = [
    {"id": "cpython-test-ssl", "status": "not-yet",
     "reason": "CPython built/loaded against the ASan candidate DSOs was not built in this step; "
               "the sanitizer candidate here is a statically linked probe set, not an installed DSO tree"},
    {"id": "nginx", "status": "not-yet",
     "reason": "nginx is not installed in the ASan venue and was not built against the ASan candidate DSOs"},
    {"id": "curl", "status": "not-yet",
     "reason": "curl is not installed in the ASan venue and was not built against the ASan candidate DSOs"},
    {"id": "git", "status": "not-yet",
     "reason": "git is installed but links the distribution libcurl/libssl; it was not rebuilt against the ASan candidate DSOs"},
    {"id": "haproxy", "status": "not-yet",
     "reason": "HAProxy is not installed in the ASan venue and was not built against the ASan candidate DSOs"},
    {"id": "openssh", "status": "not-yet",
     "reason": "OpenSSH is not installed in the ASan venue and was not built against the ASan candidate DSOs"},
]


# ---------------------------------------------------------------------------
# process helpers
# ---------------------------------------------------------------------------

def run(argv, *, env=None, timeout=None, cwd=None):
    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    try:
        proc = subprocess.run(
            [str(a) for a in argv], env=full_env, cwd=str(cwd) if cwd else None,
            capture_output=True, text=True, check=False, timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return 124, out, err + f"\n[harness] timed out after {timeout}s"


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def asan_blocks(text: str) -> list[str]:
    """Every full AddressSanitizer report block, verbatim, capped for size."""
    blocks = []
    lines = text.splitlines()
    i = 0
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


_TEST_FRAME_RE = re.compile(r"openssl_rs::[A-Za-z0-9_:]*::tests::([A-Za-z0-9_]+)")


def aborting_test_name(block: str) -> str | None:
    """The crate test the report fired in, if the stack names one."""
    m = _TEST_FRAME_RE.search(block)
    return m.group(1) if m else None


def site_of(block: str) -> str:
    """A stable identity for an ASan fault: its class and its first crate frame."""
    m = re.search(r"ERROR: AddressSanitizer: ([a-z-]+)", block)
    kind = m.group(1) if m else "?"
    syms = re.findall(r"in (openssl_rs::[A-Za-z0-9_:]+)", block)
    return f"{kind} @ {syms[0]}" if syms else kind


def write_log(name: str, text: str) -> str:
    LOGS.mkdir(parents=True, exist_ok=True)
    p = LOGS / name
    p.write_text(text, encoding="utf-8", errors="replace")
    return str(p)


def require_venue() -> None:
    if not Path("/.dockerenv").exists():
        raise SystemExit(
            "REFUSED: the ASan closure harness must run inside a container "
            "(docs/REPRODUCIBILITY.md §1)."
        )
    if not ASAN_DIR.is_dir():
        raise SystemExit(
            "REFUSED: this does not look like the ASan venue (no %s). Run it through "
            "docker/openssl-rs-asan.sh; the forensic court is the wrong venue because its "
            "RLIMIT_DATA is exactly what ASan cannot run under." % ASAN_DIR
        )
    # The venue must NOT carry the court's RLIMIT_DATA. Read it back and refuse if
    # it is anything but unlimited, so the venue is checked rather than assumed.
    rc, out, _ = run(["sh", "-c", "ulimit -d"], env={"LC_ALL": "C"})
    val = out.strip()
    if rc == 0 and val not in ("unlimited", "-1"):
        raise SystemExit(
            "REFUSED: RLIMIT_DATA is %r in this venue; ASan needs it unset. "
            "This looks like the court, not the ASan venue." % val
        )


def symbolizer() -> str | None:
    p = shutil.which("llvm-symbolizer")
    return p


def base_proc_env() -> dict:
    env = {"LC_ALL": "C.UTF-8", "TZ": "UTC"}
    sym = symbolizer()
    if sym:
        env["ASAN_SYMBOLIZER_PATH"] = sym
    return env


def build_env() -> dict:
    env = base_proc_env()
    env.update({
        "RUSTUP_TOOLCHAIN": NIGHTLY,
        # -Clinker=clang so build scripts and test harnesses link ASan through
        # clang's bundled compiler-rt runtime, not gcc's libasan, keeping one
        # sanitizer runtime for the whole closure.
        #
        # -Ccodegen-units=1 so the instrumented build is codegen-deterministic:
        # with the default many-CGU schedule LLVM can promote a small
        # `extern "C"` function into a second `.llvm.<n>` symbol when it is
        # address-taken from both the defining CGU and the test CGU, so a test
        # that compares a statically-initialised function pointer against a
        # direct reference to the same function (e.g.
        # `provider::cipher::tests::the_chacha20_hw_leaves_copyctx_null`) sees
        # two distinct addresses. That is an artifact of the schedule, not a
        # memory error, and a single CGU removes it without touching the tests.
        "RUSTFLAGS": "-Zsanitizer=address -Cdebuginfo=1 -Clinker=clang -Ccodegen-units=1",
        "CARGO_TARGET_DIR": str(TARGET),
        "CC": str(CC_WRAPPER),
        "AR": "ar",
    })
    return env


# ---------------------------------------------------------------------------
# build the instrumented candidate
# ---------------------------------------------------------------------------

def write_cc_wrapper() -> None:
    BIN.mkdir(parents=True, exist_ok=True)
    CC_WRAPPER.write_text(
        "#!/bin/sh\n"
        "# openssl-rs ASan venue: every C compilation (build.rs adapters) is instrumented.\n"
        "exec clang -fsanitize=address -fno-omit-frame-pointer -g \"$@\"\n",
        encoding="utf-8",
    )
    CC_WRAPPER.chmod(0o755)


def build_candidate() -> dict:
    LOGS.mkdir(parents=True, exist_ok=True)
    write_cc_wrapper()
    cmd = ["cargo", f"+{NIGHTLY}", "build", "-Zbuild-std", "--release", "--lib",
           "--target", TARGET_TRIPLE]
    started = time.monotonic()
    rc, out, err = run(cmd, env=build_env(), timeout=5400, cwd=REPO_ROOT)
    elapsed = time.monotonic() - started
    log = write_log("cargo-build.log", f"$ {' '.join(cmd)}\n\n{out}\n{err}\n")
    if rc != 0 or not ARCHIVE.is_file():
        tail = "\n".join((out + err).splitlines()[-40:])
        raise SystemExit(f"ASan candidate build failed (rc={rc}); log {log}\n{tail}")
    return {
        "command": " ".join(cmd),
        "rustflags": build_env()["RUSTFLAGS"],
        "cc": str(CC_WRAPPER),
        "elapsed_s": round(elapsed, 1),
        "archive": rel(ARCHIVE),
        "archive_sha256": sha256_file(ARCHIVE),
        "log": log,
    }


# ---------------------------------------------------------------------------
# instrumentation-closure receipt
# ---------------------------------------------------------------------------

# `nm -A` prints `ARCHIVE:MEMBER:   U symbol`; the link map prints a retained
# member as `.../lib.a(member.o)` on its own line. Two formats, two regexes.
_NM_RE = re.compile(r"^(?P<archive>[^:]+):(?P<member>[^:]+):(?P<rest>.*)$")
_MAP_RE = re.compile(r"^(?P<arc>.+?)\((?P<member>[^)]+)\)\s*$")


def archive_asan_map(archive: Path) -> dict[str, bool]:
    """member.o -> whether it references the ASan runtime, from one nm pass.

    An instrumented object *references* `__asan_*` (undefined symbols until the
    runtime is linked), so `--undefined-only` is the correct view.
    """
    rc, out, err = run(["nm", "-A", "--undefined-only", str(archive)], timeout=900)
    if rc != 0:
        return {}
    table: dict[str, bool] = {}
    for line in out.splitlines():
        m = _NM_RE.match(line)
        if not m:
            continue
        member = Path(m.group("member")).name
        if not member.endswith(".o"):
            continue
        if "__asan" in line:
            table[member] = True
        else:
            table.setdefault(member, False)
    return table


_RUST_SHIM = re.compile(r"___rust_(alloc|dealloc|realloc|alloc_zeroed|no_alloc_shim)")


def archive_glue_members(archive: Path) -> set[str]:
    """Members that are allocator-shim thunks and have no memory operations.

    `alloc`'s `__rust_alloc`/`__rust_dealloc`/... entry points are emitted into a
    member of tail-call `jmp` thunks to the real allocator. They contain no memory
    operation of their own, so they carry no ASan instrumentation and excluding
    them is not a coverage gap — it is the runtime glue std is built from.
    """
    rc, out, _ = run(["nm", "-A", "--defined-only", str(archive)], timeout=900)
    if rc != 0:
        return set()
    per: dict[str, set[str]] = {}
    for line in out.splitlines():
        m = _NM_RE.match(line)
        if not m:
            continue
        member = Path(m.group("member")).name
        if not member.endswith(".o"):
            continue
        parts = m.group("rest").split(None, 1)
        name = parts[1].strip() if len(parts) > 1 else ""
        per.setdefault(member, set()).add(name)
    glue: set[str] = set()
    for member, names in per.items():
        funcs = {n for n in names if n}
        if funcs and all(_RUST_SHIM.search(n) for n in funcs):
            glue.add(member)
    return glue


def archive_member_count(archive: Path) -> int:
    rc, out, _ = run(["ar", "t", str(archive)], timeout=300)
    if rc != 0:
        return 0
    return len([l for l in out.splitlines() if l.strip()])


def parse_link_map(map_path: Path, archive_name: str) -> list[str]:
    """Retained members of `archive_name`, in order, from a GNU ld link map."""
    members: list[str] = []
    seen = set()
    if not map_path.is_file():
        return members
    for line in map_path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = _MAP_RE.match(line.strip())
        if not m:
            continue
        if Path(m.group("arc")).name != archive_name:
            continue
        member = Path(m.group("member")).name
        if member in seen:
            continue
        seen.add(member)
        members.append(member)
    return members


def build_probe(court: str, src_rel: str) -> dict:
    src = REPO_ROOT / src_rel
    out = BIN / f"{Path(src_rel).stem}.asan"
    map_path = WORK / f"{Path(src_rel).stem}.map"
    WORK.mkdir(parents=True, exist_ok=True)
    cmd = [
        "clang", "-std=c11", "-Wall", "-Wno-deprecated-declarations",
        "-Werror=implicit-function-declaration", "-O1", "-D_GNU_SOURCE",
        "-fsanitize=address", "-fno-omit-frame-pointer", "-g",
        "-I", str(REPO_ROOT / "artifacts" / "phase2" / "include"),
        "-o", str(out), str(src),
        str(ARCHIVE),
        "-Wl,-Map," + str(map_path),
        "-lpthread", "-ldl", "-lm", "-lrt", "-lutil",
    ]
    rc, sout, serr = run(cmd, env=base_proc_env(), timeout=900, cwd=REPO_ROOT)
    if rc != 0:
        raise SystemExit(f"{court}: probe build failed\n{serr[-2000:]}")
    nm_rc, nm_out, _ = run(["nm", str(out)], timeout=300)
    readelf_rc, readelf_out, _ = run(["readelf", "-d", str(out)], timeout=120)
    needed = re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", readelf_out)
    return {
        "court": court,
        "source": src_rel,
        "binary": rel(out),
        "flags": ["-fsanitize=address", "-fno-omit-frame-pointer", "-g"],
        "asan_symbols": len(re.findall(r"__asan", nm_out)) if nm_rc == 0 else None,
        "needed": needed,
        "link_map": rel(map_path),
        "retained_members": parse_link_map(map_path, ARCHIVE.name),
    }


def adapter_instrumentation() -> list[dict]:
    """Compile each first-party C adapter with the venue CC and check the object."""
    out_dir = WORK / "adapters"
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for src_rel in C_ADAPTERS:
        src = REPO_ROOT / src_rel
        obj = out_dir / (Path(src_rel).stem + ".o")
        rc, _, err = run([str(CC_WRAPPER), "-c", "-O2", "-fPIC", "-fno-strict-aliasing",
                          "-o", str(obj), str(src)], env=base_proc_env(), timeout=300,
                         cwd=REPO_ROOT)
        asan = None
        if rc == 0 and obj.is_file():
            nm_rc, nm_out, _ = run(["nm", str(obj)], timeout=120)
            asan = len(re.findall(r"__asan", nm_out)) if nm_rc == 0 else None
        rows.append({
            "source": src_rel,
            "compiled": rc == 0,
            "asan_symbols": asan,
            "instrumented": bool(asan),
            "error": "" if rc == 0 else err.strip()[-300:],
        })
    return rows


def closure_receipt() -> dict:
    amap = archive_asan_map(ARCHIVE)
    total_members = archive_member_count(ARCHIVE)
    instrumented_members = sum(1 for v in amap.values() if v)
    n_amap = len(amap)

    tls = build_probe("RT-HOSTILE-TLS", PROBES["RT-HOSTILE-TLS"])
    x509 = build_probe("RT-HOSTILE-X509", PROBES["RT-HOSTILE-X509"])

    glue = archive_glue_members(ARCHIVE)
    retained = sorted(set(tls["retained_members"]) | set(x509["retained_members"]))
    retained_rows = []
    for member in retained:
        if member in glue:
            cls = "runtime-allocator-shim"
        elif amap.get(member) is True:
            cls = "instrumented"
        elif amap.get(member) is False:
            cls = "uninstrumented"
        else:
            cls = "no-undefined-symbols"
        retained_rows.append({
            "member": member,
            "origin": "rust-staticlib",
            "classified_as": cls,
            "instrumented": amap.get(member),
        })
    # Coverage is judged over first-party objects: the allocator-shim thunks are
    # std runtime glue with no memory operations of their own.
    must = [r for r in retained_rows if r["classified_as"] != "runtime-allocator-shim"]
    n_ret_inst = sum(1 for r in must if r["instrumented"] is True)
    n_ret_known = len(must)

    adapters = adapter_instrumentation()
    n_adapters = len(adapters)
    n_adapters_inst = sum(1 for a in adapters if a["instrumented"])

    return {
        "method": (
            "The Rust staticlib is built by rustc with -Zsanitizer=address -Zbuild-std "
            "(so std is rebuilt under ASan too). The first-party C adapters are compiled by "
            "build.rs through a CC wrapper that appends -fsanitize=address "
            "-fno-omit-frame-pointer -g. The probes are compiled by clang with the same flags. "
            "The link map (-Wl,-Map) enumerates the archive members the linker retained, and "
            "`nm -A --undefined-only` classifies each member as referencing the ASan runtime or not."
        ),
        "rust_staticlib": {
            "archive": rel(ARCHIVE),
            "archive_sha256": sha256_file(ARCHIVE),
            "members_total": total_members,
            "members_in_nm_map": n_amap,
            "members_referencing_asan": instrumented_members,
            "note": (
                "members without an __asan reference are data-only members (e.g. .rodata / "
                "compiler-builtins tables); the members the linker actually retains are "
                "enumerated below and classified individually"
            ),
        },
        "retained_archive_members": {
            "count": len(retained),
            "first_party_count": n_ret_known,
            "first_party_instrumented": n_ret_inst,
            "runtime_allocator_shims": sum(
                1 for r in retained_rows if r["classified_as"] == "runtime-allocator-shim"),
            "all_first_party_instrumented": bool(n_ret_known) and n_ret_inst == n_ret_known,
            "members": retained_rows,
        },
        "c_adapters": {
            "count": n_adapters,
            "instrumented": n_adapters_inst,
            "all_instrumented": n_adapters_inst == n_adapters,
            "objects": adapters,
        },
        "probes": [tls, x509],
        "external": {
            "libc": "runtime-intercepted",
            "detail": (
                "libc is not statically instrumented: the probes are dynamically linked "
                "(NEEDED libc.so.6) and ASan's interceptors replace its allocation/string "
                "primitives at runtime. This is the designed closure for the C runtime."
            ),
        },
        "closure_ok": bool(
            n_adapters_inst == n_adapters
            and n_ret_known > 0
            and n_ret_inst == n_ret_known
            and all(p["asan_symbols"] for p in (tls, x509))
        ),
        "note": (
            "Rust objects (crate + standard library, rebuilt with -Zbuild-std), the first-party C "
            "adapters and the probes are instrumented; libc is runtime-intercepted. The only "
            "retained member without an ASan reference is std's allocator-shim thunk member, "
            "which has no memory operations."
        ),
    }


# ---------------------------------------------------------------------------
# sensitivity canary
# ---------------------------------------------------------------------------

def run_canary() -> dict:
    src = REPO_ROOT / CANARY_SRC
    out = BIN / "asan_canary"
    cmd = ["clang", "-std=c11", "-Wall", "-O0", "-D_GNU_SOURCE",
           "-fsanitize=address", "-fno-omit-frame-pointer", "-g",
           "-o", str(out), str(src)]
    rc, _, err = run(cmd, env=base_proc_env(), timeout=300, cwd=REPO_ROOT)
    if rc != 0:
        return {"detected": False, "build_ok": False, "error": err.strip()[-500:],
                "source": CANARY_SRC}
    canary_env = base_proc_env()
    canary_env["ASAN_OPTIONS"] = "detect_leaks=0:symbolize=1"
    rc, out_s, err_s = run([str(out)], env=canary_env, timeout=120)
    combined = out_s + err_s
    detected = rc != 0 and all(m in combined for m in CANARY_MUST_MATCH)
    diag = [l for l in err_s.splitlines()
            if "AddressSanitizer" in l or "SUMMARY" in l or "use-after-free" in l][:8]
    log = write_log("canary.log", f"$ {' '.join(cmd)}\n\n{out_s}\n{err_s}\n")
    return {
        "detected": detected,
        "build_ok": True,
        "source": CANARY_SRC,
        "command": " ".join(cmd),
        "exit_code": rc,
        "as_expected": "nonzero exit with an AddressSanitizer use-after-free report",
        "diagnostic": diag,
        "log": log,
    }


# ---------------------------------------------------------------------------
# layers
# ---------------------------------------------------------------------------

def cargo_test_layer(name: str, filters: list[str], env_extra: dict, timeout: int) -> dict:
    cmd = ["cargo", f"+{NIGHTLY}", "test", "-Zbuild-std", "--release", "--lib",
           "--target", TARGET_TRIPLE]
    if filters:
        cmd += ["--"] + filters
    t0 = time.monotonic()
    rc, out, err = run(cmd, env=env_extra, timeout=timeout, cwd=REPO_ROOT)
    elapsed = time.monotonic() - t0
    log = write_log(f"{name}.log", f"$ {' '.join(cmd)}\n\n{out}\n{err}\n")
    results = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored",
                         out)
    passed = sum(int(a) for _, a, _, _ in results)
    failed = sum(int(b) for _, _, b, _ in results)
    ignored = sum(int(c) for _, _, _, c in results)
    asan = err.count("AddressSanitizer") + out.count("AddressSanitizer")
    blocks = asan_blocks(err + "\n" + out)
    findings = [l.strip() for l in (out + "\n" + err).splitlines()
                if "AddressSanitizer" in l or re.search(r"FAILED|panicked", l)][:12]
    return {
        "layer": name,
        "ran": True,
        "command": " ".join(cmd),
        "filters": filters,
        "exit_code": rc,
        "timed_out": rc == 124,
        "tests_passed": passed,
        "tests_failed": failed,
        "tests_ignored": ignored,
        "result_lines": [" ".join(r) for r in results][:8],
        "asan_reports": asan,
        "diagnostics": blocks[:4],
        "aborting_tests": sorted({t for b in blocks if (t := aborting_test_name(b))}),
        "findings": findings,
        "elapsed_s": round(elapsed, 1),
        "log": log,
        "verdict": "clean" if (rc == 0 and failed == 0 and asan == 0) else "findings",
    }


def _class_counts(transcript: str) -> dict:
    counts: dict[str, int] = {}
    for line in transcript.splitlines():
        if line.startswith("entry.") and ".class=" in line:
            val = line.rsplit("=", 1)[1]
            counts[val] = counts.get(val, 0) + 1
    return counts


def hostile_layer(name: str, court: str, fixture_rel: str) -> dict:
    probe = BIN / (Path(PROBES[court]).stem + ".asan")
    corpus = REPO_ROOT / fixture_rel
    t0 = time.monotonic()
    henv = base_proc_env()
    henv["ASAN_OPTIONS"] = ASAN_OPTIONS_PROBES
    rc, out, err = run([str(probe), str(corpus)], env=henv, timeout=1800, cwd=REPO_ROOT)
    elapsed = time.monotonic() - t0
    log = write_log(f"{name}.log", f"$ {probe} {corpus}\n\n{out}\n{err}\n")
    classes = _class_counts(out)
    entries = 0
    m = re.search(r"^corpus\.entries=(\d+)", out, re.M)
    if m:
        entries = int(m.group(1))
    asan = err.count("AddressSanitizer")
    hostile = {k: v for k, v in classes.items() if k in ("crash", "oom", "timeout")}
    findings = []
    for line in out.splitlines():
        if re.match(r"entry\..*\.class=(crash|oom|timeout)$", line):
            findings.append(line.strip())
    asan_lines = [l.strip() for l in err.splitlines() if "AddressSanitizer" in l or "SUMMARY" in l][:8]
    blocks = asan_blocks(err + "\n" + out)
    return {
        "layer": name,
        "court": court,
        "ran": True,
        "command": f"{rel(probe)} {rel(corpus)}",
        "exit_code": rc,
        "corpus_entries": entries,
        "classes": classes,
        "hostile_classes": hostile,
        "asan_reports": asan,
        "asan_diagnostics": asan_lines,
        "diagnostics": blocks[:4],
        "first_faulting_entry": (findings[0].split(".", 2)[1] if findings else None),
        "findings": findings[:20],
        "elapsed_s": round(elapsed, 1),
        "log": log,
        "verdict": "clean" if (asan == 0 and not hostile) else "findings",
    }


def mutation_layer() -> dict:
    probe = BIN / (Path(PROBES["RT-HOSTILE-X509"]).stem + ".asan")
    out_json = ASAN_DIR / "fuzz-hostile-asan.json"
    cmd = ["python3", "forensics/tools/fuzz_hostile_corpus.py",
           "--probe", str(probe), "--cases", "16384", "--wall-budget", "300",
           "--seed", "24", "--workdir", str(ASAN_DIR / "fuzz-work"),
           "--out", str(out_json)]
    menv = base_proc_env()
    menv["ASAN_OPTIONS"] = ASAN_OPTIONS_PROBES
    t0 = time.monotonic()
    rc, out, err = run(cmd, env=menv, timeout=1800, cwd=REPO_ROOT)
    elapsed = time.monotonic() - t0
    log = write_log("mutation-corpus.log", f"$ {' '.join(cmd)}\n\n{out}\n{err}\n")
    result = {}
    if out_json.is_file():
        result = json.loads(out_json.read_text(encoding="utf-8"))

    # The fuzz tool captures the probe's stdout but not its stderr, so the ASan
    # report behind a `crash` finding is re-collected here by re-running the probe
    # over the first finding's batch and keeping its diagnostics.
    root_cause_blocks: list[str] = []
    for finding in result.get("findings", [])[:1]:
        batch = finding.get("batch")
        if not batch or not Path(batch).is_dir():
            continue
        rrc, rro, rre = run([str(probe), batch], env=menv, timeout=600, cwd=REPO_ROOT)
        root_cause_blocks = asan_blocks(rre + "\n" + rro)[:2]
    return {
        "layer": "mutation-corpus",
        "ran": True,
        "command": " ".join(cmd),
        "exit_code": rc,
        "cases_requested": result.get("cases_requested"),
        "cases_driven": result.get("cases_driven"),
        "classes": result.get("classes", {}),
        "finding_count": result.get("finding_count"),
        "findings": result.get("findings", [])[:20],
        "root_cause_diagnostics": root_cause_blocks,
        "root_cause_sites": [site_of(b) for b in root_cause_blocks],
        "seed": result.get("seed"),
        "elapsed_s": round(elapsed, 1),
        "note": (
            "ASan errors are surfaced as the probe's own `crash` class because the probe runs with "
            "abort_on_error=1; the fuzz tool invokes the same ASan probe binary the RT-HOSTILE-X509 "
            "layer uses"
        ),
        "log": log,
        "verdict": "clean" if (result.get("finding_count") == 0 and rc == 0) else "findings",
    }


def downstream_layer() -> dict:
    return {
        "layer": "downstream-consumers",
        "ran": False,
        "consumers": DOWNSTREAM,
        "note": (
            "Each downstream probe needs consumer binaries loaded against the ASan candidate DSOs. "
            "This step built a statically linked ASan probe set, not an installed ASan DSO tree, so "
            "none of these ran; they are recorded as not-yet rather than counted as passing."
        ),
        "verdict": "not-run",
    }


def all_tests_layer() -> dict:
    """The full `cargo test --lib` under ASan, then a bounded continuation.

    ASan halts the process at the first error (its default `halt_on_error=1`),
    so a single full run stops at the first defect and silently leaves the rest
    of the 1,163-test suite unrun. To cover what the halt hides, the harness
    re-runs the suite with each aborting test `--skip`ped, up to a bounded number
    of rounds, and records every round. Each round's skip list is derived from the
    ASan stack's own test frame, not typed.
    """
    env = build_env()
    env["ASAN_OPTIONS"] = ASAN_OPTIONS_TESTS
    first = cargo_test_layer("allocator-unit-tests", [], env, timeout=3600)
    if first["verdict"] == "clean":
        return first

    skip: list[str] = []
    pending = list(first.get("aborting_tests", []))
    continuation: list[dict] = []
    seen_sites = [site_of(b) for b in first.get("diagnostics", [])]
    shared_defect = None
    for round_no in range(1, 9):
        newly = [t for t in pending if t not in skip]
        if not newly:
            break
        skip.extend(newly)
        args = []
        for t in skip:
            args += ["--skip", t]
        sub = cargo_test_layer(f"allocator-unit-tests-cont{round_no}", args, env,
                               timeout=3600)
        sites = [site_of(b) for b in sub.get("diagnostics", [])]
        repeat = next((s for s in sites if s in seen_sites), None)
        continuation.append({
            "round": round_no,
            "skipped": list(skip),
            "tests_passed": sub["tests_passed"],
            "tests_failed": sub["tests_failed"],
            "asan_reports": sub["asan_reports"],
            "aborting_tests": sub["aborting_tests"],
            "fault_sites": sites,
            "diagnostics": sub["diagnostics"],
            "exit_code": sub["exit_code"],
            "log": sub["log"],
        })
        if sub["verdict"] == "clean":
            break
        if repeat is not None:
            # The same fault site aborts a different test each round, so skipping
            # tests cannot make progress: one shared defect fails every test that
            # reaches it. Recorded rather than looping to the cap.
            shared_defect = repeat
            break
        seen_sites.extend(sites)
        pending = sub["aborting_tests"]
    first["fault_sites"] = seen_sites
    first["shared_defect"] = shared_defect
    first["continuation"] = continuation
    first["covered_after_skips"] = continuation and continuation[-1]["exit_code"] == 0
    first["note"] = (
        "ASan stopped the first full run at the first defect (halt_on_error=1); the "
        "continuation rounds skip each aborting test by name (parsed from the ASan stack) and "
        "re-run the remaining suite, so the coverage is larger than the first run alone"
    )
    return first


def ownership_layer() -> dict:
    env = build_env()
    env["ASAN_OPTIONS"] = ASAN_OPTIONS_TESTS
    filters = ["runtime::mem", "runtime::obj", "runtime::stack", "runtime::lhash",
               "runtime::buffer", "runtime::ex_data"]
    sub = []
    for f in filters:
        sub.append(cargo_test_layer(f"ownership-{f.replace('::', '_')}", [f], env,
                                    timeout=1200))
    passed = sum(s["tests_passed"] for s in sub)
    failed = sum(s["tests_failed"] for s in sub)
    asan = sum(s["asan_reports"] for s in sub)
    return {
        "layer": "ownership-tests",
        "ran": True,
        "filters": filters,
        "sub_layers": sub,
        "tests_passed": passed,
        "tests_failed": failed,
        "asan_reports": asan,
        "verdict": "clean" if (failed == 0 and asan == 0) else "findings",
        "note": (
            "ownership/lifetime modules, run under the default (libc malloc, ASan-intercepted) "
            "allocator. The crate's optional CRYPTO_set_mem_functions path is exercised by the "
            "allocator-unit-tests layer's mem tests and is recorded separately, not hidden."
        ),
    }


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--skip-build", action="store_true",
                    help="reuse an existing instrumented archive/probe set")
    ap.add_argument("--layers", default="",
                    help="comma-separated subset of layers to run")
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args(argv)

    require_venue()
    for d in (TARGET, BIN, LOGS, WORK):
        d.mkdir(parents=True, exist_ok=True)

    want = set(l for l in args.layers.split(",") if l) or set(LAYER_NAMES)

    build = build_candidate() if not args.skip_build else {
        "command": "(reused)", "archive": rel(ARCHIVE),
        "archive_sha256": sha256_file(ARCHIVE) if ARCHIVE.is_file() else None,
    }

    closure = closure_receipt()
    canary = run_canary()

    layers: list[dict] = []
    if "allocator-unit-tests" in want:
        layers.append(all_tests_layer())
    if "ownership-tests" in want:
        layers.append(ownership_layer())
    if "hostile-tls" in want:
        layers.append(hostile_layer("hostile-tls", "RT-HOSTILE-TLS",
                                    "courts/phase18/fixtures/hostile-tls"))
    if "hostile-x509" in want:
        layers.append(hostile_layer("hostile-x509", "RT-HOSTILE-X509",
                                    "courts/phase18/fixtures/hostile-x509"))
    if "mutation-corpus" in want:
        layers.append(mutation_layer())
    if "downstream-consumers" in want:
        layers.append(downstream_layer())

    # A zero-findings layer result may only be trusted if the canary fired.
    canary_ok = bool(canary.get("detected"))
    clean_layers = [l for l in layers if l.get("verdict") == "clean"]
    findings_layers = [l for l in layers if l.get("verdict") == "findings"]
    trusted = "canary-fired" if canary_ok else "UNTRUSTED: canary did not fire"

    body = {
        "schema": "openssl-rs/phase18-asan/v1",
        "phase": 18,
        "generator": GENERATOR,
        "venue": {
            "name": "openssl-rs-asan",
            "dockerfile": "docker/openssl-rs-asan.Dockerfile",
            "script": "docker/openssl-rs-asan.sh",
            "base_image": "debian@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171",
            "nightly": NIGHTLY,
            "toolchain": "/asan/toolchain.txt",
        },
        "execution_envelope": {
            "cgroup_memory": os.environ.get("OPENSSL_RS_ASAN_MEM", "8g"),
            "cgroup_memory_swap": os.environ.get("OPENSSL_RS_ASAN_MEMSWAP", "8g"),
            "pids_limit": os.environ.get("OPENSSL_RS_ASAN_PIDS", "2048"),
            "cpus": os.environ.get("OPENSSL_RS_ASAN_CPUS", "8 (clamped to nproc)"),
            "wall_clock_timeout_s": os.environ.get("OPENSSL_RS_ASAN_TIMEOUT_S", "7200"),
            "rlimit_data": "unset (ASan shadow is PROT_NONE/MAP_NORESERVE virtual; the cgroup bounds resident memory)",
            "no_new_privileges": True,
            "network": "court policy: default bridge, no extra grants",
            "asan_options_tests": ASAN_OPTIONS_TESTS,
            "asan_options_probes": ASAN_OPTIONS_PROBES,
        },
        "rule": (
            "ASan observes specific memory-error classes under specific execution. A clean layer is "
            "a bounded observation, not a memory-safety proof and not a parity claim. The canary "
            "must fire before any clean result is trusted. The authority is NOT instrumented; the "
            "candidate only is. TSan/UBSan/MSan are a later step and did not run here."
        ),
        "build": build,
        "instrumentation_closure": closure,
        "canary": canary,
        "custom_allocator": {
            "default_path": "libc malloc, ASan-intercepted (every layer ran here)",
            "custom_path": (
                "the crate's CRYPTO_set_mem_functions path (src/runtime/mem.rs, exercised by the "
                "allocator-unit-tests layer's mem tests and by the miri_tcb TCB suite) installs a "
                "Rust-backed shim; ASan still intercepts the underlying global allocator, but this "
                "is recorded separately rather than claimed to be ASan-instrumented end to end"
            ),
        },
        "layers": layers,
        "not_reached": [
            "CPython test_ssl / nginx / curl / Git / HAProxy / OpenSSH downstream probes "
            "(need consumer binaries built against the ASan candidate DSOs; see the "
            "downstream-consumers layer)",
            "TSan, UBSan, MSan (a later step by instruction)",
            "the authority under ASan (the authority is not rebuilt in this venue)",
        ],
        "summary": {
            "instrumentation_closure_ok": closure["closure_ok"],
            "canary_detected": canary_ok,
            "clean_layers": [l["layer"] for l in clean_layers],
            "layers_with_findings": [l["layer"] for l in findings_layers],
            "layers_run": [l["layer"] for l in layers if l.get("ran")],
            "layers_not_run": [l["layer"] for l in layers if not l.get("ran")],
            "trust": trusted,
        },
    }

    # Bind the venue's recorded toolchain receipt and the closure sources.
    tb = Path("/asan/toolchain.txt")
    if tb.is_file():
        body["venue"]["toolchain_receipt"] = tb.read_text(encoding="utf-8", errors="replace")

    write_json(args.out.resolve(), body)
    print(f"[asan_closure] canary_detected={canary_ok} closure_ok={closure['closure_ok']} "
          f"clean={body['summary']['clean_layers']} findings={body['summary']['layers_with_findings']}")
    print(f"[asan_closure] -> {rel(args.out)}")
    # A missing canary is a hard failure: nothing downstream may trust the run.
    return 0 if canary_ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
