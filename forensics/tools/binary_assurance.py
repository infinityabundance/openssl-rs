#!/usr/bin/env python3
"""binary_assurance.py -- record the binary TCB and check per-target claims.

Two modes, both fail closed:

    record   probe the live toolchain and venue, write the trusted-computing-base
             inventory (`evidence/etp-t6/TCB.json`) and its canonical digest;
    check    validate the recorded TCB and the claim matrix
             (`evidence/etp-t6/CLAIM-MATRIX.json`), refusing every claim that
             cannot be bound to an artefact, a target, a build profile and the
             recorded TCB for that build.

What `record` does with an unobtainable fact
--------------------------------------------
A version or digest that cannot be read is written as `UNKNOWN` together with
the command that would obtain it. It is never invented, and a probe that fails
is not allowed to look like a probe that succeeded: the component carries
`check.checked = false` and the exact failure text.

What `check` refuses
--------------------
One refusal per named condition, each naming the claim, the target and the
field:

  BA_CLAIM_TARGET_UNBOUND          a claim asserted for a target/build with no
                                   artefact at that target (rule 1);
  BA_CROSS_TARGET_INHERITANCE      a claim whose evidence is bound to a different
                                   target (rule 1);
  BA_CROSS_PROFILE_INHERITANCE     a claim whose evidence is bound to a different
                                   build profile (rule 1);
  BA_ARTEFACT_DIGEST_MISMATCH      a claim whose artefact digest/build id differs
                                   from the recorded build's artefact (rule 2);
  BA_TCB_MISMATCH                  a build or claim whose TCB digest differs from
                                   the recorded TCB (rule 3);
  BA_SOURCE_IDENTITY_MISMATCH      a build whose declared source identity differs
                                   from the artefact's recorded build source with
                                   no stated explanation (rule 4);
  BA_SOURCE_IDENTITY_UNKNOWN       the same, where both sides are `UNKNOWN` and
                                   no explanation is stated (rule 4);
  BA_FORBIDDEN_CLAIM               any status or modality text that asserts a
                                   binary/source correspondence (rule 5). The
                                   vocabulary that would permit such a status is
                                   not part of this checker.

A claim marked `asserted: false` is a recorded gap, not a pass: it must carry
`status` in `UNBINDABLE`/`NONE`, `instrument` `NONE`, an empty artefact binding
and a non-empty `unbindable_reason`.

Exit status: 0 only when every check passed; 1 for any refusal; 2 for a usage
error. Output is one sorted JSON document on stdout and one
`REFUSED <code> claim=<id> target=<triple> field=<field>: <detail>` line per
refusal on stderr.

What this does not do
---------------------
It does not decide that a claim is true, that a reproducible build implements
its source, or that any target inherits another target's evidence. A record is a
statement of what was observed and which artefact bore it.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TCB = REPO_ROOT / "evidence" / "etp-t6" / "TCB.json"
DEFAULT_MATRIX = REPO_ROOT / "evidence" / "etp-t6" / "CLAIM-MATRIX.json"

TCB_SCHEMA = "openssl-rs/etp-t6/tcb/1"
MATRIX_SCHEMA = "openssl-rs/etp-t6/claim-matrix/1"

# The checker has no positive status for a source-to-binary correspondence.  A
# document that uses one is refused rather than reinterpreted.
FORBIDDEN_TERMS = (
    "BINARY_REFINEMENT_VERIFIED",
    "REFINEMENT_VERIFIED",
    "SOURCE_BINARY_EQUIVALENT",
    "BINARY_EQUIVALENT_TO_SOURCE",
    "MACHINE_CODE_REFINES_SOURCE",
    "SOURCE_TO_BINARY_VERIFIED",
)

ALLOWED_STATUSES = {
    "IDENTICAL",
    "AGREEMENT",
    "BRANCH_SHAPE_OBSERVED",
    "SCOPED_OBSERVATION",
    "NO_LEAKAGE_EVIDENCE",
    "NOT_ESTABLISHED",
}

UNBOUND_STATUSES = {"UNBINDABLE", "NONE"}

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2


@dataclass(frozen=True)
class Refusal:
    code: str
    claim: str
    target: str
    field: str
    detail: str

    def line(self) -> str:
        return (
            f"REFUSED {self.code} claim={self.claim} target={self.target} "
            f"field={self.field}: {self.detail}"
        )


class DocumentError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# deterministic serialisation


def canonical(payload) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest_bytes(payload) -> str:
    return hashlib.sha256(canonical(payload)).hexdigest()


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def load_json_strict(path: Path):
    """Load a document that must have exactly one meaning."""

    def pairs_hook(pairs):
        seen = set()
        for key, _ in pairs:
            if key in seen:
                raise DocumentError(
                    "BA_JSON_DUPLICATE_KEY", f"{path}: duplicate key {key!r}"
                )
            seen.add(key)
        return dict(pairs)

    def reject_constant(token):
        raise DocumentError("BA_JSON_NON_FINITE", f"{path}: non-finite number {token}")

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise DocumentError("BA_DOC_UNREADABLE", f"{path}: {exc}")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise DocumentError("BA_DOC_UNREADABLE", f"{path}: not UTF-8: {exc}")
    except json.JSONDecodeError as exc:
        raise DocumentError("BA_DOC_UNREADABLE", f"{path}: {exc}")


# ---------------------------------------------------------------------------
# probing


def run_probe(argv: list[str], timeout: int = 20) -> tuple[int | None, str]:
    """Return (exit status or None, combined text). Absence is an outcome."""

    try:
        completed = subprocess.run(
            argv,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"{type(exc).__name__}: {exc}"
    text = (completed.stdout or "") + (completed.stderr or "")
    return completed.returncode, text.strip()


def which_real(tool: str) -> tuple[str | None, str | None]:
    found = shutil.which(tool)
    if not found:
        return None, None
    try:
        return found, str(Path(found).resolve())
    except OSError:
        return found, None


def version_line(argv: list[str]) -> str:
    status, text = run_probe(argv)
    if status is None or not text:
        return "UNKNOWN"
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return "UNKNOWN"


def file_digest(path: str | None) -> dict:
    if not path:
        return {
            "algorithm": "sha256",
            "value": "UNKNOWN",
            "path": None,
            "method": "resolve the path with `command -v` and run `sha256sum`",
        }
    candidate = Path(path)
    try:
        value = sha256_file(candidate)
    except OSError as exc:
        return {
            "algorithm": "sha256",
            "value": "UNKNOWN",
            "path": path,
            "method": f"`sha256sum {path}` (failed: {exc})",
        }
    return {
        "algorithm": "sha256",
        "value": value,
        "path": path,
        "method": "sha256 of the resolved file",
    }


def unknown_digest(method: str) -> dict:
    return {"algorithm": "sha256", "value": "UNKNOWN", "path": None, "method": method}


def component(
    ident: str,
    kind: str,
    name: str,
    version: str,
    digest: dict,
    could_invalidate: str,
    checked: bool,
    mechanism: str,
    evidence: str,
) -> dict:
    return {
        "id": ident,
        "kind": kind,
        "name": name,
        "version": version,
        "digest": digest,
        "could_invalidate": could_invalidate,
        "check": {
            "checked": checked,
            "mechanism": mechanism,
            "evidence": evidence,
        },
    }


def tool_component(
    ident: str,
    kind: str,
    name: str,
    tool: str,
    version_argv: list[str],
    could_invalidate: str,
    mechanism: str,
) -> dict:
    found, real = which_real(tool)
    version = version_line(version_argv) if found else "UNKNOWN"
    digest = file_digest(real)
    return component(
        ident,
        kind,
        name,
        version,
        digest,
        could_invalidate,
        checked=bool(found),
        mechanism=mechanism if found else "NONE",
        evidence=(
            f"`command -v {tool}` -> {found}; resolved {real}; `{version_argv[0]} --version`"
            if found
            else f"`command -v {tool}` found nothing"
        ),
    )


def source_profile(root: Path) -> dict:
    cargo = root / "Cargo.toml"
    try:
        data = tomllib.loads(cargo.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        data = {}
    release = (data.get("profile") or {}).get("release") or {}
    return {
        "id": "release",
        "opt_level": release.get("opt-level", 3),
        "codegen_units": release.get("codegen-units", 16),
        "lto": release.get("lto", False),
        "overflow_checks": release.get("overflow-checks", False),
        "panic": release.get("panic", "unwind"),
        "debug_assertions": release.get("debug-assertions", False),
        "debug": release.get("debug", 0),
        "strip": release.get("strip", "none"),
        "target": "x86_64-unknown-linux-gnu",
        "rustflags": os.environ.get("RUSTFLAGS", "not set"),
    }


def dispatch_scan(root: Path) -> dict:
    """Check the source for runtime CPU-feature dispatch and explicit target flags."""

    runtime_hits: list[str] = []
    cfg_hits = 0
    src = root / "src"
    if src.is_dir():
        for path in sorted(src.rglob("*.rs")):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "is_x86_feature_detected" in text or "is_aarch64_feature_detected" in text:
                runtime_hits.append(str(path.relative_to(root)))
            cfg_hits += text.count('cfg(target_arch = "x86_64")')
    flag_sources = [root / "Cargo.toml", root / "rust-toolchain.toml", root / ".cargo" / "config.toml"]
    explicit_flags: list[str] = []
    for path in flag_sources:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for marker in ("target-cpu", "target-feature"):
            if marker in text:
                explicit_flags.append(f"{path.relative_to(root)}:{marker}")
    return {
        "runtime_feature_detection_sites": runtime_hits,
        "compile_time_target_arch_sites": cfg_hits,
        "explicit_target_flags": explicit_flags,
    }


def panic_scan(root: Path) -> dict:
    profile = source_profile(root)
    ffi = root / "src" / "ffi" / "mod.rs"
    try:
        text = ffi.read_text(encoding="utf-8")
    except OSError:
        text = ""
    return {
        "profile_panic": profile["panic"],
        "guard_ffi_present": "fn guard_ffi" in text,
        "catch_unwind_present": "catch_unwind" in text,
        "assert_unwind_safe_present": "AssertUnwindSafe" in text,
    }


_PMU_CACHE: str | None = None


def pmu_probe() -> str:
    global _PMU_CACHE
    if _PMU_CACHE is None:
        status, text = run_probe(["perf", "stat", "-e", "cycles", "true"], timeout=20)
        if status is None:
            _PMU_CACHE = "UNKNOWN: perf is absent or unexecutable"
        elif "<not supported>" in text or "not supported" in text:
            _PMU_CACHE = "absent: `perf stat -e cycles true` reports `<not supported>`"
        else:
            _PMU_CACHE = (
                "UNKNOWN: perf did not report an unsupported event; see "
                "INSTRUMENT-QUALIFICATION.md"
            )
    return _PMU_CACHE


def cpu_facts() -> dict:
    model = "UNKNOWN"
    flags = "UNKNOWN"
    hypervisor = "UNKNOWN"
    try:
        text = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    for line in text.splitlines():
        if model == "UNKNOWN" and line.lower().startswith("model name"):
            model = line.split(":", 1)[-1].strip()
        elif flags == "UNKNOWN" and line.lower().startswith("flags"):
            flags = line.split(":", 1)[-1].strip()
        if model != "UNKNOWN" and flags != "UNKNOWN":
            break
    if flags != "UNKNOWN":
        tokens = flags.split()
        hypervisor = "present" if "hypervisor" in tokens else "absent"
    return {
        "model": model,
        "flags": flags,
        "flags_sha256": (
            hashlib.sha256(flags.encode("utf-8")).hexdigest() if flags != "UNKNOWN" else "UNKNOWN"
        ),
        "hypervisor": hypervisor,
    }


_KERNEL_CACHE: str | None = None


def kernel_release() -> str:
    global _KERNEL_CACHE
    if _KERNEL_CACHE is None:
        status, text = run_probe(["uname", "-r"])
        _KERNEL_CACHE = (
            text.splitlines()[0].strip() if status == 0 and text else platform.release()
        )
    return _KERNEL_CACHE


def runtime_artifacts(sysroot: str | None) -> dict:
    result = {"std_rlib": None, "panic_unwind_rlib": None}
    if not sysroot:
        return result
    libdir = Path(sysroot) / "lib" / "rustlib" / "x86_64-unknown-linux-gnu" / "lib"
    for key, pattern in (
        ("std_rlib", "libstd-*.rlib"),
        ("panic_unwind_rlib", "libpanic_unwind-*.rlib"),
    ):
        matches = sorted(libdir.glob(pattern)) if libdir.is_dir() else []
        if matches:
            result[key] = {"path": str(matches[0]), "digest": file_digest(str(matches[0]))}
    return result


def build_tcb(root: Path, recorded_at: str) -> dict:
    sysroot_status, sysroot_text = run_probe(["rustc", "--print", "sysroot"])
    sysroot = sysroot_text.splitlines()[0].strip() if sysroot_status == 0 and sysroot_text else None
    rustc_vv_status, rustc_vv = run_probe(["rustc", "-vV"])
    rustc_commit = "UNKNOWN"
    llvm_version = "UNKNOWN"
    if rustc_vv_status == 0:
        for line in rustc_vv.splitlines():
            if line.startswith("commit-hash:"):
                rustc_commit = line.split(":", 1)[1].strip()
            elif line.startswith("LLVM version:"):
                llvm_version = line.split(":", 1)[1].strip()

    rustc_binary = file_digest(str(Path(sysroot) / "bin" / "rustc")) if sysroot else unknown_digest(
        "`rustc --print sysroot` then `sha256sum <sysroot>/bin/rustc`"
    )
    llvm_paths: list[Path] = []
    llvm_digest = unknown_digest(
        "`ls <sysroot>/lib/libLLVM*` then hash the resolved file"
    )
    if sysroot:
        libdir = Path(sysroot) / "lib"
        if libdir.is_dir():
            llvm_paths = sorted({p.resolve() for p in libdir.glob("libLLVM*") if p.is_file()})
        if llvm_paths:
            llvm_digest = file_digest(str(llvm_paths[0]))

    _, rustup_path = which_real("rustup")
    rustup_digest = file_digest(rustup_path)
    _, cargo_path = which_real("cargo")
    cargo_digest = file_digest(cargo_path)

    runtime = runtime_artifacts(sysroot)
    std_digest = (
        runtime["std_rlib"]["digest"]
        if runtime.get("std_rlib")
        else unknown_digest("`ls <sysroot>/lib/rustlib/x86_64-unknown-linux-gnu/lib/libstd-*.rlib`")
    )
    panic_unwind_digest = (
        runtime["panic_unwind_rlib"]["digest"]
        if runtime.get("panic_unwind_rlib")
        else unknown_digest(
            "`ls <sysroot>/lib/rustlib/x86_64-unknown-linux-gnu/lib/libpanic_unwind-*.rlib`"
        )
    )

    libc_candidates = ["/lib/x86_64-linux-gnu/libc.so.6", "/lib64/libc.so.6"]
    libc_path = next((p for p in libc_candidates if Path(p).is_file()), None)
    loader_candidates = [
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    ]
    loader_path = None
    for candidate in loader_candidates:
        if Path(candidate).exists():
            loader_path = str(Path(candidate).resolve())
            break
    libgcc_candidates = [
        "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
        "/lib/x86_64-linux-gnu/libgcc_s.so.1",
    ]
    libgcc_path = next((p for p in libgcc_candidates if Path(p).is_file()), None)

    dispatch = dispatch_scan(root)
    panic = panic_scan(root)
    cpu = cpu_facts()

    components = [
        component(
            "rustc",
            "compiler",
            "rustc toolchain binary (LLVM backend)",
            version_line(["rustc", "-vV"]),
            rustc_binary,
            "A different rustc changes every emitted instruction; optimisation "
            "decisions and constant-time code shape can change between patch releases.",
            checked=bool(sysroot),
            mechanism="`rustc -vV` plus sha256 of `<sysroot>/bin/rustc`",
            evidence=f"commit-hash {rustc_commit}; sysroot {sysroot}",
        ),
        component(
            "rustc-commit",
            "compiler-identity",
            "rustc source commit",
            f"commit-hash: {rustc_commit}",
            unknown_digest("the commit is an identity string, not a file digest"),
            "A different rustc commit invalidates every code-generation observation.",
            checked=rustc_commit != "UNKNOWN",
            mechanism="`rustc -vV`",
            evidence=f"commit-hash {rustc_commit}",
        ),
        component(
            "llvm",
            "code-generator",
            "LLVM shipped with rustc",
            f"LLVM version: {llvm_version}",
            llvm_digest,
            "LLVM lowering, scheduling and inlining decide the emitted instruction "
            "shape; an LLVM change can add a branch or remove a cmov.",
            checked=llvm_version != "UNKNOWN",
            mechanism="`rustc -vV` for the version; sha256 of the resolved libLLVM",
            evidence=f"LLVM version {llvm_version}; {len(llvm_paths)} libLLVM file(s)",
        ),
        component(
            "rustup",
            "toolchain-manager",
            "rustup shim and toolchain selector",
            version_line(["rustup", "--version"]),
            rustup_digest,
            "The shim selects which toolchain runs; a replaced shim can run a "
            "different compiler under the recorded version string.",
            checked=rustup_path is not None,
            mechanism="`rustup --version` plus sha256 of the resolved shim",
            evidence=f"resolved {rustup_path}",
        ),
        component(
            "cargo",
            "build-driver",
            "cargo",
            version_line(["cargo", "-V"]),
            cargo_digest,
            "cargo resolves features, profiles and build scripts; a different "
            "cargo can select different inputs.",
            checked=cargo_path is not None,
            mechanism="`cargo -V` plus sha256 of the resolved binary",
            evidence=f"resolved {cargo_path}",
        ),
        tool_component(
            "cc",
            "compiler-driver",
            "C compiler driver used for the distribution link and harnesses",
            "cc",
            ["cc", "--version"],
            "The distribution DSO is linked by cc; its driver decides startup "
            "objects, PIE and linker flags.",
            "`cc --version` plus sha256 of the resolved binary",
        ),
        tool_component(
            "ld",
            "linker",
            "GNU ld",
            "ld",
            ["ld", "--version"],
            "The linker lays out sections and resolves symbol versions; a "
            "different linker changes the artefact digest and can change "
            "indirect-call resolution.",
            "`ld --version` plus sha256 of the resolved binary",
        ),
        tool_component(
            "as",
            "assembler",
            "GNU assembler",
            "as",
            ["as", "--version"],
            "Inline assembly and compiler-emitted assembly are encoded by as; a "
            "different assembler can encode a different instruction.",
            "`as --version` plus sha256 of the resolved binary",
        ),
        tool_component(
            "ar",
            "archiver",
            "GNU ar",
            "ar",
            ["ar", "--version"],
            "The crate archive is produced by ar; a different ar changes member "
            "order, metadata and the archive digest.",
            "`ar --version` plus sha256 of the resolved binary",
        ),
        tool_component(
            "objdump",
            "disassembler",
            "GNU objdump, used by the branch audit",
            "objdump",
            ["objdump", "--version"],
            "The branch audit sees instructions only through objdump; a different "
            "decoder can change the counted branches and cmovs.",
            "`objdump --version` plus sha256 of the resolved binary",
        ),
        tool_component(
            "readelf",
            "elf-reader",
            "GNU readelf, used for build-id and NEEDED records",
            "readelf",
            ["readelf", "--version"],
            "Build-id and dependency records are read through readelf; a "
            "different reader can misreport the artefact identity.",
            "`readelf --version` plus sha256 of the resolved binary",
        ),
        tool_component(
            "python3",
            "verification-runtime",
            "Python interpreter running this checker",
            "python3",
            ["python3", "-V"],
            "The checker's own result is only as trustworthy as its interpreter; "
            "a different Python can change JSON and hashing behaviour.",
            "`python3 -V` plus sha256 of the resolved interpreter",
        ),
        component(
            "libc",
            "c-library",
            "GNU C library",
            version_line(["ldd", "--version"]),
            file_digest(libc_path),
            "libc supplies allocation, I/O, threading and the process start "
            "state; a different libc changes runtime behaviour even for the "
            "same DSO bytes.",
            checked=libc_path is not None,
            mechanism="`ldd --version` plus sha256 of the resolved libc",
            evidence=f"resolved {libc_path}",
        ),
        component(
            "dynamic-loader",
            "dynamic-loader",
            "ELF interpreter for x86-64",
            "UNKNOWN: the loader has no version command",
            file_digest(loader_path),
            "The loader resolves symbols and applies relocations; a different "
            "loader can bind a call to a different definition.",
            checked=loader_path is not None,
            mechanism="readlink of /lib64/ld-linux-x86-64.so.2 plus sha256",
            evidence=f"resolved {loader_path}",
        ),
        component(
            "libgcc-s",
            "runtime",
            "GCC unwind runtime",
            "UNKNOWN: libgcc_s has no version command",
            file_digest(libgcc_path),
            "The unwinder is the panic boundary's runtime dependency; a "
            "different unwinder changes what happens between a panic and the "
            "FFI guard.",
            checked=libgcc_path is not None,
            mechanism="sha256 of the resolved libgcc_s",
            evidence=f"resolved {libgcc_path}",
        ),
        component(
            "std",
            "rust-runtime",
            "Rust standard library",
            "as shipped with rustc 1.98.1",
            std_digest,
            "std supplies allocation, panicking and platform abstractions; a "
            "different std changes runtime behaviour.",
            checked=bool(runtime.get("std_rlib")),
            mechanism="sha256 of the resolved libstd rlib",
            evidence=str(runtime.get("std_rlib", {}).get("path", "UNKNOWN")),
        ),
        component(
            "panic-unwind",
            "rust-runtime",
            "Rust panic-unwind runtime",
            "as shipped with rustc 1.98.1",
            panic_unwind_digest,
            "The panic strategy and unwinder back `guard_ffi`; a different "
            "runtime changes whether a panic is caught or aborts.",
            checked=bool(runtime.get("panic_unwind_rlib")),
            mechanism="sha256 of the resolved libpanic_unwind rlib",
            evidence=str(runtime.get("panic_unwind_rlib", {}).get("path", "UNKNOWN")),
        ),
        component(
            "panic-boundary",
            "panic-boundary",
            "guard_ffi unwind boundary",
            f"panic={panic['profile_panic']}",
            unknown_digest(
                "the boundary is repository source (`src/ffi/mod.rs`), not a "
                "third-party artefact; its consuming runtime is recorded above"
            ),
            "A profile change from unwind to abort, or a weakened guard, makes "
            "the documented failure value unreachable.",
            checked=panic["guard_ffi_present"] and panic["catch_unwind_present"],
            mechanism="read the release profile and scan src/ffi/mod.rs for guard_ffi/catch_unwind",
            evidence=(
                f"panic={panic['profile_panic']}; guard_ffi={panic['guard_ffi_present']}; "
                f"catch_unwind={panic['catch_unwind_present']}"
            ),
        ),
        component(
            "cpu-dispatch",
            "cpu-dispatch",
            "CPU feature selection",
            (
                "compile-time cfg(target_arch) selection; "
                f"{len(dispatch['runtime_feature_detection_sites'])} runtime "
                "feature-detection site(s)"
            ),
            unknown_digest(
                "a dispatch mechanism has no file digest; its identity is the "
                "source scan plus the target flags"
            ),
            "A runtime feature test or an explicit target-cpu/target-feature "
            "can select different code than the audited baseline.",
            checked=not dispatch["runtime_feature_detection_sites"],
            mechanism=(
                "scan src/**.rs for is_x86_feature_detected/is_aarch64_feature_detected, "
                "count cfg(target_arch = \"x86_64\"), and scan Cargo.toml/"
                "rust-toolchain.toml/.cargo/config.toml for target-cpu/target-feature"
            ),
            evidence=(
                f"runtime sites={dispatch['runtime_feature_detection_sites']}; "
                f"cfg(target_arch) sites={dispatch['compile_time_target_arch_sites']}; "
                f"explicit flags={dispatch['explicit_target_flags']}"
            ),
        ),
        component(
            "cpu",
            "hardware",
            "CPU that executes the artefact",
            cpu["model"],
            {
                "algorithm": "sha256",
                "value": cpu["flags_sha256"],
                "path": "/proc/cpuinfo",
                "method": "sha256 of the flags string",
            },
            "A different CPU or microarchitecture can execute the same "
            "instruction stream with different timing and different feature "
            "availability.",
            checked=cpu["model"] != "UNKNOWN",
            mechanism="read /proc/cpuinfo",
            evidence=f"hypervisor={cpu['hypervisor']}; flags digest recorded",
        ),
        component(
            "kernel",
            "operating-system",
            "Linux kernel",
            kernel_release(),
            unknown_digest("`uname -r` reports a version, not a file; a kernel "
                          "digest would need the boot image path"),
            "The kernel supplies the loader interface, scheduling and the "
            "timestamp counter; a different kernel changes the venue.",
            checked=True,
            mechanism="`uname -r`",
            evidence=kernel_release(),
        ),
        component(
            "court-image",
            "venue",
            "Court container image",
            os.environ.get("OPENSSL_RS_COURT_IMAGE", "openssl-rs-court-tools:1"),
            unknown_digest(
                "obtain on the host with `docker image inspect --format '{{.Id}}' "
                "openssl-rs-court-tools:1`"
            ),
            "A different image changes every tool and library in this table at "
            "once.",
            checked=False,
            mechanism="NONE: the container cannot inspect its own image identity "
                      "without host access",
            evidence="image name recorded; content id not obtained",
        ),
        component(
            "perf-pmu",
            "venue",
            "Hardware performance counters",
            pmu_probe(),
            unknown_digest("a PMU exposes no file to hash; identity is the venue probe"),
            "Without a PMU, no cycle or branch-counter claim can be made; a "
            "venue change that adds one does not make old results comparable.",
            checked=pmu_probe().startswith("absent") or pmu_probe().startswith("present"),
            mechanism="`perf stat -e cycles true` and text inspection",
            evidence=pmu_probe(),
        ),
    ]

    components.sort(key=lambda item: item["id"])

    tcb = {
        "schema": TCB_SCHEMA,
        "item": "ETP-T6",
        "title": "Trusted computing base for binary-level assurance",
        "recorded_at_utc": recorded_at,
        "target_triple": "x86_64-unknown-linux-gnu",
        "venue": {
            "court_image": os.environ.get(
                "OPENSSL_RS_COURT_IMAGE", "openssl-rs-court-tools:1"
            ),
            "kernel_release": kernel_release(),
            "cpu_model": cpu["model"],
            "cpu_flags_sha256": cpu["flags_sha256"],
            "hypervisor": cpu["hypervisor"],
            "nproc": os.cpu_count(),
            "hardware_pmu": pmu_probe(),
        },
        "profile": source_profile(root),
        "dispatch": dispatch,
        "panic_boundary": panic,
        "components": components,
        "assumptions": [
            "The court image content id is not recorded; the image name is a "
            "declared venue, not a verified identity.",
            "The CPU microcode revision is not recorded; only the model and the "
            "flag set are.",
            "A component with digest UNKNOWN participates in the TCB digest by "
            "its recorded version string and check state, not by bytes.",
        ],
    }
    tcb["tcb_digest"] = tcb_digest(tcb)
    return tcb


def tcb_identity(tcb: dict) -> dict:
    """The canonical part of a TCB record that a build binds to."""

    venue = tcb.get("venue") or {}
    components = []
    for item in sorted(tcb.get("components") or [], key=lambda entry: entry.get("id", "")):
        components.append(
            {
                "id": item.get("id"),
                "kind": item.get("kind"),
                "version": item.get("version"),
                "digest": (item.get("digest") or {}).get("value"),
                "checked": (item.get("check") or {}).get("checked"),
                "mechanism": (item.get("check") or {}).get("mechanism"),
            }
        )
    return {
        "schema": tcb.get("schema"),
        "target_triple": tcb.get("target_triple"),
        "venue": {
            "court_image": venue.get("court_image"),
            "kernel_release": venue.get("kernel_release"),
            "cpu_model": venue.get("cpu_model"),
            "cpu_flags_sha256": venue.get("cpu_flags_sha256"),
            "hypervisor": venue.get("hypervisor"),
            "hardware_pmu": venue.get("hardware_pmu"),
        },
        "profile": tcb.get("profile"),
        "components": components,
    }


def tcb_digest(tcb: dict) -> str:
    return digest_bytes(tcb_identity(tcb))


# ---------------------------------------------------------------------------
# checking


def walk_strings(payload, path="") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            child = f"{path}.{key}" if path else key
            found.extend(walk_strings(value, child))
    elif isinstance(payload, list):
        for index, value in enumerate(payload):
            found.extend(walk_strings(value, f"{path}[{index}]"))
    elif isinstance(payload, str):
        found.append((path, payload))
    return found


def forbidden_hits(document) -> list[tuple[str, str, str]]:
    hits: list[tuple[str, str, str]] = []
    for path, text in walk_strings(document):
        match = next((term for term in FORBIDDEN_TERMS if term in text), None)
        if match is not None:
            hits.append((path, match, text))
    return hits


def _as_list(value) -> list:
    return value if isinstance(value, list) else []


def _commit(identity) -> str:
    if isinstance(identity, dict):
        return str(identity.get("commit", "UNKNOWN"))
    return "UNKNOWN"


def check_documents(tcb: dict, matrix: dict, repo_root: Path) -> list[Refusal]:
    refusals: list[Refusal] = []

    def refuse(code, claim, target, field, detail) -> None:
        refusals.append(Refusal(code, str(claim), str(target), str(field), str(detail)))

    # ---- document shape ---------------------------------------------------
    if tcb.get("schema") != TCB_SCHEMA:
        refuse(
            "BA_SCHEMA",
            "-",
            "-",
            "schema",
            f"TCB schema is {tcb.get('schema')!r}, expected {TCB_SCHEMA!r}",
        )
    if matrix.get("schema") != MATRIX_SCHEMA:
        refuse(
            "BA_SCHEMA",
            "-",
            "-",
            "schema",
            f"matrix schema is {matrix.get('schema')!r}, expected {MATRIX_SCHEMA!r}",
        )

    # A document whose containers are not lists of objects cannot be checked;
    # refuse it here rather than crash in a later iteration.
    shape_ok = True
    components = tcb.get("components")
    if not isinstance(components, list) or any(
        not isinstance(entry, dict) for entry in components
    ):
        refuse("BA_DOC_SHAPE", "-", "-", "components", "must be a list of objects")
        shape_ok = False
    for key in ("builds", "claims"):
        value = matrix.get(key)
        if not isinstance(value, list) or any(
            not isinstance(entry, dict) for entry in value
        ):
            refuse("BA_DOC_SHAPE", "-", "-", key, "must be a list of objects")
            shape_ok = False
    if not shape_ok:
        return refusals

    seen_components: set[str] = set()
    for index, item in enumerate(_as_list(tcb.get("components"))):
        ident = item.get("id")
        if not ident:
            refuse("BA_TCB_COMPONENT", "-", "-", f"components[{index}].id", "missing id")
        elif ident in seen_components:
            refuse(
                "BA_TCB_COMPONENT",
                "-",
                "-",
                f"components[{index}].id",
                f"duplicate component id {ident!r}",
            )
        seen_components.add(ident)
        digest = (item.get("digest") or {}).get("value")
        if not digest:
            refuse(
                "BA_TCB_COMPONENT",
                "-",
                "-",
                f"components[{index}].digest.value",
                "no digest value (use UNKNOWN with a method)",
            )
        if digest == "UNKNOWN" and not (item.get("digest") or {}).get("method"):
            refuse(
                "BA_TCB_COMPONENT",
                "-",
                "-",
                f"components[{index}].digest.method",
                "UNKNOWN digest without the method that would obtain it",
            )
        check = item.get("check") or {}
        if not isinstance(check.get("checked"), bool):
            refuse(
                "BA_TCB_COMPONENT",
                "-",
                "-",
                f"components[{index}].check.checked",
                "check state must be a boolean",
            )

    recorded = tcb.get("tcb_digest")
    computed = tcb_digest(tcb)
    if recorded != computed:
        refuse(
            "BA_TCB_SELF_DIGEST",
            "-",
            "-",
            "tcb_digest",
            f"recorded {recorded!r} does not match the canonical digest {computed}",
        )

    # ---- refusal rule 5: forbidden vocabulary, anywhere -------------------
    # The scan is per claim and per build so a hit names the claim and target
    # it belongs to, rather than a document-relative JSON pointer only.
    for path, term, text in forbidden_hits(tcb):
        refuse(
            "BA_FORBIDDEN_CLAIM",
            "-",
            tcb.get("target_triple", "-"),
            f"TCB:{path}",
            f"forbidden status vocabulary {term!r} in {text!r}; no artefact bears it",
        )
    for index, entry in enumerate(_as_list(matrix.get("claims"))):
        for path, term, text in forbidden_hits(entry):
            refuse(
                "BA_FORBIDDEN_CLAIM",
                entry.get("id", f"<claim[{index}]>"),
                entry.get("target", "UNKNOWN"),
                f"CLAIM-MATRIX:claims[{index}].{path}",
                f"forbidden status vocabulary {term!r} in {text!r}; no artefact bears it",
            )
    other = {key: value for key, value in matrix.items() if key != "claims"}
    for path, term, text in forbidden_hits(other):
        refuse(
            "BA_FORBIDDEN_CLAIM",
            "-",
            "-",
            f"CLAIM-MATRIX:{path}",
            f"forbidden status vocabulary {term!r} in {text!r}; no artefact bears it",
        )

    # A build-level refusal names the first claim bound to that build, so a
    # refusal always carries a claim identifier where one exists.
    first_claim_for_build: dict[str, str] = {}
    for entry in _as_list(matrix.get("claims")):
        build_id = entry.get("build")
        if isinstance(build_id, str) and build_id not in first_claim_for_build:
            first_claim_for_build[build_id] = str(entry.get("id", "-"))

    # ---- builds -----------------------------------------------------------
    builds: dict[str, dict] = {}
    for index, build in enumerate(_as_list(matrix.get("builds"))):
        ident = build.get("id")
        if not ident:
            refuse("BA_BUILD_INCOMPLETE", "-", "-", f"builds[{index}].id", "missing id")
            continue
        if ident in builds:
            refuse(
                "BA_BUILD_DUPLICATE", "-", build.get("target", "-"), f"builds[{index}].id",
                f"duplicate build id {ident!r}",
            )
        builds[ident] = build
        for field in ("target", "abi"):
            if not build.get(field):
                refuse(
                    "BA_BUILD_INCOMPLETE", "-", build.get("target", "-"),
                    f"builds[{index}].{field}", "missing required field",
                )
        if not isinstance(build.get("profile"), dict) or not build["profile"].get("id"):
            refuse(
                "BA_BUILD_INCOMPLETE", "-", build.get("target", "-"),
                f"builds[{index}].profile", "missing profile object with an id",
            )
        if not isinstance(build.get("source_identity"), dict):
            refuse(
                "BA_BUILD_INCOMPLETE", "-", build.get("target", "-"),
                f"builds[{index}].source_identity", "missing source identity object",
            )
        if not build.get("tcb_basis"):
            refuse(
                "BA_BUILD_INCOMPLETE", "-", build.get("target", "-"),
                f"builds[{index}].tcb_basis", "missing stated TCB basis",
            )

        artefacts = _as_list(build.get("artefacts"))
        claim_label = first_claim_for_build.get(ident, "-")
        if artefacts:
            if build.get("tcb_digest") != computed:
                refuse(
                    "BA_TCB_MISMATCH",
                    claim_label,
                    build.get("target", "-"),
                    f"builds[{index}].tcb_digest",
                    f"build records {build.get('tcb_digest')!r}; TCB records {computed}",
                )
            else:
                recorded_profile = tcb.get("profile") or {}
                declared_profile = build.get("profile") or {}
                for key in (
                    "id",
                    "opt_level",
                    "codegen_units",
                    "lto",
                    "overflow_checks",
                    "panic",
                    "debug_assertions",
                ):
                    if (
                        key in declared_profile
                        and key in recorded_profile
                        and declared_profile[key] != recorded_profile[key]
                    ):
                        refuse(
                            "BA_TCB_MISMATCH",
                            claim_label,
                            build.get("target", "-"),
                            f"builds[{index}].profile.{key}",
                            f"build declares {declared_profile[key]!r}; the recorded "
                            f"TCB profile records {recorded_profile[key]!r}",
                        )
            explanation = str(build.get("source_explanation") or "").strip()
            row_source = _commit(build.get("source_identity"))
            for art_index, artefact in enumerate(artefacts):
                built_from = str(artefact.get("built_from_source", "UNKNOWN"))
                if built_from != row_source:
                    code = (
                        "BA_SOURCE_IDENTITY_UNKNOWN"
                        if built_from == "UNKNOWN" or row_source == "UNKNOWN"
                        else "BA_SOURCE_IDENTITY_MISMATCH"
                    )
                    if not explanation:
                        refuse(
                            code,
                            claim_label,
                            build.get("target", "-"),
                            f"builds[{index}].artefacts[{art_index}].built_from_source",
                            f"artefact built from {built_from!r}, build row states "
                            f"{row_source!r}, and no source_explanation is given",
                        )
                if not artefact.get("sha256"):
                    refuse(
                        "BA_ARTEFACT_DIGEST_MISMATCH",
                        claim_label,
                        build.get("target", "-"),
                        f"builds[{index}].artefacts[{art_index}].sha256",
                        "artefact has no sha256",
                    )
        else:
            if build.get("tcb_digest") not in (None, "UNRECORDED", "UNKNOWN"):
                refuse(
                    "BA_BUILD_INCOMPLETE",
                    "-",
                    build.get("target", "-"),
                    f"builds[{index}].tcb_digest",
                    "a build with no artefact must not claim a bound TCB digest",
                )

    # ---- claims -----------------------------------------------------------
    claims_seen: set[str] = set()
    for index, claim in enumerate(_as_list(matrix.get("claims"))):
        ident = str(claim.get("id") or f"<claim[{index}]>")
        target = str(claim.get("target", "UNKNOWN"))
        if ident in claims_seen:
            refuse("BA_CLAIM_DUPLICATE", ident, target, f"claims[{index}].id", "duplicate claim id")
        claims_seen.add(ident)

        status = claim.get("status")
        asserted = claim.get("asserted")
        instrument = claim.get("instrument")
        if not isinstance(asserted, bool):
            refuse("BA_CLAIM_INCOMPLETE", ident, target, f"claims[{index}].asserted",
                   "asserted must be a boolean")
            asserted = False

        if status not in ALLOWED_STATUSES and status not in UNBOUND_STATUSES:
            refuse(
                "BA_STATUS_UNKNOWN",
                ident,
                target,
                f"claims[{index}].status",
                f"status {status!r} is not in the checker's vocabulary",
            )

        if not asserted:
            if status not in UNBOUND_STATUSES:
                refuse(
                    "BA_UNBOUND_ASSERTED",
                    ident,
                    target,
                    f"claims[{index}].status",
                    f"unasserted claim carries status {status!r}",
                )
            if instrument != "NONE":
                refuse(
                    "BA_UNBOUND_ASSERTED",
                    ident,
                    target,
                    f"claims[{index}].instrument",
                    f"unasserted claim names instrument {instrument!r}; only NONE is admissible",
                )
            if not str(claim.get("unbindable_reason") or "").strip():
                refuse(
                    "BA_CLAIM_INCOMPLETE",
                    ident,
                    target,
                    f"claims[{index}].unbindable_reason",
                    "an unasserted claim must state why it cannot be bound",
                )
            if claim.get("artefact") not in (None, {}, {"id": "NONE"}):
                refuse(
                    "BA_UNBOUND_ASSERTED",
                    ident,
                    target,
                    f"claims[{index}].artefact",
                    "an unasserted claim must not carry an artefact binding",
                )
            continue

        if instrument in (None, "", "NONE"):
            refuse(
                "BA_CLAIM_TARGET_UNBOUND",
                ident,
                target,
                f"claims[{index}].instrument",
                "asserted claim has no instrument or proof bearing on it",
            )
        if status in UNBOUND_STATUSES:
            refuse(
                "BA_UNBOUND_ASSERTED",
                ident,
                target,
                f"claims[{index}].status",
                f"asserted claim carries unbound status {status!r}",
            )

        build_id = claim.get("build")
        build = builds.get(build_id) if isinstance(build_id, str) else None
        if build is None:
            refuse(
                "BA_CLAIM_BUILD_UNKNOWN",
                ident,
                target,
                f"claims[{index}].build",
                f"build {build_id!r} is not in the matrix",
            )
            continue

        # Rule 1: the claim's target and profile must be the build's, and the
        # build must have an artefact at that target.
        if build.get("target") != claim.get("target"):
            refuse(
                "BA_CROSS_TARGET_INHERITANCE",
                ident,
                target,
                f"claims[{index}].target",
                f"build {build_id!r} is for {build.get('target')!r}",
            )
        profile = build.get("profile") or {}
        if profile.get("id") != claim.get("profile"):
            refuse(
                "BA_CROSS_PROFILE_INHERITANCE",
                ident,
                target,
                f"claims[{index}].profile",
                f"build {build_id!r} is profile {profile.get('id')!r}",
            )
        if not _as_list(build.get("artefacts")):
            refuse(
                "BA_CLAIM_TARGET_UNBOUND",
                ident,
                target,
                f"claims[{index}].build",
                f"build {build_id!r} records no artefact at this target",
            )

        # Rule 1, evidence side: the evidence must name the same target and
        # profile; otherwise the result was obtained elsewhere and is inherited.
        evidence = claim.get("evidence")
        if isinstance(evidence, dict):
            if evidence.get("target") != claim.get("target"):
                refuse(
                    "BA_CROSS_TARGET_INHERITANCE",
                    ident,
                    target,
                    f"claims[{index}].evidence.target",
                    f"evidence target is {evidence.get('target')!r}",
                )
            if evidence.get("profile") != claim.get("profile"):
                refuse(
                    "BA_CROSS_PROFILE_INHERITANCE",
                    ident,
                    target,
                    f"claims[{index}].evidence.profile",
                    f"evidence profile is {evidence.get('profile')!r}",
                )
            evidence_path = evidence.get("path")
            if evidence_path:
                resolved = (repo_root / evidence_path).resolve()
                if not resolved.is_file():
                    refuse(
                        "BA_EVIDENCE_MISSING",
                        ident,
                        target,
                        f"claims[{index}].evidence.path",
                        f"{evidence_path} does not exist",
                    )
                else:
                    actual = sha256_file(resolved)
                    if evidence.get("sha256") != actual:
                        refuse(
                            "BA_EVIDENCE_DIGEST_MISMATCH",
                            ident,
                            target,
                            f"claims[{index}].evidence.sha256",
                            f"recorded {evidence.get('sha256')!r}, file is {actual}",
                        )
        elif evidence is not None:
            refuse(
                "BA_CLAIM_INCOMPLETE",
                ident,
                target,
                f"claims[{index}].evidence",
                "evidence must be an object or null",
            )

        # Rule 2: the claim's artefact must be the build's artefact.
        binding = claim.get("artefact")
        if not isinstance(binding, dict):
            refuse(
                "BA_ARTEFACT_DIGEST_MISMATCH",
                ident,
                target,
                f"claims[{index}].artefact",
                "no artefact binding",
            )
        else:
            matching = [
                art
                for art in _as_list(build.get("artefacts"))
                if art.get("id") == binding.get("id")
            ]
            if not matching:
                refuse(
                    "BA_ARTEFACT_UNKNOWN",
                    ident,
                    target,
                    f"claims[{index}].artefact.id",
                    f"artefact {binding.get('id')!r} is not recorded for build {build_id!r}",
                )
            else:
                recorded_art = matching[0]
                if recorded_art.get("sha256") != binding.get("sha256"):
                    refuse(
                        "BA_ARTEFACT_DIGEST_MISMATCH",
                        ident,
                        target,
                        f"claims[{index}].artefact.sha256",
                        f"claim records {binding.get('sha256')!r}, build records "
                        f"{recorded_art.get('sha256')!r}",
                    )
                if binding.get("build_id") != recorded_art.get("build_id"):
                    refuse(
                        "BA_ARTEFACT_DIGEST_MISMATCH",
                        ident,
                        target,
                        f"claims[{index}].artefact.build_id",
                        f"claim records {binding.get('build_id')!r}, build records "
                        f"{recorded_art.get('build_id')!r}",
                    )
                if not binding.get("sha256") or binding.get("sha256") == "UNKNOWN":
                    refuse(
                        "BA_ARTEFACT_UNKNOWN",
                        ident,
                        target,
                        f"claims[{index}].artefact.sha256",
                        "asserted claim is not bound to a recorded digest",
                    )

        # Rule 3: the claim's TCB must be the build's, and the build's TCB must
        # be the recorded one.
        if claim.get("tcb_digest") != build.get("tcb_digest"):
            refuse(
                "BA_TCB_MISMATCH",
                ident,
                target,
                f"claims[{index}].tcb_digest",
                f"claim records {claim.get('tcb_digest')!r}, build records "
                f"{build.get('tcb_digest')!r}",
            )
        if build.get("tcb_digest") != computed:
            refuse(
                "BA_TCB_MISMATCH",
                ident,
                target,
                f"claims[{index}].build",
                f"build {build_id!r} records TCB {build.get('tcb_digest')!r}, "
                f"recorded TCB is {computed}",
            )

        # Rule 4: source identity binding is enforced on the build above; a
        # claim that names a different source than its build is refused here.
        if claim.get("source_identity") is not None:
            claim_source = _commit(claim.get("source_identity"))
            build_source = _commit(build.get("source_identity"))
            if claim_source != build_source:
                refuse(
                    "BA_SOURCE_IDENTITY_MISMATCH",
                    ident,
                    target,
                    f"claims[{index}].source_identity.commit",
                    f"claim states {claim_source!r}, build states {build_source!r}",
                )

    return refusals


def summarise(tcb: dict, matrix: dict, refusals: list[Refusal]) -> dict:
    claims = _as_list(matrix.get("claims"))
    asserted = [c for c in claims if c.get("asserted") is True]
    unasserted = [c for c in claims if c.get("asserted") is not True]
    return {
        "status": "REFUSED" if refusals else "PASS",
        "tcb_digest": tcb.get("tcb_digest"),
        "builds": len(_as_list(matrix.get("builds"))),
        "claims": len(claims),
        "asserted_claims": len(asserted),
        "unbound_claims": len(unasserted),
        "tools_checked": sum(
            1 for item in _as_list(tcb.get("components"))
            if (item.get("check") or {}).get("checked") is True
        ),
        "tools_unchecked": sorted(
            str(item.get("id"))
            for item in _as_list(tcb.get("components"))
            if (item.get("check") or {}).get("checked") is not True
        ),
        "refusals": [
            {
                "code": refusal.code,
                "claim": refusal.claim,
                "target": refusal.target,
                "field": refusal.field,
                "detail": refusal.detail,
            }
            for refusal in refusals
        ],
    }


# ---------------------------------------------------------------------------
# commands


def command_record(args) -> int:
    root = Path(args.repo_root).resolve()
    recorded_at = args.recorded_at
    if not recorded_at:
        epoch = os.environ.get("SOURCE_DATE_EPOCH")
        if epoch and epoch.isdigit():
            recorded_at = datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        else:
            recorded_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    tcb = build_tcb(root, recorded_at)
    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(tcb, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = {
        "status": "RECORDED",
        "path": str(out),
        "tcb_digest": tcb["tcb_digest"],
        "components": len(tcb["components"]),
        "unchecked": sorted(
            item["id"] for item in tcb["components"] if not item["check"]["checked"]
        ),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return EXIT_OK


def command_check(args) -> int:
    root = Path(args.repo_root).resolve()
    try:
        tcb = load_json_strict(Path(args.tcb))
        matrix = load_json_strict(Path(args.matrix))
    except DocumentError as exc:
        refusal = Refusal(exc.code, "-", "-", "document", exc.detail)
        print(refusal.line(), file=sys.stderr)
        print(json.dumps(summarise({}, {}, [refusal]), indent=2, sort_keys=True))
        return EXIT_REFUSED

    refusals = check_documents(tcb, matrix, root)
    for refusal in refusals:
        print(refusal.line(), file=sys.stderr)
    print(json.dumps(summarise(tcb, matrix, refusals), indent=2, sort_keys=True))
    return EXIT_OK if not refusals else EXIT_REFUSED


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Record the binary TCB and check per-target claim bindings."
    )
    parser.add_argument("--repo-root", default=str(REPO_ROOT), help="repository root")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    record = subparsers.add_parser("record", help="probe the live toolchain and write the TCB")
    record.add_argument("--out", default=str(DEFAULT_TCB), help="TCB output path")
    record.add_argument(
        "--recorded-at",
        default=None,
        help="fixed UTC timestamp (deterministic record); default is now or SOURCE_DATE_EPOCH",
    )
    record.set_defaults(handler=command_record)

    check = subparsers.add_parser("check", help="validate the TCB and claim matrix")
    check.add_argument("--tcb", default=str(DEFAULT_TCB), help="TCB input path")
    check.add_argument("--matrix", default=str(DEFAULT_MATRIX), help="claim matrix input path")
    check.set_defaults(handler=command_check)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
