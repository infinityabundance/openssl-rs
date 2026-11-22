#!/usr/bin/env python3
"""etp6_verify.py -- offline verifier for an ETP-6 reproduction package.

The package produced by forensics/tools/etp6_package.py carries this file and a
top-level `verify.sh`.  Everything the verifier reads is a relative path under
the unpacked package: no network, no host checkout, no private state.

The verifier never infers a pass from silence.  Each step reports one of:

    PASS      the step ran here and its contract held
    FAIL      the step ran here and its contract did not hold
    NOT_RUN   the step could not run, with the missing prerequisite named

Exit status is 0 only when every *required* step is PASS.  A NOT_RUN is never a
pass, including for an executable instrument control whose external tool is
absent (that control is reported NOT_RUN and is never reported PASS).

Usage:
    ./verify.sh                     # steps 1-5; reproducibility is deferred
    ./verify.sh --full              # also run the two-build reproducibility step
    ./verify.sh --only digests      # one step (used by the negative controls)
    ./verify.sh --list
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "MANIFEST.json"
FREEZE_GIT = ROOT / "freeze-git"

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_USAGE = 2

REQUIRED_STEPS = ("digests", "claims", "interop", "instruments", "docs")
ALL_STEPS = REQUIRED_STEPS + ("reproducibility",)

# Refusal codes from instrument_qualify.py that mean "the external tool this
# instrument names is not installed here".  A missing tool is NOT_RUN, never
# PASS; a tool that is present with the wrong identity remains a FAIL.
MISSING_TOOL_CODES = {"IQ_VERSION_COMMAND"}


class Step:
    def __init__(self, ident: str, title: str, required: bool = True) -> None:
        self.id = ident
        self.title = title
        self.required = required
        self.status = "NOT_RUN"
        self.reason = "not executed"
        self.details: list[str] = []

    def pass_(self, reason: str, details: list[str] | None = None) -> None:
        self.status = "PASS"
        self.reason = reason
        self.details = details or []

    def fail(self, reason: str, details: list[str] | None = None) -> None:
        self.status = "FAIL"
        self.reason = reason
        self.details = details or []

    def not_run(self, reason: str, details: list[str] | None = None) -> None:
        self.status = "NOT_RUN"
        self.reason = reason
        self.details = details or []


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json_strict(path: Path):
    def _object(pairs):
        seen = set()
        for key, _ in pairs:
            if key in seen:
                raise ValueError(f"duplicate JSON key {key!r} in {path}")
            seen.add(key)
        return dict(pairs)

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_object)


def git_env(gitdir: Path) -> dict:
    env = dict(os.environ)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_COUNT"] = "1"
    env["GIT_CONFIG_KEY_0"] = "safe.directory"
    env["GIT_CONFIG_VALUE_0"] = str(gitdir)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    return env


def run(cmd: list[str], cwd: Path | None = None, env: dict | None = None,
        timeout: int = 1800) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=str(cwd) if cwd else None, env=env, capture_output=True,
        text=True, errors="replace", timeout=timeout, check=False,
    )


def run_bytes(cmd: list[str], env: dict | None = None,
              timeout: int = 1800) -> subprocess.CompletedProcess:
    """Capture bytes: cited blobs can be binary (the linked DSOs are)."""
    return subprocess.run(
        cmd, env=env, capture_output=True, timeout=timeout, check=False,
    )


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


# ---------------------------------------------------------------------------
# step: digests and package integrity
# ---------------------------------------------------------------------------


def step_digests(step: Step, manifest: dict, full: bool) -> None:
    """Re-derive every packaged input digest and every cited evidence digest.

    A missing evidence/document/source input is a FAIL.  A missing *tool* is
    reported here and makes the step that owns it NOT_RUN; the absence is not
    silently treated as a digest match.
    """
    inputs = manifest.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        step.fail("MANIFEST has no input list")
        return

    missing_evidence: list[str] = []
    mismatched: list[str] = []
    missing_tools: list[str] = []
    checked = 0
    expected = {entry["path"]: entry for entry in inputs if isinstance(entry, dict)}

    for entry in inputs:
        if not isinstance(entry, dict) or not entry.get("path") or not entry.get("sha256"):
            step.fail("MANIFEST has a malformed input entry")
            return
        path = ROOT / entry["path"]
        if not path.is_file():
            if entry.get("role") == "tool":
                missing_tools.append(entry["path"])
            else:
                missing_evidence.append(entry["path"])
            continue
        actual = sha256_file(path)
        checked += 1
        if actual != entry["sha256"]:
            mismatched.append(f"{entry['path']}: {actual} != {entry['sha256']}")

    on_disk = {
        rel(p) for p in ROOT.rglob("*")
        if p.is_file()
        and rel(p) != "MANIFEST.json"
        and "__pycache__" not in p.parts
        and p.suffix != ".pyc"
    }
    unexpected = sorted(on_disk - set(expected))

    details: list[str] = []
    if missing_evidence:
        details.append(f"missing inputs: {len(missing_evidence)}")
        details.extend(f"  missing: {p}" for p in missing_evidence[:40])
    if mismatched:
        details.append(f"digest mismatches: {len(mismatched)}")
        details.extend(f"  {row}" for row in mismatched[:40])
    if missing_tools:
        details.append(f"missing tools (owning step is NOT_RUN): {', '.join(missing_tools)}")
    if unexpected:
        details.append(f"files present but not in MANIFEST: {len(unexpected)}")
        details.extend(f"  unexpected: {p}" for p in unexpected[:40])

    # Cited evidence digests: S identity from the frozen object store, the
    # historical identity from its named commit, E identity from the package.
    claims_path = ROOT / "evidence/etp/claims.json"
    cited_problems: list[str] = []
    cited_ok = 0
    declared_absent: list[str] = []
    if not claims_path.is_file():
        cited_problems.append("evidence/etp/claims.json is absent")
    elif not FREEZE_GIT.is_dir():
        cited_problems.append("freeze-git object store is absent")
    elif shutil.which("git") is None:
        cited_problems.append("git is absent, so the Git-bound digests cannot be re-derived")
    else:
        try:
            document = load_json_strict(claims_path)
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            document = None
            cited_problems.append(f"claims.json does not parse: {exc}")
        if isinstance(document, dict):
            env = git_env(FREEZE_GIT)
            source = document.get("source_identity", {})
            source_commit = source.get("commit") if isinstance(source, dict) else None
            for claim in document.get("claims", []):
                for evidence in claim.get("evidence", []):
                    path = evidence.get("path")
                    want = evidence.get("sha256")
                    identity = evidence.get("digest_identity")
                    if not isinstance(want, str):
                        if evidence.get("present") is False:
                            declared_absent.append(
                                f"{claim.get('id')}: {path} (present=false, "
                                f"reconstructable={evidence.get('reconstructable')})")
                        continue
                    actual = None
                    if identity == "S" and isinstance(source_commit, str):
                        proc = run_bytes(["git", "-C", str(FREEZE_GIT), "show",
                                          f"{source_commit}:{path}"], env=env,
                                         timeout=120)
                        if proc.returncode == 0:
                            actual = hashlib.sha256(proc.stdout).hexdigest()
                    elif identity == "historical":
                        match = re.search(r"\bat commit ([0-9a-f]{7,40})\b",
                                          str(evidence.get("note", "")))
                        if match:
                            proc = run_bytes(["git", "-C", str(FREEZE_GIT), "show",
                                              f"{match.group(1)}:{path}"], env=env,
                                             timeout=120)
                            if proc.returncode == 0:
                                actual = hashlib.sha256(proc.stdout).hexdigest()
                    elif identity == "E":
                        target = ROOT / path
                        if target.is_file():
                            actual = sha256_file(target)
                    if actual is None:
                        cited_problems.append(
                            f"{claim.get('id')}: cannot re-derive {path} "
                            f"under identity {identity!r}")
                    elif actual != want:
                        cited_problems.append(
                            f"{claim.get('id')}: {path} hashes to {actual[:16]}..., "
                            f"recorded {want[:16]}...")
                    else:
                        cited_ok += 1

    if cited_problems:
        details.append(f"cited evidence digests not re-derived: {len(cited_problems)}")
        details.extend(f"  {row}" for row in cited_problems[:40])
    if declared_absent:
        details.append("cited evidence declared absent by the claim set "
                       f"(not a digest re-derivation): {len(declared_absent)}")
        details.extend(f"  {row}" for row in declared_absent[:10])

    if missing_evidence or mismatched or cited_problems:
        step.fail(
            f"package integrity failed: {len(missing_evidence)} missing, "
            f"{len(mismatched)} mismatched, {len(cited_problems)} cited digests "
            f"unresolved", details)
        return
    if unexpected:
        step.fail(f"{len(unexpected)} files are present that MANIFEST.json does not "
                  "name", details)
        return
    step.pass_(
        f"{checked} packaged inputs re-derived, {cited_ok} cited evidence digests "
        + ("re-derived from the frozen object store"
           if cited_ok else "re-derived"),
        details)


# ---------------------------------------------------------------------------
# step: claim set
# ---------------------------------------------------------------------------


def step_claims(step: Step, manifest: dict) -> None:
    tool = ROOT / "forensics/tools/etp_claims.py"
    document = ROOT / "evidence/etp/claims.json"
    schema = ROOT / "evidence/etp/claim.schema.json"
    if not tool.is_file():
        step.not_run("forensics/tools/etp_claims.py is absent")
        return
    if shutil.which("git") is None:
        step.not_run("git is absent; the Git-bound tree check cannot run")
        return
    if not FREEZE_GIT.is_dir():
        step.not_run("freeze-git object store is absent")
        return
    if not document.is_file() or not schema.is_file():
        step.not_run("the claim document or schema is absent")
        return
    proc = run([sys.executable, str(tool), "validate",
                "--document", str(document), "--schema", str(schema),
                "--repo-root", str(FREEZE_GIT)],
               cwd=ROOT, env=git_env(FREEZE_GIT))
    details = [proc.stdout.strip()[-2000:]]
    if proc.stderr.strip():
        details.append(proc.stderr.strip()[-2000:])
    if proc.returncode != 0:
        step.fail(f"etp_claims.py validate exited {proc.returncode}", details)
        return
    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError:
        step.fail("etp_claims.py validate did not emit a JSON verdict", details)
        return
    if result.get("valid") is not True or result.get("refusal_count") != 0:
        step.fail(f"claim set refused ({result.get('refusal_count')} refusal(s))",
                  details)
        return
    step.pass_(f"{result.get('claims')} claims validate with the Git-bound tree "
               f"check at {manifest.get('candidate', {}).get('frozen_source_commit', '')[:9]}",
               details)


# ---------------------------------------------------------------------------
# step: interop receipts
# ---------------------------------------------------------------------------


def step_interop(step: Step, manifest: dict) -> None:
    tool = ROOT / "courts/phase18/interop/check_receipts.py"
    if not tool.is_file():
        step.not_run("courts/phase18/interop/check_receipts.py is absent")
        return
    proc = run([sys.executable, str(tool), "--dir",
                str(ROOT / "courts/phase18/interop")], cwd=ROOT)
    details = [proc.stdout.strip()[-3000:]]
    if proc.stderr.strip():
        details.append(proc.stderr.strip()[-3000:])
    if proc.returncode != 0:
        step.fail(f"check_receipts.py exited {proc.returncode}", details)
        return
    step.pass_("interop receipts and manifests satisfy R1-R5", details)


# ---------------------------------------------------------------------------
# step: instrument register
# ---------------------------------------------------------------------------


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    # Dataclasses resolve their defining module through sys.modules while the
    # class body executes, so the module must be registered before exec_module.
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        raise
    return module


def step_instruments(step: Step, manifest: dict) -> None:
    tool = ROOT / "forensics/tools/instrument_qualify.py"
    registry = ROOT / "evidence/etp3/instruments.json"
    if not tool.is_file():
        step.not_run("forensics/tools/instrument_qualify.py is absent")
        return
    if not registry.is_file():
        step.not_run("evidence/etp3/instruments.json is absent")
        return
    try:
        iq = _load_module("instrument_qualify_etp6", tool)
        document = iq.load_registry(registry)
    except Exception as exc:  # noqa: BLE001 - refusal, not a pass
        step.fail(f"the instrument register could not be loaded: {exc}")
        return

    # Document-level fields are checked by the tracked validator itself.  The
    # per-instrument loop below is a classification of its refusals, not a
    # weaker substitute: every instrument still goes through
    # validate_instrument(), which runs the recorded version probe and checks
    # every declared path and prerequisite.
    results: list[tuple[str, str, str]] = []
    failures: list[str] = []
    missing: list[str] = []
    instruments = document.get("instruments") if isinstance(document, dict) else None
    if not isinstance(instruments, list) or not instruments:
        step.fail("the register has no instruments")
        return

    for index, entry in enumerate(instruments):
        ident = entry.get("id", f"instruments[{index}]") if isinstance(entry, dict) else f"[{index}]"
        try:
            iq.validate_instrument(index, entry, ROOT)
        except iq.Refusal as exc:
            first = str(entry.get("version_validation", {}).get("command", "")).split()
            tool_name = first[0] if first else "?"
            if exc.code in MISSING_TOOL_CODES and shutil.which(tool_name) is None:
                results.append((ident, "NOT_RUN", f"external tool {tool_name!r} is not installed"))
                missing.append(ident)
            else:
                results.append((ident, "FAIL", f"{exc.code}: {exc.message}"))
                failures.append(f"{ident}: {exc.code}: {exc.message}")
            continue
        except Exception as exc:  # noqa: BLE001 - refusal, not a pass
            results.append((ident, "FAIL", f"{type(exc).__name__}: {exc}"))
            failures.append(f"{ident}: {type(exc).__name__}: {exc}")
            continue

        control = entry.get("sensitivity_control", {})
        mode = control.get("mode")
        if mode == "recorded":
            results.append((ident, "RECORDED",
                            f"bound to {control.get('binding', {}).get('path')}"))
            continue
        if control.get("status") == "NOT_RUN":
            results.append((ident, "NOT_RUN", "no control claimed"))
            missing.append(ident)
            continue
        control_id = control.get("control_id")
        try:
            result = iq.run_control(control_id)
        except iq.Refusal as exc:
            if exc.code == "IQ_CONTROL_FIXTURE" and (
                    shutil.which("cc") is None or "exit 97" in exc.message
                    or "REFUSED" in exc.message or "No such file" in exc.message):
                results.append((ident, "NOT_RUN",
                                f"control fixture could not be built here: {exc.message[:160]}"))
                missing.append(ident)
            else:
                results.append((ident, "FAIL", f"{exc.code}: {exc.message[:300]}"))
                failures.append(f"{ident} ({control_id}): {exc.code}: {exc.message[:300]}")
            continue
        except Exception as exc:  # noqa: BLE001 - refusal, not a pass
            results.append((ident, "FAIL", f"{type(exc).__name__}: {exc}"))
            failures.append(f"{ident} ({control_id}): {type(exc).__name__}: {exc}")
            continue

        live = result.table()
        recorded = [{"name": c.get("name"), "exit": c.get("exit")}
                    for c in control.get("observed", {}).get("cases", [])]
        if not result.passed:
            bad = [c for c in result.cases if not c.ok]
            message = "; ".join(f"{c.name} exit={c.exit} expected={c.expected}" for c in bad)
            results.append((ident, "FAIL", message[:300]))
            failures.append(f"{ident} ({control_id}): {message[:300]}")
        elif live != recorded:
            results.append((ident, "FAIL", "live case table differs from the register"))
            failures.append(f"{ident} ({control_id}): live table differs from the register")
        else:
            results.append((ident, "PASS", f"{len(live)} cases match the register"))

    passed = sum(1 for _, status, _ in results if status == "PASS")
    recorded = sum(1 for _, status, _ in results if status == "RECORDED")
    not_run = sum(1 for _, status, _ in results if status == "NOT_RUN")
    details = [f"{ident:<24} {status:<9} {reason}" for ident, status, reason in results]
    summary = (f"register validated: {len(results)} instruments; {passed} executable "
               f"controls PASS, {recorded} RECORDED, {not_run} NOT_RUN")
    if failures:
        step.fail(f"instrument register refused: {len(failures)} failure(s)", details)
        return
    step.pass_(summary, details)


# ---------------------------------------------------------------------------
# step: documentation consistency
# ---------------------------------------------------------------------------


def step_docs(step: Step, manifest: dict) -> None:
    tool = ROOT / "forensics/tools/docs_consistency.py"
    if not tool.is_file():
        step.not_run("forensics/tools/docs_consistency.py is absent")
        return
    if not (ROOT / "forensics/tools/atlas_common.py").is_file():
        step.not_run("forensics/tools/atlas_common.py is absent")
        return
    proc = run([sys.executable, str(tool)], cwd=ROOT)
    details = [proc.stdout.strip()[-3000:]]
    if proc.stderr.strip():
        details.append(proc.stderr.strip()[-3000:])
    if proc.returncode != 0:
        step.fail(f"docs_consistency.py exited {proc.returncode}", details)
        return
    step.pass_("hand-written claims agree with their generated sources", details)


# ---------------------------------------------------------------------------
# step: reproducibility (--full only)
# ---------------------------------------------------------------------------


def step_reproducibility(step: Step, manifest: dict, full: bool) -> None:
    recipe = ROOT / "forensics/tools/build_reproducibility.sh"
    if not full:
        step.not_run(
            "deferred: the two-build recipe needs a Rust toolchain (rust-toolchain.toml "
            "pins 1.98.1), the court container and two release builds; run with --full "
            "inside the court, or see docs/EXTERNAL-REPRODUCTION.md")
        return
    if not recipe.is_file():
        step.not_run("forensics/tools/build_reproducibility.sh is absent")
        return
    cargo = shutil.which("cargo")
    rustc = shutil.which("rustc")
    if cargo is None or rustc is None:
        step.not_run("a Rust toolchain (cargo and rustc) is not installed")
        return
    if not Path("/.dockerenv").exists():
        step.not_run("the recipe refuses host execution (require_court.sh exit 97); "
                     "the --full step requires the court container")
        return
    out = Path(tempfile.mkdtemp(prefix="etp6-repro-"))
    env = dict(os.environ)
    env["CARGO_BUILD_JOBS"] = "4"
    proc = run(["bash", str(recipe), "--out", str(out), "--distribution"],
               cwd=ROOT, env=env, timeout=3600)
    details = [proc.stdout.strip()[-4000:], proc.stderr.strip()[-2000:]]
    if proc.returncode != 0:
        step.fail(f"build_reproducibility.sh exited {proc.returncode}", details)
        return
    step.pass_("two independent builds compared byte-for-byte, including the "
               "distribution DSO", details)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def public_manifest(manifest: dict) -> str:
    candidate = manifest.get("candidate", {})
    toolchain = manifest.get("toolchain", {})
    return (f"candidate {candidate.get('commit', '?')} "
            f"(frozen source {candidate.get('frozen_source_commit', '?')[:9]}); "
            f"rustc {toolchain.get('rustc', '?')}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--full", action="store_true",
                        help="run the two-build reproducibility step (court required)")
    parser.add_argument("--only", action="append", default=[],
                        choices=ALL_STEPS, help="run only the named step")
    parser.add_argument("--list", action="store_true", help="list the steps")
    args = parser.parse_args(argv)

    if args.list:
        for name in ALL_STEPS:
            print(f"{name}\t{'required' if name in REQUIRED_STEPS else 'with --full'}")
        return EXIT_PASS

    if not MANIFEST_PATH.is_file():
        print(f"verify: MANIFEST.json is absent under {ROOT}", file=sys.stderr)
        return EXIT_FAIL
    try:
        manifest = load_json_strict(MANIFEST_PATH)
    except Exception as exc:  # noqa: BLE001 - refusal
        print(f"verify: MANIFEST.json does not parse: {exc}", file=sys.stderr)
        return EXIT_FAIL

    selected = list(args.only) if args.only else list(REQUIRED_STEPS)
    if args.full and "reproducibility" not in selected:
        selected.append("reproducibility")

    steps = {
        "digests": Step("digests", "package integrity and cited evidence digests"),
        "claims": Step("claims", "claim set with the Git-bound tree check"),
        "interop": Step("interop", "interop receipt checker"),
        "instruments": Step("instruments", "instrument register and its controls"),
        "docs": Step("docs", "documentation consistency"),
        "reproducibility": Step("reproducibility", "two-build reproducibility",
                                required=args.full),
    }

    print("ETP-6 offline verification")
    print(f"package  {ROOT}")
    print(f"identity {public_manifest(manifest)}")
    print(f"steps    {', '.join(selected)}")
    print()

    for index, name in enumerate(ALL_STEPS, start=1):
        if name not in selected:
            continue
        step = steps[name]
        try:
            if name == "digests":
                step_digests(step, manifest, args.full)
            elif name == "claims":
                step_claims(step, manifest)
            elif name == "interop":
                step_interop(step, manifest)
            elif name == "instruments":
                step_instruments(step, manifest)
            elif name == "docs":
                step_docs(step, manifest)
            elif name == "reproducibility":
                step_reproducibility(step, manifest, args.full)
        except subprocess.TimeoutExpired as exc:
            step.fail(f"step timed out after {exc.timeout}s")
        except Exception as exc:  # noqa: BLE001 - refusal, never a pass
            step.fail(f"{type(exc).__name__}: {exc}")
        required = "required" if step.required else "optional"
        print(f"[{index}/{len(ALL_STEPS)}] {name:<16} {step.status:<8} ({required})  "
              f"{step.reason}")
        for line in step.details:
            for subline in str(line).splitlines():
                print(f"      {subline}")
        print()

    failed = [s for s in steps.values()
              if s.id in selected and s.required and s.status != "PASS"]
    print(f"RESULT: {'PASS' if not failed else 'FAIL'} "
          f"({sum(1 for s in steps.values() if s.id in selected and s.status == 'PASS')}"
          f"/{sum(1 for s in steps.values() if s.id in selected and s.required)} "
          f"required steps PASS)")
    if failed:
        for step in failed:
            print(f"  not PASS: {step.id} -> {step.status}: {step.reason}")
        return EXIT_FAIL
    return EXIT_PASS


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
