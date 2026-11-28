#!/usr/bin/env python3
"""openssl-rs — the build-input identity, derived mechanically and failing closed.

Why this exists
---------------
`PFP-83` found the circularity: an evidence commit moves `HEAD`, which changes
the tree digest, which invalidates the verification that was just recorded.  The
fix is to compare a *build-input* identity rather than the whole tree -- but a
hand-maintained path list reintroduces the defect it is meant to remove, because
`build.rs` consumes more than `src/` (the authority registry, the ABI-facade
configuration, the C adapter sources, the generated layout file).

This tool therefore derives the set from cargo's own records:

* the unit's dep-info file, which cargo writes from every source file it read;
* the build script's output, whose ``cargo:rerun-if-changed=`` and
  ``cargo:rerun-if-env-changed=`` lines are exactly the extra inputs it declared;
* the manifests that cannot be omitted (``Cargo.toml``, ``Cargo.lock``,
  ``build.rs``, ``rust-toolchain.toml``).

Nothing is inferred.  A missing dep-info, a missing build-script output, or an
input that cannot be hashed is a **refusal**, never an omission: an identity that
silently omits one input would let a real source change through unnoticed.

The reproducible DSO digest remains the authoritative artefact identity.  This
manifest is the cheap pre-filter in front of it, and the natural input to the
DSSE/Rekor attestation in `PFP-92`.

Usage
-----
    python3 forensics/tools/build_identity.py --write
    python3 forensics/tools/build_identity.py --check
    python3 forensics/tools/build_identity.py --write --profile debug

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ATLAS = Path("forensics/memory-safety/campaign/safe-c33/atlas-refresh")
MANIFEST = "build-inputs-{version}-{profile}.json"
SCHEMA = "openssl-rs.build-input-identity/v1"

MANDATORY = ("Cargo.toml", "Cargo.lock", "build.rs", "rust-toolchain.toml")

BI_MANIFEST_MISSING = "BI_MANIFEST_MISSING"
BI_DEPINFO_MISSING = "BI_DEPINFO_MISSING"
BI_BUILD_OUTPUT_MISSING = "BI_BUILD_OUTPUT_MISSING"
BI_INPUT_UNREADABLE = "BI_INPUT_UNREADABLE"
BI_ROOT_MISMATCH = "BI_ROOT_MISMATCH"
BI_INPUT_DRIFT = "BI_INPUT_DRIFT"


class Refusal(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _root(entries: list[tuple[str, str]]) -> str:
    lines = "".join(f"{path}\0{digest}\n" for path, digest in sorted(entries))
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def _dep_info(root: Path, target_dir: Path, profile: str) -> Path:
    """The dep-info cargo wrote for the library unit of this package."""
    fingerprint = target_dir / profile / ".fingerprint"
    for candidate in sorted(fingerprint.rglob("dep-lib-openssl_rs")):
        if candidate.is_file():
            return candidate
    raise Refusal(
        BI_DEPINFO_MISSING,
        f"no dep-lib-openssl_rs under {fingerprint}; the build-input set cannot be "
        "derived without cargo's own record. Build the candidate first; an "
        "underivable set is a refusal, not an omission.",
    )


def _dep_info_paths(path: Path, root: Path) -> list[str]:
    """Extract the input paths from cargo's binary dep-info record.

    The format is a length-prefixed binary list, not text, so the paths are
    recovered as printable path-shaped runs and then *checked* by hashing each
    one.  An extraction that yields nothing is a refusal: a silently empty set
    is the omission this tool exists to prevent.
    """
    text = path.read_bytes().decode("latin-1")
    tokens = re.findall(r"[A-Za-z0-9_][A-Za-z0-9_./-]*/[A-Za-z0-9_./-]*\.[A-Za-z0-9]+", text)
    paths = [token for token in tokens if not token.startswith("env-dep:")]
    if not paths:
        raise Refusal(
            BI_DEPINFO_MISSING,
            f"{path} yielded no input paths; cargo's record format may have "
            "changed, and an empty set is a refusal rather than a clean build",
        )
    return paths


def _build_output(target_dir: Path, profile: str) -> Path:
    for directory in sorted((target_dir / profile / "build").glob("openssl-rs-*")):
        output = directory / "output"
        if output.is_file():
            return output
    raise Refusal(
        BI_BUILD_OUTPUT_MISSING,
        f"no build-script output under {target_dir / profile / 'build'}; the "
        "rerun-if-changed inputs it declares are unknown, so the manifest would "
        "omit whatever build.rs reads.",
    )


def _build_script_inputs(output: Path) -> tuple[list[str], dict[str, str | None]]:
    paths: list[str] = []
    env: dict[str, str | None] = {}
    for line in output.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("cargo:rerun-if-changed="):
            value = line[len("cargo:rerun-if-changed="):].strip()
            if value:
                paths.append(value)
        elif line.startswith("cargo:rerun-if-env-changed="):
            name = line[len("cargo:rerun-if-env-changed="):].strip()
            if name:
                env[name] = os.environ.get(name)
    return paths, env


def _rebase(root: Path, declared: str) -> Path:
    """Resolve a declared input to a path inside the checkout.

    A build-script output recorded inside the court names its inputs under the
    container mount (``/work/...``), which does not exist on the host.  The
    workspace-relative suffix does.  The rebase must be *unambiguous*: if more
    than one suffix resolves, the identity is refused rather than guessed, and
    a path that resolves nowhere is refused (never dropped).
    """
    path = Path(declared)
    if ".." in path.parts:
        raise Refusal(
            BI_INPUT_UNREADABLE,
            f"declared build input {declared!r} contains '..' and could escape the "
            "checkout; an input outside the candidate is a refusal, not an omission",
        )
    if not path.is_absolute():
        candidate = root / path
        if candidate.exists():
            return candidate
        raise Refusal(BI_INPUT_UNREADABLE, f"declared build input {declared!r} does not exist")

    matches: list[Path] = []
    parts = path.parts
    for start in range(1, len(parts)):
        candidate = root.joinpath(*parts[start:])
        if candidate.exists():
            matches.append(candidate)
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise Refusal(
            BI_INPUT_UNREADABLE,
            f"declared build input {declared!r} does not exist under {root}; the "
            "manifest would omit it",
        )
    raise Refusal(
        BI_INPUT_UNREADABLE,
        f"declared build input {declared!r} matches {len(matches)} paths under "
        f"{root}; an ambiguous input is a refusal, not a guess",
    )


def _hash_input(root: Path, declared: str) -> list[tuple[str, str]]:
    """Hash one declared input; a directory contributes every file in it."""
    path = _rebase(root, declared)
    if path.is_dir():
        return [
            (str(child.relative_to(root)), _sha256_file(child))
            for child in sorted(path.rglob("*"))
            if child.is_file()
        ]
    return [(str(path.relative_to(root)), _sha256_file(path))]


def derive(root: Path, target_dir: Path, profile: str) -> dict:
    entries: list[tuple[str, str]] = []

    for name in MANDATORY:
        candidate = root / name
        if not candidate.is_file():
            raise Refusal(BI_INPUT_UNREADABLE, f"mandatory build input {name!r} is absent")
        entries.append((name, _sha256_file(candidate)))

    dep_info = _dep_info(root, target_dir, profile)
    declared = set(_dep_info_paths(dep_info, root))

    output = _build_output(target_dir, profile)
    script_paths, env = _build_script_inputs(output)
    declared.update(script_paths)

    # The dep-info names paths relative to the workspace root.  An absolute path
    # recorded in the court container is rebased onto the checkout.  A local
    # input that cannot be placed inside the checkout is refused.  Only a genuine
    # external registry dependency is excluded, and that exclusion is *recorded*
    # rather than dropped silently: an input must never vanish from the identity
    # without a witness.
    registry_markers = ("/.cargo/registry/", "/registry/src/")
    excluded: list[dict[str, str]] = []
    seen: set[str] = set(MANDATORY)
    for item in sorted(declared):
        if item.startswith("/") or item.startswith("../"):
            try:
                item = str(_rebase(root, item).relative_to(root))
            except Refusal:
                if any(marker in item for marker in registry_markers):
                    excluded.append({
                        "path": item,
                        "reason": "external cargo registry dependency, pinned by Cargo.lock",
                    })
                    continue
                raise
        if item in seen:
            continue
        seen.add(item)
        entries.extend(_hash_input(root, item))

    hashed_env = {
        name: (value if value is not None else "<unset>")
        for name, value in sorted(env.items())
    }
    entries.extend(
        (f"<env:{name}>", hashlib.sha256(value.encode("utf-8")).hexdigest())
        for name, value in hashed_env.items()
    )

    return {
        "schema": SCHEMA,
        "profile": profile,
        "derived_from": {
            "dep_info": str(dep_info.relative_to(root)),
            "build_script_output": str(output.relative_to(root)),
        },
        "toolchain": _toolchain(root),
        "declared_env": hashed_env,
        "excluded": excluded,
        "inputs": [{"path": path, "sha256": sha} for path, sha in sorted(entries)],
        "root": _root(entries),
        "input_count": len(entries),
    }


def _toolchain(root: Path) -> dict:
    pinned = (root / "rust-toolchain.toml").read_text(encoding="utf-8")
    channel = re.search(r'channel\s*=\s*"([^"]+)"', pinned)
    rustc = shutil.which("rustc")
    return {
        "pinned_channel": channel.group(1) if channel else None,
        "rustc_path": rustc,
        "rustc_version": _rustc_version(rustc),
    }


def _rustc_version(rustc: str | None) -> str | None:
    if not rustc:
        return None
    try:
        result = subprocess.run(
            [rustc, "--version"], capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None


def _version(root: Path) -> str:
    text = (root / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        raise Refusal(BI_INPUT_UNREADABLE, "Cargo.toml records no version")
    return match.group(1)


def write(root: Path, target_dir: Path, profile: str) -> Path:
    document = derive(root, target_dir, profile)
    document["version"] = _version(root)
    destination = root / ATLAS / MANIFEST.format(
        version=document["version"], profile=profile
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")
    return destination


def check(root: Path, target_dir: Path, profile: str) -> list[Refusal]:
    version = _version(root)
    path = root / ATLAS / MANIFEST.format(version=version, profile=profile)
    if not path.is_file():
        return [Refusal(BI_MANIFEST_MISSING, f"{path} is absent; the candidate has no "
                                             "build-input identity")]
    recorded = json.loads(path.read_text(encoding="utf-8"))
    try:
        current = derive(root, target_dir, profile)
    except Refusal as refusal:
        return [refusal]
    if current["root"] != recorded.get("root"):
        old = {item["path"]: item["sha256"] for item in recorded.get("inputs") or []}
        new = {item["path"]: item["sha256"] for item in current["inputs"]}
        drift = sorted(
            f"{key} ({'added' if key not in old else 'removed' if key not in new else 'changed'})"
            for key in set(old) | set(new)
            if old.get(key) != new.get(key)
        )
        return [Refusal(
            BI_ROOT_MISMATCH,
            f"build-input root {current['root'][:16]}… differs from the recorded "
            f"{str(recorded.get('root'))[:16]}…; drifting inputs: {', '.join(drift[:8])}"
            + (" …" if len(drift) > 8 else ""),
        )]
    for item in current["inputs"]:
        expected = {entry["path"]: entry["sha256"] for entry in recorded["inputs"]}
        if expected.get(item["path"]) != item["sha256"]:
            return [Refusal(BI_INPUT_DRIFT, f"{item['path']} differs from the manifest")]
    return []


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--root", default=".")
    parser.add_argument("--target-dir", default=None)
    parser.add_argument("--profile", default="release")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    target_dir = Path(args.target_dir).resolve() if args.target_dir else root / "target"

    try:
        if args.write:
            path = write(root, target_dir, args.profile)
            document = json.loads(path.read_text(encoding="utf-8"))
            print(f"build-inputs: wrote {path.relative_to(root)} "
                  f"({document['input_count']} inputs, root {document['root']})")
            return 0
        refusals = check(root, target_dir, args.profile)
    except Refusal as refusal:
        print(f"[{refusal.code}] {refusal.detail}")
        return 1

    for refusal in refusals:
        print(f"[{refusal.code}] {refusal.detail}")
    if refusals:
        return 1
    print("build-inputs: ok: the candidate's build-input root matches its manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
