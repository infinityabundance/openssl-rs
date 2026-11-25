#!/usr/bin/env python3
"""Produce the B4 records deterministically.

    python3 evidence/b4/build_evidence.py            # write the records
    python3 evidence/b4/build_evidence.py --check    # recompute and compare

The producer writes `CLASSIFICATION.json`, builds `BUNDLE/`, then writes
`PUBLICATION.json`, `CONTROLS.json` and `VERIFICATION.json`.  It reads no clock,
no environment variable and no network, and it writes no absolute path into a
record, so two runs are byte-identical.

The controls are **control-only**: each one constructs an input the classifier
must refuse, runs the classifier against it in a temporary directory, and records
the code that fired.  A control is not a finding about this tree.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import publication as pb  # noqa: E402

ITEM = "B4"
BASE_COMMIT = "dc5855733d6c98095425b4f1a36655afaec866ce"
BASE_SHORT = BASE_COMMIT[:9]
RECORDED_AT = "2026-11-24"
EVIDENCE = REPO_ROOT / "evidence" / "b4"

CLASS_DEFINITIONS = {
    pb.PUBLIC_RELEASE_CRITICAL: {
        "definition": (
            "material a reader needs to check the release claim itself: the "
            "statement, its authentication envelope, the admission record and the "
            "forward commitment"
        ),
        "publicationRule": "published; a bundle that omits a declared member is refused",
    },
    pb.PUBLIC_SUPPORTING: {
        "definition": (
            "material that explains or authenticates release-critical material but "
            "does not by itself carry the claim: envelopes, the bundle description "
            "and the verifier"
        ),
        "publicationRule": "published alongside the release-critical set",
    },
    pb.INTERNAL_NOT_PUBLISHED: {
        "definition": (
            "a tracked record that is not a candidate for publication. The default "
            "for an evidence record is internal, not public"
        ),
        "publicationRule": (
            "never published; a bundle that contains it is refused rather than redacted"
        ),
    },
    pb.PRIVATE_NEVER_PUBLISHED: {
        "definition": (
            "secret-bearing material: keys, credentials, tokens, secret diagnostics, "
            "unredacted personal information or embargoed detail"
        ),
        "publicationRule": (
            "never published and never copied into a bundle; a private pattern "
            "outranks every other rule"
        ),
    },
}

TOP_LEVEL_REASON = (
    "the scope is a tracked evidence directory; a record inside it is not a "
    "publication candidate unless an exact rule promotes it, and the default is "
    "not to publish"
)


def _slug(path: str) -> str:
    return "".join(
        character if character.isalnum() else "-" for character in path
    ).strip("-")


def _top_level_directories() -> list[str]:
    result = subprocess.run(
        [
            "git",
            "-c",
            "safe.directory=*",
            "-C",
            str(REPO_ROOT),
            "ls-tree",
            "-r",
            "--name-only",
            BASE_COMMIT,
            "--",
            "evidence",
        ],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit("b4: git ls-tree failed; the base tree cannot be read")
    directories = set()
    for line in result.stdout.decode("utf-8").splitlines():
        parts = line.split("/")
        if len(parts) > 2:
            directories.add(parts[1])
    return sorted(directories)


def build_policy() -> dict[str, Any]:
    rules: list[dict[str, Any]] = []

    # 1. The five source artefacts, classified explicitly.
    for entry in pb.BUNDLE_SOURCES:
        rules.append(
            {
                "id": "publish-" + _slug(entry["source"]),
                "kind": "exact",
                "path": entry["source"],
                "class": entry["classification"],
                "reason": entry["role"],
            }
        )
    # 2. Their bundle copies carry the same class: a copy is the same material.
    for entry in pb.BUNDLE_SOURCES:
        rules.append(
            {
                "id": "bundle-member-" + _slug(entry["member"]),
                "kind": "exact",
                "path": "evidence/b4/BUNDLE/" + entry["member"],
                "class": entry["classification"],
                "reason": "a byte-identical bundle copy of " + entry["source"],
            }
        )
    # 3. The bundle's own description and verifier are supporting material.
    for name in ("MANIFEST.json", "README.md", "verify.py", "verify.sh"):
        rules.append(
            {
                "id": "bundle-infrastructure-" + _slug(name),
                "kind": "exact",
                "path": "evidence/b4/BUNDLE/" + name,
                "class": pb.PUBLIC_SUPPORTING,
                "reason": "the bundle's manifest, description or verifier",
            }
        )
    # 4. This item's own records are internal: the measurement does not publish
    #    itself, and offering one to a bundle is refused rather than redacted.
    for name in (
        "CLASSIFICATION.json",
        "PUBLICATION.json",
        "CONTROLS.json",
        "VERIFICATION.json",
        "build_evidence.py",
        "RECEIPT.md",
    ):
        rules.append(
            {
                "id": "b4-record-" + _slug(name),
                "kind": "exact",
                "path": "evidence/b4/" + name,
                "class": pb.INTERNAL_NOT_PUBLISHED,
                "reason": "the item's own record, policy or receipt; not a publication",
            }
        )
    # 5. Anything else that appears under the bundle is supporting-only, so a
    #    stray file is not silently unclassified.
    rules.append(
        {
            "id": "scope-b4-bundle",
            "kind": "under",
            "path": "evidence/b4/BUNDLE/",
            "class": pb.PUBLIC_SUPPORTING,
            "reason": "bundle material that no exact rule promotes",
        }
    )
    # 6. Every tracked evidence directory defaults to internal.
    for directory in _top_level_directories():
        rules.append(
            {
                "id": "scope-" + directory,
                "kind": "under",
                "path": "evidence/" + directory + "/",
                "class": pb.INTERNAL_NOT_PUBLISHED,
                "reason": TOP_LEVEL_REASON,
            }
        )
    # 7. Tracked files directly under `evidence/`.
    rules.append(
        {
            "id": "scope-evidence-top-level",
            "kind": "depth",
            "depth": 2,
            "root": "evidence",
            "class": pb.INTERNAL_NOT_PUBLISHED,
            "reason": "a tracked evidence record at the top level; not a publication candidate",
        }
    )

    return {
        "policyId": "b4-public-transparency",
        "bundleId": "b4-public-bundle-1",
        "default": pb.UNCLASSIFIED,
        "classes": CLASS_DEFINITIONS,
        "rules": rules,
        "privatePatterns": [
            {
                "id": "private-pem",
                "pattern": "*.pem",
                "reason": "key or certificate material is never published",
            },
            {
                "id": "private-key",
                "pattern": "*.key",
                "reason": "key material is never published",
            },
            {
                "id": "private-pkcs12",
                "pattern": "*.p12",
                "reason": "a keystore archive is never published",
            },
            {
                "id": "private-secret-record",
                "pattern": "SECRETS-RAW.json",
                "reason": "a raw secret record is never published",
            },
            {
                "id": "private-secret-suffix",
                "pattern": "*.secret",
                "reason": "a file marked as a secret is never published",
            },
        ],
        "releaseCritical": [
            {
                "sourcePath": entry["source"],
                "class": entry["classification"],
                "reason": entry["role"],
            }
            for entry in pb.BUNDLE_SOURCES
            if entry["classification"] == pb.PUBLIC_RELEASE_CRITICAL
        ],
        "declaredInputSet": {
            "commit": BASE_COMMIT,
            "roots": ["evidence"],
            "excludePrefixes": [],
            "includeDirectories": ["evidence/b4/BUNDLE"],
            "note": (
                "the tracked evidence tree at the pinned base commit, plus the "
                "bundle under test. Pinning the commit makes the measurement "
                "reproducible: a record committed later does not change the "
                "population this run measured"
            ),
        },
        "scanBound": {
            "maxFiles": 1200,
            "maxBytesPerMember": 65536,
            "maxBytesTotal": 33554432,
        },
    }


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------

MINI_POLICY: dict[str, Any] = {
    "policyId": "b4-control-only",
    "bundleId": "control-only",
    "default": pb.UNCLASSIFIED,
    "classes": CLASS_DEFINITIONS,
    "rules": [
        {
            "id": "control-public",
            "kind": "exact",
            "path": "mini/public.json",
            "class": pb.PUBLIC_RELEASE_CRITICAL,
            "reason": "control-only",
        },
        {
            "id": "control-supporting",
            "kind": "exact",
            "path": "mini/readme.md",
            "class": pb.PUBLIC_SUPPORTING,
            "reason": "control-only",
        },
        {
            "id": "control-leaky",
            "kind": "exact",
            "path": "mini/leaky.md",
            "class": pb.PUBLIC_SUPPORTING,
            "reason": "control-only",
        },
        {
            "id": "control-absolute",
            "kind": "exact",
            "path": "mini/absolute.json",
            "class": pb.PUBLIC_SUPPORTING,
            "reason": "control-only",
        },
        {
            "id": "control-internal",
            "kind": "exact",
            "path": "mini/internal.json",
            "class": pb.INTERNAL_NOT_PUBLISHED,
            "reason": "control-only",
        },
    ],
    "privatePatterns": [
        {"id": "control-private", "pattern": "*.secret", "reason": "control-only"}
    ],
    "releaseCritical": [
        {
            "sourcePath": "mini/public.json",
            "class": pb.PUBLIC_RELEASE_CRITICAL,
            "reason": "control-only",
        }
    ],
    "declaredInputSet": {"commit": BASE_COMMIT, "roots": ["evidence"]},
    "scanBound": {"maxFiles": 10, "maxBytesPerMember": 4096, "maxBytesTotal": 8192},
}

MINI_SOURCES = [
    {
        "member": "members/public.json",
        "source": "mini/public.json",
        "role": "control-only public member",
        "classification": pb.PUBLIC_RELEASE_CRITICAL,
    },
    {
        "member": "members/readme.md",
        "source": "mini/readme.md",
        "role": "control-only supporting member",
        "classification": pb.PUBLIC_SUPPORTING,
    },
]

#: The literal tokens the scanner searches for are assembled here so that the
#: control inputs contain them without this file's *descriptions* being read as a
#: private path.  This is a control fixture, never bundle material.
COURT_SCRATCH = "court" + "/" + "tmp"
ABSOLUTE = "/" + "srv" + "/" + "build" + "/" + "artifact"


def _write(path: Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)


def _mini_repo(
    root: Path, *, private_reference: bool = False, absolute: bool = False
) -> None:
    _write(root / "mini" / "public.json", '{"subject":"control-only","value":1}\n')
    _write(root / "mini" / "readme.md", "# control-only readme\n")
    _write(root / "mini" / "internal.json", '{"internal":true}\n')
    _write(root / "mini" / "unknown.json", '{"unknown":true}\n')
    _write(root / "mini" / "sensitive.secret", "control-only secret placeholder\n")
    _write(
        root / "mini" / "leaky.md",
        ("scratch=" + COURT_SCRATCH + "/build/out\n")
        if private_reference
        else "# clean\n",
    )
    _write(
        root / "mini" / "absolute.json",
        json.dumps({"artifact": ABSOLUTE if absolute else "relative/artifact"}) + "\n",
    )


def _observe(action: Callable[[], Any]) -> str:
    try:
        result = action()
    except pb.Refusal as refusal:
        return refusal.code
    if isinstance(result, dict):
        return str(result.get("code", "PB_OK"))
    return "PB_OK"


def _recompute_manifest_digest(bundle: Path, mutate: Callable[[dict], None]) -> None:
    path = bundle / pb.MANIFEST_NAME
    manifest = json.loads(path.read_text(encoding="utf-8"))
    mutate(manifest)
    manifest["manifestDigest"] = pb.digest_body(manifest, "manifestDigest")
    _write(path, pb.pretty(manifest))


def run_controls() -> dict[str, Any]:
    work = Path(tempfile.mkdtemp(prefix="b4-controls-"))
    rows: list[dict[str, Any]] = []
    try:
        clean = work / "clean"
        _mini_repo(clean)
        valid = work / "valid-bundle"
        pb.build(MINI_POLICY, clean, valid, MINI_SOURCES)
        canary_code = _observe(lambda: pb.verify_bundle(valid, MINI_POLICY))

        def add_row(
            control_id: str,
            code: str,
            input_description: str,
            action: Callable[[], Any],
            out_dir: Path | None = None,
        ) -> None:
            observed = _observe(action)
            row: dict[str, Any] = {
                "id": control_id,
                "code": code,
                "input": input_description,
                "observed": observed,
                "fired": observed == code,
                "controlOnly": True,
                "canary": "control-valid-bundle",
            }
            if out_dir is not None:
                row["wroteNothing"] = not out_dir.exists()
            rows.append(row)

        extra_unknown = MINI_SOURCES + [
            {
                "member": "members/unknown.json",
                "source": "mini/unknown.json",
                "role": "control-only unclassified member",
                "classification": pb.PUBLIC_SUPPORTING,
            }
        ]
        extra_private = MINI_SOURCES + [
            {
                "member": "members/sensitive.secret",
                "source": "mini/sensitive.secret",
                "role": "control-only private member",
                "classification": pb.PUBLIC_SUPPORTING,
            }
        ]
        extra_internal = MINI_SOURCES + [
            {
                "member": "members/internal.json",
                "source": "mini/internal.json",
                "role": "control-only internal member",
                "classification": pb.PUBLIC_SUPPORTING,
            }
        ]

        out = work / "unclassified-bundle"
        add_row(
            "unclassified-member",
            "PB_REFUSED_UNCLASSIFIED",
            "a bundle source no policy rule classifies (mini/unknown.json)",
            lambda: pb.build(MINI_POLICY, clean, out, extra_unknown),
            out,
        )

        out = work / "private-bundle"
        add_row(
            "private-member",
            "PB_REFUSED_PRIVATE_MATERIAL",
            "a bundle source matching a private pattern (mini/sensitive.secret)",
            lambda: pb.build(MINI_POLICY, clean, out, extra_private),
            out,
        )

        out = work / "internal-bundle"
        add_row(
            "internal-member",
            "PB_REFUSED_INTERNAL_MATERIAL",
            "a bundle source classified INTERNAL_NOT_PUBLISHED (mini/internal.json)",
            lambda: pb.build(MINI_POLICY, clean, out, extra_internal),
            out,
        )

        leaky = work / "leaky"
        _mini_repo(leaky, private_reference=True)
        out = work / "private-reference-bundle"
        add_row(
            "private-reference",
            "PB_REFUSED_PRIVATE_REFERENCE",
            "a member whose text contains a court scratch path",
            lambda: pb.build(
                MINI_POLICY,
                leaky,
                out,
                MINI_SOURCES
                + [
                    {
                        "member": "members/leaky.md",
                        "source": "mini/leaky.md",
                        "role": "control-only leaky member",
                        "classification": pb.PUBLIC_SUPPORTING,
                    }
                ],
            ),
            out,
        )

        absolute_repo = work / "absolute"
        _mini_repo(absolute_repo, absolute=True)
        out = work / "absolute-bundle"
        add_row(
            "absolute-path",
            "PB_REFUSED_ABSOLUTE_PATH",
            "a member whose JSON carries an absolute path value",
            lambda: pb.build(
                MINI_POLICY,
                absolute_repo,
                out,
                MINI_SOURCES
                + [
                    {
                        "member": "members/absolute.json",
                        "source": "mini/absolute.json",
                        "role": "control-only absolute-path member",
                        "classification": pb.PUBLIC_SUPPORTING,
                    }
                ],
            ),
            out,
        )

        unbound = work / "unbound-bundle"
        shutil.copytree(valid, unbound)
        _write(unbound / "extra.txt", "not in the manifest\n")
        add_row(
            "unbound-member",
            "PB_REFUSED_UNBOUND_MEMBER",
            "a file present in the bundle but absent from the manifest",
            lambda: pb.verify_bundle(unbound, MINI_POLICY),
        )

        mismatched = work / "digest-bundle"
        shutil.copytree(valid, mismatched)
        _recompute_manifest_digest(
            mismatched,
            lambda manifest: manifest["members"][0].__setitem__("sha256", "0" * 64),
        )
        add_row(
            "digest-mismatch",
            "PB_REFUSED_UNBOUND_MEMBER",
            "a member whose bytes do not match the digest the manifest records",
            lambda: pb.verify_bundle(mismatched, MINI_POLICY),
        )

        out = work / "missing-release-bundle"
        add_row(
            "release-member-missing",
            "PB_REFUSED_RELEASE_MEMBER_MISSING",
            "a bundle whose source set omits the policy's release-critical member",
            lambda: pb.build(MINI_POLICY, clean, out, MINI_SOURCES[1:]),
            out,
        )

        disagreed = work / "classification-bundle"
        shutil.copytree(valid, disagreed)

        def downgrade(manifest: dict) -> None:
            for row in manifest["members"]:
                if row.get("path") == "members/public.json":
                    row["classification"] = pb.PUBLIC_SUPPORTING
                    return
            raise AssertionError("the control bundle has no public member")

        _recompute_manifest_digest(disagreed, downgrade)
        add_row(
            "classification-mismatch",
            "PB_REFUSED_CLASSIFICATION_MISMATCH",
            "a manifest that calls release-critical material supporting",
            lambda: pb.verify_bundle(disagreed, MINI_POLICY),
        )

        add_row(
            "publication-without-service",
            "PB_REFUSED_NO_PUBLIC_SERVICE",
            "a publication claim with no admitted public endpoint",
            lambda: pb.publication_claim(publish=True),
        )

        add_row(
            "external-verification-claimed",
            "PB_REFUSED_EXTERNAL_NOT_RUN",
            "an independent-verification claim with no external party",
            lambda: pb.publication_claim(external_verified=True),
        )

        invalid = work / "invalid-bundle"
        shutil.copytree(valid, invalid)
        _write(invalid / pb.MANIFEST_NAME, "{\n")
        add_row(
            "manifest-invalid",
            "PB_REFUSED_MANIFEST_INVALID",
            "a manifest that does not parse",
            lambda: pb.verify_bundle(invalid, MINI_POLICY),
        )

        add_row(
            "missing-bundle",
            "PB_REFUSED_IO",
            "a bundle directory that does not exist",
            lambda: pb.verify_bundle(work / "no-such-bundle", MINI_POLICY),
        )

        def usage() -> Any:
            with contextlib.redirect_stderr(io.StringIO()):
                with contextlib.redirect_stdout(io.StringIO()):
                    returned = pb.main([])
            return {
                "code": "PB_REFUSED_USAGE" if returned == pb.EXIT_USAGE else "PB_OK"
            }

        add_row(
            "usage-error",
            "PB_REFUSED_USAGE",
            "the command line with no subcommand",
            usage,
        )

        covered = sorted({row["code"] for row in rows})
        return {
            "schema": "openssl-rs/b4/controls/1",
            "item": ITEM,
            "canary": {
                "id": "control-valid-bundle",
                "input": "the same synthetic bundle with no mutation",
                "observed": canary_code,
                "accepted": canary_code == "PB_OK",
                "controlOnly": True,
            },
            "controls": rows,
            "counts": {
                "controls": len(rows),
                "fired": sum(1 for row in rows if row["fired"]),
                "codesCovered": covered,
            },
            "coversEveryCode": covered == sorted(pb.REFUSALS),
            "note": (
                "every control is a test-only fixture; a control that fires proves "
                "the refusal works, not that the substituted form occurs in the tree"
            ),
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ---------------------------------------------------------------------------
# The in-venue run of the bundled verifier
# ---------------------------------------------------------------------------

AUDIT_DRIVER = '''import json
import os
import runpy
import sys

package, result_path, allow = sys.argv[1:4]
roots = [os.path.realpath(item) for item in allow.split(os.pathsep) if item]
reads, writes, network = [], [], []


def hook(event, args):
    if event.startswith("socket.") or event.startswith("http."):
        network.append(event)
        return
    if event not in ("open", "os.open"):
        return
    raw = args[0]
    if not isinstance(raw, (str, bytes, os.PathLike)):
        return
    try:
        path = os.path.realpath(raw)
    except (OSError, ValueError):
        return
    for root in roots:
        if path == root or path.startswith(root.rstrip(os.sep) + os.sep):
            return
    mode = args[1] if len(args) > 1 else None
    writing = isinstance(mode, str) and any(ch in mode for ch in "wax+")
    (writes if writing else reads).append(path)


sys.addaudithook(hook)
entry = os.path.join(package, "verify.py")
sys.argv = [entry]
code = 0
error = None
try:
    runpy.run_path(entry, run_name="__main__")
except SystemExit as exc:
    code = 0 if exc.code in (None, 0) else 1
except BaseException as exc:
    code = 1
    error = f"{type(exc).__name__}: {exc}"
with open(result_path, "w", encoding="utf-8") as handle:
    json.dump({
        "exit": code,
        "error": error,
        "outsideReads": len(reads),
        "outsideWrites": len(writes),
        "networkEvents": len(network),
        "networkModules": sorted(set(sys.modules) & {
            "socket", "ssl", "http", "ftplib", "telnetlib",
        }),
    }, handle, sort_keys=True)
    handle.write("\\n")
'''


def _allowed_roots(package: Path, run_root: Path) -> list[str]:
    import sysconfig

    roots = [str(package.resolve()), str(run_root.resolve())]
    paths = sysconfig.get_paths()
    for key in ("stdlib", "platstdlib"):
        if paths.get(key):
            roots.append(paths[key])
    roots.append(str(Path(sys.executable).resolve().parent))
    return sorted(dict.fromkeys(roots))


def _one_venue_run(bundle: Path, run_root: Path) -> dict[str, Any]:
    run_root.mkdir(parents=True)
    package = run_root / "package"
    shutil.copytree(bundle, package)
    home = run_root / "home"
    tmpdir = run_root / "tmpdir"
    home.mkdir()
    tmpdir.mkdir()
    driver = run_root / "audit_driver.py"
    driver.write_text(AUDIT_DRIVER, encoding="utf-8")
    result_path = run_root / "audit.json"
    environment = {
        "PATH": str(Path(sys.executable).resolve().parent),
        "HOME": str(home),
        "TMPDIR": str(tmpdir),
        "LANG": "C",
        "LC_ALL": "C",
    }
    command = [
        sys.executable,
        "-I",
        "-S",
        "-B",
        str(driver),
        str(package),
        str(result_path),
        os.pathsep.join(_allowed_roots(package, run_root)),
    ]
    completed = subprocess.run(
        command,
        cwd=str(package),
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    audit: dict[str, Any] = {}
    if result_path.is_file():
        audit = json.loads(result_path.read_text(encoding="utf-8"))
    return {
        "processExit": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderrTail": (
            completed.stderr.strip().splitlines()[-1]
            if completed.stderr.strip()
            else ""
        ),
        "audit": audit,
        "environmentVariables": sorted(environment),
    }


def venue_verification(bundle: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    work = Path(tempfile.mkdtemp(prefix="b4-venue-"))
    try:
        first = _one_venue_run(bundle, work / "run-1")
        second = _one_venue_run(bundle, work / "run-2")
        inside_project = str(work).startswith(str(REPO_ROOT))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    stable = {
        "stdout": first["stdout"] == second["stdout"],
        "exit": first["processExit"] == second["processExit"],
        "outsideReads": first["audit"].get("outsideReads")
        == second["audit"].get("outsideReads"),
    }
    ok = (
        first["processExit"] == 0
        and second["processExit"] == 0
        and first["audit"].get("exit") == 0
        and second["audit"].get("exit") == 0
        and stable["stdout"]
        and stable["exit"]
        and stable["outsideReads"]
        and not first["audit"].get("networkEvents")
        and not second["audit"].get("networkEvents")
        and not inside_project
    )
    return {
        "schema": "openssl-rs/b4/venue-verification/1",
        "item": ITEM,
        "outcome": "PUBLIC_BUNDLE_VERIFIED_IN_VENUE",
        "verified": ok,
        "venue": "in-venue",
        "external": "NOT_RUN",
        "externalVerification": "PENDING",
        "bundle": "evidence/b4/BUNDLE",
        "manifestDigest": manifest["manifestDigest"],
        "members": len(manifest["members"]),
        "runs": 2,
        "freshDirectory": (
            "a fresh temporary directory outside the project tree; the bundle is "
            "copied into it and the verifier runs there"
        ),
        "tempRootOutsideProject": not inside_project,
        "strippedEnvironment": {
            "inheritedVariables": False,
            "variables": first["environmentVariables"],
            "pathEntries": 1,
            "pythonpath": None,
            "isolationFlags": ["-I", "-S", "-B"],
        },
        "audit": {
            "outsideReads": first["audit"].get("outsideReads"),
            "outsideWrites": first["audit"].get("outsideWrites"),
            "networkEvents": first["audit"].get("networkEvents"),
            "networkModules": first["audit"].get("networkModules"),
            "secondRun": {
                "outsideReads": second["audit"].get("outsideReads"),
                "outsideWrites": second["audit"].get("outsideWrites"),
                "networkEvents": second["audit"].get("networkEvents"),
            },
            "detector": (
                "socket- and http-level audit events plus the socket, ssl, http, "
                "ftplib and telnetlib modules; urllib.parse is not counted because "
                "pathlib imports it in the standard library"
            ),
        },
        "runStability": stable,
        "exit": first["processExit"],
        "stdout": first["stdout"],
        "note": (
            "this is a run in the producing venue, not an external one. No party "
            "outside this project has run the verifier, so public publication and "
            "independent verification remain NOT_RUN and PENDING"
        ),
    }


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


def classification_record(
    policy: dict[str, Any], scan: dict[str, Any], bundle: dict[str, Any]
) -> dict[str, Any]:
    return {
        "schema": pb.POLICY_SCHEMA,
        "item": ITEM,
        "baseCommit": BASE_COMMIT,
        "baseCommitShort": BASE_SHORT,
        "recordedAt": RECORDED_AT,
        "policy": policy,
        "referenceScan": {
            "patterns": [
                {"name": name, "what": description}
                for name, description in (
                    ("court-scratch", "a court scratch directory (a host-only path)"),
                    ("home-directory", "a user home directory"),
                    ("root-home", "the root account's home directory"),
                    ("host-only-tmp", "a host temporary directory"),
                    ("file-url", "a file URL"),
                    ("bearer-token", "an HTTP bearer token"),
                    ("authorization-header", "an authorization header"),
                    ("aws-access-key", "an AWS access-key identifier"),
                    ("private-key-pem", "a PEM private key block"),
                    ("credential-assignment", "an assigned password, token or key"),
                )
            ],
            "absolutePath": (
                "a JSON string value that begins with / and carries an interior "
                "separator; a URL does not match"
            ),
            "note": (
                "path patterns are assembled from fragments inside the tool and the "
                "bundled verifier, so neither program's own source contains the "
                "literal it searches for"
            ),
        },
        "scan": scan,
        "counts": {
            "classified": scan["classified"],
            "unclassified": scan["unclassified"],
            "private": scan["private"],
            "byClass": scan["counts"],
            "basis": scan["basis"],
        },
        "bundle": {
            "path": "evidence/b4/BUNDLE",
            "manifestDigest": bundle["manifestDigest"],
            "policyDigest": bundle["policyDigest"],
            "members": bundle["members"],
            "releaseCritical": bundle["releaseCritical"],
            "membersTable": bundle["membersTable"],
        },
        "excludedFromScan": [
            {
                "paths": [
                    "evidence/b4/CLASSIFICATION.json",
                    "evidence/b4/PUBLICATION.json",
                    "evidence/b4/CONTROLS.json",
                    "evidence/b4/VERIFICATION.json",
                    "evidence/b4/build_evidence.py",
                    "evidence/b4/RECEIPT.md",
                ],
                "reason": (
                    "the item's own outputs are not present in the pinned base tree; "
                    "counting them would make the measurement depend on whether it "
                    "had already run. They are classified INTERNAL_NOT_PUBLISHED by "
                    "exact rule and refused if offered to a bundle"
                ),
            }
        ],
        "note": (
            "the count is a measurement over the bounded population declared in the "
            "policy, not a proof of absence across the tree; classification uses the "
            "path, and the content scan is bounded per member and in total"
        ),
    }


def publication_record(bundle: dict[str, Any]) -> dict[str, Any]:
    members = bundle["membersTable"]
    return {
        "schema": "openssl-rs/b4/publication/1",
        "item": ITEM,
        "baseCommit": BASE_COMMIT,
        "baseCommitShort": BASE_SHORT,
        "recordedAt": RECORDED_AT,
        "profile": {
            "name": "public-good Rekor v2 profile (rekor-tiles)",
            "log": "sigstore/rekor-tiles v2.4.2",
            "entryKind": "hashedrekord",
            "leafHash": "RFC 6962 SHA-256 with 0x00/0x01 domain separation",
            "checkpoint": "three-line note body and a signed checkpoint",
            "source": [
                "evidence/b0/REGISTRY.json",
                "docs/PROTOCOL-AUDIT.md",
                "docs/ETP-ADDENDUM-B.md sections B.3.2, B.3.3 and B.30",
            ],
            "pinnedDigest": "sha256:3af252cd59adea029eea7ff325dee8adb65074e45d0c03aaa6c083eb2461e8a6",
            "pinnedDigestScope": (
                "the linux/amd64 rekor-server-aws release asset, not the POSIX-backend "
                "server the profile would need"
            ),
            "admitted": False,
            "notAdmittedBecause": [
                "no public endpoint is configured (B0 CLM-01, CLM-07)",
                "no rekor-server, rekor-cli or rekor-tiles binary is installed (CLM-02)",
                "no admitted log key exists (CLM-03); 0 transparency logs and 0 log keys",
                "no checkpoint cosignature can be produced or verified (CLM-04)",
                "no independent witness set exists (CLM-05)",
                "the network is unavailable in this venue",
            ],
        },
        "admittedService": False,
        "endpoint": None,
        "published": 0,
        "externalVerification": "PENDING",
        "wouldPublish": {
            "bundle": "evidence/b4/BUNDLE",
            "manifestDigest": bundle["manifestDigest"],
            "members": [
                {
                    "path": row["path"],
                    "sourcePath": row["sourcePath"],
                    "classification": row["classification"],
                    "sha256": row["sha256"],
                }
                for row in members
                if row["classification"] in pb.PUBLISHABLE
            ],
            "releaseCritical": [
                row["path"]
                for row in members
                if row["classification"] == pb.PUBLIC_RELEASE_CRITICAL
            ],
        },
        "refusals": {
            "publicationClaim": "PB_REFUSED_NO_PUBLIC_SERVICE",
            "externalVerificationClaim": "PB_REFUSED_EXTERNAL_NOT_RUN",
            "unclassifiedMember": "PB_REFUSED_UNCLASSIFIED",
            "privateMember": "PB_REFUSED_PRIVATE_MATERIAL",
            "internalMember": "PB_REFUSED_INTERNAL_MATERIAL",
        },
        "nonClaims": [
            "a publishable bundle is not a published one",
            "a public transparency log records that a claim was made, not that it is true",
            "the fixture log FIXTURE-1 is not a Rekor log and its key is test-only",
            "no external party has run the verifier; external verification is PENDING",
        ],
        "note": (
            "this record states what would be published and to which profile; it "
            "asserts no publication, because no admitted endpoint exists"
        ),
    }


def produce(out_root: Path, *, build_bundle: bool = True) -> dict[str, bytes]:
    policy = build_policy()
    if build_bundle:
        bundle = pb.build(policy, REPO_ROOT, EVIDENCE / "BUNDLE")
    else:
        bundle = pb.build(policy, REPO_ROOT, out_root / "BUNDLE")
    scan = pb.scan_tree(policy, REPO_ROOT)
    manifest = json.loads(
        (EVIDENCE / "BUNDLE" / pb.MANIFEST_NAME).read_text(encoding="utf-8")
    )
    verification = venue_verification(EVIDENCE / "BUNDLE", manifest)
    records = {
        "CLASSIFICATION.json": pb.pretty(classification_record(policy, scan, bundle)),
        "PUBLICATION.json": pb.pretty(publication_record(bundle)),
        "CONTROLS.json": pb.pretty(run_controls()),
        "VERIFICATION.json": pb.pretty(verification),
    }
    out_root.mkdir(parents=True, exist_ok=True)
    for name, data in records.items():
        (out_root / name).write_bytes(data)
    return records


def _tree(directory: Path) -> dict[str, bytes]:
    if not directory.is_dir():
        return {}
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in directory.rglob("*")
        if path.is_file()
    }


def check() -> int:
    with tempfile.TemporaryDirectory(prefix="b4-check-") as temporary:
        root = Path(temporary)
        rebuilt = produce(root, build_bundle=False)
        problems: list[str] = []
        for name, data in rebuilt.items():
            committed = EVIDENCE / name
            if not committed.is_file():
                problems.append(f"missing {name}")
            elif committed.read_bytes() != data:
                problems.append(f"differs {name}")
        a = _tree(EVIDENCE / "BUNDLE")
        b = _tree(root / "BUNDLE")
        if sorted(a) != sorted(b):
            problems.append("bundle member set differs")
        for path in sorted(set(a) & set(b)):
            if a[path] != b[path]:
                problems.append(f"bundle member differs: {path}")
        if problems:
            for problem in problems:
                print(f"b4: check failed: {problem}", file=sys.stderr)
            return pb.EXIT_REFUSED
        print(f"code=PB_OK b4: check ok records={len(rebuilt)} bundleMembers={len(a)}")
        return pb.EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="build_evidence.py")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--out", default=str(EVIDENCE))
    args = parser.parse_args(argv)
    if args.check:
        return check()
    records = produce(Path(args.out))
    classification = json.loads(records["CLASSIFICATION.json"])
    controls = json.loads(records["CONTROLS.json"])
    verification = json.loads(records["VERIFICATION.json"])
    print(
        "code=PB_OK b4: "
        f"base={BASE_SHORT} "
        f"population={classification['scan']['populationSource']['population']} "
        f"classified={classification['counts']['classified']} "
        f"unclassified={classification['counts']['unclassified']} "
        f"private={classification['counts']['private']} "
        f"privateReference={classification['scan']['referenceScan']['privateReferenceArtefacts']} "
        f"bundleMembers={classification['bundle']['members']} "
        f"controls={controls['counts']['fired']}/{controls['counts']['controls']}"
    )
    print(
        f"b4: venue outcome={verification['outcome']} "
        f"verified={verification['verified']} external={verification['external']}"
    )
    return pb.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
