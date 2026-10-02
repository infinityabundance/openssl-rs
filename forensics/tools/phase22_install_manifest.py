#!/usr/bin/env python3
"""openssl-rs -- Phase 22.8 installed-distribution manifest.

Runs the admitted authority's **own install** into an empty scratch root and records the whole
installed distribution -- every file, directory and symlink -- as the repository's standard atlas
document at `forensics/atlas/phase22/install-manifest.json`.

The authority's install defines the surface, not a hand-written list
--------------------------------------------------------------------
`docs/PHASE-22-SUBPHASES.md` section 6 is this plane's rule: 22.8 "must let the authority's own
install define the distribution surface. The constitution's list of what matters is not the input;
it is an output to be reconciled." So this tool does **not** enumerate what OpenSSL installs and
then check for it. It runs

    make install DESTDIR=<scratch-root>

in the already-built authority build directory `forensics/authorities/build/openssl-3.6.4-production`
(the production authority's Makefile, built from `forensics/authorities/src/openssl-3.6.4`), walks
whatever landed, and *then* reconciles that walk against the short list of surfaces the plan names
(`OpenSSLConfig.cmake`, `OpenSSLConfigVersion.cmake`, the `*.pc` files, `openssl.cnf`, the provider
module directory, the engines, `c_rehash`, `CA.pl`, ...). That list is an output of the walk, not
its input.

The install is `install` (the full target: `install_sw` + `install_ssldirs` + `install_docs`), not
`install_sw`. The full target is the honest distribution surface -- it is what a consumer who runs
`make install` sees -- and it is the reason `prefix_diff` below is not empty: the pinned prefix
`forensics/authorities/prefix/openssl-3.6.4-production` was produced by the authority build's
`install_sw` alone (`forensics/tools/authority_build.py`), so it carries no `ssl/`, no man pages and
no HTML documentation. That difference is recorded as a residual rather than hidden.

The pinned authority is read, never written
-------------------------------------------
The install goes to a scratch `DESTDIR` under the container's `/tmp`; neither the pinned source
(`forensics/authorities/src/openssl-3.6.4`) nor the pinned prefix
(`forensics/authorities/prefix/openssl-3.6.4-production`) is written. The scratch root's absolute
path is deliberately **not** recorded -- the document carries no `/tmp` path and no timestamp.

What is recorded, per entry
---------------------------
Every installed entry gets `path` (POSIX, relative to the distribution root), `kind`
(file/dir/symlink), `mode` (permission bits as four octal digits), `size`, `sha256` for regular
files and `symlink_target` for symlinks. ELF entries additionally carry `elf_kind`
(executable/shared/relocatable, with a PIE executable -- `ET_DYN` with a `PT_INTERP` -- reported as
`executable` and the raw `elf_type` kept beside it), `soname` and `dynamic_dependencies`
(`DT_NEEDED`). Each entry is classified into a `category` (library, header, provider_module,
engine, cli, pkgconfig, cmake_config, openssl_cnf, script, manpage, html_doc, symlink, directory,
other) and given one `disposition` from the plan's section-4 vocabulary (`REQUIRED_COMPATIBILITY`,
`TOOLING_ONLY`, `GENERATED_INTERMEDIATE`, ...). An entry whose disposition would be `UNKNOWN` is
counted, because "zero UNKNOWN residuals" is a seal criterion and an unclassified entry must be
visible rather than absorbed into `other`.

Determinism
-----------
`body.entries` are sorted by `path`; every count is derived, never typed; the document holds no
timestamp and no host-varying path. The installed file contents are a function of the pinned source
and the pinned build directory -- for example the man pages' footer date is the source's fixed
release date `2026-08-25`, not the wall clock -- so two installs from the same build produce the
same entries. The court that accompanies this plane
(`forensics/tools/phase22_courts.py`'s discovery of this module's `courts()`) re-derives the body
from the committed entries and exercises the classification and diff logic on controlled in-memory
mutations, so it judges the logic that built the artefact rather than a stale copy of its output.

Output
------
    forensics/atlas/phase22/install-manifest.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import stat as statmod
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    must_run,
    rel,
    resolve_authority,
    write_json,
)

GENERATOR = "forensics/tools/phase22_install_manifest.py"
ARTEFACT_REL = "forensics/atlas/phase22/install-manifest.json"
OUT_REL = ARTEFACT_REL
BUILD_DIR_REL = "forensics/authorities/build/openssl-3.6.4-production"
PREFIX_REL = "forensics/authorities/prefix/openssl-3.6.4-production"
PLAN_REL = "docs/PHASE-22-SUBPHASES.md"
SCRATCH_DEFAULT = "/tmp/phase22-install-manifest"
INSTALL_TARGET = "install"

# The classes of installed entity, in the plan's own words ("installed files, symlinks, modes,
# pkg-config, CMake metadata, config samples"). `symlink` and `directory` are classified by the
# entry's own kind; the rest by the path's role in the distribution.
CATEGORIES = (
    "library", "header", "provider_module", "engine", "cli", "pkgconfig", "cmake_config",
    "openssl_cnf", "script", "manpage", "html_doc", "symlink", "directory", "other",
)

# The plan's section-4 disposition vocabulary. `UNKNOWN` is included so an unclassified entry can
# be counted and made visible; the seal is refused while any UNKNOWN intersects a compatibility
# root.
DISPOSITIONS = (
    "REQUIRED_COMPATIBILITY", "INTERNAL_REACHABLE", "INTERNAL_UNREACHABLE_PROFILE",
    "EXCLUDED_BY_BUILD_PROFILE", "PLATFORM_EXCLUDED", "TEST_ONLY", "DEMO_ONLY", "TOOLING_ONLY",
    "GENERATED_INTERMEDIATE", "AUTHORITY_BUG_BOUNDARY", "UNKNOWN",
)

# category -> disposition. A file that only exists for the build tooling of a downstream consumer
# (`*.pc`, CMake config) is TOOLING_ONLY; a generated artefact (man/HTML docs, install layout
# directories) is GENERATED_INTERMEDIATE; anything a consumer meets at runtime is
# REQUIRED_COMPATIBILITY.
_CATEGORY_DISPOSITION = {
    "library": "REQUIRED_COMPATIBILITY",
    "header": "REQUIRED_COMPATIBILITY",
    "provider_module": "REQUIRED_COMPATIBILITY",
    "engine": "REQUIRED_COMPATIBILITY",
    "cli": "REQUIRED_COMPATIBILITY",
    "openssl_cnf": "REQUIRED_COMPATIBILITY",
    "script": "TOOLING_ONLY",
    "pkgconfig": "TOOLING_ONLY",
    "cmake_config": "TOOLING_ONLY",
    "manpage": "GENERATED_INTERMEDIATE",
    "html_doc": "GENERATED_INTERMEDIATE",
    "directory": "GENERATED_INTERMEDIATE",
    "other": "UNKNOWN",
    # `symlink` is resolved by path in `disposition_for`.
}

# The surfaces the plan's section 2 distribution root names, as a *reconciliation list*. Presence
# is computed from the walk; absence is a finding, not a silent gap.
LOOKED_FOR = (
    ("openssl-cli", "bin/openssl"),
    ("c-rehash", "bin/c_rehash"),
    ("cmake-config", "lib/cmake/OpenSSL/OpenSSLConfig.cmake"),
    ("cmake-config-version", "lib/cmake/OpenSSL/OpenSSLConfigVersion.cmake"),
    ("pkgconfig-libcrypto", "lib/pkgconfig/libcrypto.pc"),
    ("pkgconfig-libssl", "lib/pkgconfig/libssl.pc"),
    ("pkgconfig-openssl", "lib/pkgconfig/openssl.pc"),
    ("openssl-cnf", "ssl/openssl.cnf"),
    ("openssl-cnf-dist", "ssl/openssl.cnf.dist"),
    ("ct-log-list-cnf", "ssl/ct_log_list.cnf"),
    ("provider-modules-dir", "lib/ossl-modules"),
    ("provider-legacy", "lib/ossl-modules/legacy.so"),
    ("engines-dir", "lib/engines-3"),
    ("ca-pl", "ssl/misc/CA.pl"),
    ("tsget", "ssl/misc/tsget"),
    ("tsget-pl", "ssl/misc/tsget.pl"),
)

_ELF_MAGIC = b"\x7fELF"
_ELF_KIND = {"EXEC": "executable", "DYN": "shared", "REL": "relocatable"}


# ---------------------------------------------------------------------------
# reading the installed tree (I/O)
# ---------------------------------------------------------------------------

def read_install_prefix(build_dir: Path) -> str:
    """The absolute `@PREFIX` the authority was configured with, from `installdata.pm`.

    `make ... DESTDIR=<scratch>` installs to `<scratch><PREFIX>`; this is how the tool recovers the
    distribution root inside the scratch tree without guessing a path. Reading the build's own
    `installdata.pm` (rather than re-deriving it from `Configure`) keeps the anchor the install
    actually used.
    """
    installdata = build_dir / "installdata.pm"
    if not installdata.is_file():
        raise SystemExit(
            f"phase22-install-manifest: {rel(installdata)} is absent, so the install prefix is "
            "unknown; build the authority (forensics/tools/authority_build.py) first"
        )
    m = re.search(r"our\s+\@PREFIX\s*=\s*\(\s*'([^']*)'", installdata.read_text(
        encoding="utf-8", errors="replace"))
    if not m or not m.group(1):
        raise SystemExit(
            f"phase22-install-manifest: could not read @PREFIX from {rel(installdata)}"
        )
    return m.group(1)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def elf_info(path: str) -> dict | None:
    """ELF identity for one file: kind, SONAME and `DT_NEEDED`, or None if it is not ELF.

    `elf_kind` follows the ELF `e_type`, except that an `ET_DYN` object carrying a `PT_INTERP`
    program header is a position-independent **executable** (`bin/openssl` in this profile), not a
    shared library; the raw `e_type` token is kept as `elf_type` so nothing is hidden.
    """
    try:
        with open(path, "rb") as fh:
            if fh.read(4) != _ELF_MAGIC:
                return None
    except OSError:
        return None

    hdr = must_run(["readelf", "-h", str(path)])
    type_token = None
    for line in hdr.stdout.splitlines():
        s = line.strip()
        if s.startswith("Type:"):
            type_token = s.split(":", 1)[1].strip().split()[0]
            break

    dynamic = must_run(["readelf", "-d", "--wide", str(path)])
    needed: list[str] = []
    soname: str | None = None
    for line in dynamic.stdout.splitlines():
        if "(NEEDED)" in line:
            needed.append(line.rsplit("[", 1)[-1].rstrip("]"))
        elif "(SONAME)" in line:
            soname = line.rsplit("[", 1)[-1].rstrip("]")

    kind = _ELF_KIND.get(type_token or "")
    if type_token == "DYN":
        program = must_run(["readelf", "-l", "--wide", str(path)])
        if any("INTERP" in line for line in program.stdout.splitlines()):
            kind = "executable"

    return {
        "elf_kind": kind,
        "elf_type": type_token,
        "soname": soname,
        "dynamic_dependencies": sorted(set(needed)),
    }


def walk_distribution(root: Path, *, probe_elf: bool = True) -> list[dict]:
    """Every entry under `root`, recursively, as a signature row sorted by `path`.

    Symlinks are not followed: a symlink is recorded as `kind == "symlink"` with its
    `symlink_target`, never as the thing it names.
    """
    rows: list[dict] = []

    def visit(directory: str) -> None:
        with os.scandir(directory) as it:
            entries = sorted(it, key=lambda e: e.name)
        for entry in entries:
            full = entry.path
            path = Path(full).relative_to(root).as_posix()
            info = entry.stat(follow_symlinks=False)
            mode = f"{statmod.S_IMODE(info.st_mode):04o}"
            if entry.is_symlink():
                rows.append({
                    "path": path, "kind": "symlink", "mode": mode,
                    "size": info.st_size, "symlink_target": os.readlink(full),
                })
            elif entry.is_dir(follow_symlinks=False):
                rows.append({"path": path, "kind": "directory", "mode": mode, "size": None})
                visit(full)
            else:
                row = {"path": path, "kind": "file", "mode": mode, "size": info.st_size,
                       "sha256": _sha256_file(full)}
                if probe_elf:
                    row.update(elf_info(full) or {})
                rows.append(row)

    visit(str(root))
    rows.sort(key=lambda r: r["path"])
    return rows


# ---------------------------------------------------------------------------
# classification and diffing (pure -- no I/O)
# ---------------------------------------------------------------------------

def category_for(path: str, kind: str) -> str:
    """The category of one installed entry, from its own kind and its path's role."""
    if kind == "directory":
        return "directory"
    if kind == "symlink":
        return "symlink"
    parts = path.split("/")
    base = parts[-1]
    if parts[0] == "bin":
        return "cli" if base == "openssl" else "script"
    if parts[0] == "include":
        return "header"
    if parts[0] == "lib":
        if len(parts) >= 3 and parts[1] == "ossl-modules":
            return "provider_module"
        if len(parts) >= 3 and parts[1].startswith("engines"):
            return "engine"
        if len(parts) >= 3 and parts[1] == "pkgconfig":
            return "pkgconfig"
        if len(parts) >= 3 and parts[1] == "cmake":
            return "cmake_config"
        if base.startswith("lib"):
            return "library"
        return "other"
    if parts[0] == "share":
        if len(parts) >= 2 and parts[1] == "man":
            return "manpage"
        if len(parts) >= 2 and parts[1] == "doc":
            return "html_doc"
        return "other"
    if parts[0] == "ssl":
        if base.startswith(("openssl.cnf", "ct_log_list.cnf")):
            return "openssl_cnf"
        return "script"
    return "other"


def disposition_for(path: str, category: str) -> str:
    """The plan's section-4 disposition for one entry."""
    if category == "symlink":
        # A symlink's disposition follows what it participates in, by path.
        if path.startswith("share/"):
            return "GENERATED_INTERMEDIATE"
        if path.startswith(("lib/", "bin/")):
            return "REQUIRED_COMPATIBILITY"
        if path.startswith("ssl/"):
            return "TOOLING_ONLY"
        return "UNKNOWN"
    if category == "directory":
        # The `ssl/` directories are the default-path configuration root; the layout directories
        # under `bin`/`include`/`lib`/`share` are generated install scaffolding.
        if path == "ssl" or path.startswith("ssl/"):
            return "REQUIRED_COMPATIBILITY"
        return "GENERATED_INTERMEDIATE"
    return _CATEGORY_DISPOSITION[category]


def classify_entry(row: dict) -> dict:
    """Add `category` and `disposition` to one raw signature row."""
    entry = dict(row)
    category = category_for(entry["path"], entry["kind"])
    entry["category"] = category
    entry["disposition"] = disposition_for(entry["path"], category)
    return entry


def classify_entries(raw_rows: list[dict]) -> list[dict]:
    """Every raw row classified, sorted by `path`. A pure function (the court's mutation target)."""
    return sorted((classify_entry(r) for r in raw_rows), key=lambda e: e["path"])


def _tally(values: list[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in values:
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items()))


def summarize(entries: list[dict]) -> dict:
    """The `counts` block: every number derived from the entries, none typed."""
    sonames = sorted({e["soname"] for e in entries if e.get("soname")})
    return {
        "entries": len(entries),
        "files": sum(1 for e in entries if e["kind"] == "file"),
        "directories": sum(1 for e in entries if e["kind"] == "directory"),
        "symlinks": sum(1 for e in entries if e["kind"] == "symlink"),
        "elf": sum(1 for e in entries if e.get("elf_kind")),
        "sonames": len(sonames),
        "unknown_disposition": sum(1 for e in entries if e["disposition"] == "UNKNOWN"),
        "by_category": _tally([e["category"] for e in entries]),
        "by_kind": _tally([e["kind"] for e in entries]),
        "by_disposition": _tally([e["disposition"] for e in entries]),
    }


# The fields that define an entry's identity for the prefix comparison. ELF analysis is derived
# from the file's bytes and is not part of the comparison: `sha256` already pins the bytes.
_DIFF_FIELDS = ("kind", "mode", "size", "sha256", "symlink_target")


def diff_distributions(manifest: list[dict], pinned: list[dict]) -> dict:
    """The residual list between the manifest and the pinned prefix. A pure function.

    Two path sets are compared. A path in one and not the other is a residual; a path in both whose
    signature differs is a `changed` residual naming the fields. Nothing is treated as equal by
    default: an entry missing on either side is listed, not ignored.
    """
    m = {r["path"]: r for r in manifest}
    p = {r["path"]: r for r in pinned}
    common = set(m) & set(p)
    only_manifest = sorted(set(m) - set(p))
    only_pinned = sorted(set(p) - set(m))
    changed: list[dict] = []
    for path in sorted(common):
        a, b = m[path], p[path]
        fields = {}
        for field in _DIFF_FIELDS:
            if a.get(field) != b.get(field):
                fields[field] = {"manifest": a.get(field), "pinned": b.get(field)}
        if fields:
            changed.append({"path": path, "fields": fields})
    return {
        "manifest_entries": len(manifest),
        "pinned_entries": len(pinned),
        "common_entries": len(common),
        "counts": {
            "only_in_manifest": len(only_manifest),
            "only_in_pinned": len(only_pinned),
            "changed": len(changed),
        },
        "only_in_manifest": only_manifest,
        "only_in_pinned": only_pinned,
        "changed": changed,
    }


def _surfaces(entries: list[dict]) -> dict:
    """The reconciliation of the walk against the plan's named surfaces, plus the full lists."""
    by_path = {e["path"]: e for e in entries}
    looked_for = []
    for name, path in LOOKED_FOR:
        present = path in by_path
        looked_for.append({
            "name": name,
            "path": path,
            "present": present,
            "kind": by_path[path]["kind"] if present else None,
            "category": by_path[path]["category"] if present else None,
        })
    return {
        "looked_for": looked_for,
        "pkgconfig_files": sorted(e["path"] for e in entries if e["category"] == "pkgconfig"),
        "cmake_files": sorted(e["path"] for e in entries if e["category"] == "cmake_config"),
        "provider_modules": sorted(
            e["path"] for e in entries if e["category"] == "provider_module"),
        "engines": sorted(e["path"] for e in entries if e["category"] == "engine"),
        "scripts": sorted(e["path"] for e in entries if e["category"] == "script"),
        "sonames": sorted({e["soname"] for e in entries if e.get("soname")}),
    }


def build_body(raw_rows: list[dict], pinned_rows: list[dict], meta: dict) -> dict:
    """The atlas body from the manifest's raw rows and the pinned prefix's signature rows.

    A pure function of its three arguments, so the sensitivity court can call it on a mutated copy
    of the committed artefact and require the derived entries, counts, surface reconciliation and
    `prefix_diff` to move exactly as the mutation says.
    """
    entries = classify_entries(raw_rows)
    body = dict(meta)
    body["entries"] = entries
    body["pinned"] = sorted((dict(r) for r in pinned_rows), key=lambda r: r["path"])
    body["counts"] = summarize(entries)
    body.update(_surfaces(entries))
    body["prefix_diff"] = diff_distributions(entries, body["pinned"])
    return body


# ---------------------------------------------------------------------------
# RT-PHASE22-INSTALL -- the sensitivity court
# ---------------------------------------------------------------------------
#
# The court drives this module's own pure logic -- `classify_entries`, `summarize`,
# `diff_distributions`, `_surfaces` -- over the committed artefact's own rows and over controlled
# mutations of them in memory. Like every Phase 22 court it is an FRF-style challenge, not a file
# existence check: it FAILS if the logic is insensitive to its own defect class.

COURT_ID = "RT-PHASE22-INSTALL"

# Categories a manifest that actually saw a full `make install` must have produced. A manifest that
# missed any of these is a manifest that did not walk the distribution.
_REQUIRED_CATEGORIES = (
    "library", "header", "provider_module", "engine", "cli", "pkgconfig", "cmake_config",
    "openssl_cnf", "script", "manpage", "symlink", "directory",
)


def _raw(row: dict) -> dict:
    """A committed entry stripped of its classification -- what `classify_entries` consumed."""
    return {k: v for k, v in row.items() if k not in ("category", "disposition")}


def _surfaces_block(body: dict) -> dict:
    """The surface-reconciliation keys of a body, for the round-trip comparison."""
    keys = ("looked_for", "pkgconfig_files", "cmake_files", "provider_modules", "engines",
            "scripts", "sonames")
    return {k: body[k] for k in keys}


def court_install(artefact: Path) -> dict:
    body = json.loads(artefact.read_text(encoding="utf-8"))["body"]
    raw = [_raw(e) for e in body["entries"]]
    pinned = body["pinned"]
    checks: list[tuple[str, bool]] = []

    # -- baseline: the artefact is a whole distribution, and the named surfaces are present -----
    checks.append(("baseline: the manifest has entries", body["counts"]["entries"] > 0))
    checks.append(("baseline: the manifest has symlinks", body["counts"]["symlinks"] > 0))
    checks.append(("baseline: the manifest has ELF entries", body["counts"]["elf"] > 0))
    checks.append(("baseline: no entry is left UNKNOWN", body["counts"]["unknown_disposition"] == 0))
    present = set(body["counts"]["by_category"])
    missing = [c for c in _REQUIRED_CATEGORIES if c not in present]
    checks.append((f"baseline: every required category present (missing: {missing})",
                   not missing))
    checks.append(("baseline: the CMake config is found",
                   "lib/cmake/OpenSSL/OpenSSLConfig.cmake" in body["cmake_files"]
                   and "lib/cmake/OpenSSL/OpenSSLConfigVersion.cmake" in body["cmake_files"]))
    checks.append(("baseline: the pkg-config files are found",
                   {"lib/pkgconfig/libcrypto.pc", "lib/pkgconfig/libssl.pc",
                    "lib/pkgconfig/openssl.pc"} <= set(body["pkgconfig_files"])))
    checks.append(("baseline: the provider module and the config sample are found",
                   "lib/ossl-modules/legacy.so" in body["provider_modules"]
                   and any(e["name"] == "openssl-cnf" and e["present"]
                           for e in body["looked_for"])))

    # -- round-trip: re-derive the whole body from the artefact's own rows -----------------------
    rebuilt = classify_entries(copy.deepcopy(raw))
    checks.append(("round-trip: entries equal", rebuilt == body["entries"]))
    checks.append(("round-trip: counts equal", summarize(rebuilt) == body["counts"]))
    checks.append(("round-trip: surface reconciliation equal",
                   _surfaces(rebuilt) == _surfaces_block(body)))
    checks.append(("round-trip: prefix_diff equal",
                   diff_distributions(rebuilt, pinned) == body["prefix_diff"]))

    # -- mutation 1: add a library entry ---------------------------------------------------------
    lib = {"path": "lib/libsynth.so.3", "kind": "file", "mode": "0755", "size": 4096,
           "sha256": "0" * 64}
    lib_entries = classify_entries(copy.deepcopy(raw) + [lib])
    by_path = {e["path"]: e for e in lib_entries}
    checks.append(("add-library: library category rose by one",
                   summarize(lib_entries)["by_category"].get("library")
                   == body["counts"]["by_category"]["library"] + 1))
    checks.append(("add-library: the entry is classified library/REQUIRED_COMPATIBILITY",
                   by_path[lib["path"]]["category"] == "library"
                   and by_path[lib["path"]]["disposition"] == "REQUIRED_COMPATIBILITY"))
    checks.append(("add-library: entry count rose by one",
                   summarize(lib_entries)["entries"] == body["counts"]["entries"] + 1))
    lib_diff = diff_distributions(lib_entries, pinned)
    checks.append(("add-library: the new path is a manifest-only residual",
                   lib["path"] in lib_diff["only_in_manifest"]
                   and lib_diff["counts"]["only_in_manifest"]
                   == body["prefix_diff"]["counts"]["only_in_manifest"] + 1))

    # -- mutation 2: add a symlink, and require its target to be read ----------------------------
    link = {"path": "lib/libsynth.so", "kind": "symlink", "mode": "0777",
            "size": len("libsynth.so.3"), "symlink_target": "libsynth.so.3"}
    link_entries = classify_entries(copy.deepcopy(raw) + [link])
    link_by_path = {e["path"]: e for e in link_entries}
    checks.append(("add-symlink: the symlink count rose by one",
                   summarize(link_entries)["symlinks"] == body["counts"]["symlinks"] + 1))
    checks.append(("add-symlink: the entry is classified symlink",
                   link_by_path[link["path"]]["category"] == "symlink"))
    checks.append(("add-symlink: its target is read, not followed",
                   link_by_path[link["path"]].get("symlink_target") == "libsynth.so.3"))
    checks.append(("add-symlink: a library symlink keeps the library disposition",
                   link_by_path[link["path"]]["disposition"] == "REQUIRED_COMPATIBILITY"))

    # -- mutation 3: change a mode on a shared entry ---------------------------------------------
    pinned_paths = {r["path"] for r in pinned}
    already_changed = {c["path"] for c in body["prefix_diff"]["changed"]}
    idx = next((i for i, r in enumerate(raw)
                if r["path"] in pinned_paths and r["path"] not in already_changed), None)
    if idx is None:
        checks.append(("change-mode: no shared entry to mutate (pinned prefix absent)",
                       not pinned_paths))
    else:
        mutated = copy.deepcopy(raw)
        path = mutated[idx]["path"]
        mutated[idx]["mode"] = "0600" if mutated[idx]["mode"] != "0600" else "0644"
        moved = diff_distributions(classify_entries(mutated), pinned)
        changed = {c["path"]: c["fields"] for c in moved["changed"]}
        checks.append(("change-mode: the entry appears as changed", path in changed))
        checks.append(("change-mode: the differing field is named",
                       "mode" in changed.get(path, {})))
        checks.append(("change-mode: the presence residuals are unaffected",
                       moved["counts"]["only_in_manifest"]
                       == body["prefix_diff"]["counts"]["only_in_manifest"]
                       and moved["counts"]["only_in_pinned"]
                       == body["prefix_diff"]["counts"]["only_in_pinned"]))

    # -- mutation 4: add a provider module --------------------------------------------------------
    module = {"path": "lib/ossl-modules/synth.so", "kind": "file", "mode": "0755",
              "size": 8192, "sha256": "1" * 64, "elf_kind": "shared", "elf_type": "DYN",
              "soname": None, "dynamic_dependencies": ["libc.so.6"]}
    module_entries = classify_entries(copy.deepcopy(raw) + [module])
    module_counts = summarize(module_entries)
    checks.append(("add-provider-module: provider_module category rose by one",
                   module_counts["by_category"].get("provider_module")
                   == body["counts"]["by_category"]["provider_module"] + 1))
    checks.append(("add-provider-module: elf count rose by one",
                   module_counts["elf"] == body["counts"]["elf"] + 1))
    checks.append(("add-provider-module: it is REQUIRED_COMPATIBILITY",
                   {e["path"]: e for e in module_entries}[module["path"]]["disposition"]
                   == "REQUIRED_COMPATIBILITY"))

    # -- mutation 5: an entry present only in the pinned prefix -----------------------------------
    ghost = {"path": "include/openssl/ghost.h", "kind": "file", "mode": "0644", "size": 1,
             "sha256": "2" * 64}
    ghost_diff = diff_distributions(classify_entries(copy.deepcopy(raw)), pinned + [ghost])
    checks.append(("add-pinned-only: the ghost is a pinned-only residual",
                   ghost["path"] in ghost_diff["only_in_pinned"]))
    checks.append(("add-pinned-only: only_in_pinned rose by one",
                   ghost_diff["counts"]["only_in_pinned"]
                   == body["prefix_diff"]["counts"]["only_in_pinned"] + 1))
    checks.append(("add-pinned-only: only_in_manifest is unaffected",
                   ghost_diff["counts"]["only_in_manifest"]
                   == body["prefix_diff"]["counts"]["only_in_manifest"]))

    failures = [desc for desc, ok in checks if not ok]
    d = body["prefix_diff"]["counts"]
    return {
        "court": COURT_ID,
        "artefact": ARTEFACT_REL,
        "entries": body["counts"]["entries"],
        "symlinks": body["counts"]["symlinks"],
        "elf": body["counts"]["elf"],
        "categories": body["counts"]["by_category"],
        "prefix_diff": d,
        "pinned_prefix_present": bool(body.get("pinned_prefix_present")),
        "mutations": ["round-trip", "add-library", "add-symlink", "change-mode",
                      "add-provider-module", "add-pinned-only"],
        "observations": len(checks),
        "failures": failures,
        "verdict": "pass" if not failures else "fail",
        "summary": (f"{body['counts']['entries']} entries, {body['counts']['symlinks']} symlinks, "
                    f"{body['counts']['elf']} ELF; prefix_diff {d['only_in_manifest']}/"
                    f"{d['only_in_pinned']}/{d['changed']}"),
    }


def courts() -> list[dict]:
    """`RT-PHASE22-INSTALL`, or `[]` while the artefact has not landed.

    Discovered by `forensics/tools/phase22_courts.py` rather than listed there, so landing this
    plane adds a file and nothing else.
    """
    artefact = REPO_ROOT / ARTEFACT_REL
    if not artefact.is_file():
        return []
    return [court_install(artefact)]


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def _meta(prefix: str) -> dict:
    return {
        "install_method": "the authority's own `make install` into an empty scratch DESTDIR",
        "install_target": "install (install_sw + install_ssldirs + install_docs)",
        "install_command": ["make", INSTALL_TARGET, "DESTDIR=<scratch-root>"],
        "build_dir": BUILD_DIR_REL,
        "distribution_root": PREFIX_REL,
        "install_prefix": prefix,
        "scratch_root": (
            "a scratch DESTDIR outside the repository; its absolute path and any timestamp are "
            "deliberately not recorded, so the document carries no host-varying path"
        ),
        "producer": (
            "the pinned authority build directory's own Makefile and installdata.pm; the authority "
            "is never reconfigured"
        ),
        "sort_key": "path (POSIX, relative to the distribution root)",
        "authority_prefix_note": (
            "The pinned prefix " + PREFIX_REL + " was installed by the authority build's "
            "`install_sw` alone (forensics/tools/authority_build.py), so it carries no `ssl/`, no "
            "man pages and no HTML documentation. This manifest is the full `make install`, so "
            "`prefix_diff.only_in_manifest` is dominated by those install-scope differences. They "
            "are recorded as residuals rather than hidden: the pinned prefix under-represents the "
            "distribution surface, and a consumer who runs `make install` sees the larger tree."
        ),
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--scratch", default=SCRATCH_DEFAULT,
                    help="scratch DESTDIR for the install (default: %(default)s)")
    ap.add_argument("--keep", action="store_true",
                    help="reuse an existing scratch install instead of re-running make install")
    args = ap.parse_args(argv)

    auth = resolve_authority(args.authority)
    build_dir = REPO_ROOT / BUILD_DIR_REL
    if not (build_dir / "Makefile").is_file():
        raise SystemExit(
            f"phase22-install-manifest: {BUILD_DIR_REL}/Makefile is absent; build the authority "
            "(forensics/tools/authority_build.py) first"
        )

    prefix = read_install_prefix(build_dir)
    scratch = Path(args.scratch)
    dist_root = scratch / Path(prefix).relative_to("/")

    if not args.keep:
        shutil.rmtree(scratch, ignore_errors=True)
        scratch.mkdir(parents=True, exist_ok=True)
        print(f"[phase22-install-manifest] make {INSTALL_TARGET} DESTDIR=<scratch> in {BUILD_DIR_REL} ...")
        must_run(["make", INSTALL_TARGET, f"DESTDIR={scratch}"], cwd=build_dir)
    if not dist_root.is_dir():
        raise SystemExit(
            f"phase22-install-manifest: the installed tree is missing under the scratch root "
            f"(expected the prefix {prefix} to exist there); the install did not complete"
        )

    raw = walk_distribution(dist_root, probe_elf=True)

    pinned_root = auth.prefix
    pinned: list[dict] = []
    pinned_present = pinned_root.is_dir()
    if pinned_present:
        pinned = walk_distribution(pinned_root, probe_elf=False)

    body = build_body(raw, pinned, _meta(prefix))
    body["pinned_prefix_present"] = pinned_present
    if not pinned_present:
        body["prefix_diff"]["note"] = (
            f"the pinned prefix {PREFIX_REL} is absent from this checkout, so there is nothing to "
            "compare against and every manifest entry is a residual"
        )

    doc = envelope(
        kind="phase22-install-manifest",
        authority=auth.id,
        inputs=[
            InputRef(name="phase-22-plan", path=REPO_ROOT / PLAN_REL),
            InputRef(
                name="pinned-prefix-signature",
                sha256=content_hash(body["pinned"]),
                note=("sha256 of the canonical JSON of the pinned prefix's entry signatures; the "
                      "prefix is an untracked directory, so its state is pinned by this digest "
                      "rather than by a path"),
            ),
        ],
        body=body,
        generator=GENERATOR,
    )
    write_json(REPO_ROOT / OUT_REL, doc)

    c = body["counts"]
    d = body["prefix_diff"]["counts"]
    print(f"[phase22-install-manifest] install={body['install_target']}")
    print(f"  entries={c['entries']} files={c['files']} dirs={c['directories']} "
          f"symlinks={c['symlinks']} elf={c['elf']} sonames={c['sonames']} "
          f"unknown={c['unknown_disposition']}")
    print(f"  categories={c['by_category']}")
    print(f"  listened-for: cmake={body['cmake_files']} pkgconfig={body['pkgconfig_files']} "
          f"providers={body['provider_modules']} engines={body['engines']}")
    print(f"  prefix_diff: only_in_manifest={d['only_in_manifest']} "
          f"only_in_pinned={d['only_in_pinned']} changed={d['changed']} "
          f"(pinned_present={pinned_present})")
    print(f"  -> {rel(REPO_ROOT / OUT_REL)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
