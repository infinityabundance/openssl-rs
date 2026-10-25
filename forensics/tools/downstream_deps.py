#!/usr/bin/env python3
"""openssl-rs — the downstream build/link dependency registry.

A downstream recipe names a **capability** (``libevent``, ``ncurses``, ``libudev``,
``pcre1``, ``libxml2``, ``autotools``) instead of repeating a list of pinned Debian
URLs.  The registry maps every capability to a versioned **bundle**: the exact set
of Debian packages that supplies the runtime libraries, headers, development
symlinks, ``pkg-config`` metadata and (where applicable) build tools the
capability requires.

The four invariants are enforced here, in the resolver, not only in a court:

1. **Subject isolation** — no bundle may provide or replace ``libssl`` or
   ``libcrypto``.  :func:`_assert_subject_isolated` runs on every resolve and
   refuses a package name, URL basename, pool path or declared install path that
   looks like an OpenSSL subject artefact.
2. **Version coherence** — the packages of a component must carry one Debian
   version; the development symlink must resolve to the same ELF the pinned
   runtime package exposes under the declared SONAME; and the installed
   ``pkg-config`` ``Version`` and header version macro must agree with the
   component's upstream version.  The static half runs in
   :func:`validate_bundle` (callable from the resolver); the filesystem half runs
   in :func:`verify_installed`, which the executor calls after extraction.
3. **Source immutability** — :func:`assert_isolated_install_root` refuses an
   install root that overlaps the consumer's extracted source tree, and
   :func:`assert_within_install_root` refuses a package path that escapes the
   install root through a symlink (except an explicitly declared external
   runtime).
4. **Reproducibility** — every bundle carries a content hash over its package
   URLs, published digests and declared install layout.  :func:`resolve` verifies
   the recorded hash and a recipe names the exact bundle it used.

Where published metadata supplies no digest the package is recorded as
``UNRESOLVED``.  Nothing is invented: a package whose digest is ``UNRESOLVED``
is reported and refused by :func:`resolve` unless the caller explicitly opts in,
so an unverifiable dependency cannot silently become a build input.  A coherence
*axis* with no published evidence (a header with no version macro, an external
runtime SONAME) is recorded in the component's ``unresolved`` list and is never
counted as verified.

Outputs
-------
  forensics/tools/downstream_deps.json   the authored registry (validated data)

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import sys
from pathlib import Path

REGISTRY_PATH = Path(__file__).resolve().with_name("downstream_deps.json")
SCHEMA = "openssl-rs/downstream-deps/v1"
UNRESOLVED = "UNRESOLVED"

# A Debian pool path that identifies the OpenSSL source package.  A bundle that
# acquires bytes from it is refused even when the file name is unremarkable.
_OPENSSL_POOL = re.compile(r"(?:^|/)pool/main/o/openssl(?:/|$)")
# Basenames that would provide or replace the subject.  Deliberately anchored at
# the start: ``libevent_openssl.so`` is a libevent module (a subject *consumer*),
# not an OpenSSL provider, and must remain admissible.
_SUBJECT_NAME = re.compile(r"^(?:libssl|libcrypto|openssl)(?:[0-9._-]|$)")
_DEB_NAME = re.compile(
    r"^(?P<name>[^_]+)_(?P<version>[^_]+)_(?P<arch>[^_]+)\.deb$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CAPABILITY_NAME = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")


class DependencyError(RuntimeError):
    """A dependency bundle failed an enforced invariant."""


# --------------------------------------------------------------------------------------------
# canonical content addressing
# --------------------------------------------------------------------------------------------

def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _package_identity(package: dict) -> dict:
    """The subset of a package spec that affects what is installed and how.

    Prose (``note``) is excluded: editing an explanation must not invalidate a
    content address that pins bytes and build paths.
    """
    return {
        "name": package.get("name"),
        "url": package.get("url"),
        "sha256": package.get("sha256"),
        "archive": package.get("archive"),
        "extract": package.get("extract"),
        "include_dirs": list(package.get("include_dirs") or []),
        "library_dirs": list(package.get("library_dirs") or []),
        "pkgconfig_dirs": list(package.get("pkgconfig_dirs") or []),
        "bin_dirs": list(package.get("bin_dirs") or []),
        "links": dict(package.get("links") or {}),
    }


def _component_identity(component: dict) -> dict:
    return copy.deepcopy(component)


def bundle_content_hash(bundle: dict) -> str:
    """The content address of a bundle: its packages, digests and install layout."""
    payload = {
        "bundle_id": bundle.get("bundle_id"),
        "version": bundle.get("version"),
        "packages": [_package_identity(p) for p in bundle.get("packages") or []],
        "components": [_component_identity(c) for c in bundle.get("components") or []],
    }
    digest = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def package_version_from_url(url: str) -> tuple[str, str, str] | None:
    """Return ``(name, version, arch)`` for a Debian package URL, else ``None``."""
    name = str(url).rsplit("/", 1)[-1]
    match = _DEB_NAME.match(name)
    if not match:
        return None
    return match.group("name"), match.group("version"), match.group("arch")


# --------------------------------------------------------------------------------------------
# invariant 1 — subject isolation
# --------------------------------------------------------------------------------------------

def subject_artifacts(bundle: dict) -> list[str]:
    """Every name, URL component and install path in *bundle* that names the subject."""
    found: list[str] = []

    def check(label: str, value: object) -> None:
        text = str(value or "")
        if _SUBJECT_NAME.match(text.rsplit("/", 1)[-1]):
            found.append(f"{label}:{text}")

    for package in bundle.get("packages") or []:
        name = str(package.get("name") or "")
        url = str(package.get("url") or "")
        check("package", name)
        if _SUBJECT_NAME.match(url.rsplit("/", 1)[-1]):
            found.append(f"url:{url}")
        if _OPENSSL_POOL.search(url):
            found.append(f"pool:{url}")
        for key in ("include_dirs", "library_dirs", "pkgconfig_dirs", "bin_dirs"):
            for value in package.get(key) or []:
                check(key, value)
        for link, target in (package.get("links") or {}).items():
            check("link", link)
            check("link_target", target)
    for component in bundle.get("components") or []:
        for key, value in (component.get("runtime") or {}).items():
            check(f"runtime.{key}", value)
        for key, value in (component.get("development") or {}).items():
            check(f"development.{key}", value)
        for key, value in (component.get("pkgconfig") or {}).items():
            if key in ("path", "file"):
                check(f"pkgconfig.{key}", value)
        for key, value in (component.get("header") or {}).items():
            if key in ("path", "file"):
                check(f"header.{key}", value)
        for value in component.get("tools") or []:
            check("tool", value)
    return found


def _assert_subject_isolated(bundle: dict) -> None:
    artifacts = subject_artifacts(bundle)
    if artifacts:
        raise DependencyError(
            f"bundle {bundle.get('bundle_id')!r} violates subject isolation: it names "
            f"{', '.join(artifacts[:4])}; a capability bundle may never provide or replace "
            f"libssl/libcrypto/openssl")


# --------------------------------------------------------------------------------------------
# invariant 2 — version coherence (static half)
# --------------------------------------------------------------------------------------------

def _version_relation(observed: str, expected: str, relation: str) -> bool:
    if relation == "exact":
        return observed == expected
    if relation == "prefix":
        return observed.startswith(expected)
    raise DependencyError(f"unknown version relation {relation!r}")


def _check_component_versions(bundle: dict, component: dict, problems: list[str]) -> None:
    name = str(component.get("name") or "?")
    debian_version = str(component.get("debian_version") or "")
    upstream = str(component.get("upstream_version") or "")
    packages = {str(p.get("name")): p for p in bundle.get("packages") or []}
    members = [str(n) for n in component.get("packages") or []]
    if not members:
        problems.append(f"{bundle.get('bundle_id')}: component {name!r} names no packages")
        return
    if not debian_version or not upstream:
        problems.append(f"{bundle.get('bundle_id')}: component {name!r} has no version pair")
        return
    for member in members:
        package = packages.get(member)
        if package is None:
            problems.append(f"{bundle.get('bundle_id')}: component {name!r} names unknown "
                            f"package {member!r}")
            continue
        parsed = package_version_from_url(str(package.get("url") or ""))
        if parsed is None:
            problems.append(f"{bundle.get('bundle_id')}: {member!r} is not a Debian package URL")
            continue
        observed_name, observed_version, _arch = parsed
        if observed_name != member:
            problems.append(f"{bundle.get('bundle_id')}: package {member!r} URL names "
                            f"{observed_name!r}")
        if observed_version != debian_version:
            problems.append(f"{bundle.get('bundle_id')}: component {name!r} declares "
                            f"{debian_version!r} but {member!r} carries "
                            f"{observed_version!r}")
        if not observed_version.startswith(upstream):
            problems.append(f"{bundle.get('bundle_id')}: component {name!r} upstream "
                            f"{upstream!r} is not a prefix of {observed_version!r}")
    _check_component_layout(bundle, component, packages, members, problems)


def _check_component_layout(bundle: dict, component: dict, packages: dict,
                            members: list[str], problems: list[str]) -> None:
    name = str(component.get("name") or "?")
    bid = bundle.get("bundle_id")

    def declared_in(key: str, path: str) -> bool:
        # Every package in the bundle extracts into the same install root, so a
        # directory declared by any member is available to every component.
        return any(str(path).startswith(str(d).rstrip("/") + "/") or str(path) == str(d)
                   for package in packages.values() for d in package.get(key) or [])

    kind = str(component.get("kind") or "library")
    if kind not in ("library", "tool"):
        problems.append(f"{bid}: component {name!r} has unknown kind {kind!r}")
    unresolved = [str(u) for u in component.get("unresolved") or []]
    for axis in ("runtime", "development", "pkgconfig", "header"):
        if kind == "tool":
            continue
        present = component.get(axis)
        if not present and not any(u.startswith(axis + ":") for u in unresolved):
            problems.append(f"{bid}: component {name!r} has no {axis} evidence and does not "
                            f"record it as UNRESOLVED")
    if kind == "tool" and not component.get("tools"):
        problems.append(f"{bid}: tool component {name!r} declares no tools")

    runtime = component.get("runtime")
    if runtime:
        path = str(runtime.get("path") or "")
        soname = str(runtime.get("soname") or "")
        rp = str(runtime.get("package") or "")
        if rp not in members:
            problems.append(f"{bid}: component {name!r} runtime package {rp!r} is not a member")
        if not path or Path(path).name != soname:
            problems.append(f"{bid}: component {name!r} runtime path {path!r} does not name "
                            f"SONAME {soname!r}")
        if not declared_in("library_dirs", str(Path(path).parent)):
            problems.append(f"{bid}: component {name!r} runtime path {path!r} is not under a "
                            f"declared library dir")
        if runtime.get("external"):
            external_path = str(runtime.get("external_path") or "")
            if not external_path.startswith("/"):
                problems.append(f"{bid}: component {name!r} external runtime needs an absolute "
                                f"external_path")

    development = component.get("development")
    if development:
        link = str(development.get("link") or "")
        dp = str(development.get("package") or "")
        if dp not in members:
            problems.append(f"{bid}: component {name!r} development package {dp!r} is not a member")
        if not declared_in("library_dirs", str(Path(link).parent)):
            problems.append(f"{bid}: component {name!r} development link {link!r} is not under a "
                            f"declared library dir")

    pkgconfig = component.get("pkgconfig")
    if pkgconfig:
        path = str(pkgconfig.get("path") or "")
        if not declared_in("pkgconfig_dirs", str(Path(path).parent)):
            problems.append(f"{bid}: component {name!r} pkg-config {path!r} is not under a "
                            f"declared pkgconfig dir")
        relation = str(pkgconfig.get("match") or "exact")
        if relation not in ("exact", "prefix"):
            problems.append(f"{bid}: component {name!r} has unknown pkg-config relation "
                            f"{relation!r}")
        if not _version_relation(str(pkgconfig.get("version") or ""),
                                 str(component.get("upstream_version") or ""), relation):
            problems.append(f"{bid}: component {name!r} pkg-config version "
                            f"{pkgconfig.get('version')!r} does not {relation}-match the upstream "
                            f"version")

    header = component.get("header")
    if header:
        path = str(header.get("path") or "")
        if not declared_in("include_dirs", str(Path(path).parent)):
            problems.append(f"{bid}: component {name!r} header {path!r} is not under a declared "
                            f"include dir")
        if not header.get("regex"):
            problems.append(f"{bid}: component {name!r} header probe has no regex")
        relation = str(header.get("match") or "exact")
        if not _version_relation(str(header.get("version") or ""),
                                 str(component.get("upstream_version") or ""), relation):
            problems.append(f"{bid}: component {name!r} header version "
                            f"{header.get('version')!r} does not {relation}-match the upstream "
                            f"version")

    for tool in component.get("tools") or []:
        if not declared_in("bin_dirs", str(Path(tool).parent)):
            problems.append(f"{bid}: component {name!r} tool {tool!r} is not under a declared "
                            f"bin dir")


def validate_bundle(bundle: dict) -> list[str]:
    """Static invariants for one bundle.  An empty list means it may be resolved."""
    problems: list[str] = []
    bid = str(bundle.get("bundle_id") or "")
    if not bid.startswith("cap:") or "@" not in bid:
        problems.append(f"bundle id {bid!r} is not `cap:<capability>@<version>`")
    if not str(bundle.get("version") or ""):
        problems.append(f"{bid}: bundle has no version")
    packages = bundle.get("packages") or []
    if not packages:
        problems.append(f"{bid}: bundle has no packages")
    seen_names: set[str] = set()
    for package in packages:
        name = str(package.get("name") or "")
        if not name:
            problems.append(f"{bid}: a package has no name")
        if name in seen_names:
            problems.append(f"{bid}: package {name!r} is listed twice")
        seen_names.add(name)
        digest = str(package.get("sha256") or "")
        if digest != UNRESOLVED and not _SHA256.match(digest):
            problems.append(f"{bid}: package {name!r} has an invalid SHA-256 {digest!r}")
        if package_version_from_url(str(package.get("url") or "")) is None:
            problems.append(f"{bid}: package {name!r} has no Debian URL")
    problems += [f"{bid}: subject isolation: {a}" for a in subject_artifacts(bundle)]

    referenced: list[str] = []
    components = bundle.get("components") or []
    if not components:
        problems.append(f"{bid}: bundle has no components")
    for component in components:
        _check_component_versions(bundle, component, problems)
        referenced += [str(n) for n in component.get("packages") or []]
    for component in components:
        members = [str(n) for n in component.get("packages") or []]
        if len(members) != len(set(members)):
            problems.append(f"{bid}: component {component.get('name')!r} names a package twice")
    for name in sorted(set(referenced)):
        if name not in seen_names:
            problems.append(f"{bid}: component references unknown package {name!r}")
    for name in sorted(seen_names - set(referenced)):
        problems.append(f"{bid}: package {name!r} belongs to no component")

    recorded = str(bundle.get("sha256") or "")
    computed = bundle_content_hash(bundle)
    if recorded != computed:
        problems.append(f"{bid}: recorded content hash {recorded!r} does not match the "
                        f"recomputed {computed!r}")
    return problems


def unresolved_packages(bundle: dict) -> list[str]:
    return [str(p.get("name")) for p in bundle.get("packages") or []
            if str(p.get("sha256")) == UNRESOLVED]


# --------------------------------------------------------------------------------------------
# invariant 3 — source immutability
# --------------------------------------------------------------------------------------------

def assert_isolated_install_root(install_root: Path, source_root: Path) -> None:
    """Refuse an auxiliary install root that overlaps the consumer's source tree.

    The install root may not be the source root, inside it, or an ancestor of it.
    Symlinks are resolved first, so a lexical path that looks disjoint but
    resolves into the source tree is refused.
    """
    install = Path(os.path.abspath(install_root))
    source = Path(os.path.abspath(source_root))
    try:
        install_real = Path(install_root).resolve()
        source_real = Path(source_root).resolve()
    except OSError as exc:  # pragma: no cover - defensive, paths exist in the executor
        raise DependencyError(f"cannot resolve the auxiliary install roots: {exc}") from exc
    for a, b in ((install, source), (install_real, source_real)):
        if a == b:
            raise DependencyError(
                f"the auxiliary install root {install_root} is the consumer source tree; a "
                f"bundle may never install into the source it builds")
        if a.is_relative_to(b):
            raise DependencyError(
                f"the auxiliary install root {install_root} is inside the consumer source tree "
                f"{source_root}; source immutability is not negotiable")
        if b.is_relative_to(a):
            raise DependencyError(
                f"the consumer source tree {source_root} is inside the auxiliary install root "
                f"{install_root}; extraction could overwrite it")


def assert_within_install_root(path: Path, install_root: Path) -> None:
    """Refuse a package file that escapes the install root through a symlink."""
    root = Path(os.path.abspath(install_root))
    try:
        root = Path(install_root).resolve()
    except OSError:  # pragma: no cover - a not-yet-created root is still checked lexically
        pass
    try:
        resolved = Path(path).resolve()
    except OSError as exc:  # pragma: no cover - defensive
        raise DependencyError(f"cannot resolve {path}: {exc}") from exc
    if resolved != root and not resolved.is_relative_to(root):
        raise DependencyError(
            f"{path} resolves to {resolved}, outside the auxiliary install root {install_root}; "
            f"installing it would modify the consumer's tree or the venue")


# --------------------------------------------------------------------------------------------
# invariant 2 — version coherence (filesystem half)
# --------------------------------------------------------------------------------------------

def _read_pkgconfig_version(path: Path) -> str | None:
    text = path.read_text(encoding="utf-8", errors="replace")
    variables: dict[str, str] = {}
    version_field: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Version:"):
            version_field = stripped.split(":", 1)[1].strip()
        elif "=" in stripped and not stripped.startswith("#"):
            key, value = stripped.split("=", 1)
            variables[key.strip()] = value.strip()
    if version_field is None:
        return None
    for _ in range(8):
        match = re.search(r"\$\{([^}]+)\}", version_field)
        if not match:
            break
        replacement = variables.get(match.group(1), "")
        version_field = version_field.replace(match.group(0), replacement)
    return version_field


def _read_header_version(path: Path, regex: str) -> str | None:
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(regex, text, re.MULTILINE)
    if not match:
        return None
    groups = [g for g in match.groups() if g is not None]
    return ".".join(groups) if groups else None


def verify_installed(install_root: Path, bundles: list[dict],
                     *, strict: bool = True) -> list[str]:
    """Verify a materialised bundle tree against its declared coherence evidence.

    Checks, per component: the pinned runtime package exposes the declared
    SONAME; the development symlink resolves to the same ELF; the installed
    ``pkg-config`` ``Version`` and header version macro agree with the component's
    upstream version; and every declared tool exists.  Returns the problems; with
    ``strict`` a non-empty result raises :class:`DependencyError`.
    """
    root = Path(install_root)
    problems: list[str] = []
    for bundle in bundles:
        bid = str(bundle.get("bundle_id") or "?")
        for component in bundle.get("components") or []:
            name = str(component.get("name") or "?")
            upstream = str(component.get("upstream_version") or "")
            runtime = component.get("runtime") or {}
            runtime_path: Path | None = None
            if runtime:
                runtime_path = root / str(runtime.get("path") or "")
                if not runtime_path.exists():
                    problems.append(f"{bid}/{name}: runtime SONAME {runtime_path} is absent")
                    runtime_path = None
                else:
                    soname = str(runtime.get("soname") or "")
                    if runtime_path.name != soname:
                        problems.append(f"{bid}/{name}: runtime path {runtime_path.name!r} is "
                                        f"not SONAME {soname!r}")
                    if runtime.get("external"):
                        external = Path(str(runtime.get("external_path") or ""))
                        if not external.exists():
                            problems.append(f"{bid}/{name}: declared external runtime "
                                            f"{external} is absent from the venue")
            development = component.get("development") or {}
            if development:
                link = root / str(development.get("link") or "")
                if not link.exists() and not development.get("external_target"):
                    problems.append(f"{bid}/{name}: development link {link} is absent")
                elif link.exists():
                    try:
                        real = link.resolve()
                    except OSError as exc:
                        problems.append(f"{bid}/{name}: cannot resolve {link}: {exc}")
                        real = None
                    if real is not None and development.get("external_target"):
                        soname = str(runtime.get("soname") or "")
                        if soname and real.name != soname:
                            problems.append(
                                f"{bid}/{name}: development symlink {link} resolves to "
                                f"{real.name!r}, not to SONAME {soname!r}")
                    elif real is not None and runtime_path is not None:
                        if real != runtime_path.resolve():
                            problems.append(
                                f"{bid}/{name}: development symlink {link} resolves to {real}, "
                                f"not to the runtime SONAME {runtime_path}")
                    if real is not None and runtime.get("external"):
                        external = Path(str(runtime.get("external_path") or ""))
                        if external.exists() and real != external.resolve():
                            problems.append(
                                f"{bid}/{name}: development symlink {link} resolves to {real}, "
                                f"not to the declared external runtime {external}")
            pkgconfig = component.get("pkgconfig") or {}
            if pkgconfig:
                pc = root / str(pkgconfig.get("path") or "")
                if not pc.exists():
                    problems.append(f"{bid}/{name}: pkg-config file {pc} is absent")
                else:
                    observed = _read_pkgconfig_version(pc)
                    relation = str(pkgconfig.get("match") or "exact")
                    expected = str(pkgconfig.get("version") or "")
                    if observed is None:
                        problems.append(f"{bid}/{name}: {pc} declares no Version")
                    elif observed != expected:
                        problems.append(f"{bid}/{name}: {pc} Version is {observed!r}, "
                                        f"not the pinned {expected!r}")
                    elif not _version_relation(observed, upstream, relation):
                        problems.append(f"{bid}/{name}: pkg-config Version {observed!r} does "
                                        f"not {relation}-match upstream {upstream!r}")
            header = component.get("header") or {}
            if header:
                header_path = root / str(header.get("path") or "")
                if not header_path.exists():
                    problems.append(f"{bid}/{name}: header {header_path} is absent")
                else:
                    observed = _read_header_version(header_path, str(header.get("regex") or ""))
                    expected = str(header.get("version") or "")
                    relation = str(header.get("match") or "exact")
                    if observed is None:
                        problems.append(f"{bid}/{name}: header {header_path} has no version "
                                        f"matching {header.get('regex')!r}")
                    elif observed != expected:
                        problems.append(f"{bid}/{name}: header version {observed!r} is not the "
                                        f"pinned {expected!r}")
                    elif not _version_relation(observed, upstream, relation):
                        problems.append(f"{bid}/{name}: header version {observed!r} does not "
                                        f"{relation}-match upstream {upstream!r}")
            for tool in component.get("tools") or []:
                tool_path = root / str(tool)
                if not tool_path.exists():
                    problems.append(f"{bid}/{name}: declared tool {tool_path} is absent")
                elif not os.access(tool_path, os.X_OK):
                    problems.append(f"{bid}/{name}: declared tool {tool_path} is not executable")
    if strict and problems:
        raise DependencyError("; ".join(problems[:6]) +
                              (f" (+{len(problems) - 6} more)" if len(problems) > 6 else ""))
    return problems


# --------------------------------------------------------------------------------------------
# loading and resolving
# --------------------------------------------------------------------------------------------

def load_registry(path: Path | str | None = None) -> dict:
    target = Path(path) if path is not None else REGISTRY_PATH
    if not target.is_file():
        raise DependencyError(f"the dependency registry {target} is absent")
    try:
        registry = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DependencyError(f"the dependency registry {target} is not JSON: {exc}") from exc
    problems = validate_registry(registry)
    if problems:
        raise DependencyError("the dependency registry is invalid: " + "; ".join(problems[:6]) +
                              (f" (+{len(problems) - 6} more)" if len(problems) > 6 else ""))
    return registry


def validate_registry(registry: dict) -> list[str]:
    problems: list[str] = []
    if registry.get("schema") != SCHEMA:
        problems.append(f"schema is {registry.get('schema')!r}, not {SCHEMA!r}")
    capabilities = registry.get("capabilities")
    if not isinstance(capabilities, dict) or not capabilities:
        return problems + ["the registry defines no capabilities"]
    seen_bundles: set[str] = set()
    for capability, entry in sorted(capabilities.items()):
        if not _CAPABILITY_NAME.match(capability):
            problems.append(f"capability name {capability!r} is not a slug")
        bundles = (entry or {}).get("bundles")
        if not isinstance(bundles, list) or not bundles:
            problems.append(f"capability {capability!r} has no bundles")
            continue
        for bundle in bundles:
            bid = str(bundle.get("bundle_id") or "")
            if bid in seen_bundles:
                problems.append(f"bundle id {bid!r} is defined twice")
            seen_bundles.add(bid)
            if not bid.startswith(f"cap:{capability}@"):
                problems.append(f"bundle {bid!r} does not belong to capability "
                                f"{capability!r}")
            problems += [f"capability {capability!r}: {p}" for p in validate_bundle(bundle)]
            unresolved = unresolved_packages(bundle)
            if unresolved:
                problems.append(f"bundle {bid!r} has UNRESOLVED package digest(s): "
                                f"{', '.join(unresolved)}")
    return problems


def capability_names(registry: dict) -> list[str]:
    return sorted((registry.get("capabilities") or {}).keys())


def _bundle_for(registry: dict, capability: str, bundle_id: str | None) -> dict:
    entry = (registry.get("capabilities") or {}).get(capability)
    if not entry:
        raise DependencyError(f"the registry defines no capability {capability!r}; "
                              f"known: {', '.join(capability_names(registry))}")
    bundles = entry.get("bundles") or []
    if bundle_id is None:
        if len(bundles) != 1:
            raise DependencyError(
                f"capability {capability!r} has {len(bundles)} bundles; a recipe must name the "
                f"exact bundle it uses")
        return bundles[0]
    for bundle in bundles:
        if bundle.get("bundle_id") == bundle_id:
            return bundle
    raise DependencyError(f"capability {capability!r} has no bundle {bundle_id!r}")


def resolve(registry: dict, capability: str, *, bundle_id: str | None = None,
            allow_unresolved: bool = False) -> dict:
    """Resolve one capability request, enforcing every invariant on the way out.

    Returns ``{"capability", "bundle_id", "sha256", "packages", "components"}``.
    """
    bundle = _bundle_for(registry, capability, bundle_id)
    _assert_subject_isolated(bundle)
    problems = validate_bundle(bundle)
    if problems:
        raise DependencyError("; ".join(problems[:6]))
    unresolved = unresolved_packages(bundle)
    if unresolved and not allow_unresolved:
        raise DependencyError(
            f"bundle {bundle.get('bundle_id')!r} has no published digest for "
            f"{', '.join(unresolved)}; mark it UNRESOLVED and refuse it rather than invent one")
    resolved = copy.deepcopy(bundle)
    resolved["capability"] = capability
    resolved["sha256"] = bundle_content_hash(bundle)
    return resolved


def resolve_many(registry: dict, requests: list[dict | str], *,
                 allow_unresolved: bool = False) -> list[dict]:
    """Resolve a recipe's capability requests, refusing duplicates and version conflicts."""
    resolved: list[dict] = []
    seen_capabilities: set[str] = set()
    first_url: dict[str, tuple[str, str]] = {}
    for request in requests:
        if isinstance(request, str):
            capability, bundle_id = request, None
        elif isinstance(request, dict):
            capability = str(request.get("capability") or "")
            bundle_id = request.get("bundle")
        else:
            raise DependencyError(f"a capability request must be a name or an object, got "
                                  f"{type(request).__name__}")
        if not capability:
            raise DependencyError("a capability request names no capability")
        if capability in seen_capabilities:
            raise DependencyError(f"capability {capability!r} is requested twice")
        seen_capabilities.add(capability)
        bundle = resolve(registry, capability, bundle_id=bundle_id,
                         allow_unresolved=allow_unresolved)
        for package in bundle.get("packages") or []:
            url = str(package.get("url"))
            digest = str(package.get("sha256"))
            if url in first_url and first_url[url][1] != digest:
                raise DependencyError(
                    f"package {url} is pinned to two digests: {first_url[url][1]} and {digest}")
            first_url[url] = (capability, digest)
        resolved.append(bundle)
    return resolved


def merge_specs(bundles: list[dict]) -> list[dict]:
    """The executor's aux specs for a set of resolved bundles, de-duplicated by URL."""
    specs: list[dict] = []
    seen: set[str] = set()
    for bundle in bundles:
        for package in bundle.get("packages") or []:
            url = str(package.get("url"))
            if url in seen:
                continue
            seen.add(url)
            spec = {k: copy.deepcopy(v) for k, v in package.items() if k != "name"}
            specs.append(spec)
    return specs


def resolve_recipe(requests: list[dict | str], *, registry: dict | None = None) -> list[dict]:
    """Resolve a recipe's capabilities against the on-disk registry."""
    return resolve_many(registry or load_registry(), requests)


def inventory(registry: dict) -> dict:
    """Compact counts for receipts: capabilities, bundles, packages and duplicate URLs."""
    capabilities = registry.get("capabilities") or {}
    bundles = [b for entry in capabilities.values() for b in entry.get("bundles") or []]
    urls = [str(p.get("url")) for b in bundles for p in b.get("packages") or []]
    return {
        "capabilities": len(capabilities),
        "bundles": len(bundles),
        "package_definitions": len(urls),
        "unique_package_urls": len(set(urls)),
        "unresolved": sum(1 for b in bundles for _ in unresolved_packages(b)),
        "capability_names": sorted(capabilities),
    }


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def _self_test() -> int:
    registry = load_registry()
    info = inventory(registry)
    failures: list[str] = []
    # Every capability resolves with its invariants enforced.
    for capability in capability_names(registry):
        for bundle in registry["capabilities"][capability]["bundles"]:
            try:
                resolve(registry, capability, bundle_id=bundle["bundle_id"])
            except DependencyError as exc:
                failures.append(f"{capability}: {exc}")
    # A synthetic subject bundle must be refused by the resolver, not merely documented.
    synthetic = copy.deepcopy(registry["capabilities"]["libevent"]["bundles"][0])
    synthetic["bundle_id"] = "cap:libevent@0"
    synthetic["version"] = "0"
    synthetic["packages"] = copy.deepcopy(synthetic["packages"])
    synthetic["packages"].append({
        "name": "libssl3", "url": "http://example.invalid/libssl3_3.0_amd64.deb",
        "sha256": "0" * 64, "archive": "deb", "extract": ["dpkg-deb", "-x"],
    })
    try:
        _assert_subject_isolated(synthetic)
        failures.append("the resolver admitted a bundle that provides libssl3")
    except DependencyError:
        pass
    # An invented digest must not be accepted: a mutated package changes the bundle hash.
    mutated = copy.deepcopy(registry["capabilities"]["libevent"]["bundles"][0])
    mutated["packages"][0]["sha256"] = "1" * 64
    if not any("content hash" in p for p in validate_bundle(mutated)):
        failures.append("a mutated package digest did not invalidate the bundle content hash")
    # Source immutability: an install root inside the source tree is refused.
    try:
        assert_isolated_install_root(Path("/tmp/src/aux"), Path("/tmp/src"))
        failures.append("the resolver admitted an install root inside the source tree")
    except DependencyError:
        pass
    if failures:
        print("[downstream-deps] self-test FAILED")
        for failure in failures:
            print("  " + failure)
        return 1
    print(f"[downstream-deps] self-test ok: {info['capabilities']} capabilities, "
          f"{info['bundles']} bundles, {info['package_definitions']} package definitions "
          f"({info['unique_package_urls']} unique URLs), subject isolation, version coherence, "
          f"source immutability and content addressing enforced")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return _self_test()
    if "--inventory" in argv:
        print(json.dumps(inventory(load_registry()), indent=2, sort_keys=True))
        return 0
    print(__doc__.splitlines()[0])
    print("usage: downstream_deps.py [--self-test|--inventory]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
