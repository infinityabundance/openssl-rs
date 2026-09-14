#!/usr/bin/env python3
"""openssl-rs — authority acquisition.

Admits an OpenSSL upstream release as a forensic *authority*: downloads the
release archive, verifies it against the upstream-published SHA-256, extracts
the source tree, and records a content-addressed manifest.

This is Phase 1, step 1-3 of the custodian program (docs/CUSTODIAN_CONTRACT.md):
no candidate work may reference an authority that has not been admitted here.

Design rules
------------
* Raw authority material is immutable. We never edit an extracted source tree.
* Admission fails closed. A checksum mismatch aborts; it is never normalised
  away, and it is never recorded as a successful admission.
* Everything is content-addressed. The registry records the archive hash, the
  published hash, and a root hash over a per-file manifest of the source tree,
  so later tampering is detectable.
* The tool is deterministic: re-running it on an unchanged archive and tree
  reproduces byte-identical evidence, and it does not embed wall-clock time
  into the parts of the record that describe the artifact (only the retrieval
  event carries a timestamp, kept separate from artifact identity).

Usage
-----
    python3 forensics/tools/authority_acquire.py --all
    python3 forensics/tools/authority_acquire.py --authority openssl-3.6.4-production
    python3 forensics/tools/authority_acquire.py --all --verify-only

Exit codes: 0 success, 1 acquisition/verification failure, 2 usage error.
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
import tarfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
AUTH_ROOT = REPO_ROOT / "forensics" / "authorities"
DOWNLOADS = AUTH_ROOT / "downloads"
SRC_ROOT = AUTH_ROOT / "src"
REGISTRY = AUTH_ROOT / "AUTHORITIES.json"
REGISTRY_SCHEMA = "openssl-rs/authorities/v1"

CHUNK = 1 << 20
USER_AGENT = "openssl-rs-authority-acquire/1 (+custodian evidence tooling)"


@dataclass
class AuthoritySpec:
    """An upstream release admitted as an authority."""

    id: str
    role: str  # "production" | "historical"
    version: str
    series: str
    source_url: str
    checksum_url: str
    archive_name: str
    source_dir_name: str
    notes: str = ""
    released: Optional[str] = None

    @property
    def archive_path(self) -> Path:
        return DOWNLOADS / self.archive_name

    @property
    def source_path(self) -> Path:
        return SRC_ROOT / self.source_dir_name


# The admitted authority set. Extending this list is a deliberate, reviewable
# act (docs/AUTHORITY_POLICY.md); authority identities are never inferred.
SPECS: list[AuthoritySpec] = [
    AuthoritySpec(
        id="openssl-3.6.4-production",
        role="production",
        version="3.6.4",
        series="3.6",
        released="2026-08-25",
        # NOTE: https://mirror.openssl-library.org/source/openssl-3.6.4.tar.gz
        # is NOT the archive. That path serves an HTML page; the mirror's own
        # /source/ index links the release asset below. The HTML response was
        # caught by the archive-magic check (see validate_archive).
        source_url=(
            "https://github.com/openssl/openssl/releases/download/"
            "openssl-3.6.4/openssl-3.6.4.tar.gz"
        ),
        checksum_url=(
            "https://github.com/openssl/openssl/releases/download/"
            "openssl-3.6.4/openssl-3.6.4.tar.gz.sha256"
        ),
        archive_name="openssl-3.6.4.tar.gz",
        source_dir_name="openssl-3.6.4",
        notes=(
            "Production authority. OpenSSL 3.6.4 is a security-fix release in "
            "the 3.6 series; the candidate targets this behaviour."
        ),
    ),
    AuthoritySpec(
        id="openssl-3.6.3-historical",
        role="historical",
        version="3.6.3",
        series="3.6",
        # The 3.6.3 tarball is no longer on the mirror's current /source/
        # directory; it is retained on the pinned GitHub release tag.
        source_url=(
            "https://github.com/openssl/openssl/releases/download/"
            "openssl-3.6.3/openssl-3.6.3.tar.gz"
        ),
        checksum_url=(
            "https://github.com/openssl/openssl/releases/download/"
            "openssl-3.6.3/openssl-3.6.3.tar.gz.sha256"
        ),
        archive_name="openssl-3.6.3.tar.gz",
        source_dir_name="openssl-3.6.3",
        notes=(
            "Historical authority retained because downstream archaeology "
            "(bind9-rs) observed OpenSSL 3.6.3. Used for the oracle-vs-oracle "
            "3.6.3 -> 3.6.4 trajectory court (docs/SECURITY_DIVERGENCE_POLICY.md). "
            "Behaviour unique to 3.6.3 must not be reintroduced into production "
            "when it corresponds to an upstream security fix."
        ),
    ),
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def http_get(url: str, *, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return resp.read()


def download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=120) as resp, tmp.open("wb") as out:  # noqa: S310
        shutil.copyfileobj(resp, out, CHUNK)
    tmp.replace(dest)


_SHA256_RE = re.compile(r"\b([0-9a-fA-F]{64})\b")

# gzip magic. OpenSSL releases `<version>.tar.gz`; the archived tar stream is
# itself an archive, so a correct download begins with the gzip magic. An HTTP
# error page or a mirror landing page begins with '<!DO' or similar.
GZIP_MAGIC = b"\x1f\x8b"

# A sane lower bound for a real OpenSSL source archive. This is a guard against
# silently admitting a small error page, not a substitute for the checksum.
MIN_ARCHIVE_BYTES = 1 << 20  # 1 MiB


def validate_archive(spec: AuthoritySpec) -> None:
    """Refuse artifacts that are not plausibly the gzip source archive.

    This runs *before* checksum verification so that a wrong-URL response is
    reported as a content error rather than as a checksum mismatch of an HTML
    page. The checksum check remains the authoritative gate.
    """
    size = spec.archive_path.stat().st_size
    with spec.archive_path.open("rb") as fh:
        magic = fh.read(2)
    if magic != GZIP_MAGIC:
        snippet = spec.archive_path.read_bytes()[:120].decode("utf-8", "replace")
        raise SystemExit(
            f"FATAL: {spec.id}: downloaded artifact is not gzip "
            f"(magic={magic!r}, size={size}). First bytes: {snippet!r}\n"
            f"       source_url={spec.source_url}\n"
            f"       The URL likely returned an HTML page, not the release archive."
        )
    if size < MIN_ARCHIVE_BYTES:
        raise SystemExit(
            f"FATAL: {spec.id}: archive implausibly small ({size} bytes < "
            f"{MIN_ARCHIVE_BYTES}); refusing admission."
        )


def fetch_published_sha256(spec: AuthoritySpec) -> str:
    """Fetch the upstream-published SHA-256 for the archive.

    Upstream publishes `<archive>.sha256` files in one of two shapes:

        <hex>  *<filename>        (BSD `shasum -a 256` style)

    or occasionally a bare hex digest. We accept either and refuse anything
    that does not yield exactly one 64-hex-digit digest.
    """
    try:
        body = http_get(spec.checksum_url).decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:  # pragma: no cover - network dependent
        raise SystemExit(f"FATAL: cannot fetch published checksum for {spec.id}: {exc}")
    matches = _SHA256_RE.findall(body)
    if len(matches) != 1:
        raise SystemExit(
            f"FATAL: published checksum for {spec.id} is ambiguous "
            f"({len(matches)} digests found at {spec.checksum_url})"
        )
    return matches[0].lower()


def extract_source(spec: AuthoritySpec) -> None:
    """Extract the tarball into the authority source area.

    Deterministic and idempotent: if the tree already exists we leave it alone
    (raw authority material is immutable). Use --force to re-extract.
    """
    if spec.source_path.exists():
        return
    SRC_ROOT.mkdir(parents=True, exist_ok=True)
    staging = SRC_ROOT / (spec.source_dir_name + ".extracting")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    with tarfile.open(spec.archive_path, "r:gz") as tf:
        _safe_extract(tf, staging)
    # tarballs contain a single top-level directory named after the release
    entries = list(staging.iterdir())
    if len(entries) != 1 or not entries[0].is_dir():
        raise SystemExit(
            f"FATAL: unexpected archive layout for {spec.id}: {[e.name for e in entries]}"
        )
    entries[0].rename(spec.source_path)
    staging.rmdir()


def _safe_extract(tf: tarfile.TarFile, dest: Path) -> None:
    """Extract, refusing path traversal and absolute paths."""
    dest_resolved = dest.resolve()
    for member in tf.getmembers():
        target = (dest / member.name).resolve()
        if not str(target).startswith(str(dest_resolved) + os.sep):
            raise SystemExit(f"FATAL: archive member escapes destination: {member.name}")
        if member.issym() or member.islnk():
            # OpenSSL release tarballs contain no links; refuse them so the
            # extracted tree cannot reference anything outside itself.
            raise SystemExit(f"FATAL: archive contains a link member: {member.name}")
    tf.extractall(dest)  # noqa: S202 - members validated above


def source_manifest(spec: AuthoritySpec) -> dict:
    """Per-file SHA-256 manifest plus a root hash over the source tree.

    The root hash is SHA-256 over the newline-joined, lexicographically sorted
    lines "<file-sha256>  <repo-relative-path>". It is order-independent
    (sorting is explicit) and insensitive to extraction ordering.
    """
    root = spec.source_path
    entries = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        entries.append((rel, sha256_file(path), path.stat().st_size))
    lines = [f"{h}  {rel}\n" for rel, h, _ in entries]
    root_hash = hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()
    total_bytes = sum(size for _, _, size in entries)
    return {
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "root_hash_algorithm": "sha256(<sha256>  <path>\\n, lexicographic)",
        "root_hash": root_hash,
        "files": [{"path": rel, "sha256": h, "size": size} for rel, h, size in entries],
    }


def load_registry() -> dict:
    if REGISTRY.exists():
        return json.loads(REGISTRY.read_text())
    return {"schema": REGISTRY_SCHEMA, "authorities": []}


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


def admit(spec: AuthoritySpec, *, force: bool, verify_only: bool) -> dict:
    print(f"[authority] {spec.id}")
    if not verify_only:
        if force or not spec.archive_path.exists():
            print(f"  download  {spec.source_url}")
            download(spec.source_url, spec.archive_path)
        else:
            print(f"  reuse     {spec.archive_path.relative_to(REPO_ROOT)}")

    if not spec.archive_path.exists():
        raise SystemExit(f"FATAL: archive missing for {spec.id}: {spec.archive_path}")

    if not verify_only:
        validate_archive(spec)

    published = fetch_published_sha256(spec)
    actual = sha256_file(spec.archive_path)
    ok = published == actual
    print(f"  sha256    {actual}")
    print(f"  published {published}")
    print(f"  verified  {'yes' if ok else 'NO'}")
    if not ok:
        raise SystemExit(
            f"FATAL: checksum mismatch for {spec.id}: archive does not match "
            f"the upstream-published digest. Admission refused."
        )

    if not verify_only:
        extract_source(spec)

    manifest = source_manifest(spec)
    print(f"  files     {manifest['file_count']}")
    print(f"  root      {manifest['root_hash']}")

    manifest_name = f"SOURCE_MANIFEST.{spec.version}.json"
    if not verify_only:
        write_json(AUTH_ROOT / manifest_name, manifest)

    return {
        "id": spec.id,
        "role": spec.role,
        "series": spec.series,
        "version": spec.version,
        "released": spec.released,
        "upstream": {
            "product": "openssl",
            "source_url": spec.source_url,
            "checksum_url": spec.checksum_url,
            "checksum_kind": "sha256",
        },
        "artifact": {
            "filename": spec.archive_name,
            "sha256": actual,
            "published_sha256": published,
            "checksum_verified": ok,
            "size_bytes": spec.archive_path.stat().st_size,
        },
        "source_tree": {
            "path": spec.source_path.relative_to(REPO_ROOT).as_posix(),
            "manifest": manifest_name,
            "root_hash": manifest["root_hash"],
            "file_count": manifest["file_count"],
            "total_bytes": manifest["total_bytes"],
        },
        "notes": spec.notes,
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Admit OpenSSL authorities.")
    ap.add_argument("--authority", action="append", default=[],
                    help="authority id to admit (repeatable)")
    ap.add_argument("--all", action="store_true", help="admit every known authority")
    ap.add_argument("--force", action="store_true", help="re-download and re-extract")
    ap.add_argument("--verify-only", action="store_true",
                    help="verify existing archives/trees, change nothing")
    args = ap.parse_args(argv)

    if args.all and args.authority:
        ap.error("use either --all or --authority, not both")
    if not args.all and not args.authority:
        ap.error("specify --all or at least one --authority")

    specs = SPECS if args.all else [s for s in SPECS if s.id in set(args.authority)]
    unknown = set(args.authority) - {s.id for s in SPECS}
    if unknown:
        ap.error(f"unknown authority id(s): {sorted(unknown)}")

    registry = load_registry()
    by_id = {a["id"]: a for a in registry["authorities"]}
    for spec in specs:
        record = admit(spec, force=args.force, verify_only=args.verify_only)
        by_id[spec.id] = record

    if not args.verify_only:
        registry["authorities"] = [by_id[k] for k in sorted(by_id)]
        registry["schema"] = REGISTRY_SCHEMA
        write_json(REGISTRY, registry)
        print(f"[registry] wrote {REGISTRY.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
