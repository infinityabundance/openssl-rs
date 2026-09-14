#!/usr/bin/env python3
"""openssl-rs — shared atlas infrastructure.

Common utilities for the Phase 1 archaeology generators. Every atlas generator
in forensics/tools/ imports this module so that provenance, determinism and
authority binding are enforced in one place rather than re-implemented (and
diverging) per generator.

Determinism contract
--------------------
Atlas files are *derived evidence* and must be reproducible byte-for-byte from
(a) the admitted authorities and (b) the generator sources. Therefore:

  * no wall-clock time, PID, hostname, absolute path or environment value is
    ever written into an atlas file;
  * JSON is emitted with sort_keys=True and a trailing newline;
  * all inputs are content-addressed and their hashes recorded in the file;
  * any set-like structure is emitted as a sorted list.

Wall-clock and environment belong in *captures* and *receipts* (the record of
an execution event), never in the derived atlas.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
FORENSICS = REPO_ROOT / "forensics"
AUTH_ROOT = FORENSICS / "authorities"
ATLAS = FORENSICS / "atlas"
CUSTOMER_ROOT = FORENSICS
REGISTRY = AUTH_ROOT / "AUTHORITIES.json"
BUILD_RECORDS = ATLAS / "BUILD_RECORDS.json"

PRODUCTION_AUTHORITY = "openssl-3.6.4-production"
HISTORICAL_AUTHORITY = "openssl-3.6.3-historical"


class AtlasError(RuntimeError):
    """Fatal condition: the generator cannot produce trustworthy evidence."""


# ---------------------------------------------------------------------------
# hashing / canonicalisation
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


IMPLEMENTED_SURFACE = FORENSICS / "atlas" / "implemented-surface.json"


def implemented_surface_input() -> InputRef:
    """The implemented surface as an *evidence* input, for the obligation ledgers.

    Bound by `body_hash`, not by the file digest. The artefact also records
    build-product observations (the archive digest, the compiler-emitted symbol
    count), so its file digest is not reproducible across machines; binding it
    would push a build product into every ledger that consumes the surface.
    `body_hash` is computed over the evidence subset of the body, so it is a
    function of committed inputs only. See docs/DECISIONS.md D30.
    """
    doc = json.loads(IMPLEMENTED_SURFACE.read_text(encoding="utf-8"))
    return InputRef(
        name="implemented-surface",
        sha256=doc["body_hash"],
        note=(
            "evidence digest (body_hash) of forensics/atlas/implemented-surface.json; "
            "the artefact's file digest is deliberately not used because the file "
            "also records build-product observations"
        ),
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> str:
    """Canonical JSON used for content-addressing derived objects."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def content_hash(obj: Any) -> str:
    return sha256_bytes(canonical_json(obj).encode("utf-8"))


def write_json(path: Path, obj: Any) -> str:
    """Write an atlas file deterministically. Returns its sha256."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")
    return sha256_bytes(text.encode("utf-8"))


def write_text(path: Path, text: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not text.endswith("\n"):
        text += "\n"
    path.write_text(text, encoding="utf-8")
    return sha256_bytes(text.encode("utf-8"))


def rel(path: Path) -> str:
    """Repository-relative POSIX path, or the absolute path if outside."""
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def authority_atlas_dir(authority_id: str) -> Path:
    """Atlas output directory for one authority.

    The atlas is scoped per authority rather than flat, because a claim is
    always made *of a specific authority*. A flat layout would silently let the
    last-generated authority overwrite the evidence of an earlier one.
    """
    return ATLAS / authority_id


# ---------------------------------------------------------------------------
# subprocess
# ---------------------------------------------------------------------------

@dataclass
class CmdResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run(argv: list[str], *, cwd: Optional[Path] = None) -> CmdResult:
    proc = subprocess.run(
        argv, cwd=str(cwd) if cwd else None,
        capture_output=True, text=True, check=False,
    )
    return CmdResult(argv=argv, returncode=proc.returncode,
                     stdout=proc.stdout, stderr=proc.stderr)


def must_run(argv: list[str], *, cwd: Optional[Path] = None) -> CmdResult:
    res = run(argv, cwd=cwd)
    if not res.ok:
        raise AtlasError(
            f"command failed ({res.returncode}): {' '.join(argv)}\n{res.stderr.strip()}"
        )
    return res


# ---------------------------------------------------------------------------
# authority + build records
# ---------------------------------------------------------------------------

def load_registry() -> dict:
    if not REGISTRY.exists():
        raise AtlasError(f"authority registry missing: {REGISTRY}")
    return json.loads(REGISTRY.read_text())


def load_build_records() -> dict[str, dict]:
    if not BUILD_RECORDS.exists():
        raise AtlasError(
            f"build records missing: {BUILD_RECORDS}; run authority_build.py first"
        )
    data = json.loads(BUILD_RECORDS.read_text())
    return {b["id"]: b for b in data.get("builds", [])}


def authority_source(authority_id: str) -> Path:
    reg = load_registry()
    for a in reg["authorities"]:
        if a["id"] == authority_id:
            return REPO_ROOT / a["source_tree"]["path"]
    raise AtlasError(f"authority not admitted: {authority_id}")


def authority_prefix(authority_id: str) -> Path:
    builds = load_build_records()
    if authority_id not in builds:
        raise AtlasError(f"authority not built: {authority_id}")
    return REPO_ROOT / builds[authority_id]["prefix"]


def authority_build_dir(authority_id: str) -> Path:
    builds = load_build_records()
    if authority_id not in builds:
        raise AtlasError(f"authority not built: {authority_id}")
    return REPO_ROOT / builds[authority_id]["build_dir"]


@dataclass
class Authority:
    """An admitted + built authority, resolved to concrete paths."""

    id: str
    version: str
    role: str
    source: Path
    prefix: Path

    @property
    def libdir(self) -> Path:
        for cand in ("lib", "lib64"):
            if (self.prefix / cand).is_dir():
                return self.prefix / cand
        return self.prefix / "lib"

    def dso(self, name: str) -> Path:
        # Prefer the versioned runtime object (libcrypto.so.3), falling back to
        # the linker name (libcrypto.so).
        for cand in (f"{name}.so.3", f"{name}.so"):
            p = self.libdir / cand
            if p.exists() or p.is_symlink():
                return p
        raise AtlasError(f"{self.id}: {name} not found under {self.libdir}")


def resolve_authority(authority_id: str) -> Authority:
    reg = load_registry()
    rec = next((a for a in reg["authorities"] if a["id"] == authority_id), None)
    if rec is None:
        raise AtlasError(f"authority not admitted: {authority_id}")
    return Authority(
        id=rec["id"],
        version=rec["version"],
        role=rec["role"],
        source=REPO_ROOT / rec["source_tree"]["path"],
        prefix=authority_prefix(authority_id),
    )


def all_authority_ids() -> list[str]:
    reg = load_registry()
    return sorted(a["id"] for a in reg["authorities"])


# ---------------------------------------------------------------------------
# atlas document envelope
# ---------------------------------------------------------------------------

@dataclass
class InputRef:
    """A content-addressed input to an atlas document."""

    name: str
    path: Optional[Path] = None
    sha256: Optional[str] = None
    note: Optional[str] = None

    def resolved(self) -> dict:
        out: dict[str, Any] = {"name": self.name}
        if self.path is not None:
            out["path"] = self.path.relative_to(REPO_ROOT).as_posix()
            if self.sha256 is None:
                out["sha256"] = sha256_file(self.path)
            else:
                out["sha256"] = self.sha256
        if self.sha256 is not None and self.path is None:
            out["sha256"] = self.sha256
        if self.note:
            out["note"] = self.note
        return out


def envelope(kind: str, generator: str, inputs: Iterable[InputRef],
             body: dict, *, authority: Optional[str] = None) -> dict:
    """Wrap a generator body in the standard atlas document envelope.

    Keeping the envelope uniform is what lets atlas_reconcile.py compare
    inventories across evidence planes without special-casing each file.
    """
    doc: dict[str, Any] = {
        "schema": f"openssl-rs/atlas/{kind}/v1",
        "kind": kind,
        "generator": generator,
        "inputs": [i.resolved() for i in inputs],
        "body": body,
    }
    if authority:
        doc["authority"] = authority
    return doc


# ---------------------------------------------------------------------------
# .num file parsing (util/libcrypto.num, util/libssl.num)
# ---------------------------------------------------------------------------

_NUM_LINE = re.compile(
    r"^(?P<symbol>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s+(?P<ordinal>[0-9]+)"
    r"\s+(?P<version>[0-9A-Za-z_]+)"
    r"(?:\s+(?P<condition>\S+.*?))?"
    r"\s*$"
)


@dataclass
class NumEntry:
    """One line of an OpenSSL linker `.num` inventory.

    The condition field grammar (as produced by util/mkdef.pl) is four
    colon-separated fields, any of which after the first may be empty:

        STATUS : PLATFORM : KIND : CONDS

    Examples observed in util/libcrypto.num:

        EXIST::FUNCTION:DEPRECATEDIN_3_0,EC      status=EXIST platform=None
                                                 kind=FUNCTION
                                                 conds=[DEPRECATEDIN_3_0, EC]
        EXIST:VMS:FUNCTION:OCSP                  platform=VMS -> not built on ELF
        NOEXIST::FUNCTION:                       declared, deliberately NOT
                                                 exported (e.g. ERR_put_error)

    Modelling `status` and `platform` explicitly is what stops the reconciler
    from reporting a correct absence as a defect.
    """

    symbol: str
    ordinal: int
    version: str          # e.g. "3_0_0" -> normalised to "OPENSSL_3.0.0"
    status: str           # "EXIST", "NOEXIST", ...
    platform: Optional[str]  # e.g. "VMS"; None means platform-independent
    kind: str             # "FUNCTION", "VARIABLE", ""
    conditions: list[str]  # e.g. ["DEPRECATEDIN_3_0", "EC"]
    raw: str

    @property
    def version_node(self) -> str:
        return "OPENSSL_" + self.version.replace("_", ".")

    @property
    def deprecated(self) -> bool:
        return any(c.startswith("DEPRECATEDIN_") for c in self.conditions)

    @property
    def declared_nonexistent(self) -> bool:
        return self.status.upper() != "EXIST"

    @property
    def platform_scoped_away(self) -> bool:
        """True if the entry is scoped to a non-ELF platform.

        The admitted authority profile is linux-x86_64 (ELF), so an entry
        scoped to VMS or a legacy platform is *expected* to be absent and its
        absence is not a residual.
        """
        return self.platform is not None and self.platform.upper() != "LINUX"


def parse_num_file(path: Path) -> tuple[list[NumEntry], list[dict]]:
    """Parse a linker `.num` inventory.

    Returns (entries, unparsed). Unparsed lines are *residuals*, not noise:
    the caller must surface them so a silent parse failure cannot quietly
    shrink the inventory.
    """
    entries: list[NumEntry] = []
    unparsed: list[dict] = []
    for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _NUM_LINE.match(line)
        if not m:
            unparsed.append({"line": lineno, "text": raw})
            continue
        condition = m.group("condition") or ""
        status = kind = ""
        platform: Optional[str] = None
        conditions: list[str] = []
        if condition:
            fields = condition.split(":", 3)
            status = fields[0]
            if len(fields) > 1:
                platform = fields[1] or None
            if len(fields) > 2:
                kind = fields[2]
            if len(fields) > 3:
                conditions = [c for c in fields[3].split(",") if c]
            if not status:
                unparsed.append({"line": lineno, "text": raw})
                continue
        entries.append(NumEntry(
            symbol=m.group("symbol"),
            ordinal=int(m.group("ordinal")),
            version=m.group("version"),
            status=status,
            platform=platform,
            kind=kind,
            conditions=conditions,
            raw=line,
        ))
    return entries, unparsed


# ---------------------------------------------------------------------------
# Generated linker version script (libcrypto.ld / libssl.ld)
# ---------------------------------------------------------------------------

# A version script is the *build-profile-specific* export promise. It is
# generated from the .num inventory at configure time, so the difference
# between the two is exactly the set of exclusions the build configuration made.
#
#   OPENSSL_3.0.0 {
#       global:
#           ACCESS_DESCRIPTION_free;
#           ...
#       local:
#           *;
#   };

_LD_NODE = re.compile(r"^(?P<node>[A-Za-z_][A-Za-z0-9_.]*)\s*\{\s*$")
_LD_SYMBOL = re.compile(r"^\s*(?P<symbol>[A-Za-z_][A-Za-z0-9_]*)\s*;\s*$")


def parse_version_script(path: Path) -> dict[str, list[str]]:
    """Parse a GNU ld version script into {version_node: [symbols]}.

    Only `global:` symbols are collected; the `local:` block (typically `*;`)
    is not a symbol list.
    """
    nodes: dict[str, list[str]] = {}
    current: Optional[str] = None
    in_global = False
    for line in path.read_text().splitlines():
        if line.lstrip().startswith("#") or not line.strip():
            continue
        m = _LD_NODE.match(line)
        if m:
            current = m.group("node")
            nodes.setdefault(current, [])
            in_global = False
            continue
        stripped = line.strip()
        if stripped == "global:":
            in_global = True
            continue
        if stripped == "local:":
            in_global = False
            continue
        if stripped == "};" or stripped == "}":
            current = None
            in_global = False
            continue
        if current is not None and in_global:
            ms = _LD_SYMBOL.match(line)
            if ms:
                nodes[current].append(ms.group("symbol"))
    return {k: sorted(set(v)) for k, v in nodes.items()}


# ---------------------------------------------------------------------------
# ELF dynamic symbol table parsing (readelf --dyn-syms --wide)
# ---------------------------------------------------------------------------

@dataclass
class DynSym:
    name: str
    value: int
    size: int
    stype: str      # FUNC, OBJECT, NOTYPE, ...
    bind: str       # GLOBAL, WEAK, LOCAL
    vis: str        # DEFAULT, PROTECTED, HIDDEN
    ndx: str
    version: Optional[str]  # from name suffix symbol@@VERSION

    @property
    def defined(self) -> bool:
        return self.ndx != "UND"


_DYNSYM_ROW = re.compile(
    r"^\s*(?P<num>\d+):\s+"
    r"(?P<value>[0-9a-fA-F]+)\s+"
    r"(?P<size>\d+)\s+"
    r"(?P<type>\S+)\s+"
    r"(?P<bind>\S+)\s+"
    r"(?P<vis>\S+)\s+"
    r"(?P<ndx>\S+)\s+"
    r"(?P<name>\S+)\s*$"
)


def read_dynsyms(path: Path) -> list[DynSym]:
    res = run(["readelf", "--dyn-syms", "--wide", str(path)])
    syms: list[DynSym] = []
    for line in res.stdout.splitlines():
        m = _DYNSYM_ROW.match(line)
        if not m:
            continue
        raw_name = m.group("name")
        version = None
        name = raw_name
        if "@" in raw_name:
            name, _, version = raw_name.partition("@")
            version = version.lstrip("@")
        syms.append(DynSym(
            name=name,
            value=int(m.group("value"), 16),
            size=int(m.group("size")),
            stype=m.group("type"),
            bind=m.group("bind"),
            vis=m.group("vis"),
            ndx=m.group("ndx"),
            version=version,
        ))
    return syms


# readelf version-info parsing (version definition / needs sections)


def read_version_definition_names(path: Path) -> list[str]:
    """Return the version *definition* node names in a DSO (e.g. OPENSSL_3.0.0).

    readelf --version-info prints three sections. In the definition section each
    entry is a row like:

        000000: Rev: 1  Flags: BASE  Index: 1  Cnt: 1  Name: libcrypto.so.3
        0x001c: Rev: 1  Flags: none  Index: 2  Cnt: 2  Name: OPENSSL_3.0.0

    We extract the `Name:` token from every row inside the definition section
    only, so the version-needs (dependency) names are never mixed in.
    """
    res = run(["readelf", "--version-info", "--wide", str(path)])
    if not res.ok:
        raise AtlasError(f"readelf --version-info failed for {path}: {res.stderr.strip()}")
    names: list[str] = []
    in_def = False
    for line in res.stdout.splitlines():
        if "Version definition section" in line:
            in_def = True
            continue
        if "Version symbols section" in line or "Version needs section" in line:
            in_def = False
            continue
        if in_def and "Name:" in line:
            token = line.rsplit("Name:", 1)[1].strip()
            if token:
                names.append(token)
    # The BASE node is the library's own SONAME, not an ABI version namespace.
    return [n for n in names if n.startswith("OPENSSL_")]


def read_version_needed_names(path: Path) -> list[str]:
    """Return the version *needs* (i.e. dependency) names of an ELF object."""
    res = run(["readelf", "--version-info", "--wide", str(path)])
    names: list[str] = []
    in_needs = False
    for line in res.stdout.splitlines():
        if "Version needs section" in line:
            in_needs = True
            continue
        if "Version definition section" in line or "Version symbols section" in line:
            in_needs = False
            continue
        if in_needs and "Name:" in line:
            token = line.rsplit("Name:", 1)[1].strip()
            if token:
                names.append(token)
    return names


def main(argv: list[str]) -> int:  # pragma: no cover - module is a library
    print("atlas_common is a library; use a generator such as atlas_symbols.py")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
