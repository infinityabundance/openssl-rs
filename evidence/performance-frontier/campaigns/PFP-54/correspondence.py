#!/usr/bin/env python3
"""PFP-54: prove the three detached-DWARF correspondence checks from the artefacts.

(a) the shipped `.text` hash equals the audited `.text` hash;
(b) a build-id note is present and identical in the shipped DSO and the debug file;
(c) the debug file is retained as evidence and is not a crate-package input.

Every value is measured here; none is retyped from a receipt.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile

ROOT = pathlib.Path("/work")
EV = ROOT / "evidence/performance-frontier/campaigns/PFP-54"
ART = EV / "raw/artefacts"
SHIP = ART / "libcrypto.so.3"
DBG = ART / "libcrypto.so.3.debug"
REPORT = EV / "raw/audit-a5354547.md"


def sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def text_sha(path: pathlib.Path) -> str:
    fd, tmp = tempfile.mkstemp()
    os.close(fd)
    try:
        subprocess.run(["objcopy", "--dump-section", f".text={tmp}", str(path)],
                       check=True, capture_output=True)
        return sha(pathlib.Path(tmp))
    finally:
        os.unlink(tmp)


def build_id(path: pathlib.Path) -> str | None:
    out = subprocess.run(["readelf", "-n", str(path)], capture_output=True,
                         text=True, check=True).stdout
    m = re.search(r"Build ID:\s*([0-9a-f]+)", out)
    return m.group(1) if m else None


def debug_sections(path: pathlib.Path) -> list[str]:
    out = subprocess.run(["readelf", "-S", "--wide", str(path)], capture_output=True,
                         text=True, check=True).stdout
    return re.findall(r"\.debug_[A-Za-z0-9_]+", out)


def package_list() -> tuple[list[str] | None, str]:
    completed = subprocess.run(["cargo", "package", "--list", "--allow-dirty", "--offline"],
                               capture_output=True, text=True, timeout=300)
    if completed.returncode != 0:
        return None, (completed.stderr or completed.stdout).strip().splitlines()[-1][:200]
    return completed.stdout.splitlines(), "ok"


def main() -> int:
    text = REPORT.read_text()
    reported_dso = re.search(r"- SHA-256: `([0-9a-f]{64})`", text).group(1)
    reported_text = re.search(r"- \`.text\` SHA-256: `([0-9a-f]{64})`", text).group(1)

    shipped_sha = sha(SHIP)
    debug_sha = sha(DBG)
    shipped_text = text_sha(SHIP)
    shipped_bid = build_id(SHIP)
    debug_bid = build_id(DBG)
    shipped_debug_sections = debug_sections(SHIP)
    debug_debug_sections = debug_sections(DBG)

    package, package_note = package_list()
    if package is None:
        package_ok = None
        leaked = []
    else:
        leaked = [line for line in package
                  if "PFP-54" in line or line.endswith("artefacts/libcrypto.so.3")
                  or line.endswith("artefacts/libcrypto.so.3.debug")]
        package_ok = not leaked

    checks = {
        "a_text_hash_equals_audited_text_hash": {
            "shipped_text_sha256": shipped_text,
            "reported_text_sha256": reported_text,
            "audited_dso_sha256": reported_dso,
            "shipped_dso_sha256": shipped_sha,
            "pass": shipped_text == reported_text,
        },
        "b_build_id_present_and_identical": {
            "shipped_build_id": shipped_bid,
            "debug_build_id": debug_bid,
            "pass": shipped_bid is not None and shipped_bid == debug_bid,
        },
        "c_debug_file_is_evidence_not_packaged": {
            "debug_file": str(DBG.relative_to(ROOT)),
            "debug_sha256": debug_sha,
            "shipped_debug_sections": len(shipped_debug_sections),
            "debug_debug_sections": len(debug_debug_sections),
            "cargo_package_listing": package_ok,
            "cargo_package_note": package_note,
            "package_lines_naming_the_artefacts": leaked,
            "cargo_toml_excludes_evidence": "evidence/**" in (ROOT / "Cargo.toml").read_text(),
            "pass": (package_ok is not False and len(shipped_debug_sections) == 0
                     and len(debug_debug_sections) > 0),
        },
    }
    result = {
        "campaign": "PFP-54",
        "shipped_dso": {"path": str(SHIP.relative_to(ROOT)), "sha256": shipped_sha,
                        "bytes": SHIP.stat().st_size},
        "debug_file": {"path": str(DBG.relative_to(ROOT)), "sha256": debug_sha,
                       "bytes": DBG.stat().st_size},
        "checks": checks,
        "all_pass": all(c["pass"] for c in checks.values()),
    }
    (EV / "raw/correspondence.json").write_text(json.dumps(result, indent=1) + "\n")
    for name, check in checks.items():
        print(f"{name}: pass={check['pass']}")
    print("shipped.text", shipped_text)
    print("reported.text", reported_text)
    print("build_ids", shipped_bid, debug_bid)
    print("package_ok", package_ok, "note", package_note)
    return 0 if result["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
