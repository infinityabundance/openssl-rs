#!/usr/bin/env python3
"""Publish harness logs content-addressed, so a clean checkout can verify them.

`court/` is gitignored, so a manifest that names `court/tmp/...` points at bytes
that do not exist for anyone who clones this repository. This copies each log to
`courts/phase18/interop/logs/<sha256>.log` — the name *is* the digest — and
appends an index entry with size, origin and digest. Nothing is rewritten: the
bytes are copied verbatim, because a normalised log is not the log.

Usage:
    publish_logs.py NAME=PATH [NAME=PATH ...]

Exit status: 0 when every log was published or was already present with the same
digest; non-zero on a read error or an index conflict (same name, different
bytes), which is the case that must never be resolved silently.
"""

import hashlib
import json
import pathlib
import shutil
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[3]
LOGS = ROOT / "courts" / "phase18" / "interop" / "logs"
INDEX = LOGS / "INDEX.json"


def main(argv):
    if not argv:
        print("usage: publish_logs.py NAME=PATH ...", file=sys.stderr)
        return 2
    LOGS.mkdir(parents=True, exist_ok=True)
    index = json.loads(INDEX.read_text()) if INDEX.exists() else {"schema": "openssl-rs/interop-log-index/1", "logs": {}}
    failed = 0
    for spec in argv:
        if "=" not in spec:
            print(f"publish_logs: bad argument {spec!r}", file=sys.stderr)
            failed += 1
            continue
        name, path = spec.split("=", 1)
        src = pathlib.Path(path)
        if not src.exists():
            print(f"publish_logs: missing {path}", file=sys.stderr)
            failed += 1
            continue
        data = src.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        dest = LOGS / f"{digest}.log"
        if dest.exists() and dest.read_bytes() != data:
            print(f"publish_logs: {dest} exists with different bytes", file=sys.stderr)
            failed += 1
            continue
        if not dest.exists():
            dest.write_bytes(data)
        entry = index["logs"].get(name)
        if entry is not None and entry["sha256"] != digest:
            print(
                f"publish_logs: name {name!r} already indexes {entry['sha256']}, refusing to "
                f"repoint it at {digest}",
                file=sys.stderr,
            )
            failed += 1
            continue
        index["logs"][name] = {
            "sha256": digest,
            "bytes": len(data),
            "path": str(dest.relative_to(ROOT)),
            "origin": name + " (copied from the run's work directory; the bytes are verbatim)",
            "published": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        print(f"{name:<28} {digest}  {len(data):>8} bytes  -> {dest.relative_to(ROOT)}")
    INDEX.write_text(json.dumps(index, indent=1, sort_keys=True) + "\n")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
