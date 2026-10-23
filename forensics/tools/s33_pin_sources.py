#!/usr/bin/env python3
"""S33: fetch every selected pristine source (and pinned aux package) and compute its SHA-256.

No URL is accepted on faith: the HTTP status, the final URL after redirect, the byte
count and the digest are emitted for the receipt.  A digest that disagrees with the
authored recipe is reported as a mismatch, never silently accepted.
"""
import hashlib
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import downstream_build_link as bl


def fetch(name: str, url: str, pinned: str | None) -> dict:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "openssl-rs-s33/1"})
        with urllib.request.urlopen(req, timeout=240) as resp:
            status = resp.status
            final = resp.geturl()
            data = resp.read()
        digest = hashlib.sha256(data).hexdigest()
        row = {"name": name, "url": url, "final_url": final, "http_status": status,
               "bytes": len(data), "sha256": digest}
        if pinned is not None:
            row["pinned_sha256"] = pinned
            row["pin_matches"] = digest == pinned
        print("%-34s HTTP %s %10d %s%s" % (
            name, status, len(data), digest,
            "" if pinned is None else (" OK" if digest == pinned else " MISMATCH")),
            flush=True)
        return row
    except Exception as exc:  # noqa: BLE001 - an unreachable host is a result, not a crash
        print("%-34s FAILED %s: %s" % (name, type(exc).__name__, exc), flush=True)
        return {"name": name, "url": url, "error": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    rows = []
    for spec in bl._S23_SPECS:
        rows.append(fetch("source:" + spec["family"], spec["url"], spec.get("sha256")))
        for aux in spec.get("aux_sources") or []:
            rows.append(fetch("aux:" + aux["url"].rsplit("/", 1)[-1], aux["url"],
                              aux.get("sha256")))
    bad = [r["name"] for r in rows if r.get("error") or r.get("pin_matches") is False]
    print("ROWS=%d UNREACHABLE_OR_MISMATCH=%d" % (len(rows), len(bad)))
    print("JSON=" + json.dumps(rows, sort_keys=True))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
