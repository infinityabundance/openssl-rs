#!/usr/bin/env python3
"""S23: pin build-time dependency .debs (headers/runtime) from bookworm."""
import hashlib
import os
import re
import urllib.request

POOL = "https://deb.debian.org/debian/pool/main"
OUT = "/work/court/tmp/s23-deps"
os.makedirs(OUT, exist_ok=True)

WANT = {
    "binutils": "binutils-dev_",
    "xerces-c": "libxerces-c",
    "libbson": "libbson-",
    "krb5": "libkrb5-dev_",
    "glib2.0": "libglib2.0-",
}


def get(url):
    with urllib.request.urlopen(url, timeout=90) as r:
        return r.read()


for src, prefix in WANT.items():
    letter = src[0]
    if src.startswith("lib"):
        letter = "lib" + src[3]
    base = f"{POOL}/{letter}/{src}/"
    try:
        listing = get(base).decode("utf-8", "replace")
    except Exception as exc:
        print(f"{src}: LISTING-FAIL {exc}")
        continue
    available = sorted(set(re.findall(r'href="([^"]+\.deb)"', listing)))
    cands = [a for a in available if a.startswith(prefix)]
    # Prefer amd64/all and the newest (last) version.
    arch = [a for a in cands if a.endswith("_amd64.deb") or a.endswith("_all.deb")]
    print(f"{src}: candidates={arch[-12:]}")
    if not arch:
        print(f"{src}: NONE (all={available[-8:]})")
        continue
    target = arch[-1]
    url = base + target
    try:
        data = get(url)
    except Exception as exc:
        print(f"{src}: FETCH-FAIL {url} {exc}")
        continue
    with open(os.path.join(OUT, target), "wb") as fh:
        fh.write(data)
    print(f"PIN {src:12} {len(data):>9} {hashlib.sha256(data).hexdigest()} {url}")
