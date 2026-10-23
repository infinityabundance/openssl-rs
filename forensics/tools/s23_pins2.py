#!/usr/bin/env python3
"""S23: pin the two non-bookworm sources (GitHub release, Debian pool)."""
import hashlib
import os
import urllib.request

OUT = "/work/court/tmp/s23-src"
os.makedirs(OUT, exist_ok=True)
URLS = {
    "libdigidocpp": "https://github.com/open-eid/libdigidocpp/releases/download/v4.5.1/libdigidocpp-4.5.1.tar.gz",
    "gftp": "https://deb.debian.org/debian/pool/main/g/gftp/gftp_2.9.1~beta.orig.tar.xz",
}
for name, url in URLS.items():
    req = urllib.request.Request(url, headers={"User-Agent": "openssl-rs-s23/1"})
    with urllib.request.urlopen(req, timeout=180) as r:
        data = r.read()
        final = r.geturl()
        status = r.status
    target = url.rsplit("/", 1)[-1]
    with open(os.path.join(OUT, target), "wb") as fh:
        fh.write(data)
    print(f"{name} {status} {len(data)} {hashlib.sha256(data).hexdigest()} {final}")
