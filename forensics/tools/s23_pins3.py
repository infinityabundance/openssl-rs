#!/usr/bin/env python3
"""S23: pin the final two Debian sources."""
import hashlib
import os
import urllib.request

OUT = "/work/court/tmp/s23-src"
os.makedirs(OUT, exist_ok=True)
URLS = {
    "gss-ntlmssp": "https://deb.debian.org/debian/pool/main/g/gss-ntlmssp/gss-ntlmssp_1.2.0.orig.tar.gz",
    "cxxtools": "https://deb.debian.org/debian/pool/main/c/cxxtools/cxxtools_3.0.0.orig.tar.gz",
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
