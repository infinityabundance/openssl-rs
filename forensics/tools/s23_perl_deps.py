#!/usr/bin/env python3
"""S23: pin the Perl build-time dependencies (pure-Perl debs + XS sources)."""
import hashlib
import os
import re
import urllib.request

POOL = "https://deb.debian.org/debian/pool/main"
OUT = "/work/court/tmp/s23-src"
os.makedirs(OUT, exist_ok=True)

DEBS = {
    "libcrypt-openssl-guess-perl": f"{POOL}/libc/libcrypt-openssl-guess-perl/",
    "libcrypt-urandom-perl": f"{POOL}/libc/libcrypt-urandom-perl/",
    "libextutils-cchecker-perl": f"{POOL}/libe/libextutils-cchecker-perl/",
    "libextutils-pkgconfig-perl": f"{POOL}/libe/libextutils-pkgconfig-perl/",
    "libconvert-asn1-perl": f"{POOL}/libc/libconvert-asn1-perl/",
}
SOURCES = {
    "bignum": f"{POOL}/libc/libcrypt-openssl-bignum-perl/libcrypt-openssl-bignum-perl_0.09.orig.tar.gz",
    "random": f"{POOL}/libc/libcrypt-openssl-random-perl/libcrypt-openssl-random-perl_0.15.orig.tar.gz",
}


def get(url):
    with urllib.request.urlopen(url, timeout=90) as r:
        return r.read()


for name, url in DEBS.items():
    try:
        listing = get(url).decode("utf-8", "replace")
    except Exception as exc:
        print(f"{name}: LISTING-FAIL {exc}")
        continue
    debs = sorted(set(re.findall(r'href="([^"]+\.deb)"', listing)))
    matches = [d for d in debs if d.startswith(name + "_")]
    if not matches:
        print(f"{name}: NO DEB in {debs[-5:]}")
        continue
    target = matches[-1]
    full = url + target
    data = get(full)
    with open(os.path.join(OUT, target), "wb") as fh:
        fh.write(data)
    print(f"PIN {name:32} {len(data):>8} {hashlib.sha256(data).hexdigest()} {full}")

for name, url in SOURCES.items():
    data = get(url)
    target = url.rsplit("/", 1)[-1]
    with open(os.path.join(OUT, target), "wb") as fh:
        fh.write(data)
    print(f"PIN {name:32} {len(data):>8} {hashlib.sha256(data).hexdigest()} {url}")
