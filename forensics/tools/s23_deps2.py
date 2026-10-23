#!/usr/bin/env python3
"""S23: pin the exact bookworm dependency .debs."""
import hashlib
import os
import urllib.request

POOL = "https://deb.debian.org/debian/pool/main"
OUT = "/work/court/tmp/s23-deps"
os.makedirs(OUT, exist_ok=True)

FILES = [
    ("b/binutils", "binutils-dev_2.40-2_amd64.deb"),
    ("x/xerces-c", "libxerces-c3.2_3.2.4+debian-1_amd64.deb"),
    ("x/xerces-c", "libxerces-c-dev_3.2.4+debian-1_amd64.deb"),
    ("m/mongo-c-driver", "libbson-1.0-0_1.23.1-1_amd64.deb"),
    ("m/mongo-c-driver", "libbson-dev_1.23.1-1_amd64.deb"),
    ("k/krb5", "libkrb5-dev_1.20.1-2+deb12u5_amd64.deb"),
    ("k/krb5", "libkrb5-3_1.20.1-2+deb12u5_amd64.deb"),
    ("k/krb5", "libgssapi-krb5-2_1.20.1-2+deb12u5_amd64.deb"),
]
for pool, name in FILES:
    url = f"{POOL}/{pool}/{name}"
    try:
        with urllib.request.urlopen(url, timeout=90) as r:
            data = r.read()
    except Exception as exc:
        print(f"FAIL {url} {exc}")
        continue
    with open(os.path.join(OUT, name), "wb") as fh:
        fh.write(data)
    print(f"{len(data):>9} {hashlib.sha256(data).hexdigest()} {url}")
