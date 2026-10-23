#!/usr/bin/env python3
"""S23 probe: resolve bookworm source versions and orig tarball filenames."""
import json
import re
import urllib.request

PKGS = [
    "php8.2", "ruby3.1", "strongswan", "sbsigntool", "xar", "dcmtk",
    "libnet-ssleay-perl", "libcrypt-smime-perl", "libcrypt-openssl-x509-perl",
    "libcrypt-openssl-rsa-perl", "libcrypt-openssl-ec-perl",
    "libcrypt-openssl-pkcs10-perl", "libcrypt-openssl-aes-perl",
    "libcrypt-openssl-bignum-perl", "libcrypt-openssl-random-perl",
    "libcrypt-openssl-dsa-perl", "coturn", "openiked", "krb5", "postfix",
    "aws-c-cal", "libgit2", "poco", "libmongocrypt", "libp11", "opencryptoki",
    "xml-security-c", "libdigidocpp", "xmlrpc-c", "gftp",
]


def get(url):
    with urllib.request.urlopen(url, timeout=40) as r:
        return r.read().decode("utf-8", "replace")


for src in PKGS:
    try:
        api = json.loads(get(f"https://sources.debian.org/api/src/{src}/"))
    except Exception as exc:
        print(f"{src}: API-FAIL {exc}")
        continue
    vers = [v for v in api.get("versions", []) if "bookworm" in (v.get("suites") or [])]
    if not vers:
        print(f"{src}: NOT-IN-BOOKWORM (versions={[v['version'] for v in api.get('versions',[])][:3]})")
        continue
    version = vers[0]["version"]
    upstream = version.split("-")[0]
    letter = src[0]
    if src.startswith("lib"):
        letter = "lib" + src[3]
    try:
        listing = get(f"https://deb.debian.org/debian/pool/main/{letter}/{src}/")
    except Exception as exc:
        print(f"{src}: POOL-FAIL {exc}")
        continue
    files = re.findall(r'href="([^"]+\.orig\.tar\.[a-z0-9]+)"', listing)
    matches = sorted({f for f in files if f.startswith(f"{src}_{upstream}.")})
    print(f"{src}: bookworm={version} upstream={upstream} orig={matches}")
