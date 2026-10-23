#!/usr/bin/env python3
"""S23: fetch every selected pristine source and compute its SHA-256.

No URL is accepted on faith: the HTTP status, the final URL (after redirect),
the byte count and the digest are printed for the receipt.
"""
import hashlib
import json
import os
import urllib.request

URLS = {
    "php": "https://deb.debian.org/debian/pool/main/p/php8.2/php8.2_8.2.32.orig.tar.xz",
    "ruby": "https://deb.debian.org/debian/pool/main/r/ruby3.1/ruby3.1_3.1.2.orig.tar.xz",
    "strongswan": "https://deb.debian.org/debian/pool/main/s/strongswan/strongswan_5.9.8.orig.tar.bz2",
    "sbsigntool": "https://deb.debian.org/debian/pool/main/s/sbsigntool/sbsigntool_0.9.4.orig.tar.xz",
    "xar": "https://deb.debian.org/debian/pool/main/x/xar/xar_1.8.0.498.orig.tar.gz",
    "dcmtk": "https://deb.debian.org/debian/pool/main/d/dcmtk/dcmtk_3.6.7.orig.tar.gz",
    "perl-net-ssleay": "https://deb.debian.org/debian/pool/main/libn/libnet-ssleay-perl/libnet-ssleay-perl_1.92.orig.tar.gz",
    "perl-crypt-smime": "https://deb.debian.org/debian/pool/main/libc/libcrypt-smime-perl/libcrypt-smime-perl_0.28.orig.tar.gz",
    "perl-crypt-openssl-x509": "https://deb.debian.org/debian/pool/main/libc/libcrypt-openssl-x509-perl/libcrypt-openssl-x509-perl_1.9.14.orig.tar.gz",
    "perl-crypt-openssl-rsa": "https://deb.debian.org/debian/pool/main/libc/libcrypt-openssl-rsa-perl/libcrypt-openssl-rsa-perl_0.33.orig.tar.gz",
    "libcrypt-openssl-ec-perl": "https://deb.debian.org/debian/pool/main/libc/libcrypt-openssl-ec-perl/libcrypt-openssl-ec-perl_1.32.orig.tar.gz",
    "libcrypt-openssl-pkcs10-perl": "https://deb.debian.org/debian/pool/main/libc/libcrypt-openssl-pkcs10-perl/libcrypt-openssl-pkcs10-perl_0.19.orig.tar.gz",
    "perl-crypt-openssl-aes": "https://cpan.metacpan.org/authors/id/T/TI/TIMLEGGE/Crypt-OpenSSL-AES-0.23.tar.gz",
    "perl-crypt-openssl-dsa": "https://deb.debian.org/debian/pool/main/libc/libcrypt-openssl-dsa-perl/libcrypt-openssl-dsa-perl_0.20.orig.tar.gz",
    "coturn": "https://deb.debian.org/debian/pool/main/c/coturn/coturn_4.6.1.orig.tar.gz",
    "openiked": "https://deb.debian.org/debian/pool/main/o/openiked/openiked_7.2.orig.tar.gz",
    "krb5": "https://deb.debian.org/debian/pool/main/k/krb5/krb5_1.20.1.orig.tar.gz",
    "postfix": "https://deb.debian.org/debian/pool/main/p/postfix/postfix_3.7.11.orig.tar.gz",
    "libgit2": "https://deb.debian.org/debian/pool/main/libg/libgit2/libgit2_1.5.1+ds.orig.tar.xz",
    "poco": "https://deb.debian.org/debian/pool/main/p/poco/poco_1.11.0.orig.tar.bz2",
    "libengine-pkcs11-openssl": "https://deb.debian.org/debian/pool/main/libp/libp11/libp11_0.4.12.orig.tar.gz",
    "opencryptoki": "https://deb.debian.org/debian/pool/main/o/opencryptoki/opencryptoki_3.8.1+dfsg.orig.tar.gz",
    "xml-security-c": "https://deb.debian.org/debian/pool/main/x/xml-security-c/xml-security-c_2.0.4.orig.tar.bz2",
    "xmlrpc-c": "https://deb.debian.org/debian/pool/main/x/xmlrpc-c/xmlrpc-c_1.33.14.orig.tar.gz",
    "libmongocrypt": "https://deb.debian.org/debian/pool/main/libm/libmongocrypt/libmongocrypt_1.7.2.orig.tar.gz",
}

OUT = "/work/court/tmp/s23-src"
os.makedirs(OUT, exist_ok=True)
rows = {}
for name, url in URLS.items():
    tail = url.rsplit("/", 1)[-1]
    dest = os.path.join(OUT, tail)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "openssl-rs-s23/1"})
        with urllib.request.urlopen(req, timeout=180) as resp:
            status = resp.status
            final = resp.geturl()
            data = resp.read()
        with open(dest, "wb") as fh:
            fh.write(data)
        digest = hashlib.sha256(data).hexdigest()
        rows[name] = {"url": url, "final_url": final, "http_status": status,
                      "bytes": len(data), "sha256": digest, "file": tail}
        print(f"{name:32} {status} {len(data):>10} {digest} {tail}")
    except Exception as exc:
        rows[name] = {"url": url, "error": f"{type(exc).__name__}: {exc}"}
        print(f"{name:32} FAILED {type(exc).__name__}: {exc}")
print("JSON=" + json.dumps(rows, sort_keys=True))
