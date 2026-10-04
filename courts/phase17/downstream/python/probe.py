#!/usr/bin/env python3
#
# openssl-rs — Phase 17 downstream: exercise CPython's `ssl` and `hashlib` modules when the
# interpreter is linked against the candidate shell. Part (a) of the proof, plus (3).
#
# Run with the candidate-built interpreter, e.g.:
#   /court/python/Python-3.12.15/python \
#       /work/courts/phase17/downstream/python/probe.py
#
import sys

print("Python:", sys.version.split()[0])
print("sys.executable:", sys.executable)

print("\n== ssl surface ==")
import ssl

print("ssl.OPENSSL_VERSION:", ssl.OPENSSL_VERSION)
print("ssl.OPENSSL_VERSION_INFO:", ssl.OPENSSL_VERSION_INFO)
print("ssl.HAS_TLSv1_3:", getattr(ssl, "HAS_TLSv1_3", None))
print("ssl.TLSVersion members:", [v.name for v in ssl.TLSVersion])

# (a) a default client context: create_default_context() is PROTOCOL_TLS_CLIENT, which
# exercises SSL_CTX_set_min_proto_version / _max_proto_version under the hood.
ctx = ssl.create_default_context()
print("ssl.create_default_context(): OK")
print("  protocol       :", ctx.protocol)
print("  verify_mode    :", ctx.verify_mode)
print("  check_hostname :", ctx.check_hostname)
print("  minimum_version:", ctx.minimum_version)
print("  maximum_version:", ctx.maximum_version)

c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
print("SSLContext(PROTOCOL_TLS_CLIENT): min=%s max=%s" % (c.minimum_version, c.maximum_version))
s = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
print("SSLContext(PROTOCOL_TLS_SERVER): min=%s max=%s" % (s.minimum_version, s.maximum_version))

# The min/max proto setters are the ctrl that once tripped curl. Exercise them directly.
c.minimum_version = ssl.TLSVersion.TLSv1_2
c.maximum_version = ssl.TLSVersion.TLSv1_3
print("after set min/max: min=%s max=%s" % (c.minimum_version, c.maximum_version))
print("ssl: OK")

print("\n== hashlib / hmac surface ==")
import hashlib
import hmac

print("hashlib.sha256(b'abc'):", hashlib.sha256(b"abc").hexdigest())
print("hashlib.sha512(b'abc'):", hashlib.sha512(b"abc").hexdigest())
print("hashlib.sha1(b'abc')  :", hashlib.sha1(b"abc").hexdigest())
print("hashlib.md5(b'abc')   :", hashlib.md5(b"abc").hexdigest())
print("hashlib.sha3_256(abc) :", hashlib.new("sha3_256", b"abc").hexdigest())
print("hashlib.blake2b(abc)  :", hashlib.blake2b(b"abc").hexdigest())
print("'sha256' in algorithms_available:", "sha256" in hashlib.algorithms_available)
print("hmac.new(key,msg,sha256):", hmac.new(b"key", b"msg", hashlib.sha256).hexdigest())
print("pbkdf2_hmac(sha256)   :", hashlib.pbkdf2_hmac("sha256", b"pw", b"salt", 1000, 32).hex())
try:
    print("scrypt(n=16,r=1,p=1)  :", hashlib.scrypt(b"pw", salt=b"salt", n=16, r=1, p=1, dklen=16).hex())
except Exception as e:  # noqa: BLE001 - report, do not hide
    print("scrypt FAILED: %s: %s" % (type(e).__name__, e))
print("hashlib: OK")

print("\nprobe.py: OK")
