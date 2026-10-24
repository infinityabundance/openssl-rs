"""Phase-25 L7 workload for M2Crypto.

The rebuilt SWIG extension performs RSA PKCS#1 v1.5 signing and verification
through the subject libcrypto; a tampered digest must not verify.
"""
import sys

sys.path.insert(0, sys.argv[1])

from M2Crypto import EVP, RSA  # noqa: E402

key = RSA.load_key(sys.argv[2])
payload = b"phase25-m2crypto-payload"

digest = EVP.MessageDigest("sha256")
digest.update(payload)
signature = key.sign_rsa(digest.digest())
public = key.pub()

print("m2_sign=ok" if len(signature) == 256 else "m2_sign=fail")
print("m2_verify=ok" if public.verify_rsa(digest.digest(), signature) else "m2_verify=fail")

tampered = EVP.MessageDigest("sha256")
tampered.update(payload + b"x")
print("m2_tamper=rejected" if not public.verify_rsa(tampered.digest(), signature)
      else "m2_tamper=fail")
