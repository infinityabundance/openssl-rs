"""Phase-25 L7 workload for py-scrypt.

The extension `_scrypt` is the family's OpenSSL consumer (the setup links
`-lcrypto`). Two salts must produce different 32-byte KDF outputs.
"""
import sys

sys.path.insert(0, sys.argv[1])

import scrypt  # noqa: E402

first = scrypt.hash(b"phase25-payload", b"fixture-salt", N=16, r=1, p=1, buflen=32)
second = scrypt.hash(b"phase25-payload", b"other-salt", N=16, r=1, p=1, buflen=32)
print("scrypt_hash=ok" if len(first) == 32 else "scrypt_hash=fail")
print("scrypt_differs=ok" if first != second else "scrypt_differs=fail")
