# PFP-7 — deterministic differential against the authority

**Digest:** `6d002db2…` vs OpenSSL 3.6.4 `611e511d…`.
**Harness:** `harness/pfp7_diff.c` → `raw/diff/{candidate,authority,diff}.txt`, `raw/diff/summary.txt`.

## Transcript

**4,185 lines per side, byte-identical** (`DIFF_RESULT=IDENTICAL`; `diff.txt` is
empty). Every return code and every output byte of a 256-byte buffer is printed,
including the bytes the implementation left untouched, and the two files are
compared with `diff -u`.

| population | cases per key/blinding arm | arms | total |
|---|---:|---:|---:|
| `RSA_private_encrypt`, `RSA_NO_PADDING` (4 inputs) | 4 | 4 | 16 |
| `RSA_private_encrypt`, `RSA_PKCS1_PADDING` (4 messages) | 4 | 4 | 16 |
| `RSA_private_decrypt`, `RSA_NO_PADDING` (3 ciphertexts) | 3 | 4 | 12 |
| `RSA_private_decrypt`, `RSA_PKCS1_PADDING` (3 valid ciphertexts) | 3 | 4 | 12 |
| malformed PKCS#1 population (6 named cases) | 6 | 4 | 24 |
| `RSA_private_decrypt`, `RSA_PKCS1_OAEP_PADDING` (2 ciphertexts) | 2 | 4 | 8 |
| malformed PKCS#1 sweep (1,024 deterministic blocks) | 1024 | 4 | 4096 |

Arms: `{CRT key, non-CRT key (n,e,d only)} × {blinding on, blinding off}`.

## The malformed population and the zero-length synthetic answer

The named cases (candidate == authority, every arm):

| case | return code |
|---|---|
| zero-length input | −1 (both) |
| longer than the modulus | −1 |
| all-zero block | **207** (synthetic answer) |
| `n − 1` | **198** (synthetic answer) |
| all-`0xff` block | −1 |
| length-correct garbage | **97** (synthetic answer) |

The 1,024-block sweep over the same four arms contains **16 zero-length
synthetic answers** (`rc=0`, 4 per arm) and 4,080 other synthetic lengths; the
whole sweep is byte-identical to the authority, including the untouched-buffer
bytes of every rejected block. So the implicit-rejection surface — return code,
answer length (including zero) and output contents — is unchanged, case by case,
over 4,096 malformed inputs.

Scope note: PFP-31's malformed-ciphertext population is ML-KEM's, and PFP-7
changes no code, so it is unaffected by construction; the RSA surface above is
the equivalent population for this row.
