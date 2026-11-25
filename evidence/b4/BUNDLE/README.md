# Public publication bundle — B4

This directory is a **candidate** publication bundle. It is built only from
material the classification policy admits. It has been verified **in this
venue**; no external party has run the verifier, and no transparency log
holds these digests. A publishable bundle is not a published one.

## Members

| member | class | bytes | sha256 | source |
|---|---|---:|---|---|
| `members/a10-envelope-a8-shard-000.json` | `PUBLIC_SUPPORTING` | 1130 | `5bf418cc5b014d985199ce9e17cde859647303327f6bbd111279d3ed299503a9` | `evidence/a10/ENVELOPES/a8-shard-000.json` |
| `members/a17-freeze-forward.json` | `PUBLIC_RELEASE_CRITICAL` | 4948 | `19b3bd00bcadd8a52332fdc944895edec8f25abd23e796c3aa4cd4d938a9e4f0` | `evidence/a17/FREEZE-forward.json` |
| `members/a5-admission.json` | `PUBLIC_RELEASE_CRITICAL` | 5120 | `d4871ec97ae3a27b8ec820896e292429e44b4db4d11d2671a69b9dc0230ddc0a` | `evidence/a5/ADMISSION.json` |
| `members/a9-statement-a8-shard-000.json` | `PUBLIC_RELEASE_CRITICAL` | 714 | `ea67963abf16e9b1e33a86d0eec5e35354f3a890497055867e942eac41d22582` | `evidence/a9/STATEMENTS/a8-shard-000.json` |
| `members/b1-publication.json` | `PUBLIC_RELEASE_CRITICAL` | 3729 | `765fcdf5a1db612ab43e2d56294ddc48528d0e0e4eabc85ff07244f2d77ab6b9` | `evidence/b1/PUBLICATION.json` |
| `verify.py` | `PUBLIC_SUPPORTING` | 10378 | `11d74675d00515b1d0a84e383d95346a587210848b31e79373306d2fcf763a36` | `None` |
| `verify.sh` | `PUBLIC_SUPPORTING` | 299 | `3bf63f990b974a30315c3260388286eacdca5abd16eba4792f09727043935937` | `None` |

## Labels

The B1 publication record is the test fixture **FIXTURE-1**: its log is a
six-leaf fixture, its checkpoint key is a test-only HMAC-SHA256 key, and it
is not a Rekor log entry. The A10 envelope signature is test-only as well.

## Verify it

```sh
python3 verify.py          # Python 3.8 or newer
sh verify.sh               # the same, through the shell wrapper
```

The verifier checks the manifest body against its own digest, every member
against its recorded size and SHA-256, that no undeclared file is present,
that every release-critical member the embedded policy declares is present
with the declared class, that each member's class agrees with the embedded
policy, and that no member carries a private reference or an absolute path.

## Non-claims

* A pass means these files are internally consistent and classified for
  publication. It is not a publication, an inclusion proof, a signature by
  an authority, or a statement that any claim in a member is true.
* The manifest is not self-authenticating: a rewritten bundle can carry a
  rewritten manifest. Obtain its digest through a channel you trust.
* No external party has run this verifier. The external status is `PENDING`.
