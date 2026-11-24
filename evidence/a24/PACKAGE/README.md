# A24 external verification package

This directory is a self-contained bundle: the A23 verifier, its frozen
specification, its producer and the expected records. It runs with a Python
interpreter at or above the declared minimum and nothing else.

## What it is

* `verify.py` recomputes the A23 records from `evidence/a23/SPEC.json` with the
  packaged producer, compares each produced record byte-for-byte with the
  packaged expected record, and first checks the package against its own
  manifest (the manifest body digest and every member digest), so a tampered
  package is refused before anything runs.
* `evidence/a23/build_evidence.py` is the producer; `forensics/tools/` holds the
  reference evaluator and the implementation adapters it imports.
* `PACKAGE-MANIFEST.json` names every member by path, size and SHA-256, the entry
  point, the minimum interpreter, the exact commands, and the declarations
  `network: false` and `privateState: none`.

## How to run it

Unpack or copy this directory into an empty place that is not the project
checkout, then run, with a fresh home and temporary directory:

    env -i PATH=<directory containing python3> HOME=<fresh dir> TMPDIR=<fresh dir> \
        python3 verify.py

The same command is `sh verify.sh` when a POSIX shell is available. A run prints
one JSON line and exits 0 when every record matched.

## What a pass establishes, and what it does not

It establishes that, from these files alone, the packaged producer reproduces the
packaged specification and that the four records are byte-identical. It does not
establish that any claim in those records is true, that the A23 differential is a
proof, or that a party outside this project has run the package. No external
party has run this package, so its external status is
`EXTERNAL_REVIEW_PENDING`, which is not a pass.

## What it must not need

No network, no interpreter search path, no environment token, no absolute path,
no file outside this directory, no shell beyond the convenience wrapper, and no
toolchain beyond the interpreter. The builder and the verifier refuse a package
that violates any of these.
