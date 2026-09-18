#!/usr/bin/env python3
"""openssl-rs — the correctness-vector tool behind the `CT-*` courts.

Two independent evidence planes, and this is the second
-------------------------------------------------------
For a *compatibility* port the authority oracle dominates: the question "does the candidate
behave like the admitted authority?" is answered by compiling one program twice and diffing
the transcripts, and that is what every `RT-*` court does. A **cryptographic primitive** is
the one place where a second plane answers a different question:

    RT-DIGEST   OpenSSL differential      -> "does it behave like the admitted authority?"
    CT-DIGEST   construction/spec vectors -> "does it satisfy the underlying construction?"

Neither implies the other, and the two failures are different defects:

  * a **CT pass is not OpenSSL parity.** A portable arm can satisfy every published vector
    and still differ from the authority in an observable way — a different `Transform`
    boundary, a context field the authority leaves and this one clears, an error path. The
    vector set does not contain the authority's behaviour; the differential transcript does.
  * an **RT pass is not independent cryptographic correctness.** Two implementations can
    agree with each other, byte for byte, and both be wrong against the standard — a shared
    transcription error, a wrong table read from the same wrong place. What that is ruled out
    by is a *second, independent statement of the expected bytes*: a value the standard
    itself publishes, which no transcription of the implementation can move. That is what this
    plane carries, and its precise scope is the next section.
  * and a CT pass is **not formal validation**. The corpora considered below are published for
    informal verification, not certification: NIST publishes the CAVP vectors for informal
    verification and warns that using them is not itself validation, and Project Wycheproof is
    maintained as an implementation-independent corpus of known-attack and edge cases that its
    maintainers recommend integrating into CI rather than treating as a certificate.

So a `CT-*` court runs the crate **only** — there is no differential comparison, which is why
it is a different driver shape from the `RT-*` courts and why `phase8_courts.py` carries a
second registry for it. A correctness court's verdict is per-vector and loud: one mismatched
vector fails the court, and the input, the expected bytes and the actual bytes are recorded
for every mismatch. There is no partial-credit summary and no "mostly passed" verdict,
because a check that hides which vector failed is not evidence.

What this plane's independence actually is, stated precisely
-----------------------------------------------------------
This is **candidate-only construction verification using standard-derived vectors mirrored in
the pinned OpenSSL test corpus**. Each part of that is meant literally:

  * **candidate-only** — the probe is compiled against the candidate distribution shell alone;
    no authority transcript is produced or compared;
  * **standard-derived** — every vector's expected bytes are a value a *standard* publishes
    (RFC 1320 §A.5, RFC 1321 §A.5, FIPS 180-4 / RFC 6234 §8.5, ISO/IEC 10118-3, the
    Rijmen–Barreto Whirlpool submission), named per algorithm and per vector below;
  * **mirrored in the pinned OpenSSL test corpus** — the bytes are read out of the pinned
    authority's own `test/recipes/30-test_evp_data/evpmd_*.txt`, each of which cites the
    standard in its `Title`, and each mirror file is content-addressed.

That is a claim about **data independence**, and it is weaker than "an external corpus". The
vectors are independent of the implementation *code* — a transcription error in `src/digest/`
cannot move them, which is the blind spot of the differential plane. They are **not**
independent of the pinned tree, because the pinned tree is where this repository reads the
mirrored bytes. A reader who wants an oracle this repository never read must supply one.

A second kind of vector is marked `derivation: independent`: the standard publishes the
*construction* but not a test for that exact input (the 55/56/63/64/65-byte padding
boundaries, in particular), so the expected bytes are computed by an implementation that is
neither the crate nor the pinned authority build, the oracle is named in the vector's
provenance, and what that establishes is stated with it. `UNKNOWN` is a valid provenance
value here and is preferred to a guess.

Because the corpus contains both kinds, the claim `run_court` attaches to a `CT-*` record is
**generated from the census of the vectors it just ran** -- how many are mirrored and how many
independently derived, and by which oracle -- rather than a fixed sentence. A claim a generator
owns must be generated (D205), and a fixed "every vector is mirrored" sentence went false the
moment the first `derivation: independent` vector landed while every individual record stayed
honest (D208). The `rhash` oracle additionally records its tool, version and exact command, so
the bytes can be reproduced rather than trusted; `rhash` is not in the pinned court image, and
that cost is stated with the record.

Where the committed vectors come from
-------------------------------------
`forensics/vectors/<algorithm>.json` is committed data in the atlas envelope
(`schema`/`kind`/`generator`/`inputs`/`body`, `forensics/tools/atlas_common.py:envelope`).
Each file records, for its algorithm, the standard it is drawn from, its **primary source**
(identifier and section), the authority file the bytes were mirrored from with that file's
sha256 in `inputs[]`, and **per vector** the source file, the line, the section title, the
form the bytes were written in, and the derivation. The bytes are the bytes OpenSSL's own
test suite already ships in `test/recipes/30-test_evp_data/evpmd_*.txt` inside the pinned
authority source tree — they are already in the pinned tree and their provenance is checkable
offline, and no network is used and nothing is vendored. They were extracted with this tool's
`--emit` mode, not typed by hand, so a transcription of the corpus into this file is not
itself a transcription error.

What the primary-source layer does and does not establish
---------------------------------------------------------
Naming a primary source and content-addressing the mirror establishes two things and no more:

  * that the **primary source is named** — a reader can see which standard's values these are
    meant to be; and
  * that the **mirrored bytes' identity is fixed** — a changed mirror is detectable, because
    each mirror file's sha256 is committed in the envelope's `inputs[]` and each vector's line
    is committed per vector.

It does **not** establish that the mirror is faithful to a primary source nobody in this
repository has read. No RFC and no ISO standard is vendored here, and the tool fetches
nothing; the name is a pointer, not a checked citation.

Corpora considered and declined
-------------------------------
  * **NIST CAVP** (`shabytetestvectors` and the SHA-3/SHAKE sets): declined here. The vectors
    we need for these nine constructions are already present in the authority's own file for
    every one of them, with a section title naming the standard, and fetching CAVP needs the
    network. NIST's own note is recorded above: their use is informal verification, not
    validation. A later CT court that wants a construction the authority does not ship vectors
    for should record the corpus, its version and its retrieval as an explicit decision rather
    than vendoring it silently.
  * **Project Wycheproof**: declined here. It is a known-attack corpus for *signature and AEAD
    verification* surfaces, not a correctness oracle for a digest construction, and it needs
    the network to obtain. It is the right corpus, with the right caveat, for a later `CT-*`
    court over RSA/DSA/ECDSA verification, and this header records it so that court does not
    have to rediscover the reason.

Zero new dependencies
---------------------
Only the Python standard library and `forensics/tools/atlas_common.py`; the probe is C in
`courts/phase8/ct_digest.c` and links only the candidate distribution shell. Nothing here
fetches, vendors or shells out for a corpus.

Outputs
-------
  forensics/vectors/<algorithm>.json     (with `--emit`, from the pinned authority tree)
  forensics/vectors/aes.json             (with `--emit-ciphers`, the cipher-shaped set below)
  artifacts/phase8/COURTS.json           (the `CT-*` records, via `phase8_courts.py`)

A cipher vector is a different record from a digest vector -- a key, an IV, an operation, an
input and an output rather than a message and a digest -- so it has its own schema
(`cipher-vectors-*`), its own loader and its own driver (`run_cipher_court`, probed by
`courts/phase8/ct_cipher.c`), while the provenance rules above apply unchanged. The pinned
court image carries no independent cipher implementation, so a cipher boundary vector cannot
carry an independent oracle the way a digest boundary can; the cipher sets record that cost
the way D208 records `rhash`'s absence.

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    envelope,
    rel,
    resolve_authority,
    run,
    write_json,
)

VECTOR_DIR = REPO_ROOT / "forensics" / "vectors"
GENERATOR = "forensics/tools/correctness_vectors.py"

# The candidate distribution shell the correctness probe links against. It is the same
# artefact the differential courts link, built by `forensics/tools/build_phase2.sh`, which the
# pipeline runs before any stratum's courts. A correctness court therefore runs the *crate's*
# implementation through the same distribution shell a consumer would load.
CANDIDATE_DIR = REPO_ROOT / "artifacts" / "phase2"
PROBE = REPO_ROOT / "courts" / "phase8" / "ct_digest.c"
# The cipher correctness probe: the same candidate-only shape, with a cipher-shaped record
# (key, IV, operation, input) rather than a digest-shaped one.
CIPHER_PROBE = REPO_ROOT / "courts" / "phase8" / "ct_cipher.c"
CIPHER_KIND_PREFIX = "cipher-vectors-"

# The committed vectors' schema/kind prefix. `envelope` writes
# `openssl-rs/atlas/correctness-vectors-<algorithm>/v1`.
KIND_PREFIX = "correctness-vectors-"


class VectorError(SystemExit):
    """A committed vector file is malformed or names something the tool cannot evaluate."""


# ---------------------------------------------------------------------------
# The extraction table: what `--emit` reads, and what it records about it
# ---------------------------------------------------------------------------
#
# Every corpus is a file the pinned authority already ships. `openssl_digest` is the exact
# `Digest =` value in that file; `algorithm` is the token the C probe dispatches on.
@dataclass(frozen=True)
class EmitSource:
    algorithm: str
    openssl_digest: str
    digest_bytes: int
    standard: str
    primary_source: str
    source_file: str
    # Some corpora carry a construction at an output length other than its default (BLAKE2's
    # `Size` parameter, for instance). This plane's driver is fixed-length, so a block whose
    # output length is not `digest_bytes` is skipped rather than raising -- but only when the
    # source says so, and the count is reported. A fixed-width source still fails closed on a
    # mismatch, which is D206's contract.
    variable_output: bool = False
    # MDC2's corpus carries `Padding = 1` and `Padding = 2` blocks, which select the context's
    # `pad_type`. This plane's driver calls the one-shot `MDC2`, whose `pad_type` is 1, so only
    # the default-padding blocks are mirrored here; the second padding arm is observed by
    # `RT-DIGEST`'s explicit `pad_type = 2` call instead (D215).
    fixed_padding_only: bool = False
    # Some constructions have no oracle in the pinned image at all. MDC2 is not in `hashlib` and
    # RHash has no MDC2 implementation, so no independent implementation within reach can answer
    # a boundary input. Skipping the boundary set is recorded on the file rather than filled
    # with the authority's own answer, which would be no oracle at all (D208/D215).
    boundary_oracle: bool = True


EMIT_SOURCES: tuple[EmitSource, ...] = (
    EmitSource("md4", "MD4", 16, "RFC 1320 (MD4)",
               "RFC 1320 (MD4) §A.5",
               "test/recipes/30-test_evp_data/evpmd_md.txt"),
    EmitSource("md5", "MD5", 16, "RFC 1321 (MD5)",
               "RFC 1321 (MD5) §A.5",
               "test/recipes/30-test_evp_data/evpmd_md.txt"),
    EmitSource("ripemd160", "RIPEMD160", 20, "ISO/IEC 10118-3 (RIPEMD-160)",
               "ISO/IEC 10118-3 (RIPEMD-160); Bosselaers' RIPEMD-160 publication, test vectors",
               "test/recipes/30-test_evp_data/evpmd_ripemd.txt"),
    EmitSource("sha1", "SHA1", 20, "FIPS 180-4; RFC 6234 §8.5",
               "FIPS 180-4; RFC 6234 §8.5",
               "test/recipes/30-test_evp_data/evpmd_sha.txt"),
    EmitSource("sha224", "SHA224", 28, "FIPS 180-4; RFC 6234 §8.5",
               "FIPS 180-4; RFC 6234 §8.5",
               "test/recipes/30-test_evp_data/evpmd_sha.txt"),
    EmitSource("sha256", "SHA256", 32, "FIPS 180-4; RFC 6234 §8.5",
               "FIPS 180-4; RFC 6234 §8.5",
               "test/recipes/30-test_evp_data/evpmd_sha.txt"),
    EmitSource("sha384", "SHA384", 48, "FIPS 180-4; RFC 6234 §8.5",
               "FIPS 180-4; RFC 6234 §8.5",
               "test/recipes/30-test_evp_data/evpmd_sha.txt"),
    EmitSource("sha512", "SHA512", 64, "FIPS 180-4; RFC 6234 §8.5",
               "FIPS 180-4; RFC 6234 §8.5",
               "test/recipes/30-test_evp_data/evpmd_sha.txt"),
    EmitSource("whirlpool", "WHIRLPOOL", 64, "ISO/IEC 10118-3 (Whirlpool)",
               "ISO/IEC 10118-3 (Whirlpool); Rijmen–Barreto submission, test vectors",
               "test/recipes/30-test_evp_data/evpmd_whirlpool.txt"),
    # 8.1b's constructions. `NULL` (zero-length output) and the raw `KECCAK-*`/`KECCAK-KMAC-*`
    # spellings have no entry here: `NULL` cannot satisfy the schema's positive `digest_bytes`, and
    # no oracle for raw Keccak (the NIST `hashlib` sha3 names are the pad-0x06 sponge, not the
    # pad-0x01 Keccak spellings) is available offline. `SHAKE-128`/`SHAKE-256` are absent because
    # their corpus outputs are variable-length and the single-`digest_bytes` schema cannot hold a
    # variable-length XOF vector; D207 records all three exclusions.
    EmitSource("sha256_192", "SHA256-192", 24,
               "SHA2-256/192 (SHA-256 with a 24-byte output)",
               "UNKNOWN",
               "test/recipes/30-test_evp_data/evpmd_sha.txt"),
    EmitSource("sha512_224", "SHA512-224", 28, "FIPS 180-4",
               "FIPS 180-4",
               "test/recipes/30-test_evp_data/evpmd_sha.txt"),
    EmitSource("sha512_256", "SHA512-256", 32, "FIPS 180-4",
               "FIPS 180-4",
               "test/recipes/30-test_evp_data/evpmd_sha.txt"),
    EmitSource("sha3_224", "SHA3-224", 28, "FIPS 202",
               "FIPS 202",
               "test/recipes/30-test_evp_data/evpmd_sha.txt"),
    EmitSource("sha3_256", "SHA3-256", 32, "FIPS 202",
               "FIPS 202",
               "test/recipes/30-test_evp_data/evpmd_sha.txt"),
    EmitSource("sha3_384", "SHA3-384", 48, "FIPS 202",
               "FIPS 202",
               "test/recipes/30-test_evp_data/evpmd_sha.txt"),
    EmitSource("sha3_512", "SHA3-512", 64, "FIPS 202",
               "FIPS 202",
               "test/recipes/30-test_evp_data/evpmd_sha.txt"),
    EmitSource("blake2s256", "BLAKE2s256", 32, "RFC 7693 (BLAKE2)",
               "RFC 7693; BLAKE2 reference implementation",
               "test/recipes/30-test_evp_data/evpmd_blake.txt", variable_output=True),
    EmitSource("blake2b512", "BLAKE2b512", 64, "RFC 7693 (BLAKE2)",
               "RFC 7693; BLAKE2 reference implementation",
               "test/recipes/30-test_evp_data/evpmd_blake.txt", variable_output=True),
    EmitSource("sm3", "SM3", 32, "GB/T 32905-2016 (SM3)",
               "GB/T 32905-2016; ISO/IEC 10118-3 (SM3)",
               "test/recipes/30-test_evp_data/evpmd_sm3.txt"),
    EmitSource("md5_sha1", "MD5-SHA1", 36, "MD5||SHA-1 concatenation (no standard)",
               "UNKNOWN",
               "test/recipes/30-test_evp_data/evpmd_md.txt"),
    # MDC2 is the DES-based digest D197 moved from 8.1 to 8.2. Its observable is a digest, so it
    # belongs in this plane; its two-padding corpus is filtered to the default padding (D215).
    EmitSource("mdc2", "MDC2", 16, "ISO/IEC 10118-2 (MDC-2)",
               "ISO/IEC 10118-2 (MDC-2)",
               "test/recipes/30-test_evp_data/evpmd_mdc2.txt",
               fixed_padding_only=True, boundary_oracle=False),
)

# The primary sources the plan names but whose constructions 8.1a has not transcribed. They are
# recorded here so the provenance layer is complete for the algorithms the *plan* assigns a
# primary source, not only for the nine that currently have vectors; D206 states them.
DECLARED_PRIMARY_SOURCES: dict[str, str] = {
    "sha3-224": "FIPS 202",
    "sha3-256": "FIPS 202",
    "sha3-384": "FIPS 202",
    "sha3-512": "FIPS 202",
    "shake128": "FIPS 202",
    "shake256": "FIPS 202",
}


# ---------------------------------------------------------------------------
# The independent oracle for the boundary vectors
# ---------------------------------------------------------------------------
#
# The standards publish test *suites*; they do not publish a value for every length a padding
# boundary sits on. For those lengths the expected bytes are computed by an implementation that
# is neither the crate nor the pinned authority build, and the oracle is recorded per vector so
# the reader can see which one. `--self-check` validates each oracle against the primary
# source's published values that the pinned corpus also mirrors:
#
#   * MD5, RIPEMD-160, SHA-1 and the four SHA-2 widths are carried by `hashlib`, the Python
#     standard library. `hashlib.new(name, data)` is the oracle.
#   * MD4 and Whirlpool are NOT carried by `hashlib` on this platform, so their boundary
#     expectations are the committed table below, derived once with `rhash` (an independent
#     implementation, not the crate and not the pinned authority build).
#
# The `rhash` derivation is recorded rather than implied, because an oracle whose environment is
# not recorded is not reproducible: the tool, its version and the invocation are named below, and
# `forensics/vectors/md4.json`/`whirlpool.json` carry a `provenance.generation` object with the
# same record per vector. **`rhash` is not present in the pinned court image**, so this is a
# host-side derivation reproduced from the command and version and not an in-court one; the cost
# is that `--self-check` cannot re-derive the table inside the court. What it *can* do, and does,
# is compare the table against the corpus's published MD4/Whirlpool values wherever they overlap,
# which is the in-court check that a changed table is caught. The version recorded is the one the
# table was verified against; any other version is a different oracle and would need its own
# record.
#
# The table is keyed by the boundary label, and the label maps to a deterministic input
# (`BOUNDARY_INPUTS`), so the input is not a free parameter. A missing entry is reported as
# `UNKNOWN` rather than guessed.
_HASHLIB_NAMES: dict[str, str] = {
    "md5": "md5",
    "ripemd160": "ripemd160",
    "sha1": "sha1",
    "sha224": "sha224",
    "sha256": "sha256",
    "sha384": "sha384",
    "sha512": "sha512",
    "sha512_224": "sha512_224",
    "sha512_256": "sha512_256",
    "sha3_224": "sha3_224",
    "sha3_256": "sha3_256",
    "sha3_384": "sha3_384",
    "sha3_512": "sha3_512",
    "blake2s256": "blake2s",
    "blake2b512": "blake2b",
    "sm3": "sm3",
    "md5_sha1": "md5-sha1",
}

_REFERENCE_DIGESTS: dict[str, dict[str, str]] = {
    "md4": {
        "empty": "31d6cfe0d16ae931b73c59d7e0c089c0",
        "one": "bde52cb31de33e46245e05fbdbd6fb24",
        "len55": "04d44dc3dbdcf7604f259009de6e352f",
        "len56": "cdbc435e37e7a468d04702cf9eba65bb",
        "len63": "45a8744e99878276c47927b0164921f4",
        "len64": "87733dbe6c3fc125ee30897c751bd9d6",
        "len65": "82dd3042d4378ef1b420f15c61975b8b",
        "multi1000": "9a27d966bf4984d8597862b1c33bfbba",
    },
    "whirlpool": {
        "empty": "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3",
        "one": "8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a",
        "len55": "9490d80b61a90716243c8854f28c6d1b2ca895067fdbcdaf8483e96353179c6af7816baa0f1ec859326cf855b8dced4cb30e29c4893e45af404d7da642f6b6e4",
        "len56": "ce08bd26d1bae698fdf22420c6dbd11267097839503b05d9f5b520e7d1da5c35258bc3b78a6e99637080ca3e9d31fb00bb975481c8d9aa11dae1eedaa1afccc3",
        "len63": "ec4cfc4d8df48186253eb657efdf65c9bc39f46d95de48f3c516e68fe1f3606ddf0d92f8063611d7317439cff16f396292a083c1f69e22a2c80c252d5fe9e494",
        "len64": "015fa29ae06ddf8283a0ceb0694dc2b3fde2389255339480ca0e89b71423f9d88d32beb038fa9e5cf554627d26a8104fdac59c8b04a04f227f3c02d0e660116c",
        "len65": "b54e396db3adc9e3c01742aaa514e936f4fd5fffaf5838c0dbe187d410840367654d7837842f77577b3995379f3ccadd72267ebbb40695f4662f6bcb4a074dc3",
        "multi1000": "249fedc61e575baa0580a0350d58a415b47388357c2137a820fd861ffeb5b9ac5d2d560a1f62422dba1f2f010195335032c5696a946e2d746906cc63e22e7e54",
    },
}

# `rhash`'s own name for the two constructions it supplies, for the provenance string, with the
# version and invocation recorded per D208: an oracle that does not name its version and command
# is not reproducible. `rhash` is absent from the pinned court image, so the record is what makes
# the derivation checkable rather than an in-court rerun.
_REFERENCE_ORACLE_VERSION = "rhash v1.4.6"
_REFERENCE_ORACLE_GENERATION = {
    "tool": "rhash",
    "version": "v1.4.6",
    "environment": (
        "developer host (RHash v1.4.6); rhash is NOT present in the pinned court image, so this "
        "derivation is reproducible from the tool, version and command recorded here but not "
        "inside the court. --self-check is the in-court check against the corpus's published "
        "values."
    ),
}
_HASHLIB_ORACLE = "hashlib (Python standard library)"


def _reference_oracle(algorithm: str) -> str:
    """The `rhash` oracle string for one construction, version and command named.

    `rhash` spells both of these as its own algorithm name (`--md4`, `--whirlpool`), and
    `--simple` prints `<hex>  (stdin)`; the first whitespace-separated field is the digest. The
    command is the one the committed table was produced with.
    """
    return (
        f"{_REFERENCE_ORACLE_VERSION} (independent implementation, neither the crate nor the "
        f"authority build); `rhash --{algorithm} --simple -` over the vector's input bytes, "
        f"first whitespace-separated field of stdout"
    )


def _pattern(n: int) -> bytes:
    """A deterministic non-trivial byte pattern, so a boundary input is reproducible."""
    return bytes(((i * 7) + 3) & 0xFF for i in range(n))


# The boundary inputs every implemented construction is checked at: the empty message, one byte,
# the five padding boundaries (55/56/63/64/65, where 64 and 65 straddle the block edge and the
# two-block padding arm is first taken), and a message longer than one block.
BOUNDARY_INPUTS: tuple[tuple[str, bytes], ...] = (
    ("empty", b""),
    ("one", b"a"),
    ("len55", _pattern(55)),
    ("len56", _pattern(56)),
    ("len63", _pattern(63)),
    ("len64", _pattern(64)),
    ("len65", _pattern(65)),
    ("multi1000", _pattern(1000)),
)

# Every boundary vector is driven through all three update shapes: one call, two calls, and one
# byte per call. Self-consistency is not enough -- three equally wrong splits agree with each
# other -- so each mode is compared to the same committed expected bytes.
BOUNDARY_MODES: tuple[str, ...] = ("one", "two", "byte")


def _oracle_digest(algorithm: str, label: str, data: bytes) -> tuple[bytes, str] | None:
    """The boundary expectation for `(algorithm, label)`, or `None` (UNKNOWN)."""
    name = _HASHLIB_NAMES.get(algorithm)
    if name is not None:
        return hashlib.new(name, data).digest(), _HASHLIB_ORACLE
    if algorithm == "sha256_192":
        # SHA-256/192 is SHA-256 with a 24-byte output, and this is that definition rather than a
        # guess: FIPS 180-4's SHA-256 truncated. `hashlib` carries no `sha256_192`, so the
        # derivation is named on the vector rather than left implicit.
        return hashlib.sha256(data).digest()[:24], (
            _HASHLIB_ORACLE
            + " (sha256 truncated to 192 bits; the construction is SHA-256 with a 24-byte output)"
        )
    table = _REFERENCE_DIGESTS.get(algorithm)
    if table is not None and label in table:
        return bytes.fromhex(table[label]), _reference_oracle(algorithm)
    return None


# ---------------------------------------------------------------------------
# Committed vectors: loading and validation
# ---------------------------------------------------------------------------

MODES_ONE_SHOT = ("one", "two", "byte")


def _valid_mode(mode: str) -> bool:
    if mode in MODES_ONE_SHOT:
        return True
    return mode.startswith("count:") and mode[6:].isdigit() and int(mode[6:]) > 0


@dataclass
class Vector:
    id: str
    standard: str
    primary_source: str
    input: bytes
    expected: bytes
    modes: list[str]
    provenance: dict


@dataclass
class VectorSet:
    path: Path
    algorithm: str
    openssl_digest: str
    digest_bytes: int
    standard: str
    primary_source: str
    provenance: dict
    vectors: list[Vector] = field(default_factory=list)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VectorError(f"correctness-vectors: {message}")


def load_vector_set(path: Path) -> VectorSet:
    """Load one committed vector file, validating the envelope and every vector.

    A malformed file is a hard failure rather than a skipped corpus: a vector set that is not
    quite readable is exactly the way a court would quietly stop checking something.

    The provenance contract is the one the tool's header states: every vector names a primary
    source (or says `UNKNOWN`), and a vector whose bytes are mirrored states where. A vector
    that is neither mirrored nor explicitly an independent derivation is malformed.
    """
    doc = json.loads(path.read_text(encoding="utf-8"))
    _require(isinstance(doc, dict), f"{rel(path)} is not a JSON object")
    schema = str(doc.get("schema", ""))
    _require(schema.startswith(f"openssl-rs/atlas/{KIND_PREFIX}"),
             f"{rel(path)}: schema {schema!r} does not start with "
             f"'openssl-rs/atlas/{KIND_PREFIX}'")
    _require(doc.get("kind", "").startswith(KIND_PREFIX),
             f"{rel(path)}: kind {doc.get('kind')!r} does not start with {KIND_PREFIX!r}")
    body = doc.get("body")
    _require(isinstance(body, dict), f"{rel(path)}: body is missing")
    algorithm = str(body.get("algorithm", ""))
    _require(algorithm != "", f"{rel(path)}: body.algorithm is missing")
    openssl_digest = str(body.get("openssl_digest", ""))
    _require(openssl_digest != "", f"{rel(path)}: body.openssl_digest is missing")
    digest_bytes = body.get("digest_bytes")
    _require(isinstance(digest_bytes, int) and digest_bytes > 0,
             f"{rel(path)}: body.digest_bytes must be a positive integer")
    standard = str(body.get("standard", ""))
    _require(standard != "", f"{rel(path)}: body.standard is missing")
    primary_source = str(body.get("primary_source", "UNKNOWN"))
    _require(primary_source != "", f"{rel(path)}: body.primary_source must be a string")

    raw_vectors = body.get("vectors")
    _require(isinstance(raw_vectors, list) and raw_vectors,
             f"{rel(path)}: body.vectors must be a non-empty list")

    vectors: list[Vector] = []
    seen: set[str] = set()
    for i, raw in enumerate(raw_vectors):
        where = f"{rel(path)}: vectors[{i}]"
        _require(isinstance(raw, dict), f"{where} is not an object")
        vid = str(raw.get("id", ""))
        _require(vid != "", f"{where}.id is missing")
        _require(vid not in seen, f"{where}.id {vid!r} is duplicated")
        seen.add(vid)
        v_standard = str(raw.get("standard", standard))
        input_hex = str(raw.get("input_hex", ""))
        expected_hex = str(raw.get("expected_hex", ""))
        _require(len(expected_hex) == digest_bytes * 2,
                 f"{where}: expected_hex is {len(expected_hex)} hex digits, "
                 f"not {digest_bytes * 2} for {algorithm}")
        provenance = raw.get("provenance")
        _require(isinstance(provenance, dict),
                 f"{where}: provenance must be an object")
        v_primary = str(provenance.get("primary_source", primary_source))
        _require(v_primary != "", f"{where}: provenance.primary_source must not be empty")
        derivation = str(provenance.get("derivation", ""))
        _require(derivation in ("corpus", "independent"),
                 f"{where}: provenance.derivation must be 'corpus' or 'independent'")
        if derivation == "corpus":
            _require(provenance.get("file") and provenance.get("line") is not None,
                     f"{where}: a mirrored vector must name the mirror file and line")
        else:
            _require(provenance.get("oracle"),
                     f"{where}: an independent vector must name its oracle")
        raw_modes = raw.get("modes", ["one"])
        _require(isinstance(raw_modes, list) and raw_modes,
                 f"{where}: modes must be a non-empty list")
        modes = [str(m) for m in raw_modes]
        for m in modes:
            _require(_valid_mode(m),
                     f"{where}: mode {m!r} is not one of {MODES_ONE_SHOT} or 'count:<n>'")
        try:
            input_bytes = bytes.fromhex(input_hex)
            expected = bytes.fromhex(expected_hex)
        except ValueError as exc:
            raise VectorError(f"{where}: not hex ({exc})") from exc
        vectors.append(Vector(vid, v_standard, v_primary, input_bytes, expected, modes,
                              provenance))

    return VectorSet(path=path, algorithm=algorithm, openssl_digest=openssl_digest,
                     digest_bytes=digest_bytes, standard=standard,
                     primary_source=primary_source,
                     provenance=body.get("provenance", {}), vectors=vectors)


def load_all(vector_dir: Path = VECTOR_DIR) -> list[VectorSet]:
    paths = sorted(vector_dir.glob("*.json"))
    if not paths:
        raise VectorError(
            f"correctness-vectors: no vector files under {rel(vector_dir)}; a CT-* court "
            "with no committed vectors would be a court that checks nothing"
        )
    sets = []
    for p in paths:
        kind = str(json.loads(p.read_text(encoding="utf-8")).get("kind", ""))
        if kind.startswith(CIPHER_KIND_PREFIX):
            continue
        sets.append(load_vector_set(p))
    return sets


# ---------------------------------------------------------------------------
# The cipher vector set: a different schema, because a cipher has a key
# ---------------------------------------------------------------------------
#
# A digest vector is (message, digest); a cipher vector is (key, IV, operation, input,
# output). Folding them into one schema would have made every digest field optional and
# every cipher field a stringly-typed extra, so the cipher set is its own loader and its own
# driver, in the same envelope and with the same provenance contract.


@dataclass
class CipherVector:
    id: str
    cipher: str
    operation: str
    key: bytes
    iv: bytes
    input: bytes
    expected: bytes
    standard: str
    primary_source: str
    provenance: dict
    aad: bytes = b""
    tag: bytes = b""
    # The CTS variant (`CS1`/`CS2`/`CS3`), empty for every construction that has no such
    # parameter. It is the vector's own field because `AES-*-CBC-CTS` is three constructions
    # under one name (`cipher_cts.c:33-46`), and the corpus's `CTSMode` line is where the
    # variant is chosen.
    ctsmode: str = ""


@dataclass
class CipherVectorSet:
    path: Path
    algorithm: str
    standard: str
    primary_source: str
    provenance: dict
    vectors: list[CipherVector] = field(default_factory=list)


def load_cipher_vector_set(path: Path) -> CipherVectorSet:
    """Load one committed cipher vector file, validating envelope and provenance."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    _require(isinstance(doc, dict), f"{rel(path)} is not a JSON object")
    kind = str(doc.get("kind", ""))
    _require(kind.startswith(CIPHER_KIND_PREFIX),
             f"{rel(path)}: kind {kind!r} does not start with {CIPHER_KIND_PREFIX!r}")
    body = doc.get("body")
    _require(isinstance(body, dict), f"{rel(path)}: body is missing")
    algorithm = str(body.get("algorithm", ""))
    _require(algorithm != "", f"{rel(path)}: body.algorithm is missing")
    standard = str(body.get("standard", ""))
    _require(standard != "", f"{rel(path)}: body.standard is missing")
    primary_source = str(body.get("primary_source", "UNKNOWN"))
    raw_vectors = body.get("vectors")
    _require(isinstance(raw_vectors, list) and raw_vectors,
             f"{rel(path)}: body.vectors must be a non-empty list")

    vectors: list[CipherVector] = []
    seen: set[str] = set()
    for i, raw in enumerate(raw_vectors):
        where = f"{rel(path)}: vectors[{i}]"
        _require(isinstance(raw, dict), f"{where} is not an object")
        vid = str(raw.get("id", ""))
        _require(vid != "", f"{where}.id is missing")
        _require(vid not in seen, f"{where}.id {vid!r} is duplicated")
        seen.add(vid)
        cipher = str(raw.get("cipher", ""))
        operation = str(raw.get("operation", "")).upper()
        _require(cipher != "", f"{where}.cipher is missing")
        _require(operation in ("ENCRYPT", "DECRYPT"),
                 f"{where}.operation must be ENCRYPT or DECRYPT")
        provenance = raw.get("provenance")
        _require(isinstance(provenance, dict), f"{where}: provenance must be an object")
        derivation = str(provenance.get("derivation", ""))
        _require(derivation in ("corpus", "independent"),
                 f"{where}: provenance.derivation must be 'corpus' or 'independent'")
        if derivation == "corpus":
            _require(provenance.get("file") and provenance.get("line") is not None,
                     f"{where}: a mirrored vector must name the mirror file and line")
        else:
            _require(provenance.get("oracle"),
                     f"{where}: an independent vector must name its oracle")
        try:
            key = bytes.fromhex(str(raw.get("key_hex", "")))
            iv = bytes.fromhex(str(raw.get("iv_hex", "")))
            input_bytes = bytes.fromhex(str(raw.get("input_hex", "")))
            expected = bytes.fromhex(str(raw.get("expected_hex", "")))
            aad = bytes.fromhex(str(raw.get("aad_hex", "")))
            tag = bytes.fromhex(str(raw.get("tag_hex", "")))
        except ValueError as exc:
            raise VectorError(f"{where}: not hex ({exc})") from exc
        vectors.append(CipherVector(
            vid, cipher, operation, key, iv, input_bytes, expected,
            str(raw.get("standard", standard)),
            str(provenance.get("primary_source", primary_source)), provenance,
            aad=aad, tag=tag, ctsmode=str(raw.get("ctsmode", "")).upper()))

    return CipherVectorSet(path=path, algorithm=algorithm, standard=standard,
                           primary_source=primary_source,
                           provenance=body.get("provenance", {}), vectors=vectors)


def load_all_ciphers(vector_dir: Path = VECTOR_DIR) -> list[CipherVectorSet]:
    sets = []
    for p in sorted(vector_dir.glob("*.json")):
        kind = str(json.loads(p.read_text(encoding="utf-8")).get("kind", ""))
        if kind.startswith(CIPHER_KIND_PREFIX):
            sets.append(load_cipher_vector_set(p))
    return sets


def _cipher_derivation_census(sets: list[CipherVectorSet]) -> dict:
    corpus = independent = 0
    oracles: dict[str, int] = {}
    for vs in sets:
        for v in vs.vectors:
            if str(v.provenance.get("derivation")) == "corpus":
                corpus += 1
            else:
                independent += 1
                name = str(v.provenance.get("oracle", "UNKNOWN"))
                oracles[name] = oracles.get(name, 0) + 1
    return {"vectors": corpus + independent, "corpus": corpus,
            "independent": independent, "oracles": dict(sorted(oracles.items())),
            "files": len(sets)}


def run_cipher_court(
    name: str,
    algorithms: tuple[str, ...],
    *,
    vector_dir: Path = VECTOR_DIR,
    candidate_dir: Path = CANDIDATE_DIR,
    probe: Path = CIPHER_PROBE,
    work_dir: Path,
    authority_id: str = PRODUCTION_AUTHORITY,
) -> dict:
    """Run one cipher correctness court (`CT-CIPHER`): candidate-only, per-vector and loud."""
    all_sets = {s.algorithm: s for s in load_all_ciphers(vector_dir)}
    wanted = sorted(set(algorithms))
    missing = [a for a in wanted if a not in all_sets]
    if missing:
        return {
            "court": name, "plane": "correctness", "verdict": "fail",
            "stage": "vectors-missing",
            "detail": [f"no committed cipher vectors for algorithm {a!r} under "
                       f"{rel(vector_dir)}" for a in missing],
        }
    sets = [all_sets[a] for a in wanted]

    calls: list[tuple[int, CipherVectorSet, CipherVector]] = []
    for vs in sets:
        for v in vs.vectors:
            calls.append((len(calls), vs, v))

    work_dir.mkdir(parents=True, exist_ok=True)
    call_path = work_dir / f"{name.lower()}.calls.tsv"
    call_path.write_text("".join(
        f"{i}\t{v.cipher}\t{v.operation}\t{v.key.hex()}\t{v.iv.hex()}\t{v.input.hex()}"
        f"\t{v.aad.hex()}\t{len(v.tag)}\t{v.ctsmode}\n"
        for i, _vs, v in calls), encoding="utf-8")

    binary = work_dir / f"{name.lower()}.candidate"
    ok, err = compile_probe(probe, binary, candidate_dir / "include", candidate_dir)
    if not ok:
        return {"court": name, "plane": "correctness", "verdict": "fail",
                "stage": "compile-candidate", "probe": rel(probe),
                "detail": err.splitlines()[:16],
                "needs": ("the candidate distribution shell to export the low-level "
                          "cipher entry points; run forensics/tools/build_phase2.sh")}

    res = run([str(binary), str(call_path)])
    if res.returncode != 0:
        return {"court": name, "plane": "correctness", "verdict": "fail",
                "stage": "candidate-run",
                "detail": {"exit_code": res.returncode,
                           "stderr": res.stderr.splitlines()[:16]}}

    produced = _parse_probe(res.stdout)
    failures: list[dict] = []
    results: list[dict] = []
    per_algorithm: dict[str, dict] = {}
    vector_failed: set[tuple[str, str]] = set()
    for vs in sets:
        per_algorithm[vs.algorithm] = {
            "standard": vs.standard, "primary_source": vs.primary_source,
            "source": rel(vs.path), "total": len(vs.vectors), "passed": 0, "failed": 0}

    calls_checked = 0
    for index, vs, v in calls:
        calls_checked += 1
        status, value = produced.get(index, ("err", "no-result-line"))
        # An AEAD vector's answer is the ciphertext followed by its tag and then the probe's
        # own accept and reject answers; a non-AEAD vector's tag is empty, so the same
        # comparison serves both.
        want = (v.expected + v.tag).hex() + ("0101" if v.tag else "")
        good = status == "ok" and value == want
        results.append({"algorithm": vs.algorithm, "id": v.id,
                        "cipher": v.cipher, "operation": v.operation,
                        "passed": good,
                        "input_hex": v.input.hex(), "expected_hex": want,
                        "actual_hex": value if status == "ok" else None})
        if good:
            continue
        vector_failed.add((vs.algorithm, v.id))
        failures.append({"algorithm": vs.algorithm, "id": v.id, "cipher": v.cipher,
                         "operation": v.operation, "standard": v.standard,
                         "primary_source": v.primary_source,
                         "input_hex": v.input.hex(), "expected_hex": want,
                         "actual_hex": value if status == "ok" else None,
                         "probe_status": status,
                         "probe_detail": None if status == "ok" else value,
                         "provenance": v.provenance})

    total = 0
    for vs in sets:
        summary = per_algorithm[vs.algorithm]
        passed = sum(1 for v in vs.vectors
                     if (vs.algorithm, v.id) not in vector_failed)
        summary["passed"] = passed
        summary["failed"] = len(vs.vectors) - passed
        total += len(vs.vectors)

    census = _cipher_derivation_census(sets)
    oracle_parts = "; ".join(f"{n} by {name}" for name, n in census["oracles"].items())
    passed_vectors = total - len(vector_failed)
    return {
        "court": name, "plane": "correctness", "kind": "cipher-vectors",
        "probe": rel(probe),
        "candidate_shared_object": rel(candidate_dir / "libcrypto.so.3"),
        "authority": authority_id,
        "vectors_checked": total, "vectors_passed": passed_vectors,
        "vectors_failed": total - passed_vectors, "calls_checked": calls_checked,
        "derivation_census": census, "algorithms": per_algorithm,
        "results": results, "failures": failures,
        "stage": "vector-mismatch" if failures else "compare",
        "verdict": "pass" if not failures else "fail",
        "claim": (
            "A correctness-vector PASS means candidate-only construction verification: the "
            "candidate's low-level cipher produced the committed expected bytes for every "
            f"vector. Of the {census['vectors']} committed vectors, {census['corpus']} are "
            "published standard values mirrored through the pinned OpenSSL test corpus and "
            f"{census['independent']} are independently-derived boundary vectors with named "
            f"oracles ({oracle_parts}) -- these counts are read from the {census['files']} "
            "committed `forensics/vectors/*.json` cipher sets by `correctness_vectors.py`, "
            "not typed. It is NOT OpenSSL parity and NOT formal validation. See D201/D208 "
            "and docs/PHASE-8-SUBPHASES.md."
        ),
    }


# ---------------------------------------------------------------------------
# The correctness driver: compile the candidate probe, run it, compare
# ---------------------------------------------------------------------------

def compile_probe(src: Path, out: Path, include: Path, libdir: Path) -> tuple[bool, str]:
    """Compile the candidate-only correctness probe.

    The flags are the differential runner's (`phase8_courts.py:compile_probe`), for the same
    reason: `-Werror=implicit-function-declaration` turns a forgotten prototype into a build
    failure instead of a call through an assumed `int` return.
    """
    res = run([
        "clang", "-std=c11", "-Wall", "-Werror=implicit-function-declaration", "-O1",
        "-D_GNU_SOURCE",
        "-I", str(include),
        "-o", str(out), str(src),
        "-L", str(libdir), "-lcrypto",
        f"-Wl,-rpath,{libdir}",
    ])
    return res.ok, res.stderr.strip()


def _parse_probe(stdout: str) -> dict[int, tuple[str, str]]:
    results: dict[int, tuple[str, str]] = {}
    for line in stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        try:
            index = int(parts[0])
        except ValueError:
            continue
        results[index] = (parts[1], parts[2])
    return results


def _oracle_family(oracle: str) -> str:
    """The short family name of an oracle string, for the census (e.g. `hashlib`, `rhash`)."""
    return oracle.split(" (", 1)[0].strip() or "UNKNOWN"


def _derivation_census(sets: list[VectorSet]) -> dict:
    """Count the committed vectors by derivation, and the independent ones by oracle family.

    This is the census the `CT-DIGEST` claim is **generated from** rather than typing a fixed
    sentence: when D206 added independently-derived boundary vectors, a claim that said every
    vector was mirrored went stale while every individual vector record stayed honest (D205's
    rule, applied to a generated claim rather than a hand-written one).
    """
    corpus = 0
    independent = 0
    oracles: dict[str, int] = {}
    for vs in sets:
        for v in vs.vectors:
            derivation = str(v.provenance.get("derivation", ""))
            if derivation == "corpus":
                corpus += 1
            elif derivation == "independent":
                independent += 1
                family = _oracle_family(str(v.provenance.get("oracle", "")))
                oracles[family] = oracles.get(family, 0) + 1
    return {
        "vectors": corpus + independent,
        "corpus": corpus,
        "independent": independent,
        "oracles": dict(sorted(oracles.items())),
        "files": len(sets),
    }


def run_court(
    name: str,
    algorithms: tuple[str, ...],
    *,
    vector_dir: Path = VECTOR_DIR,
    candidate_dir: Path = CANDIDATE_DIR,
    probe: Path = PROBE,
    work_dir: Path,
    authority_id: str = PRODUCTION_AUTHORITY,
) -> dict:
    """Run one `CT-*` court and return its record.

    The record is `pass` only when every vector in every named algorithm produced exactly its
    committed expected bytes. Anything else — a missing vector set, a probe that will not
    compile, a probe that dies, a single mismatch — is `fail`, with the reason and, for
    mismatches, every failing vector's input/expected/actual.
    """
    all_sets = {s.algorithm: s for s in load_all(vector_dir)}
    wanted = sorted(set(algorithms))
    missing = [a for a in wanted if a not in all_sets]
    if missing:
        return {
            "court": name, "plane": "correctness", "verdict": "fail",
            "stage": "vectors-missing",
            "detail": [f"no committed vectors for algorithm {a!r} under {rel(vector_dir)}"
                       for a in missing],
            "needs": ("a committed forensics/vectors/<algorithm>.json with per-vector "
                      "provenance, extracted from a corpus already in the pinned authority "
                      "tree (see this tool's `--emit` mode)"),
        }

    sets = [all_sets[a] for a in wanted]

    # One call per (vector, update mode). A vector passes only when every mode it names
    # produced its committed expected bytes, and a mismatch is reported per call so the mode
    # that failed is visible. `vectors_checked` counts vector definitions; `calls_checked`
    # counts the executions, which is the number the collector actually drives.
    calls: list[tuple[int, str, str, bytes]] = []
    index_of: dict[int, tuple[VectorSet, Vector, str]] = {}
    next_index = 0
    for vs in sets:
        for v in vs.vectors:
            for mode in v.modes:
                calls.append((next_index, vs.algorithm, mode, v.input))
                index_of[next_index] = (vs, v, mode)
                next_index += 1

    work_dir.mkdir(parents=True, exist_ok=True)
    call_path = work_dir / f"{name.lower()}.calls.tsv"
    call_path.write_text(
        "".join(f"{i}\t{algo}\t{mode}\t{data.hex()}\n" for i, algo, mode, data in calls),
        encoding="utf-8",
    )

    candidate_lib = candidate_dir
    candidate_include = candidate_dir / "include"
    binary = work_dir / f"{name.lower()}.candidate"
    ok, err = compile_probe(probe, binary, candidate_include, candidate_lib)
    if not ok:
        return {
            "court": name, "plane": "correctness", "verdict": "fail",
            "stage": "compile-candidate",
            "probe": rel(probe),
            "detail": err.splitlines()[:16],
            "needs": ("the candidate distribution shell "
                      f"({rel(candidate_dir / 'libcrypto.so.3')}) to export the low-level "
                      "Init/Update/Final entry points for: " + ", ".join(wanted)
                      + ". Run forensics/tools/build_phase2.sh first."),
        }

    res = run([str(binary), str(call_path)])
    if res.returncode != 0:
        return {
            "court": name, "plane": "correctness", "verdict": "fail",
            "stage": "candidate-run",
            "detail": {"exit_code": res.returncode,
                       "stderr": res.stderr.splitlines()[:16]},
        }

    produced = _parse_probe(res.stdout)

    total = 0
    calls_checked = 0
    failures: list[dict] = []
    results: list[dict] = []
    per_algorithm: dict[str, dict] = {}
    vector_failed: dict[str, bool] = {}
    for vs in sets:
        per_algorithm[vs.algorithm] = {
            "standard": vs.standard, "primary_source": vs.primary_source,
            "source": rel(vs.path),
            "digest_bytes": vs.digest_bytes, "total": len(vs.vectors),
            "passed": 0, "failed": 0,
        }
        vector_failed[vs.algorithm] = False

    for index, (vs, v, mode) in index_of.items():
        calls_checked += 1
        status, value = produced.get(index, ("err", "no-result-line"))
        ok = status == "ok" and value == v.expected.hex()
        results.append({
            "algorithm": vs.algorithm,
            "id": v.id,
            "mode": mode,
            "passed": ok,
            "input_hex": v.input.hex(),
            "expected_hex": v.expected.hex(),
            "actual_hex": value if status == "ok" else None,
        })
        if ok:
            continue
        vector_failed[vs.algorithm] = True
        failures.append({
            "algorithm": vs.algorithm,
            "id": v.id,
            "mode": mode,
            "standard": v.standard,
            "primary_source": v.primary_source,
            "input_hex": v.input.hex(),
            "expected_hex": v.expected.hex(),
            "actual_hex": value if status == "ok" else None,
            "probe_status": status,
            "probe_detail": None if status == "ok" else value,
            "provenance": v.provenance,
        })

    # A vector counts as passed only when every mode it names passed, so the summary does not
    # give partial credit to a vector whose split-update arm failed.
    vector_failed_ids: set[tuple[str, str]] = {(f["algorithm"], f["id"]) for f in failures}
    for vs in sets:
        summary = per_algorithm[vs.algorithm]
        passed = sum(1 for v in vs.vectors if (vs.algorithm, v.id) not in vector_failed_ids)
        summary["passed"] = passed
        summary["failed"] = len(vs.vectors) - passed
        total += len(vs.vectors)

    # The claim is generated from the census of the very vectors this court just ran, so a later
    # slice that adds a derivation the sentence does not mention cannot leave it stale. See D205
    # (a generator owns its quantity) and D208.
    census = _derivation_census(sets)
    oracle_parts = "; ".join(f"{n} by {name}" for name, n in census["oracles"].items())
    passed_vectors = total - len(vector_failed_ids)

    return {
        "court": name,
        "plane": "correctness",
        "kind": "construction-vectors",
        "probe": rel(probe),
        "candidate_shared_object": rel(candidate_dir / "libcrypto.so.3"),
        "authority": authority_id,
        "vectors_checked": total,
        "vectors_passed": passed_vectors,
        "vectors_failed": total - passed_vectors,
        "calls_checked": calls_checked,
        "derivation_census": census,
        "algorithms": per_algorithm,
        "results": results,
        "failures": failures,
        "stage": "vector-mismatch" if failures else "compare",
        "verdict": "pass" if not failures else "fail",
        "claim": (
            "A correctness-vector PASS means candidate-only construction verification: the "
            "candidate's construction produced the committed expected bytes for every "
            "vector and every update mode. Of the "
            f"{census['vectors']} committed vectors, {census['corpus']} are published standard "
            "values mirrored through the pinned OpenSSL test corpus and "
            f"{census['independent']} are independently-derived boundary vectors with named "
            f"oracles ({oracle_parts}) -- these counts are read from the "
            f"{census['files']} committed `forensics/vectors/<algorithm>.json` files by "
            "`correctness_vectors.py`, not typed. It is NOT OpenSSL parity: the corpus does "
            "not contain the authority's observable behaviour, and that is RT-DIGEST's "
            "question. It is NOT independent cryptographic validation and NOT formal "
            "validation: the mirrored vectors are the standards' published values, and "
            "published test vectors are informal verification, not a certificate. NIST CAVP "
            "and Project Wycheproof are corpora this plane does NOT use; they are recorded as "
            "declined-with-reason in correctness_vectors.py's header. See docs/DECISIONS.md "
            "D201 and D208 and docs/PHASE-8-SUBPHASES.md."
        ),
    }


# ---------------------------------------------------------------------------
# `--emit`: regenerate the committed vectors from the pinned authority tree
# ---------------------------------------------------------------------------

def _c_unquote(value: str) -> bytes:
    """Decode an OpenSSL evp_test quoted-string `Input`."""
    body = value.strip()
    if not (body.startswith('"') and body.endswith('"') and len(body) >= 2):
        raise VectorError(f"correctness-vectors: not a quoted string: {value!r}")
    inner = body[1:-1]
    out = bytearray()
    i = 0
    while i < len(inner):
        ch = inner[i]
        if ch != "\\":
            out.append(ord(ch))
            i += 1
            continue
        i += 1
        if i >= len(inner):
            raise VectorError(f"correctness-vectors: trailing backslash in {value!r}")
        esc = inner[i]
        mapping = {"n": 0x0A, "t": 0x09, "r": 0x0D, "0": 0x00,
                   "\\": 0x5C, '"': 0x22}
        out.append(mapping[esc])
        i += 1
    return bytes(out)


def _parse_evp_blocks(text: str) -> list[tuple[str, list[tuple[str, str, int]]]]:
    """Split an `evp_test` data file into `(title, ordered key/value/line entries)` blocks.

    Ordered, because a repeated-message block carries several `Input`/`Ncopy` pairs and the
    order is what says which `Count` multiplies which pair. The single-message reader below
    collapses a block to a dict because it only ever reads one `Input`.
    """
    blocks: list[tuple[str, list[tuple[str, str, int]]]] = []
    title = ""
    current: list[tuple[str, str, int]] = []

    def flush() -> None:
        nonlocal current
        if current:
            blocks.append((title, current))
            current = []

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line == "":
            flush()
            continue
        if line.startswith("#"):
            continue
        if line.startswith("Title"):
            flush()
            _, _, value = line.partition("=")
            title = value.strip()
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        current.append((key.strip(), value.strip(), lineno))
    flush()
    return blocks


def _parse_evpmd(text: str) -> list[tuple[str, int, dict[str, str]]]:
    """The single-message `(title, digest-line, fields)` records of an `evp_test` file.

    Blocks that carry `Ncopy`/`Count` are excluded here and read by `_parse_evpmd_repeats`:
    they are not one message but a repeated one, and the tool drives them through a distinct
    mode so the repetition itself is part of what is checked.
    """
    records: list[tuple[str, int, dict[str, str]]] = []
    for title, entries in _parse_evp_blocks(text):
        fields: dict[str, str] = {}
        digest_line = 0
        for key, value, lineno in entries:
            if key == "Digest":
                digest_line = lineno
            fields[key] = value
        if ("Digest" in fields and "Input" in fields and "Output" in fields
                and "Ncopy" not in fields and "Count" not in fields):
            records.append((title, digest_line, fields))
    return records


def _parse_evpmd_repeats(text: str) -> list[tuple[str, int, str, bytes, int, str]]:
    """The `Ncopy`/`Count` records as `(title, digest-line, digest, base, reps, output-hex)`.

    Every repeated block in this corpus builds its message from one byte string, so the whole
    message is `base` repeated `reps` times and the vector can be committed as the base plus a
    `count:<reps>` mode rather than two megabytes of hex. `Count` multiplies the pair it
    follows, which is the arithmetic that makes SHA-1/224/256/384/512 and Whirlpool's blocks
    all describe one 1,000,000-byte message; a block whose inputs differ, or whose length is
    not a whole number of copies, is refused rather than approximated.
    """
    records: list[tuple[str, int, str, bytes, int, str]] = []
    for title, entries in _parse_evp_blocks(text):
        if not any(key in ("Ncopy", "Count") for key, _, _ in entries):
            continue
        digest_line = 0
        digest = ""
        output: str | None = None
        pairs: list[list] = []
        current: list | None = None
        for key, value, lineno in entries:
            if key == "Digest":
                digest_line = lineno
                digest = value
            elif key == "Input":
                if current is not None:
                    pairs.append(current)
                if value == "":
                    current = [b"", 1, None]
                elif value.startswith('"'):
                    current = [_c_unquote(value), 1, None]
                else:
                    current = [bytes.fromhex(value), 1, None]
            elif key == "Ncopy" and current is not None:
                current[1] = int(value)
            elif key == "Count" and current is not None:
                current[2] = int(value)
            elif key == "Output":
                output = value
        if current is not None:
            pairs.append(current)
        if output is None or not pairs:
            continue
        bases = {bytes(inp) for inp, _ncopy, _count in pairs}
        if len(bases) != 1:
            raise VectorError(
                f"correctness-vectors: {title!r} repeats several different inputs; that is "
                "a multi-segment message this tool refuses to flatten"
            )
        base = bases.pop()
        total = 0
        for inp, ncopy, count in pairs:
            seg = len(inp) * ncopy
            total += seg * (count if count is not None else 1)
        if not base or total == 0 or total % len(base) != 0:
            raise VectorError(
                f"correctness-vectors: {title!r} does not reduce to a whole number of copies"
            )
        records.append((title, digest_line, digest, base, total // len(base), output))
    return records


def _emit_one(source: EmitSource, auth_source: Path, authority_id: str,
              vector_dir: Path) -> dict:
    src_path = auth_source / source.source_file
    if not src_path.is_file():
        raise VectorError(
            f"correctness-vectors: {rel(src_path)} is absent; --emit needs the pinned "
            "authority source tree"
        )
    text = src_path.read_text(encoding="utf-8")
    stem = src_path.stem
    wanted = source.openssl_digest.upper()
    mirror_sha256 = hashlib.sha256(src_path.read_bytes()).hexdigest()

    def corpus_provenance(line: int, title: str, form: str, repeats: int | None = None) -> dict:
        prov = {
            "primary_source": source.primary_source,
            "derivation": "corpus",
            "file": rel(src_path),
            "line": line,
            "title": title,
            "form": form,
            "authority": authority_id,
            "mirror_sha256": mirror_sha256,
        }
        if repeats is not None:
            prov["repeats"] = repeats
        return prov

    vectors: list[dict] = []
    skipped: int = 0

    # (1) The single-message corpus vectors, as before.
    for title, digest_line, fields in _parse_evpmd(text):
        if fields["Digest"].upper() != wanted:
            continue
        if source.fixed_padding_only and fields.get("Padding", "1") not in ("", "1"):
            # A non-default padding arm the one-shot driver cannot select; `RT-DIGEST`
            # observes `pad_type = 2` directly instead (D215).
            skipped += 1
            continue
        raw_input = fields["Input"]
        if raw_input == "":
            input_bytes = b""
            form = "empty"
        elif raw_input.startswith('"'):
            input_bytes = _c_unquote(raw_input)
            form = "quoted-string"
        else:
            input_bytes = bytes.fromhex(raw_input)
            form = "hex"
        expected = bytes.fromhex(fields["Output"])
        if len(expected) != source.digest_bytes:
            if source.variable_output:
                skipped += 1
                continue
            raise VectorError(
                f"{rel(src_path)}:{digest_line}: {fields['Digest']} output is "
                f"{len(expected)} bytes, expected {source.digest_bytes}"
            )
        vectors.append({
            "id": f"{source.algorithm}-{stem}-{digest_line}",
            "standard": source.standard,
            "input_hex": input_bytes.hex(),
            "expected_hex": expected.hex(),
            "modes": ["one"],
            "provenance": corpus_provenance(digest_line, title, form),
        })

    if not vectors:
        raise VectorError(
            f"correctness-vectors: no {source.openssl_digest} vectors found in "
            f"{rel(src_path)}"
        )

    # (2) The corpus's repeated-message (`Ncopy`/`Count`) vectors. These are known expected
    # digests for a message no single vector covers -- a multi-block input -- so they are
    # committed as the base plus a `count:<reps>` mode rather than as megabytes of hex.
    for title, digest_line, digest, base, reps, output_hex in _parse_evpmd_repeats(text):
        if digest.upper() != wanted:
            continue
        expected = bytes.fromhex(output_hex)
        if len(expected) != source.digest_bytes:
            if source.variable_output:
                skipped += 1
                continue
            raise VectorError(
                f"{rel(src_path)}:{digest_line}: {digest} repeated output is "
                f"{len(expected)} bytes, expected {source.digest_bytes}"
            )
        vectors.append({
            "id": f"{source.algorithm}-repeat-{reps}",
            "standard": source.standard,
            "input_hex": base.hex(),
            "expected_hex": expected.hex(),
            "modes": [f"count:{reps}"],
            "provenance": corpus_provenance(digest_line, title, "repeat", repeats=reps),
        })

    # (3) The boundary vectors. The expected bytes are the oracle's, because the standard
    # publishes the construction but not a vector for these exact inputs; each vector names the
    # oracle and says so. A missing oracle is `UNKNOWN`, never a guess.
    boundary_skipped: str | None = None
    if not source.boundary_oracle:
        boundary_skipped = (
            "no independent oracle for this construction is present in the pinned court image "
            "(`hashlib` has no MDC2, and RHash has no MDC2 implementation), so no boundary "
            "vector is emitted rather than one whose expected bytes came from the authority "
            "it is supposed to check. Recorded, not guessed (D208, D215)."
        )
    for label, data in (() if boundary_skipped else BOUNDARY_INPUTS):
        got = _oracle_digest(source.algorithm, label, data)
        if got is None:
            raise VectorError(
                f"correctness-vectors: UNKNOWN boundary oracle for {source.algorithm}/{label}; "
                "add the committed reference digest rather than guessing one"
            )
        expected, oracle = got
        if len(expected) != source.digest_bytes:
            raise VectorError(
                f"correctness-vectors: oracle for {source.algorithm}/{label} answered "
                f"{len(expected)} bytes, expected {source.digest_bytes}"
            )
        prov = {
            "primary_source": source.primary_source,
            "derivation": "independent",
            "oracle": oracle,
            "label": label,
            "note": (
                "The primary source publishes the construction but not a vector for this "
                "input; the expected bytes are the named oracle's answer. The oracle is "
                "data-independent of the crate and of the pinned authority build, but this "
                "is NOT a primary-source published value. Run --self-check to compare the "
                "oracle against the primary-source values the corpus mirrors."
            ),
        }
        # An oracle that is not the in-court `hashlib` carries its own generation record: tool,
        # version and the exact command, so the bytes can be reproduced rather than trusted. The
        # `hashlib` oracle needs none -- `--self-check` re-runs it in the court.
        if oracle.startswith("rhash"):
            prov["generation"] = {
                **_REFERENCE_ORACLE_GENERATION,
                "command": f"rhash --{source.algorithm} --simple -",
            }
        vectors.append({
            "id": f"{source.algorithm}-boundary-{label}",
            "standard": source.standard,
            "input_hex": data.hex(),
            "expected_hex": expected.hex(),
            "modes": list(BOUNDARY_MODES),
            "provenance": prov,
        })

    body = {
        "algorithm": source.algorithm,
        "openssl_digest": source.openssl_digest,
        "digest_bytes": source.digest_bytes,
        "standard": source.standard,
        "primary_source": source.primary_source,
        "court": "CT-DIGEST",
        "provenance": {
            "corpus": rel(src_path),
            "corpus_sha256": mirror_sha256,
            "authority": authority_id,
            "primary_source": source.primary_source,
            "note": (
                "Candidate-only construction verification: the primary source is named above, "
                "the bytes are mirrored through the pinned corpus (`corpus_sha256`), and the "
                "mirror's identity is fixed. This does NOT establish that the mirror is "
                "faithful to a primary source nobody in this repository has read. A CT pass "
                "is not formal validation. See D206."
            ),
        },
        "vectors": vectors,
    }
    if boundary_skipped:
        body["provenance"]["boundary_vectors_skipped"] = boundary_skipped
    doc = envelope(
        kind=f"{KIND_PREFIX}{source.algorithm}",
        generator=GENERATOR,
        inputs=[InputRef(name="authority-evp-vector-file", path=src_path)],
        body=body,
        authority=authority_id,
    )
    out = vector_dir / f"{source.algorithm}.json"
    write_json(out, doc)
    return {"algorithm": source.algorithm, "path": rel(out), "vectors": len(vectors),
            "skipped": skipped, "source": rel(src_path)}


def emit_all(authority_id: str, vector_dir: Path = VECTOR_DIR) -> list[dict]:
    auth_source = resolve_authority(authority_id).source
    vector_dir.mkdir(parents=True, exist_ok=True)
    return [_emit_one(s, auth_source, authority_id, vector_dir) for s in EMIT_SOURCES]


# The one cipher corpus this plane emits from. It is a plain keyed-block `evp_test` file: each
# block names a `Cipher`, and CBC/CFB/OFB blocks carry an `IV`. Only the constructions the
# candidate has a low-level arm for are emitted (`AES-{128,192,256}-{ECB,CBC,CFB,OFB}`); GCM
# and the other AEAD spellings are 8.3's and are skipped rather than half-modelled.
AES_CIPHER_SOURCE = "test/recipes/30-test_evp_data/evpciph_aes_common.txt"
RC4_CIPHER_SOURCE = "test/recipes/30-test_evp_data/evpciph_rc4.txt"
_AES_CIPHER_RE = re.compile(r"^AES-(128|192|256)-(ECB|CBC|CFB|OFB)$")


def _parse_cipher_blocks(text: str) -> list[dict]:
    """The keyed `Cipher =` blocks, each with the line its `Cipher` line sits on."""
    blocks: list[dict] = []
    cur: dict | None = None
    title = ""
    for lineno, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            if cur is not None:
                blocks.append(cur)
                cur = None
            continue
        if "=" not in s:
            continue
        key, _, value = s.partition("=")
        key = key.strip()
        value = value.strip()
        if key == "Title":
            title = value
        elif key == "Cipher":
            if cur is not None:
                blocks.append(cur)
            cur = {"cipher": value, "line": lineno, "title": title}
        elif cur is not None:
            cur[key.lower()] = value
    if cur is not None:
        blocks.append(cur)
    return blocks


def emit_ciphers(authority_id: str, vector_dir: Path = VECTOR_DIR) -> list[dict]:
    """Regenerate the cipher vector sets (`forensics/vectors/aes.json`, `rc4.json`)."""
    auth = resolve_authority(authority_id)
    src_path = auth.source / AES_CIPHER_SOURCE
    if not src_path.is_file():
        raise VectorError(f"correctness-vectors: {rel(src_path)} is absent")
    text = src_path.read_text(encoding="utf-8")
    mirror_sha256 = hashlib.sha256(src_path.read_bytes()).hexdigest()

    vectors: list[dict] = []
    n = 0
    for block in _parse_cipher_blocks(text):
        cipher = block.get("cipher", "")
        if not _AES_CIPHER_RE.match(cipher):
            continue
        needed = ("key", "plaintext", "ciphertext")
        if any(k not in block for k in needed):
            continue
        # `evp_test`'s default operation is ENCRYPT, and the SP 800-38A sections spell only
        # the encrypt direction for most blocks.
        operation = block.get("operation", "ENCRYPT").strip().upper()
        if operation not in ("ENCRYPT", "DECRYPT"):
            continue
        n += 1
        vectors.append({
            "id": f"aes-{cipher.lower()}-{n}",
            "cipher": cipher,
            "operation": operation,
            "key_hex": block["key"].lower(),
            "iv_hex": block.get("iv", "").lower(),
            "input_hex": block["plaintext"].lower(),
            "expected_hex": block["ciphertext"].lower(),
            "standard": "FIPS-197; NIST SP 800-38A",
            "provenance": {
                "primary_source": "FIPS-197; NIST SP 800-38A",
                "derivation": "corpus",
                "file": rel(src_path),
                "line": block["line"],
                "title": block.get("title", ""),
                "form": "keyed-block",
                "authority": authority_id,
                "mirror_sha256": mirror_sha256,
            },
        })

    # One independently-derived boundary: the empty message. No standard publishes a value for
    # an empty ECB/CBC input, and none is needed -- the construction emits nothing for no input
    # blocks -- so the oracle is the construction's own definition.
    empty_oracle = ("the construction's definition (FIPS-197 §5.1, SP 800-38A §6.1): an empty "
                    "message has no blocks and emits no bytes")
    for cipher in ("AES-128-ECB", "AES-128-CBC"):
        n += 1
        vectors.append({
            "id": f"aes-{cipher.lower()}-empty-{n}",
            "cipher": cipher,
            "operation": "ENCRYPT",
            "key_hex": "000102030405060708090a0b0c0d0e0f",
            "iv_hex": ("00000000000000000000000000000000"
                       if cipher.endswith("CBC") else ""),
            "input_hex": "",
            "expected_hex": "",
            "standard": "FIPS-197; NIST SP 800-38A",
            "provenance": {
                "primary_source": "UNKNOWN",
                "derivation": "independent",
                "label": "empty",
                "oracle": empty_oracle,
                "note": "the expected bytes are the construction's own answer, not a "
                        "published test value",
            },
        })

    body = {
        "algorithm": "aes",
        "court": "CT-CIPHER",
        "openssl_cipher": "AES-{128,192,256}-{ECB,CBC,CFB,OFB}",
        "standard": "FIPS-197; NIST SP 800-38A",
        "primary_source": "FIPS-197; NIST SP 800-38A",
        "provenance": {
            "corpus": rel(src_path),
            "corpus_sha256": mirror_sha256,
            "authority": authority_id,
            "primary_source": "FIPS-197; NIST SP 800-38A",
            "note": (
                "Candidate-only construction verification: the primary source is named, the "
                "bytes are mirrored through the pinned corpus (`corpus_sha256`), and the "
                "mirror's identity is fixed. This does NOT establish that the mirror is "
                "faithful to a primary source nobody here has read, and a CT pass is not "
                "formal validation. An independent implementation of AES is not present in "
                "the pinned court image (there is no `hashlib` for ciphers), so no cipher "
                "boundary can carry an independent oracle beyond the empty-message one, "
                "whose answer is the construction's own. See D208 on the same kind of "
                "recorded cost for `rhash`."
            ),
        },
        "vectors": vectors,
    }
    doc = envelope(
        kind=f"{CIPHER_KIND_PREFIX}aes",
        generator=GENERATOR,
        inputs=[InputRef(name="authority-evp-vector-file", path=src_path)],
        body=body,
        authority=authority_id,
    )
    out = vector_dir / "aes.json"
    write_json(out, doc)
    rows = [{"path": rel(out), "vectors": len(vectors), "source": rel(src_path)}]

    # RC4 is a stream cipher in the same corpus format: `Cipher = RC4`, a key, a plaintext and
    # a ciphertext, with no IV. It is emitted into its own set so the census is per cipher.
    rc4_path = auth.source / RC4_CIPHER_SOURCE
    if not rc4_path.is_file():
        raise VectorError(f"correctness-vectors: {rel(rc4_path)} is absent")
    rc4_text = rc4_path.read_text(encoding="utf-8")
    rc4_mirror = hashlib.sha256(rc4_path.read_bytes()).hexdigest()
    rc4_vectors: list[dict] = []
    n = 0
    for block in _parse_cipher_blocks(rc4_text):
        if block.get("cipher", "").strip().upper() != "RC4":
            continue
        if any(k not in block for k in ("key", "plaintext", "ciphertext")):
            continue
        n += 1
        rc4_vectors.append({
            "id": f"rc4-{n}",
            "cipher": "RC4",
            "operation": "ENCRYPT",
            "key_hex": block["key"].lower(),
            "iv_hex": "",
            "input_hex": block["plaintext"].lower(),
            "expected_hex": block["ciphertext"].lower(),
            "standard": "RC4 (as published in the sci.crypt posting OpenSSL transcribes)",
            "provenance": {
                "primary_source": "UNKNOWN",
                "derivation": "corpus",
                "file": rel(rc4_path),
                "line": block["line"],
                "title": block.get("title", ""),
                "form": "keyed-block",
                "authority": authority_id,
                "mirror_sha256": rc4_mirror,
            },
        })
    # The empty input is the one boundary whose answer needs no oracle: a stream cipher over
    # zero bytes emits zero bytes and leaves the state unadvanced.
    n += 1
    rc4_vectors.append({
        "id": f"rc4-empty-{n}",
        "cipher": "RC4",
        "operation": "ENCRYPT",
        "key_hex": "0123456789abcdef0123456789abcdef",
        "iv_hex": "",
        "input_hex": "",
        "expected_hex": "",
        "standard": "RC4",
        "provenance": {
            "primary_source": "UNKNOWN",
            "derivation": "independent",
            "label": "empty",
            "oracle": ("the construction's definition: RC4 over a zero-byte input emits no "
                       "bytes and leaves its state unchanged"),
            "note": "the expected bytes are the construction's own answer, not a published "
                    "test value",
        },
    })
    rc4_body = {
        "algorithm": "rc4",
        "court": "CT-CIPHER",
        "openssl_cipher": "RC4",
        "standard": "RC4",
        "primary_source": "UNKNOWN",
        "provenance": {
            "corpus": rel(rc4_path),
            "corpus_sha256": rc4_mirror,
            "authority": authority_id,
            "primary_source": "UNKNOWN",
            "note": (
                "Candidate-only construction verification. The primary source is recorded as "
                "UNKNOWN rather than guessed: the corpus's title is 'RC4 tests' and no standard "
                "publishes these bytes; the bytes are mirrored through the pinned corpus and "
                "their identity fixed. A CT pass is not OpenSSL parity and not formal "
                "validation. No independent RC4 oracle exists in the pinned court image, so "
                "only the empty-input boundary carries an independent oracle."
            ),
        },
        "vectors": rc4_vectors,
    }
    rc4_doc = envelope(
        kind=f"{CIPHER_KIND_PREFIX}rc4",
        generator=GENERATOR,
        inputs=[InputRef(name="authority-evp-vector-file", path=rc4_path)],
        body=rc4_body,
        authority=authority_id,
    )
    rc4_out = vector_dir / "rc4.json"
    write_json(rc4_out, rc4_doc)
    rows.append({"path": rel(rc4_out), "vectors": len(rc4_vectors),
                 "source": rel(rc4_path)})

    for family in CIPHER_RECIPE_FAMILIES:
        rows.append(_emit_recipe_family(authority_id, family, vector_dir))
    return rows


# The recipe-backed cipher families. Each is a plain keyed-block `evp_test` file whose blocks
# name a `Cipher`; only the spellings the low-level probe can drive are emitted (the `-CFB1`,
# `-CFB8` and `-CTS` spellings are bit- or construction-specific arms with their own entry
# points and are skipped rather than half-modelled). This list grows with the subphase, one
# entry per family commit.
class CipherRecipeFamily:
    def __init__(self, algorithm: str, source: str, cipher_re: str, standard: str,
                 openssl_cipher: str, independent_modes: tuple[str, ...],
                 empty_key_hex: str, empty_iv_hex: str, note: str | None = None,
                 aead: bool = False):
        self.algorithm = algorithm
        self.source = source
        self.cipher_re = re.compile(cipher_re)
        self.standard = standard
        self.openssl_cipher = openssl_cipher
        self.independent_modes = independent_modes
        self.empty_key_hex = empty_key_hex
        self.empty_iv_hex = empty_iv_hex
        self.note = note
        self.aead = aead


CIPHER_RECIPE_FAMILIES: list[CipherRecipeFamily] = [
    CipherRecipeFamily(
        "des", "test/recipes/30-test_evp_data/evpciph_des.txt",
        r"^DES-(ECB|CBC|CFB|OFB)$", "FIPS 46-3 / FIPS PUB 81",
        "DES-{ECB,CBC,CFB,OFB}", ("DES-ECB", "DES-CBC"),
        "133457799bbcdff1", "0000000000000000"),
    CipherRecipeFamily(
        "rc2", "test/recipes/30-test_evp_data/evpciph_rc2.txt",
        r"^RC2-(40-|64-)?(ECB|CBC|CFB|OFB)$", "RFC 2268",
        "RC2-{40-,64-,}{ECB,CBC,CFB,OFB}", ("RC2-ECB", "RC2-CBC"),
        "00000000000000000000000000000000", "0000000000000000"),
    CipherRecipeFamily(
        "bf", "test/recipes/30-test_evp_data/evpciph_bf.txt",
        r"^BF-(ECB|CBC|CFB|OFB)$", "Schneier's Blowfish (self-generated corpus)",
        "BF-{ECB,CBC,CFB,OFB}", ("BF-ECB", "BF-CBC"),
        "000102030405060708090a0b0c0d0e0f", "0000000000000000"),
    CipherRecipeFamily(
        "cast5", "test/recipes/30-test_evp_data/evpciph_cast5.txt",
        r"^CAST5-(ECB|CBC|CFB|OFB)$", "RFC 2144",
        "CAST5-{ECB,CBC,CFB,OFB}", ("CAST5-ECB", "CAST5-CBC"),
        "0123456712345678234567893456789a", "0000000000000000"),
    CipherRecipeFamily(
        "idea", "test/recipes/30-test_evp_data/evpciph_idea.txt",
        r"^IDEA-(ECB|CBC|CFB|OFB)$", "Ascom IDEA (Lai-Massey)",
        "IDEA-{ECB,CBC,CFB,OFB}", ("IDEA-ECB", "IDEA-CBC"),
        "00010002000300040005000600070008", "0000000000000000"),
    CipherRecipeFamily(
        "seed", "test/recipes/30-test_evp_data/evpciph_seed.txt",
        r"^SEED-(ECB|CBC|CFB|OFB)$", "RFC 4269 (KISA SEED)",
        "SEED-{ECB,CBC,CFB,OFB}", ("SEED-ECB", "SEED-CBC"),
        "00000000000000000000000000000000", "00000000000000000000000000000000"),
    CipherRecipeFamily(
        "camellia", "test/recipes/30-test_evp_data/evpciph_camellia.txt",
        r"^CAMELLIA-(128|192|256)-(ECB|CBC|CFB|OFB|CTR)$", "RFC 3713 (NTT Camellia)",
        "CAMELLIA-{128,192,256}-{ECB,CBC,CFB,OFB,CTR}",
        ("CAMELLIA-128-ECB", "CAMELLIA-128-CBC"),
        "0123456789abcdeffedcba9876543210", "00000000000000000000000000000000"),
    # 8.3 -- the key-wrap family. The `id-aes*-wrap` names are RFC 3394's and RFC 5649's own;
    # the corpus also carries alias spellings (`aes256-WRAP`, `ID-aes256-WRAP`) and the CAVP
    # `*-WRAP-INV` negative set, which are excluded by the regex rather than half-modelled. There
    # is no empty-input boundary: both constructions refuse a zero-length input, so the
    # independent-oracle list is empty and the note says why (D208: no oracle in the pinned image).
    CipherRecipeFamily(
        "wrap", "test/recipes/30-test_evp_data/evpciph_aes_wrap.txt",
        r"^id-aes(128|192|256)-wrap(-pad)?$", "RFC 3394; RFC 5649",
        "id-aes{128,192,256}-{wrap,wrap-pad}", (),
        "", "",
        note=(
            "Candidate-only construction verification: the primary sources are RFC 3394 (KW) "
            "and RFC 5649 (KWP), and the bytes are mirrored through the pinned corpus "
            "(`corpus_sha256`), whose identity is fixed. No independent key-wrap implementation "
            "is present in the pinned court image, so no boundary vector carries an independent "
            "oracle here: both constructions refuse a zero-length input and every legal input's "
            "output is already a published value. This is the recorded cost of D208, not an "
            "omission."
        )),
    # 8.3 -- GCM. The corpus is NIST SP 800-38D's own test cases plus the boringssl set; every
    # block carries an `AAD` and a `Tag`, and the probe's AEAD path prints the ciphertext, the
    # tag, and its own accept/reject answers, so a rejected tag is a committed expectation
    # rather than an unchecked claim. Only the encrypt direction is mirrored (an AEAD decrypt
    # vector's tag is an input, not an output). `aes-*-gcm` is matched case-sensitively, which
    # excludes the corpus's `AES-128-GcM` case-spelling test.
    CipherRecipeFamily(
        "gcm", "test/recipes/30-test_evp_data/evpciph_aes_common.txt",
        r"^aes-(128|192|256)-gcm$", "NIST SP 800-38D",
        "aes-{128,192,256}-gcm", (),
        "", "",
        note=(
            "Candidate-only construction verification: the primary source is NIST SP 800-38D, "
            "and the bytes are mirrored through the pinned corpus (`corpus_sha256`), whose "
            "identity is fixed. Every vector's expected tail is `accept || reject`, the "
            "probe's own tag-verification arms, so the reject path is checked on every vector "
            "rather than asserted once. No independent GCM implementation is present in the "
            "pinned court image, so no boundary vector carries an independent oracle beyond "
            "the corpus's own empty-plaintext, one-block and multi-block cases; that is the "
            "recorded cost of D208."
        ), aead=True),
    # 8.3 -- CCM. The corpus is NIST SP 800-38C's CAVS decryption-verification set, so its
    # negative blocks carry `Result = CIPHERUPDATE_ERROR` (skipped by the result-key rule) and
    # only the encrypt direction is mirrored. What remains covers every even tag length in
    # [4,16] and every L in [2,8], and every vector's expected tail is `accept || reject`.
    CipherRecipeFamily(
        "ccm", "test/recipes/30-test_evp_data/evpciph_aes_ccm_cavs.txt",
        r"^aes-(128|192|256)-ccm$", "NIST SP 800-38C; RFC 3610",
        "aes-{128,192,256}-ccm", (),
        "", "",
        note=(
            "Candidate-only construction verification: the primary sources are NIST SP 800-38C "
            "and RFC 3610, and the bytes are mirrored through the pinned corpus "
            "(`corpus_sha256`), whose identity is fixed. The corpus is the CAVS "
            "decryption-verification set, so its `Result = CIPHERUPDATE_ERROR` negative blocks "
            "are skipped by the result-key rule and every mirrored block is an encryption; each "
            "vector's expected tail is `accept || reject`, the probe's own tag-verification "
            "arms, so the reject path is a committed expectation on every vector. No "
            "independent CCM implementation is present in the pinned court image, so no "
            "boundary vector carries an independent oracle; that is the recorded cost of D208."
        ), aead=True),
    # 8.3 -- XTS. `evpciph_aes_common.txt`'s XTS section is IEEE Std 1619-2007's own vectors;
    # both directions are mirrored (a mode, not an AEAD, so a decrypt vector's output is the
    # plaintext). The two `Result = KEY_SET_ERROR` blocks are skipped by the result-key rule.
    CipherRecipeFamily(
        "xts", "test/recipes/30-test_evp_data/evpciph_aes_common.txt",
        r"^aes-(128|256)-xts$", "IEEE 1619-2007; NIST SP 800-38E",
        "aes-{128,256}-xts", (),
        "", ""),
    # 8.3 -- OCB. The corpus is RFC 7253's own AES-128 vectors: every block carries an `AAD`
    # (one is empty) and a `Tag`, and one block is the RFC's `Result = CIPHERFINAL_ERROR`
    # forgery, skipped by the result-key rule. The nonce length varies (the corpus uses 12 and
    # 15 octets) and the tag length is the vector's own, so `M` and the nonce are read from the
    # block rather than fixed.
    # 8.3 -- CTS. `AES-*-CBC-CTS` is three constructions under one name: CS1 is the NIST
    # variant, CS3 the Kerberos one, and CS2 is CS3 for a partial block and plain CBC for an
    # aligned one (`cipher_cts.c:33-46`). The corpus's `CTSMode` line chooses the variant, so
    # it is a vector field rather than a fixed family parameter, and the two blocks whose
    # aligned length makes CS1 and CS2 equal to CBC are the boundary that exercises it. The
    # `NextIV` line every block carries is the updated IV the authority leaves behind; this
    # driver's record has no field for it, so it is not compared.
    CipherRecipeFamily(
        "cts", "test/recipes/30-test_evp_data/evpciph_aes_cts.txt",
        r"^AES-(128|192|256)-CBC-CTS$", "NIST SP 800-38A Addendum (CS1/CS2); RFC 2040 (CS3)",
        "AES-{128,192,256}-CBC-CTS", (),
        "636869636b656e207465726979616b69", "00000000000000000000000000000000",
        note=(
            "Candidate-only construction verification: the primary sources are NIST SP 800-38A "
            "Addendum (CS1 and CS2) and RFC 2040's Kerberos variant (CS3), and the bytes are "
            "mirrored through the pinned corpus (`corpus_sha256`), whose identity is fixed. "
            "The `CTSMode` line selects the variant. No independent CTS implementation is "
            "present in the pinned court image, so no boundary vector carries an independent "
            "oracle beyond the aligned-length CS1/CS2 blocks, which the standard defines as "
            "plain CBC; that is the recorded cost of D208."
        )),
]


def _emit_recipe_family(authority_id: str, family: CipherRecipeFamily,
                        vector_dir: Path) -> dict:
    """Mirror one recipe file's keyed blocks into a cipher vector set."""
    auth = resolve_authority(authority_id)
    src_path = auth.source / family.source
    if not src_path.is_file():
        raise VectorError(f"correctness-vectors: {rel(src_path)} is absent")
    text = src_path.read_text(encoding="utf-8")
    mirror = hashlib.sha256(src_path.read_bytes()).hexdigest()

    vectors: list[dict] = []
    n = 0
    skipped = 0
    for block in _parse_cipher_blocks(text):
        cipher = block.get("cipher", "")
        if not family.cipher_re.match(cipher):
            continue
        if any(k not in block for k in ("key", "plaintext", "ciphertext")):
            continue
        if "result" in block:
            # A block that names an expected error result is a *rejection* test; this driver's
            # record models outputs, not diagnostics, so it is skipped rather than recorded as
            # a value the probe cannot produce. `RT-CIPHER` observes the refusal arms directly.
            skipped += 1
            continue
        if family.aead and block.get("operation", "ENCRYPT").strip().upper() == "DECRYPT":
            # An AEAD decrypt vector's expected value is the plaintext and its tag is an
            # input to be verified, not an output; the driver's record has one output field,
            # so only the encrypt direction is mirrored. The reject arm is exercised by the
            # probe's own accept/reject self-check (see below) and by `RT-CIPHER`.
            skipped += 1
            continue
        if family.aead and "tag" not in block:
            skipped += 1
            continue
        if "keybits" in block:
            # The effective-key-bits parameter is an observable, but this driver's record has no
            # field for it; `RT-CIPHER` compares the 40/64/128 schedules directly instead.
            skipped += 1
            continue
        operation = block.get("operation", "ENCRYPT").strip().upper()
        if operation == "DECRYPT":
            input_hex, expected_hex = block["ciphertext"].lower(), block["plaintext"].lower()
        else:
            operation = "ENCRYPT"
            input_hex, expected_hex = block["plaintext"].lower(), block["ciphertext"].lower()
        n += 1
        vec = {
            "id": f"{family.algorithm}-{n}",
            "cipher": cipher,
            "operation": operation,
            "key_hex": block["key"].lower(),
            "iv_hex": block.get("iv", "").lower(),
            "input_hex": input_hex,
            "expected_hex": expected_hex,
            "aad_hex": block.get("aad", "").lower(),
            "tag_hex": block.get("tag", "").lower(),
            "standard": family.standard,
            "provenance": {
                "primary_source": family.standard,
                "derivation": "corpus",
                "file": rel(src_path),
                "line": block["line"],
                "title": block.get("title", ""),
                "form": "keyed-block",
                "authority": authority_id,
                "mirror_sha256": mirror,
            },
        }
        # Only the CTS families carry a variant, so a family without one keeps its committed
        # files byte-identical rather than growing an empty field on every vector.
        ctsmode = block.get("ctsmode", "").strip().upper()
        if ctsmode:
            vec["ctsmode"] = ctsmode
        vectors.append(vec)

    # One independently-derived boundary per family: the empty message. No standard publishes
    # a value for an empty input, and none is needed -- a block cipher over zero blocks emits
    # nothing, and a feedback mode over zero bytes emits nothing and leaves the IV untouched.
    empty_oracle = ("the construction's definition: a block or feedback mode over a zero-byte "
                    "input emits no bytes")
    for cipher in family.independent_modes:
        n += 1
        vectors.append({
            "id": f"{family.algorithm}-{cipher.lower()}-empty-{n}",
            "cipher": cipher,
            "operation": "ENCRYPT",
            "key_hex": family.empty_key_hex,
            "iv_hex": family.empty_iv_hex if (cipher.endswith("CBC") or cipher.endswith("CTS"))
                     else "",
            "input_hex": "",
            "expected_hex": "",
            "standard": family.standard,
            "provenance": {
                "primary_source": "UNKNOWN",
                "derivation": "independent",
                "label": "empty",
                "oracle": empty_oracle,
                "note": "the expected bytes are the construction's own answer, not a "
                        "published test value",
            },
        })

    body = {
        "algorithm": family.algorithm,
        "court": "CT-CIPHER",
        "openssl_cipher": family.openssl_cipher,
        "standard": family.standard,
        "primary_source": family.standard,
        "provenance": {
            "corpus": rel(src_path),
            "corpus_sha256": mirror,
            "authority": authority_id,
            "primary_source": family.standard,
            "note": (
                family.note if family.note is not None else
                "Candidate-only construction verification: the primary source is named, the "
                "bytes are mirrored through the pinned corpus (`corpus_sha256`), and the "
                "mirror's identity is fixed. This does NOT establish that the mirror is "
                "faithful to a primary source nobody here has read, and a CT pass is not "
                "formal validation. No independent implementation of this cipher is present "
                "in the pinned court image, so only the empty-input boundary carries an "
                "independent oracle, whose answer is the construction's own (D211/D215)."
            ),
        },
        "vectors": vectors,
    }
    doc = envelope(kind=f"{CIPHER_KIND_PREFIX}{family.algorithm}", generator=GENERATOR,
                   inputs=[InputRef(name="authority-evp-vector-file", path=src_path)],
                   body=body, authority=authority_id)
    out = vector_dir / f"{family.algorithm}.json"
    write_json(out, doc)
    return {"path": rel(out), "vectors": len(vectors), "skipped": skipped,
            "source": rel(src_path)}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def self_check(vector_dir: Path = VECTOR_DIR) -> int:
    """Compare each oracle against the primary-source values the pinned corpus mirrors.

    The boundary vectors' expected bytes are the oracle's answers, so the oracle itself is the
    thing to check. For the algorithms `hashlib` carries, every corpus vector is recomputed and
    compared; for MD4 and Whirlpool the committed `rhash` table is compared wherever a corpus
    vector's input is one the table also holds. A corpus vector with no oracle is reported as
    UNVERIFIED -- not a failure, because the standards' published values are the corpus's own
    and the mirror's sha256 already fixes them.
    """
    checked = 0
    unverified = 0
    findings: list[str] = []
    boundary_by_input = {data.hex(): label for label, data in BOUNDARY_INPUTS}
    for vs in load_all(vector_dir):
        name = _HASHLIB_NAMES.get(vs.algorithm)
        table = _REFERENCE_DIGESTS.get(vs.algorithm)
        for v in vs.vectors:
            if v.provenance.get("derivation") != "corpus":
                continue
            repeated = v.input
            is_repeat = False
            for mode in v.modes:
                if mode.startswith("count:"):
                    repeated = repeated * int(mode[6:])
                    is_repeat = True
            if name is not None:
                actual = hashlib.new(name, repeated).digest()
                checked += 1
            elif not is_repeat and table is not None and v.input.hex() in boundary_by_input:
                actual = bytes.fromhex(table[boundary_by_input[v.input.hex()]])
                checked += 1
            else:
                unverified += 1
                continue
            if actual != v.expected:
                findings.append(
                    f"{vs.algorithm} {v.id}: oracle {actual.hex()} != corpus "
                    f"{v.expected.hex()}"
                )
    for finding in findings:
        print(f"  SELF-CHECK MISMATCH {finding}")
    print(f"  oracle self-check: {checked} corpus vectors verified, {unverified} unverified "
          f"(no oracle), {len(findings)} mismatch(es)")
    return 1 if findings else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--emit", action="store_true",
                    help="regenerate forensics/vectors/*.json from the pinned authority tree")
    ap.add_argument("--emit-ciphers", action="store_true",
                    help="regenerate forensics/vectors/aes.json from the pinned cipher corpus")
    ap.add_argument("--list", action="store_true",
                    help="list the committed vector sets and their vector counts")
    ap.add_argument("--self-check", action="store_true",
                    help="check each boundary oracle against the corpus's published values")
    ap.add_argument("--algorithm", action="append", default=None,
                    help="(with the default mode) run one court over these algorithms")
    ap.add_argument("--candidate", default=str(CANDIDATE_DIR),
                    help="candidate distribution shell directory")
    ap.add_argument("--work-dir", default=str(REPO_ROOT / "court" / "phase8"))
    args = ap.parse_args(argv)

    if args.emit:
        for row in emit_all(args.authority):
            skipped = row.get("skipped", 0)
            print(f"  emitted {row['path']:<40} {row['vectors']:>3} vectors "
                  + (f"({skipped} skipped: non-default output length) " if skipped else "")
                  + f"from {row['source']}")
        return 0

    if args.emit_ciphers:
        for row in emit_ciphers(args.authority):
            print(f"  emitted {row['path']:<40} {row['vectors']:>3} vectors from {row['source']}")
        return 0

    if args.self_check:
        return self_check()

    if args.list:
        for vs in load_all():
            calls = sum(len(v.modes) for v in vs.vectors)
            print(f"  {vs.algorithm:<10} {len(vs.vectors):>3} vectors  {calls:>3} calls  "
                  f"{vs.standard:<24} {rel(vs.path)}")
        return 0

    algorithms = tuple(args.algorithm) if args.algorithm else tuple(
        s.algorithm for s in load_all())
    record = run_court(
        "CT-DIGEST", algorithms,
        candidate_dir=Path(args.candidate),
        work_dir=Path(args.work_dir),
        authority_id=args.authority,
    )
    if "vectors_checked" not in record:
        print(f"  CT-DIGEST: FAIL stage={record.get('stage')}")
        detail = record.get("detail")
        if isinstance(detail, dict):
            for line in detail.get("stderr", []):
                print(f"    {line}")
            if detail.get("exit_code") is not None:
                print(f"    exit_code={detail['exit_code']}")
        elif detail:
            for line in detail:
                print(f"    {line}")
        if record.get("needs"):
            print(f"    needs: {record['needs']}")
        return 1
    print(f"  CT-DIGEST: {record['vectors_passed']}/{record['vectors_checked']} "
          f"vectors, {record['calls_checked']} calls, verdict={record['verdict']}")
    for failure in record.get("failures", []):
        print(f"    FAIL {failure['algorithm']} {failure['id']} mode={failure['mode']}")
        print(f"      input    = {failure['input_hex'] or '<empty>'}")
        print(f"      expected = {failure['expected_hex']}")
        print(f"      actual   = {failure['actual_hex'] or failure['probe_detail']}")
    if record["verdict"] != "pass":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
