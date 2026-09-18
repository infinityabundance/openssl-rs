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
  artifacts/phase8/COURTS.json           (the `CT-*` records, via `phase8_courts.py`)

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
import hashlib
import json
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

# `rhash`'s own name for the two constructions it supplies, for the provenance string.
_REFERENCE_ORACLE = "rhash (independent implementation, neither the crate nor the authority build)"
_HASHLIB_ORACLE = "hashlib (Python standard library)"


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
    table = _REFERENCE_DIGESTS.get(algorithm)
    if table is not None and label in table:
        return bytes.fromhex(table[label]), _REFERENCE_ORACLE
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
    return [load_vector_set(p) for p in paths]


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
        "algorithms": per_algorithm,
        "results": results,
        "failures": failures,
        "stage": "vector-mismatch" if failures else "compare",
        "verdict": "pass" if not failures else "fail",
        "claim": (
            "A correctness-vector PASS means candidate-only construction verification: the "
            "candidate's construction produced the committed expected bytes for every "
            "vector and every update mode, where the vectors are standard-derived values "
            "mirrored in the pinned OpenSSL test corpus. It is NOT OpenSSL parity: the "
            "corpus does not contain the authority's observable behaviour, and that is "
            "RT-DIGEST's question. It is NOT independent cryptographic validation and NOT "
            "formal validation: the vectors are the standards' published values, and "
            "published test vectors are informal verification, not a certificate. NIST CAVP "
            "and Project Wycheproof are corpora this plane does NOT use; they are recorded as "
            "declined-with-reason in correctness_vectors.py's header. See docs/DECISIONS.md "
            "D201 and docs/PHASE-8-SUBPHASES.md."
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

    # (1) The single-message corpus vectors, as before.
    for title, digest_line, fields in _parse_evpmd(text):
        if fields["Digest"].upper() != wanted:
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
    for label, data in BOUNDARY_INPUTS:
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
        vectors.append({
            "id": f"{source.algorithm}-boundary-{label}",
            "standard": source.standard,
            "input_hex": data.hex(),
            "expected_hex": expected.hex(),
            "modes": list(BOUNDARY_MODES),
            "provenance": {
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
            },
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
            "source": rel(src_path)}


def emit_all(authority_id: str, vector_dir: Path = VECTOR_DIR) -> list[dict]:
    auth_source = resolve_authority(authority_id).source
    vector_dir.mkdir(parents=True, exist_ok=True)
    return [_emit_one(s, auth_source, authority_id, vector_dir) for s in EMIT_SOURCES]


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
            print(f"  emitted {row['path']:<40} {row['vectors']:>3} vectors "
                  f"from {row['source']}")
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
