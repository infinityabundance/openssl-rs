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
    source_file: str


EMIT_SOURCES: tuple[EmitSource, ...] = (
    EmitSource("md4", "MD4", 16, "RFC 1320 (MD4) §A.5",
               "test/recipes/30-test_evp_data/evpmd_md.txt"),
    EmitSource("md5", "MD5", 16, "RFC 1321 (MD5) §A.5",
               "test/recipes/30-test_evp_data/evpmd_md.txt"),
    EmitSource("ripemd160", "RIPEMD160", 20, "ISO/IEC 10118-3 (RIPEMD-160)",
               "test/recipes/30-test_evp_data/evpmd_ripemd.txt"),
    EmitSource("sha1", "SHA1", 20, "FIPS 180-4; RFC 6234 §8.5",
               "test/recipes/30-test_evp_data/evpmd_sha.txt"),
    EmitSource("sha224", "SHA224", 28, "FIPS 180-4; RFC 6234 §8.5",
               "test/recipes/30-test_evp_data/evpmd_sha.txt"),
    EmitSource("sha256", "SHA256", 32, "FIPS 180-4; RFC 6234 §8.5",
               "test/recipes/30-test_evp_data/evpmd_sha.txt"),
    EmitSource("sha384", "SHA384", 48, "FIPS 180-4; RFC 6234 §8.5",
               "test/recipes/30-test_evp_data/evpmd_sha.txt"),
    EmitSource("sha512", "SHA512", 64, "FIPS 180-4; RFC 6234 §8.5",
               "test/recipes/30-test_evp_data/evpmd_sha.txt"),
    EmitSource("whirlpool", "WHIRLPOOL", 64, "ISO/IEC 10118-3 (Whirlpool)",
               "test/recipes/30-test_evp_data/evpmd_whirlpool.txt"),
)


# ---------------------------------------------------------------------------
# Committed vectors: loading and validation
# ---------------------------------------------------------------------------

@dataclass
class Vector:
    id: str
    standard: str
    input: bytes
    expected: bytes
    provenance: dict


@dataclass
class VectorSet:
    path: Path
    algorithm: str
    openssl_digest: str
    digest_bytes: int
    standard: str
    provenance: dict
    vectors: list[Vector] = field(default_factory=list)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VectorError(f"correctness-vectors: {message}")


def load_vector_set(path: Path) -> VectorSet:
    """Load one committed vector file, validating the envelope and every vector.

    A malformed file is a hard failure rather than a skipped corpus: a vector set that is not
    quite readable is exactly the way a court would quietly stop checking something.
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
        _require(isinstance(provenance, dict) and provenance.get("file")
                 and provenance.get("line") is not None,
                 f"{where}: provenance must name the source file and line")
        try:
            input_bytes = bytes.fromhex(input_hex)
            expected = bytes.fromhex(expected_hex)
        except ValueError as exc:
            raise VectorError(f"{where}: not hex ({exc})") from exc
        vectors.append(Vector(vid, v_standard, input_bytes, expected, provenance))

    return VectorSet(path=path, algorithm=algorithm, openssl_digest=openssl_digest,
                     digest_bytes=digest_bytes, standard=standard,
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

    calls: list[tuple[int, str, bytes]] = []
    index_of: dict[int, tuple[VectorSet, Vector]] = {}
    next_index = 0
    for vs in sets:
        for v in vs.vectors:
            calls.append((next_index, vs.algorithm, v.input))
            index_of[next_index] = (vs, v)
            next_index += 1

    work_dir.mkdir(parents=True, exist_ok=True)
    call_path = work_dir / f"{name.lower()}.calls.tsv"
    call_path.write_text(
        "".join(f"{i}\t{algo}\t{data.hex()}\n" for i, algo, data in calls),
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
    passed = 0
    failures: list[dict] = []
    results: list[dict] = []
    per_algorithm: dict[str, dict] = {}
    for vs in sets:
        per_algorithm[vs.algorithm] = {
            "standard": vs.standard, "source": rel(vs.path),
            "digest_bytes": vs.digest_bytes, "total": len(vs.vectors),
            "passed": 0, "failed": 0,
        }

    for index, (vs, v) in index_of.items():
        total += 1
        summary = per_algorithm[vs.algorithm]
        status, value = produced.get(index, ("err", "no-result-line"))
        ok = status == "ok" and value == v.expected.hex()
        results.append({
            "algorithm": vs.algorithm,
            "id": v.id,
            "passed": ok,
            "input_hex": v.input.hex(),
            "expected_hex": v.expected.hex(),
            "actual_hex": value if status == "ok" else None,
        })
        if ok:
            passed += 1
            summary["passed"] += 1
            continue
        summary["failed"] += 1
        failures.append({
            "algorithm": vs.algorithm,
            "id": v.id,
            "standard": v.standard,
            "input_hex": v.input.hex(),
            "expected_hex": v.expected.hex(),
            "actual_hex": value if status == "ok" else None,
            "probe_status": status,
            "probe_detail": None if status == "ok" else value,
            "provenance": v.provenance,
        })

    return {
        "court": name,
        "plane": "correctness",
        "kind": "construction-vectors",
        "probe": rel(probe),
        "candidate_shared_object": rel(candidate_dir / "libcrypto.so.3"),
        "authority": authority_id,
        "vectors_checked": total,
        "vectors_passed": passed,
        "vectors_failed": total - passed,
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


def _parse_evpmd(text: str) -> list[tuple[str, int, dict[str, str]]]:
    """Split an `evp_test` data file into (title, digest-line, fields) records.

    Only blocks that carry a `Digest`, an `Input` and an `Output` and **no** `Ncopy`/`Count`
    are returned: the repeated-count vectors are a streaming/`Count` behaviour rather than a
    single message, and CT-DIGEST is checking the construction over one message.
    """
    records: list[tuple[str, int, dict[str, str]]] = []
    title = ""
    block: list[tuple[int, str]] = []

    def flush() -> None:
        nonlocal block
        if not block:
            return
        fields: dict[str, str] = {}
        digest_line = 0
        for lineno, line in block:
            key, sep, value = line.partition("=")
            if not sep:
                continue
            key = key.strip()
            value = value.strip()
            if key == "Digest":
                digest_line = lineno
            fields[key] = value
        if ("Digest" in fields and "Input" in fields and "Output" in fields
                and "Ncopy" not in fields and "Count" not in fields):
            records.append((title, digest_line, fields))
        block = []

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line == "":
            flush()
            continue
        if line.startswith("#"):
            continue
        if line.startswith("Title"):
            _, _, value = line.partition("=")
            title = value.strip()
            block = []
            continue
        block.append((lineno, line))
    flush()
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

    vectors: list[dict] = []
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
            "provenance": {
                "file": rel(src_path),
                "line": digest_line,
                "title": title,
                "form": form,
                "authority": authority_id,
            },
        })

    if not vectors:
        raise VectorError(
            f"correctness-vectors: no {source.openssl_digest} vectors found in "
            f"{rel(src_path)}"
        )

    body = {
        "algorithm": source.algorithm,
        "openssl_digest": source.openssl_digest,
        "digest_bytes": source.digest_bytes,
        "standard": source.standard,
        "court": "CT-DIGEST",
        "provenance": {
            "corpus": rel(src_path),
            "authority": authority_id,
            "note": ("Extracted from the pinned authority's own test data with "
                     "`correctness_vectors.py --emit`; the bytes and the expected digest are "
                     "verbatim from that file. A CT pass is not formal validation."),
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

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--emit", action="store_true",
                    help="regenerate forensics/vectors/*.json from the pinned authority tree")
    ap.add_argument("--list", action="store_true",
                    help="list the committed vector sets and their vector counts")
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

    if args.list:
        for vs in load_all():
            print(f"  {vs.algorithm:<10} {len(vs.vectors):>3} vectors  "
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
          f"vectors passed, verdict={record['verdict']}")
    for failure in record.get("failures", []):
        print(f"    FAIL {failure['algorithm']} {failure['id']}")
        print(f"      input    = {failure['input_hex'] or '<empty>'}")
        print(f"      expected = {failure['expected_hex']}")
        print(f"      actual   = {failure['actual_hex'] or failure['probe_detail']}")
    if record["verdict"] != "pass":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
