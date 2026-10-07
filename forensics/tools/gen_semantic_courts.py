#!/usr/bin/env python3
"""openssl-rs — the semantic multitrack courts' evidence (Phase 23.8).

Phase 23.8 is the **semantic multitrack courts** (`docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 2,
row 23.8): the oracle-to-oracle (authority A vs authority B) and candidate-to-authority courts, with
side-specific adapters that emit the **same normalized observation vocabulary**, so the two sides of
a comparison are read the same way and a comparison is a comparison rather than a translation.

What this tool does, in two tiers
---------------------------------
  * **`--measure`** runs *only* in the court container, where both admitted authorities are built.
    It compiles `courts/phase23/semantic_probe.c` twice — once against each authority's own prefix —
    runs each binary, and captures the **raw transcript** (stdout, stderr and exit code) of each
    side. It then derives the normalized observation rows from those raw bytes and writes
    `forensics/multitrack/semantic-courts.json`. The raw transcripts are stored *in* the artefact,
    so the normalization can be re-derived and a difference the vocabulary would have erased stays
    visible in the bytes it was read from.

  * **the default run** is what the court and `regen_all.sh` drive: it reads the committed artefact,
    re-derives every normalized observation from the **preserved raw transcript** through the same
    adapter, re-classifies every difference against the committed 23.6 delta engine, and rewrites the
    artefact. It needs no compiler and no authority prefix, so the committed artefact cannot drift
    from the raw evidence it carries.

The vocabulary, the adapters, and what they must not do
-------------------------------------------------------
Every observation is the line `OBS <key>=<value>` on **both** sides. Where an API is identical the
same probe text is read on both sides, so the readings are directly comparable. Where a declaration
differs across the pair — `SSL_VALUE_QUIC_MAX_PENDING_CONNS` and
`X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH` are public in 3.6.4 and absent from 3.6.3 — the probe
carries a side-specific `#ifdef` adapter that emits the **same key** on both sides, with the value on
the side that declares it and the literal `<absent>` on the side that does not. The adapter therefore
*normalizes the shape* and *preserves the difference*: an adapter that mapped both sides to the same
reading would erase the difference under investigation, and the court refuses exactly that
(`semantic_court_findings`).

Every authority-to-authority difference is classified as a **release delta** and tied to the 23.6
delta engine where the engine carries the same entity: the observation names the fine delta dimension
and the entity id the engine keys its row by, and the court requires the named row to resolve in the
committed `forensics/deltas/openssl-3.6.3--openssl-3.6.4.json`, or — for an `error_behavior` reading,
the dimension the engine records *absent* with its reason — requires the absent dimension to be named
there. A difference the vocabulary cannot classify is refused rather than read plausibly.

Honest unavailability
---------------------
A pair that cannot be executed in this venue is recorded `not_run` with its reason and is never
counted as passing. The 0.9.8zh authority is built in the separate **historical** venue
(`docs/REPRODUCIBILITY.md` sections 1.1 and 1.2); its installed prefix is a historical-venue product
and its pre-3.0 headers are not compile-compatible with the 3.6.4 probe, so it is not run here.

Outputs
-------
  forensics/multitrack/semantic-courts.json   the normalized observations, their raw transcripts, the
                                              classified release deltas, the candidate-to-authority
                                              disposition and the not-run list

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    HISTORICAL_AUTHORITY,
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    rel,
    resolve_authority,
    sha256_file,
    write_json,
)

GENERATOR = "forensics/tools/gen_semantic_courts.py"
PROBE = REPO_ROOT / "courts" / "phase23" / "semantic_probe.c"
OUT = REPO_ROOT / "forensics" / "multitrack" / "semantic-courts.json"
DELTA = REPO_ROOT / "forensics" / "deltas" / "openssl-3.6.3--openssl-3.6.4.json"
BUILD_RECORDS = REPO_ROOT / "forensics" / "atlas" / "BUILD_RECORDS.json"
SCRATCH = REPO_ROOT / "court" / "phase23"
AUTH_ROOT = REPO_ROOT / "forensics" / "authorities"

AUTHORITY_A = HISTORICAL_AUTHORITY        # openssl-3.6.3-historical
AUTHORITY_B = PRODUCTION_AUTHORITY        # openssl-3.6.4-production

# The one venue marker: `--measure` refuses anywhere but the court container, exactly as
# `historical_build.py` refuses without the historical venue's marker.
COURT_MARKER = Path("/.dockerenv")

# The literal `<absent>` the probe emits for a declaration a side does not carry, or a behaviour it
# could not observe: it is a reading the probe wrote, not a sentinel this module substitutes.

# The shared normalized observation vocabulary: every key the probe emits on **both** sides, the
# coarse compatibility dimension it is about, the semantic class a divergence is, and the tie to the
# 23.6 delta engine. `delta` is the `(fine_dimension, entity_id)` the engine keys a row by, or None
# where the engine carries no row for the entity. `absent_dimension` names a 23.6 `absent_dimensions`
# entry the reading is the behavioural evidence for. `divergent` is the class a difference takes; a
# key whose sides should always agree has no `divergent` and a difference falls back to
# `behaviour_changed` (which the court requires to be corroborated, so a silent fallback is a finding,
# not a free pass).
def _spec(dimension: str, *, divergent: str | None = None,
          delta: tuple[str, str] | None = None,
          absent_dimension: str | None = None,
          non_claim: str | None = None) -> dict:
    return {"dimension": dimension, "divergent": divergent, "delta": delta,
            "absent_dimension": absent_dimension, "non_claim": non_claim}


OBSERVATION_SPECS: dict[str, dict] = {
    # version reporting: the release identity the oracle-version trajectory is about. The runtime
    # number and banner differ because the version-stamp macros changed, so both are tied to the
    # macro the engine keys the movement by.
    "version.patch": _spec("source_api", divergent="release_identity",
                           delta=("macro_value", "macro:OPENSSL_VERSION_PATCH")),
    "version.number": _spec("source_api", divergent="release_identity",
                            delta=("macro_value", "macro:OPENSSL_VERSION_PATCH"),
                            non_claim="a version number is not a compatibility claim"),
    "version.str": _spec("source_api", divergent="release_identity",
                         delta=("macro_value", "macro:OPENSSL_VERSION_STR")),
    "version.full": _spec("source_api", divergent="release_identity",
                          delta=("macro_value", "macro:OPENSSL_FULL_VERSION_STR")),
    "version.release_date": _spec("source_api", divergent="release_identity",
                                  delta=("macro_value", "macro:OPENSSL_RELEASE_DATE")),
    "version.text.macro": _spec("source_api", divergent="release_identity",
                                delta=("macro_value", "macro:OPENSSL_VERSION_TEXT")),
    "version.text.runtime": _spec("source_api", divergent="release_identity",
                                  delta=("macro_value", "macro:OPENSSL_VERSION_TEXT")),
    # presence adapters: a declaration public in one authority and absent from the other. The
    # difference is preserved as `<absent>` on the side that lacks it.
    "presence.SSL_VALUE_QUIC_MAX_PENDING_CONNS": _spec(
        "source_api", divergent="declaration_added",
        delta=("api_presence", "macro:SSL_VALUE_QUIC_MAX_PENDING_CONNS")),
    "presence.X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH": _spec(
        "source_api", divergent="declaration_added",
        delta=("api_presence", "macro:X509_R_CRL_SIGNATURE_ALGORITHM_MISMATCH")),
    # error behaviour: the dimension the 23.6 engine records `absent` with its reason, for which
    # this court supplies the behavioural reading.
    "error.reason.CRL_SIGNATURE_ALGORITHM_MISMATCH": _spec(
        "error", divergent="declaration_added", absent_dimension="error_behavior"),
    "error.reason.MALLOC_FAILURE": _spec(
        "error", divergent="behaviour_changed", absent_dimension="error_behavior"),
    # identical APIs: the same probe on both sides, expected to agree.
    "const.EVP_MAX_MD_SIZE": _spec("source_api"),
    "const.SHA256_DIGEST_LENGTH": _spec("source_api"),
    "const.TLS1_3_VERSION": _spec("source_api"),
    "const.X509_V_OK": _spec("source_api"),
    "behaviour.EVP_sha256": _spec("semantic"),
    # behaviours of exported symbols the 23.6 engine records as a machine-code-size movement: the
    # reading is expected to agree, which corroborates the engine's implementation-size adjudication.
    "behaviour.OSSL_parse_url": _spec("abi", divergent="behaviour_changed",
                                      delta=("abi_symbol_presence", "function:OSSL_parse_url")),
    "behaviour.BN_uadd": _spec("abi", divergent="behaviour_changed",
                               delta=("abi_symbol_presence", "function:BN_uadd")),
    "behaviour.BN_ucmp": _spec("abi", divergent="behaviour_changed",
                               delta=("abi_symbol_presence", "function:BN_ucmp")),
    "behaviour.OPENSSL_uni2utf8": _spec(
        "semantic", divergent="behaviour_changed",
        delta=("abi_symbol_presence", "function:OPENSSL_uni2utf8")),
}

# The 23.6 delta file's fine dimensions and the coarse compatibility dimension each maps onto. Read
# here rather than restated so a reading's coarse dimension cannot drift from the engine's.
DELTA_DIMENSION_TO_COARSE = {
    "api_presence": "source_api",
    "macro_value": "source_api",
    "abi_symbol_presence": "abi",
}


def read_json(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"gen-semantic-courts: {rel(path)} is absent")
    return json.loads(path.read_text(encoding="utf-8"))


def _body(doc: dict) -> dict:
    return doc.get("body", doc)


def parse_transcript(text: str) -> dict[str, str]:
    """`{key: value}` for every `OBS key=value` line of a raw transcript.

    The first occurrence of a key wins, so a probe that emitted a key twice would not silently
    overwrite the first reading with the second. A key with no `=` is not an observation.
    """
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line.startswith("OBS "):
            continue
        key, sep, value = line[len("OBS "):].partition("=")
        if sep and key not in out:
            out[key] = value
    return out


# --------------------------------------------------------------------------------------------
# the 23.6 delta engine index, so a reading is tied to the engine's own row rather than restated
# --------------------------------------------------------------------------------------------

def delta_index(body: dict) -> dict[tuple[str, str], dict]:
    """`{(fine_dimension, entity_id): row}` for the committed edge delta.

    Rows live under `receipts[].{added,removed,changed}`, each a list of directed, evidence-bearing
    rows. The index is built from that engine's own output, so a court that resolves a reading
    against it is checking the engine rather than a second list.
    """
    index: dict[tuple[str, str], dict] = {}
    for receipt in body.get("receipts") or []:
        for bucket in ("added", "removed", "changed"):
            for row in receipt.get(bucket) or []:
                dim = row.get("dimension")
                eid = row.get("entity_id")
                if dim and eid and (dim, eid) not in index:
                    index[(dim, eid)] = row
    return index


def _delta_reference(spec: dict) -> dict | None:
    if spec.get("delta") is None:
        return None
    fine, entity = spec["delta"]
    return {"dimension": fine, "entity_id": entity, "delta_file": rel(DELTA),
            "compat_dimension": DELTA_DIMENSION_TO_COARSE.get(fine, spec["dimension"])}


# --------------------------------------------------------------------------------------------
# the normalized observation vocabulary: derived from the raw transcripts, never typed beside them
# --------------------------------------------------------------------------------------------

def derive_observations(raw: dict, delta: dict) -> list[dict]:
    """Every normalized observation, re-derived from the **preserved raw transcripts**.

    A pure function of the raw bytes and the 23.6 delta body. Both sides are read through the same
    parser, so the vocabulary is shared by construction; where the readings differ, the difference is
    classified from the spec and tied to the engine's own row (or to the engine's named absent
    dimension). The raw value is never rewritten: `<absent>` is a reading the side genuinely emitted,
    and an unobserved key is `<missing>`, which the court refuses.
    """
    pa = parse_transcript(raw["authority_a"]["stdout"])
    pb = parse_transcript(raw["authority_b"]["stdout"])
    index = delta_index(delta)
    rows: list[dict] = []
    for key in sorted(OBSERVATION_SPECS):
        spec = OBSERVATION_SPECS[key]
        va = pa.get(key, "<missing>")
        vb = pb.get(key, "<missing>")
        agreement = va == vb
        if agreement:
            classification = "agreed"
        else:
            classification = spec["divergent"] or "behaviour_changed"
        rec: dict = {
            "observation_id": "SO-" + key,
            "vocabulary": key,
            "dimension": spec["dimension"],
            "authority_a": raw["authority_a"]["authority_id"],
            "authority_b": raw["authority_b"]["authority_id"],
            "observed_a": va,
            "observed_b": vb,
            "agreement": agreement,
            "classification": classification,
            "release_delta": None,
            "absent_dimension": spec.get("absent_dimension"),
            "evidence": ["forensics/multitrack/semantic-courts.json#raw_transcripts"],
            "adjudication": _adjudication(spec, va, vb, agreement, index),
        }
        ref = _delta_reference(spec)
        if ref is not None:
            rec["release_delta"] = ref
        if spec.get("non_claim"):
            rec["non_claims"] = [spec["non_claim"]]
        if not agreement and ref is not None:
            row = index.get(spec["delta"])
            if row is not None:
                rec["release_delta"] = {**ref, "classification": row.get("classification"),
                                        "facet": row.get("facet"),
                                        "adjudication": row.get("adjudication")}
        rows.append(rec)
    return rows


def _adjudication(spec: dict, va: str, vb: str, agreement: bool,
                  index: dict[tuple[str, str], dict]) -> str:
    """What the reading means about the release movement, said rather than left to a reader."""
    key = None
    if spec.get("delta") is not None:
        key = index.get(spec["delta"])
    if agreement:
        if key is not None and key.get("facet") == "st_size":
            return ("the 23.6 engine records this exported symbol's machine-code size changed; the "
                    "behavioural reading agrees, so the movement is an implementation-size "
                    "observation and not an ABI contract change")
        if key is not None:
            return (f"the 23.6 engine records {spec['delta'][0]} movement for "
                    f"{spec['delta'][1]}; this behavioural reading agrees")
        return "both authorities read the same value on this observation"
    if spec.get("absent_dimension"):
        return (f"the reading is the behavioural evidence for the `{spec['absent_dimension']}` "
                f"dimension the 23.6 engine records absent with its reason")
    if key is not None:
        return (f"the 23.6 engine records {spec['delta'][0]} "
                f"{key.get('classification')} for {spec['delta'][1]}; the divergent reading "
                f"corroborates it")
    return "the two authorities read different values on this observation"


def _vocabulary(rows: list[dict]) -> list[str]:
    return sorted({r["vocabulary"] for r in rows})


def _classified(rows: list[dict]) -> list[dict]:
    """Every divergent reading, as the release delta it is. A one-line projection for the reader."""
    return [{"observation_id": r["observation_id"], "vocabulary": r["vocabulary"],
             "dimension": r["dimension"], "classification": r["classification"],
             "observed_a": r["observed_a"], "observed_b": r["observed_b"],
             "release_delta": r["release_delta"]}
            for r in rows if not r["agreement"]]


# --------------------------------------------------------------------------------------------
# the artefact body: re-derived from the raw transcripts, or measured in the court container
# --------------------------------------------------------------------------------------------

def not_run() -> list[dict]:
    """The authority pairs a semantic court cannot execute in this venue, each with its reason.

    Recorded here rather than omitted, so a pair that was skipped is a stated distance and never a
    court quietly counted as passing (`docs/PHASE-23-MULTITRACK-SUBPHASES.md` section 3.2).
    """
    return [
        {
            "pair": [PRODUCTION_AUTHORITY, "openssl-0.9.8zh-historical"],
            "direction": "authority_a_vs_authority_b",
            "reason": (
                "the 0.9.8zh authority is built in the separate historical venue "
                "(`docker/openssl-rs-historical.Dockerfile`, GCC 10 / Perl 5.32, pinned "
                "independently of the forensic court's GCC 12 / Perl 5.36; "
                "`docs/REPRODUCIBILITY.md` sections 1.1 and 1.2). Its installed prefix is a "
                "historical-venue build product not present in the forensic court venue, and its "
                "pre-3.0 headers and ABI are not compile-compatible with the 3.6.4 probe, so the "
                "oracle-to-oracle comparison is not executed here rather than approximated."
            ),
        },
        {
            "pair": [HISTORICAL_AUTHORITY, "openssl-0.9.8zh-historical"],
            "direction": "authority_a_vs_authority_b",
            "reason": (
                "the same venue separation: 3.6.3 is a forensic-venue authority and 0.9.8zh a "
                "historical-venue one, so neither prefix is present in the other venue and no "
                "single probe can be linked against both in one container. The 0.9.8zh epoch is "
                "measured by the historical-venue façade plane (23.7), not by an oracle-to-oracle "
                "semantic court."
            ),
        },
    ]


def candidate_to_authority() -> dict:
    """Where the candidate-to-authority dimension is discharged, and why it is not duplicated here.

    23.8 owns the **shared normalized observation vocabulary**; the candidate-vs-authority
    *execution* is already the subject of two committed court families, and inventing a third that
    measured the same thing would be a second registry for one fact. The court verifies the named
    courts exist in their own registries rather than taking this statement on trust.
    """
    return {
        "disposition": "discharged_by_existing_courts",
        "statement": (
            "the candidate-to-authority dimension is executed by the existing Phase-2 ABI family "
            "and Phase-17 runtime family, so 23.8 does not stage a duplicate court; what 23.8 adds "
            "is the shared vocabulary — the one `courts/phase23/semantic_probe.c` source, whose "
            "normalized `OBS key=value` rows both the oracle-to-oracle and a candidate run would be "
            "read through, so the candidate and the oracle are read the same way"
        ),
        "existing_courts": [
            {"artefact": "artifacts/phase2/COURTS.json",
             "courts": ["ABI-SYMBOL", "ABI-LAYOUT", "ABI-CONSTANTS", "ABI-MATRIX",
                        "ABI-SUBSTITUTION", "ABI-LINK", "ABI-LOAD"],
             "how": "the candidate distribution shell is compiled against the authority headers and "
                    "run/linked against the candidate DSOs, so the source-surface constants and the "
                    "binary substitution are candidate-to-authority comparisons"},
            {"artefact": "artifacts/phase17/COURTS.json",
             "courts": ["RT-TLS13-INTEROP", "RT-CLI-BODIES", "RT-CROSS-DSO-STATE",
                        "RT-DOWNSTREAM-CONSUMER"],
             "how": "the same probe source executes once against the authority and once against the "
                    "candidate, so the runtime behaviour is a candidate-to-authority comparison"},
        ],
    }


def measured_raw(raw_a: dict, raw_b: dict) -> dict:
    """The `raw_transcripts` block, with each transcript's content-addressed identity."""
    return {
        "authority_a": {**raw_a, "sha256": content_hash(raw_a["stdout"])},
        "authority_b": {**raw_b, "sha256": content_hash(raw_b["stdout"])},
    }


def build_body(raw: dict, *, probe_sha: str) -> dict:
    """The artefact body from the raw transcripts: pure, so the default run reproduces it exactly."""
    delta = _body(read_json(DELTA))
    rows = derive_observations(raw, delta)
    return {
        "authority_a": raw["authority_a"]["authority_id"],
        "authority_b": raw["authority_b"]["authority_id"],
        "direction": "authority_a -> authority_b",
        "authorities": {
            "authority_a": {"id": raw["authority_a"]["authority_id"],
                             "release_id": raw["authority_a"]["release_id"]},
            "authority_b": {"id": raw["authority_b"]["authority_id"],
                             "release_id": raw["authority_b"]["release_id"]},
        },
        "probe": {"source": rel(PROBE), "sha256": probe_sha,
                  "vocabulary": _vocabulary(rows)},
        "raw_transcripts": raw,
        "observations": rows,
        "classified_differences": _classified(rows),
        "differs": sum(1 for r in rows if not r["agreement"]),
        "agrees": sum(1 for r in rows if r["agreement"]),
        "not_run": not_run(),
        "candidate_to_authority": candidate_to_authority(),
        "boundary": (
            "The oracle-to-oracle comparison is bounded to the two forensic-venue authorities "
            "openssl-3.6.3-historical and openssl-3.6.4-production, on the linux/x86_64 default "
            "shared/legacy profile, over the observation vocabulary the probe emits. It is a "
            "behavioural reading of a named pair and is not a compatibility claim about either "
            "authority, and it is not a source-line diff. `error_behavior` is read behaviourally "
            "here while the 23.6 delta engine records the dimension absent for want of a committed "
            "per-authority plane; the 0.9.8zh epoch is not compared (see not_run)."
        ),
    }


# --------------------------------------------------------------------------------------------
# the measurement: compile and run the probe against each authority, in the court venue only
# --------------------------------------------------------------------------------------------

def _raw_transcript(authority_id: str, release_id: str, prefix: Path) -> dict:
    SCRATCH.mkdir(parents=True, exist_ok=True)
    binary = SCRATCH / f"probe.{authority_id}"
    compile_argv = [
        "clang", "-std=c11", "-O1", "-D_GNU_SOURCE",
        f'-DSEMANTIC_AUTHORITY_ID="{authority_id}"',
        f'-DSEMANTIC_RELEASE_ID="{release_id}"',
        "-I", str(prefix / "include"),
        "-o", str(binary), str(PROBE),
        "-L", str(prefix / "lib"), "-lcrypto", "-lssl",
        f"-Wl,-rpath,{prefix / 'lib'}", "-lpthread", "-ldl",
    ]
    cc = subprocess.run(compile_argv, capture_output=True, text=True, check=False)
    if cc.returncode != 0:
        raise SystemExit(f"gen-semantic-courts: probe compile failed for {authority_id}:\n"
                         f"{cc.stderr}")
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = str(prefix / "lib")
    env["OPENSSL_MODULES"] = str(prefix / "lib" / "ossl-modules")
    env["OPENSSL_CONF"] = "/dev/null"
    env.pop("OPENSSL_CONF_INCLUDE", None)
    proc = subprocess.run(["timeout", "60", str(binary)], env=env, capture_output=True, check=False)
    if proc.returncode != 0:
        raise SystemExit(f"gen-semantic-courts: probe run failed for {authority_id} "
                         f"(exit {proc.returncode})")
    return {"authority_id": authority_id, "release_id": release_id,
            "exit": proc.returncode,
            "stdout": proc.stdout.decode("latin-1"),
            "stderr": proc.stderr.decode("latin-1")}


def measure() -> int:
    if not COURT_MARKER.exists():
        raise SystemExit(
            "gen-semantic-courts: --measure compiles and runs the authority probes, so it refuses "
            "the host; run it in the court venue "
            "(`bash docker/openssl-rs-court.sh exec python3 "
            "forensics/tools/gen_semantic_courts.py --measure`)"
        )
    a = resolve_authority(AUTHORITY_A)
    b = resolve_authority(AUTHORITY_B)
    print(f"[semantic-courts] measuring {a.id} vs {b.id}")
    raw_a = _raw_transcript(a.id, a.version if a.version.startswith("openssl-")
                            else f"openssl-{a.version}", a.prefix)
    raw_b = _raw_transcript(b.id, b.version if b.version.startswith("openssl-")
                            else f"openssl-{b.version}", b.prefix)
    raw = measured_raw(raw_a, raw_b)
    body = build_body(raw, probe_sha=sha256_file(PROBE))
    _write(body)
    # The staged probe binaries are scratch, not evidence: the raw transcripts are committed, so the
    # binaries are removed and nothing but the transcript is carried forward.
    for stale in SCRATCH.glob("probe.*"):
        stale.unlink(missing_ok=True)
    print(f"[semantic-courts] {body['differs']} classified difference(s), "
          f"{body['agrees']} agreeing observation(s), {len(body['not_run'])} not-run pair(s)")
    return 0


def _write(body: dict) -> None:
    inputs = [
        InputRef(name="semantic-probe", path=PROBE),
        InputRef(name="delta-engine", path=DELTA),
        InputRef(name="build-records", path=BUILD_RECORDS),
        InputRef(name="authority-a-manifest",
                 path=AUTH_ROOT / "SOURCE_MANIFEST.3.6.3.json"),
        InputRef(name="authority-b-manifest",
                 path=AUTH_ROOT / "SOURCE_MANIFEST.3.6.4.json"),
    ]
    doc = envelope("semantic-courts", GENERATOR, inputs, body, authority=PRODUCTION_AUTHORITY)
    write_json(OUT, doc)


def rederive() -> int:
    """Re-derive the artefact from its own preserved raw transcripts (the default, pure run)."""
    body = _body(read_json(OUT))
    raw = body.get("raw_transcripts")
    if not raw:
        raise SystemExit(f"gen-semantic-courts: {rel(OUT)} carries no raw_transcripts; "
                         f"run --measure in the court venue first")
    fresh = build_body(raw, probe_sha=sha256_file(PROBE))
    _write(fresh)
    print(f"[semantic-courts] re-derived {len(fresh['observations'])} observation(s), "
          f"{fresh['differs']} classified difference(s)")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="compile and run the probes against both authorities in the court venue, "
                         "then write the artefact (requires the built authority prefixes)")
    args = ap.parse_args(argv)
    if args.measure:
        return measure()
    if not OUT.is_file():
        raise SystemExit(f"gen-semantic-courts: {rel(OUT)} is absent; run --measure first")
    return rederive()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
