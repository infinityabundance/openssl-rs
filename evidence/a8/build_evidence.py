#!/usr/bin/env python3
"""build_evidence.py -- produce the A8 code-scanning export evidence.

The producer of `evidence/a8/{PLAN,MANIFEST,CONTROLS}.json` and
`evidence/a8/SHARD-000.sarif`. Every count, digest and identity is read from
`evidence/a1/SARIF.json` by `forensics/tools/code_scanning_export.py`; nothing
is typed here. The shard count is asserted from the population and the limit,
and the union check is asserted from the manifest the tool derives, so a change
in the parent stops the producer rather than being written as if it were the
recorded export.

The synthetic 12,001-result population exists only to prove the 5,000-result
boundary (three shards at 5,000 / 5,000 / 2,001) and is labelled as synthetic in
`PLAN.json`. The tracked A1 population is 4,245 results, so the real export has
one shard; a second real shard cannot be produced without inventing a
population, and this producer does not invent one.

Re-running at one source identity reproduces the four files byte-for-byte.

Usage:
    python3 evidence/a8/build_evidence.py
    python3 evidence/a8/build_evidence.py --out DIR

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "forensics" / "tools"
sys.path.insert(0, str(TOOLS))

import code_scanning_export as export  # noqa: E402

OUT_DIR = Path(__file__).resolve().parent
PARENT_PATH = "evidence/a1/SARIF.json"
SYNTHETIC_COUNT = 12001


def _read_parent(repo_root: Path) -> tuple[bytes, dict]:
    path = repo_root / PARENT_PATH
    raw = path.read_bytes()
    document = json.loads(raw)
    return raw, document


def build(repo_root: Path) -> dict[str, str]:
    """Return the four evidence files keyed by name; raise on a changed parent."""
    raw, document = _read_parent(repo_root)
    export.validate_parent(document)

    identities = export.exact_identities(document)
    limit = export.MAX_RESULTS
    expected_real_shards = (len(identities) + limit - 1) // limit

    shards = export.plan(document, limit)
    if len(shards) != expected_real_shards:
        raise AssertionError(
            f"the real plan has {len(shards)} shard(s), not {expected_real_shards}"
        )
    for shard in shards:
        if len(shard["results"]) > limit:
            raise AssertionError(f"shard {shard['index']} exceeds the limit")

    manifest_document = export.manifest(
        document,
        shards,
        parent_bytes=raw,
        parent_path=PARENT_PATH,
        limit=limit,
    )
    if manifest_document["union"]["equalsParent"] is not True:
        raise AssertionError(
            "the real export's union does not equal the parent: "
            f"{manifest_document['union']}"
        )
    if manifest_document["parent"]["resultCount"] != len(identities):
        raise AssertionError("the manifest parent count is not the population")

    logs = [export.emit(document, shard, manifest_document) for shard in shards]
    texts = [export.serialize_sarif(log) for log in logs]
    report = export.verify(
        manifest_document,
        [
            {"bytes": text.encode("utf-8"), "document": log}
            for text, log in zip(texts, logs)
        ],
        {"path": PARENT_PATH, "bytes": raw, "document": document},
    )
    if report["union"] != "complete" or report["duplicates"] != 0:
        raise AssertionError(f"the real export did not verify: {report}")

    plan_document = export.plan_document(document, raw, PARENT_PATH, limit)
    synthetic = plan_document["synthetic"]
    expected_synthetic_shards = (SYNTHETIC_COUNT + limit - 1) // limit
    if synthetic["resultCount"] != SYNTHETIC_COUNT:
        raise AssertionError("the synthetic population lost results")
    if synthetic["shardCount"] != expected_synthetic_shards:
        raise AssertionError(
            f"the synthetic plan has {synthetic['shardCount']} shards, not "
            f"{expected_synthetic_shards}"
        )
    boundaries = synthetic["boundaries"]
    if [row["first"] for row in boundaries] != [
        index * limit for index in range(len(boundaries))
    ]:
        raise AssertionError("the synthetic shard boundaries are not input-order cuts")
    if boundaries[-1]["count"] != SYNTHETIC_COUNT - (len(boundaries) - 1) * limit:
        raise AssertionError("the synthetic tail shard does not hold the remainder")
    if plan_document["real"]["shardCount"] != len(shards):
        raise AssertionError("the recorded real plan disagrees with the plan")

    controls = export.build_controls(document, raw)
    if len(controls) != len(export.REFUSALS):
        raise AssertionError(
            f"{len(controls)} controls over {len(export.REFUSALS)} codes"
        )
    if {control["code"] for control in controls} != set(export.REFUSALS):
        raise AssertionError("the controls do not cover every refusal code")

    controls_document = export.controls_document(controls)
    if len(controls_document["codes"]) != len(export.REFUSALS):
        raise AssertionError("the recorded refusal table is not the code table")

    return {
        "PLAN.json": export.dump_document(plan_document),
        "MANIFEST.json": export.dump_document(manifest_document),
        "SHARD-000.sarif": export.serialize_sarif(logs[0]),
        "CONTROLS.json": export.dump_document(controls_document),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=OUT_DIR)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)

    try:
        documents = build(args.repo_root)
    except export.Refusal as refusal:
        print(str(refusal), file=sys.stderr)
        return 2
    except AssertionError as error:
        print(f"producer assertion failed: {error}", file=sys.stderr)
        return 1

    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in documents.items():
        (args.out / name).write_text(text, encoding="utf-8")

    raw, document = _read_parent(args.repo_root)
    shards = export.plan(document, export.MAX_RESULTS)
    manifest_document = export.manifest(
        document,
        shards,
        parent_bytes=raw,
        parent_path=PARENT_PATH,
        limit=export.MAX_RESULTS,
    )
    plan_document = export.plan_document(document, raw, PARENT_PATH, export.MAX_RESULTS)
    controls = export.build_controls(document, raw)
    print(
        f"parent={PARENT_PATH} bytes={len(raw)} "
        f"results={manifest_document['parent']['resultCount']} "
        f"runs={manifest_document['parent']['runCount']} "
        f"limit={export.MAX_RESULTS} shards={manifest_document['shardCount']}"
    )
    for entry in manifest_document["shards"]:
        print(
            f"shard {entry['index']}: results={entry['resultCount']} "
            f"bytes={entry['bytes']} sha256={entry['sha256']} "
            f"first={entry['firstResult']} last={entry['lastResult']}"
        )
    print(
        "candidate token="
        f"{manifest_document['candidate']['token']} "
        f"mixed={manifest_document['candidate']['mixed']} "
        f"runs={manifest_document['candidate']['runCount']} "
        f"distinct={manifest_document['candidate']['distinctCount']}"
    )
    print(f"union={manifest_document['union']}")
    print(
        f"synthetic: results={SYNTHETIC_COUNT} "
        f"shards={plan_document['synthetic']['shardCount']} boundaries="
        + ",".join(
            f"{row['first']}-{row['last']}"
            for row in plan_document["synthetic"]["boundaries"]
        )
    )
    print(f"controls={len(controls)} codes={len(export.REFUSALS)}")
    print(
        "wrote "
        + ", ".join(
            f"{name} ({len(text.encode('utf-8'))} bytes)"
            for name, text in documents.items()
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
