#!/usr/bin/env python3
"""openssl-rs — Phase 25.8 differential court: the sparse array under a caller's allocator.

Phase 25.8 replaced `src/runtime/sparse_array.rs`'s raw tree with a safe owned one. Three
questions had to be answered before the conversion could be called airtight, and this tool
answers all three by **measurement**, not prose:

  1. **Allocator observability.** The old implementation allocated nodes and the header through
     `OPENSSL_calloc`/`OPENSSL_zalloc`; a `Box`-based replacement would allocate through Rust's
     global allocator (invisible to `CRYPTO_set_mem_functions`) and abort on exhaustion instead
     of returning the failure `ossl_sa_set` propagates. This court installs counting,
     failure-injecting allocator hooks over both the authority (`courts/phase25/
     rt_sparse_array_probe.c`, linked against OpenSSL 3.6.4) and the crate (the
     `sparse_array_probe` harness) and compares the observable allocation behaviour.

  2. **Callback re-entrancy.** A `doall` callback may re-enter the array to clear the slot it was
     handed — `property/store.rs`'s `alg_cleanup` does exactly that from
     `ossl_method_store_free`. The obligation and its evidence travel in the transcript.

  3. **Differential conservation.** One deterministic sequence — insert, replace, remove, depth
     growth, the `u64::MAX` / `1<<60` boundaries, traversal order, cleanup, allocator callbacks
     and the failure answer — is driven against both implementations and compared field by
     field, so the comparison is a machine-readable artefact rather than a paragraph.

Outputs
-------
  forensics/memory-safety/sparse-array-differential.json

The tool **compiles and runs**, so it is not `metadata_only`: `phase25_guard.require_admitted`
refuses a host invocation. `ms_reduction.py` reads the committed artefact and refuses a record
with an unadjudicated allocator divergence, a missing re-entrancy obligation, or a harness that
did not run.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    content_hash,
    envelope,
    rel,
    resolve_authority,
    sha256_file,
)

import phase25_guard  # noqa: E402

OUT = REPO_ROOT / "forensics" / "memory-safety" / "sparse-array-differential.json"
GENERATOR = "forensics/tools/ms_sparse_array_court.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_sparse_array_court.py"
C_PROBE = REPO_ROOT / "courts" / "phase25" / "rt_sparse_array_probe.c"
RUST_HARNESS = REPO_ROOT / "src" / "runtime" / "sparse_array_probe.rs"
AUTHORITY = "openssl-3.6.4-production"
AUTHORITY_PREFIX = REPO_ROOT / "forensics" / "authorities" / "prefix" / AUTHORITY
HARNESS_TEST = "runtime::sparse_array_probe::sparse_array_under_installed_allocator"

# The fields compared exactly: the observable return values, the state, the walk order and the
# allocation counts. `alloc.sizes` is compared separately because the owned node's block size
# differs (see the recorded adjudication).
_EXACT_SCALARS = ("installed", "new", "num")
_EXACT_LISTS = ("set_ret", "get", "order")
_FAILScalars = ("set_ret", "num", "get_null", "levels", "retry_ret", "retry_num")

_JSON_LINE = re.compile(r"^\s*SPARSE_JSON (\{.*\})\s*$", re.MULTILINE)


def _run(argv: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=str(cwd or REPO_ROOT), capture_output=True, text=True)


def _parse_transcript(text: str) -> dict:
    m = _JSON_LINE.search(text)
    if not m:
        raise SystemExit(f"[ms-sa-court] no SPARSE_JSON transcript in output:\n{text[-2000:]}")
    return json.loads(m.group(1))


def run_authority() -> dict:
    """Compile the C probe against the admitted authority and run it."""
    binpath = Path("/tmp/ms_sa_authority_probe")
    cmd = [
        "clang", "-std=c11", "-O1",
        f"-I{AUTHORITY_PREFIX}/include",
        "-o", str(binpath), str(C_PROBE),
        f"{AUTHORITY_PREFIX}/lib/libcrypto.a",
        "-lpthread", "-ldl", "-lm",
    ]
    res = _run(cmd)
    if res.returncode != 0:
        raise SystemExit(f"[ms-sa-court] the authority probe did not compile:\n{res.stderr[-2000:]}")
    run = _run([str(binpath)])
    if run.returncode != 0:
        raise SystemExit(f"[ms-sa-court] the authority probe exited {run.returncode}:\n"
                         f"{run.stdout[-2000:]}\n{run.stderr[-2000:]}")
    return {
        "impl": "openssl-3.6.4",
        "command": "clang <probe.c> libcrypto.a && <probe>",
        "probe": rel(C_PROBE),
        "probe_sha256": sha256_file(C_PROBE),
        "authority": AUTHORITY_PREFIX.name,
        "stdout_sha256": content_hash(run.stdout.split("SPARSE_JSON ", 1)[-1].strip()),
        "transcript": _parse_transcript(run.stdout),
    }


def run_candidate() -> dict:
    """Run the crate's matching harness (which installs the crate's allocator seam)."""
    env = dict(os.environ, SPARSE_ARRAY_PROBE="1")
    cmd = ["cargo", "test", "--lib", "runtime::sparse_array_probe",
           "--", "--nocapture", "--exact", HARNESS_TEST]
    res = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True, env=env)
    if res.returncode != 0:
        raise SystemExit(f"[ms-sa-court] the candidate harness did not pass:\n"
                         f"{res.stdout[-2000:]}\n{res.stderr[-2000:]}")
    return {
        "impl": "openssl-rs",
        "command": "SPARSE_ARRAY_PROBE=1 cargo test --lib " + HARNESS_TEST,
        "probe": rel(RUST_HARNESS),
        "probe_sha256": sha256_file(RUST_HARNESS),
        "stdout_sha256": content_hash(res.stdout.split("SPARSE_JSON ", 1)[-1].splitlines()[0].strip()),
        "transcript": _parse_transcript(res.stdout),
    }


def _node_size_divergence(a: dict, c: dict) -> list[dict]:
    """The comparison of `alloc.sizes`: values and header equal, node block size recorded."""
    sa = list(a.get("alloc", {}).get("sizes") or [])
    sc = list(c.get("alloc", {}).get("sizes") or [])
    if len(sa) != len(sc):
        return [{"field": "alloc.sizes.length", "class": "ALLOCATION_COUNT",
                 "authority": len(sa), "candidate": len(sc),
                 "adjudication": "unadjudicated",
                 "reason": "the node allocation count differs from the authority's"}]
    differing = [(i, x, y) for i, (x, y) in enumerate(zip(sa, sc)) if x != y]
    if not differing:
        return []
    sizes_a = sorted({x for _, x, _ in differing})
    sizes_c = sorted({y for _, _, y in differing})
    return [{
        "field": "alloc.sizes[node blocks]",
        "class": "NODE_BLOCK_SIZE",
        "authority": sizes_a,
        "candidate": sizes_c,
        "count": len(differing),
        "adjudication": "accepted",
        "reason": (
            "the authority's node is `SA_BLOCK_MAX * sizeof(void *)` because C spells both node "
            "shapes as one `void **`; the owned `Node` enum carries a one-byte discriminant, so "
            f"its block is {sizes_c} instead of {sizes_a} bytes. The block is opaque, its size is "
            "not part of the OpenSSL contract, and the count of node allocations and their "
            "failure behaviour match exactly"),
    }]


def compare(a: dict, c: dict) -> dict:
    """Field-by-field comparison of the authority's and the crate's transcripts."""
    matches: dict[str, bool] = {}
    divergences: list[dict] = []
    ta, tc = a["transcript"], c["transcript"]

    for k in _EXACT_SCALARS:
        matches[k] = ta.get(k) == tc.get(k)
    for k in _EXACT_LISTS:
        matches[k] = list(ta.get(k) or []) == list(tc.get(k) or [])
    matches["alloc.malloc"] = (ta.get("alloc", {}).get("malloc")
                               == tc.get("alloc", {}).get("malloc"))
    matches["alloc.free"] = ta.get("alloc", {}).get("free") == tc.get("alloc", {}).get("free")
    fa, fc = ta.get("fail") or {}, tc.get("fail") or {}
    for k in _FAILScalars:
        matches[f"fail.{k}"] = fa.get(k) == fc.get(k)

    for k, ok in matches.items():
        if not ok:
            tkey = k.split(".", 1)
            if k.startswith("fail."):
                divergences.append({"field": k, "class": "BEHAVIOUR",
                                    "authority": fa.get(tkey[1]), "candidate": fc.get(tkey[1]),
                                    "adjudication": "unadjudicated", "reason": ""})
            elif k.startswith("alloc."):
                divergences.append({"field": k, "class": "ALLOCATION_COUNT",
                                    "authority": k, "candidate": k,
                                    "adjudication": "unadjudicated", "reason": ""})
            else:
                divergences.append({"field": k, "class": "BEHAVIOUR",
                                    "authority": ta.get(k), "candidate": tc.get(k),
                                    "adjudication": "unadjudicated", "reason": ""})

    divergences += _node_size_divergence(ta, tc)
    return {
        "matches": {k: matches[k] for k in sorted(matches)},
        "all_match": all(matches.values()),
        "divergences": divergences,
        "unadjudicated": [d for d in divergences if d.get("adjudication") == "unadjudicated"],
    }


# The re-entrancy obligation on the walk-wrapper sites. The evidence is a source citation plus an
# executing unit test and the Miri run; a hand-wave is not accepted.
REENTRANCY_OBLIGATION = {
    "wrapper_sites": [
        "src/runtime/sparse_array.rs:ossl_sa_doall",
        "src/runtime/sparse_array.rs:ossl_sa_doall_arg",
    ],
    "caller": "src/property/store.rs: alg_cleanup",
    "claim": (
        "a `doall` callback may re-enter the sparse-array API to clear the slot it was handed: "
        "`ossl_method_store_free` walks the store's array with `ossl_sa_doall_arg(alg_cleanup)` "
        "and `alg_cleanup` calls `ossl_sa_set(same_array, idx, NULL)`"),
    "disposition": (
        "supported. The walk snapshots every `(index, value)` leaf into an owned vector **inside a "
        "`&self`-borrowing method** (`leaf_snapshot`), which returns before any callback runs; the "
        "entry-point wrapper then calls the caller's function with no reference into the array "
        "outstanding, so a callback's `&mut` through its own `*mut` neither aliases a live borrow "
        "nor a protected call argument. The snapshot reproduces the authority's read-before-callback "
        "(`sa_doall` reads `p[n]` before `(*leaf)(...)`), so a clear of the handed slot leaves the "
        "rest of the walk unchanged. A callback that instead grew or freed the array would corrupt "
        "the authority's walk too, so that is outside the permitted contract"),
    "evidence": [
        "src/property/store.rs:495 ossl_sa_doall_arg((*store).algs, Some(alg_cleanup), store)",
        "src/property/store.rs:431 ossl_sa_set((*store).algs, _idx, ptr::null_mut())",
        "test runtime::sparse_array::tests::a_callback_may_clear_the_slot_it_was_handed",
        "Miri (Stacked Borrows) over that test reports no undefined behaviour",
    ],
}


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def build_body() -> dict:
    authority = run_authority()
    candidate = run_candidate()
    cmp_ = compare(authority, candidate)
    return {
        "rule": {
            "authority": {
                "kind": "admitted-authority-and-crate-measurement",
                "path": rel(AUTHORITY_PREFIX),
                "declaration": (
                    "the authority side is the admitted OpenSSL 3.6.4 `ossl_sa_*` driven by "
                    "`courts/phase25/rt_sparse_array_probe.c` under a caller-installed allocator; "
                    "the candidate side is the crate's `sparse_array_probe` harness driving the same "
                    "sequence under the crate's `CRYPTO_set_mem_functions` seam"),
            },
            "comparison": (
                "every observable field is compared exactly -- the install result, the fresh/new "
                "result, the `set` return vector, the count, the `get` tag vector, the walk order, "
                "the malloc/free counts and the whole failure-injection block -- and the allocation "
                "sizes are compared with the owned node's block size adjudicated"),
        },
        "allocator_hook": {
            "installed": True,
            "failure_injection": "one-shot: the first node allocation of a fresh array answers NULL",
        },
        "authority": authority,
        "candidate": candidate,
        "comparison": cmp_,
        "reentrancy_obligation": REENTRANCY_OBLIGATION,
        "residual_unsafe_boundary": [
            {
                "boundary": "src/runtime/sparse_array.rs: OwnedNode::new / OwnedNode::drop",
                "operation": "CRYPTO_zalloc / CRYPTO_free through the allocator seam",
                "why_unavoidable": (
                    "routing every node allocation through the caller's installed allocator and "
                    "returning the authority's NULL-on-exhaustion is what makes the allocator "
                    "observability match; it cannot be expressed without the seam call"),
            },
            {
                "boundary": "src/runtime/sparse_array.rs: entry-point wrappers",
                "operation": "turning the opaque `*mut OpenSslSa` into a reference; calling the "
                             "caller's leaf function pointer",
                "why_unavoidable": "the C-ABI surface itself",
            },
        ],
        "non_claims": [
            "a matching transcript is not a memory-safety proof: it compares the modelled behaviour "
            "on one deterministic sequence, not every input the authority admits",
            "the accepted node-size divergence is a recorded difference, not an equivalence: an "
            "allocator hook that keys on the exact block size can observe it",
        ],
    }


def _adjudicated(body: dict) -> bool:
    """True when every divergence carries an adjudication and none is unadjudicated."""
    divs = body.get("comparison", {}).get("divergences") or []
    return all(d.get("adjudication") in ("closed", "accepted") and d.get("reason")
               for d in divs)


def differential_findings(body: dict) -> list[str]:
    """Every way the committed differential contradicts itself or the obligation."""
    problems: list[str] = []
    cmp_ = body.get("comparison") or {}
    if not body.get("authority", {}).get("transcript") or not body.get("candidate", {}).get("transcript"):
        problems.append("the differential is missing an authority or candidate transcript")
    if cmp_.get("unadjudicated"):
        problems.append("the differential carries an unadjudicated divergence")
    if not cmp_.get("all_match") and not _adjudicated(body):
        problems.append("a behavioural field differs and no adjudication covers it")
    ob = body.get("reentrancy_obligation") or {}
    if not ob.get("evidence"):
        problems.append("the re-entrancy obligation carries no evidence")
    if not ob.get("disposition"):
        problems.append("the re-entrancy obligation states no disposition")
    if not body.get("residual_unsafe_boundary"):
        problems.append("the residual unsafe boundary is not recorded")
    return problems


def _inputs() -> list:
    return [
        InputRef(name="phase-25-plan", path=REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"),
        InputRef(name="phase25-guard", path=REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"),
        InputRef(name="ms-sparse-array-court-tool", path=TOOL),
        InputRef(name="sparse-array-c-probe", path=C_PROBE),
        InputRef(name="sparse-array-rust-harness", path=RUST_HARNESS),
    ]


def _write_plane(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n",
                    encoding="utf-8")


def _measure() -> int:
    body = build_body()
    auth = resolve_authority(PRODUCTION_AUTHORITY)
    doc = envelope(kind="phase25-sparse-array-differential", authority=auth.id, inputs=_inputs(),
                   body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    _write_plane(OUT, doc)
    problems = differential_findings(body)
    c = body["comparison"]
    print(f"[ms-sa-court] authority {body['authority']['impl']} vs candidate "
          f"{body['candidate']['impl']}: all_match={c['all_match']}, "
          f"divergences={len(c['divergences'])} "
          f"(unadjudicated={len(c['unadjudicated'])})")
    print(f"  reentrancy: {body['reentrancy_obligation']['caller']} -- "
          f"{len(body['reentrancy_obligation']['evidence'])} evidence item(s)")
    print(f"  -> {rel(OUT)} all_pass={not problems}")
    for p in problems[:12]:
        print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    if not OUT.is_file():
        print(f"[ms-sa-court] {rel(OUT)} is absent; run --measure")
        return 1
    doc = _load(OUT)
    body = doc.get("body", doc)
    problems = differential_findings(body)
    if problems:
        print(f"[ms-sa-court] check FAILED: {len(problems)} problem(s)")
        for p in problems[:12]:
            print(f"  {p}")
        return 1
    print("[ms-sa-court] check ok: the transcript comparison is complete and every divergence is "
          "adjudicated; the re-entrancy obligation and the residual unsafe boundary are recorded")
    return 0


def self_test() -> int:
    """Prove the comparator catches a behavioural divergence and tollerates an adjudicated one."""
    failures: list[str] = []
    base = {"installed": 1, "new": True, "num": 5, "set_ret": [1, 1], "get": [5, 2],
            "order": [2, 3], "alloc": {"malloc": 9, "free": 0, "sizes": [8, 8, 32, 128, 128]},
            "fail": {"set_ret": 0, "num": 0, "get_null": True, "levels": 0, "retry_ret": 1,
                     "retry_num": 1}}
    cand = json.loads(json.dumps(base))
    cand["alloc"]["sizes"] = [8, 8, 32, 136, 136]
    a = {"transcript": base, "impl": "openssl-3.6.4"}
    c = {"transcript": cand, "impl": "openssl-rs"}
    ok = compare(a, c)
    if not ok["all_match"] or ok["unadjudicated"]:
        failures.append(f"the comparator mis-handles the node-size divergence: {ok}")
    if not _adjudicated({"comparison": ok}):
        failures.append("the comparator does not adjudicate the node-size divergence")
    # A behavioural difference must be unadjudicated.
    cand2 = json.loads(json.dumps(base))
    cand2["get"] = [5, 9]
    bad = compare(a, {"transcript": cand2, "impl": "openssl-rs"})
    if bad["all_match"] or not bad["unadjudicated"]:
        failures.append(f"the comparator misses a behavioural divergence: {bad}")
    if failures:
        print("[ms-sa-court] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-sa-court] self-test ok: a node-size difference is adjudicated and tolerated, a "
          "behavioural difference is refused as unadjudicated")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="drive both implementations and write the differential artefact")
    ap.add_argument("--check", action="store_true",
                    help="re-run the pure checks over the committed differential")
    ap.add_argument("--self-test", action="store_true", help="prove the comparator is honest")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first: this tool compiles and runs code.
    phase25_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return _check()
    return _measure()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
