#!/usr/bin/env python3
"""openssl-rs — Phase 25 X.509 policy-tree differential court: the policy graph under a caller's
allocator.

Phase 11 landed the RFC 5280 policy tree (`crypto/x509/pcy_*.c`) as raw heap blocks and the Phase-25
X.509 policy-tree campaign (`P25-X509-002`, the unit this tool serves) is the baseline the later
conversion units must not regress. This tool stands up the **differential harness** and records
**baseline parity on the unconverted crate** by **measurement**, not prose:

  1. **Behaviour.** One deterministic sequence -- `X509_policy_check` over the NULL, empty, single
     trust-anchor, policy-free, explicit-policy, single-policy, user-policy and mapped-policy
     certificate stacks, plus the CVE-2023-0464 node cap -- is driven against both the authority
     (`courts/phase25/rt_x509_policy_differential.c`, linked against OpenSSL 3.6.4) and the crate
     (`examples/x509_policy_differential.rs`), and the return word, the explicit flag, the built
     tree's shape, the `X509_policy_level_get0_node` traversal order and the `get0` pointer identity
     are compared field by field.

  2. **Allocator observability.** Both sides install a counting, size-recording, failure-injecting
     allocator through `CRYPTO_set_mem_functions` and record the graph window's `CRYPTO_*` call
     counts and block sizes, the injected-failure answer (the failure must yield the authority's
     `INTERNAL`), the cleanup free-counts and the certificate refcounts. The crate's containers and
     `ASN1_OBJECT` blocks are not routed through the hook, which two **measured controls** prove
     (a bare `OPENSSL_sk_new_null` and a bare `OBJ_txt2obj` are visible on the authority and
     invisible on the crate); the divergence that follows is adjudicated, not papered over.

Outputs
-------
  forensics/memory-safety/x509-policy-differential.json

The tool **compiles and runs**, so it is not `metadata_only`: `phase25_guard.require_admitted`
refuses a host invocation.

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

OUT = REPO_ROOT / "forensics" / "memory-safety" / "x509-policy-differential.json"
GENERATOR = "forensics/tools/ms_x509_policy_court.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_x509_policy_court.py"
C_PROBE = REPO_ROOT / "courts" / "phase25" / "rt_x509_policy_differential.c"
RUST_HARNESS = REPO_ROOT / "examples" / "x509_policy_differential.rs"
CAMPAIGN = REPO_ROOT / "forensics" / "memory-safety" / "campaign" / "x509-policy-tree" / "HANDOFF.md"
AUTHORITY = "openssl-3.6.4-production"
AUTHORITY_PREFIX = REPO_ROOT / "forensics" / "authorities" / "prefix" / AUTHORITY
HARNESS_EXAMPLE = "x509_policy_differential"
PROBE_ENV = "X509_POLICY_PROBE"

_JSON_LINE = re.compile(r"^\s*X509_POLICY_JSON (\{.*\})\s*$", re.MULTILINE)

# The behavioural fields compared exactly: the install result, the whole case vector (the return
# word, the explicit flag, the tree shape and the traversal order), the `get0` identity, the cap and
# the certificate refcounts, and the failure sequence's answer.
_BEHAVIOUR_DICTS = ("ident", "cap", "refcount")
_FAIL_ANSWER = ("ret", "tree", "levels", "expl")
# The allocator counts, compared and -- when they differ -- adjudicated by
# `_allocator_divergences`. `stacks`/`objects` are the controls and are compared as evidence, not
# as behaviour.
_COUNT_FIELDS = (
    ("alloc", "malloc"),
    ("alloc", "free"),
    ("cleanup", "malloc"),
    ("cleanup", "free"),
    ("fail", "malloc"),
    ("fail", "free"),
)

# The graph's own block sizes (the `#[repr(C)]` node and the tree/levels array). They are the
# allocations that must be conserved; the 32/40-byte blocks are dominated by the containers and the
# ASN1 objects the crate does not route through the hook.
_GRAPH_BLOCK_SIZES = (24, 64)


def _run(argv: list[str], cwd: Path | None = None, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=str(cwd or REPO_ROOT), capture_output=True, text=True, env=env)


def _parse_transcript(text: str) -> dict:
    m = _JSON_LINE.search(text)
    if not m:
        raise SystemExit(f"[ms-x509-policy-court] no X509_POLICY_JSON transcript in output:\n{text[-2000:]}")
    return json.loads(m.group(1))


def run_authority() -> dict:
    """Compile the C probe against the admitted authority and run it."""
    binpath = Path("/tmp/ms_x509_policy_authority_probe")
    cmd = [
        "clang", "-std=c11", "-O1",
        f"-I{AUTHORITY_PREFIX}/include",
        "-o", str(binpath), str(C_PROBE),
        f"{AUTHORITY_PREFIX}/lib/libcrypto.a",
        "-lpthread", "-ldl", "-lm",
    ]
    res = _run(cmd)
    if res.returncode != 0:
        raise SystemExit(f"[ms-x509-policy-court] the authority probe did not compile:\n{res.stderr[-3000:]}")
    run = _run([str(binpath)])
    if run.returncode != 0:
        raise SystemExit(f"[ms-x509-policy-court] the authority probe exited {run.returncode}:\n"
                         f"{run.stdout[-2000:]}\n{run.stderr[-2000:]}")
    return {
        "impl": "openssl-3.6.4",
        "command": "clang <probe.c> libcrypto.a && <probe>",
        "probe": rel(C_PROBE),
        "probe_sha256": sha256_file(C_PROBE),
        "authority": AUTHORITY_PREFIX.name,
        "stdout_sha256": content_hash(run.stdout.split("X509_POLICY_JSON ", 1)[-1].strip()),
        "transcript": _parse_transcript(run.stdout),
    }


def run_candidate() -> dict:
    """Run the crate's matching harness (which installs the crate's allocator seam)."""
    env = dict(os.environ, **{PROBE_ENV: "1"})
    cmd = ["cargo", "run", "--quiet", "--example", "x509_policy_differential"]
    res = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True, env=env)
    if res.returncode != 0:
        raise SystemExit(f"[ms-x509-policy-court] the candidate harness did not pass:\n"
                         f"{res.stdout[-3000:]}\n{res.stderr[-2000:]}")
    return {
        "impl": "openssl-rs",
        "command": f"{PROBE_ENV}=1 cargo run --example x509_policy_differential",
        "probe": rel(RUST_HARNESS),
        "probe_sha256": sha256_file(RUST_HARNESS),
        "stdout_sha256": content_hash(res.stdout.split("X509_POLICY_JSON ", 1)[-1].splitlines()[0].strip()),
        "transcript": _parse_transcript(res.stdout),
    }


def _graph_block_census(sizes: list) -> dict:
    return {s: sum(1 for x in sizes if x == s) for s in _GRAPH_BLOCK_SIZES}


# The reason the raw allocator counters and sizes diverge. It names the measured mechanism controls
# and the two source sites, so the adjudication cites an experiment and a citation rather than a
# belief.
_CONTAINER_REASON = (
    "The crate's `OPENSSL_sk_*` containers allocate through Rust's global allocator "
    "(`src/runtime/stack.rs`: `from_boxes`/`sk_reserve` build a `Box<Inner>`/`Vec`) and its "
    "`ASN1_OBJECT` blocks through libc `malloc` (`src/runtime/obj.rs`), so a caller-installed "
    "`CRYPTO_set_mem_functions` hook does not observe them; the authority allocates both through "
    "`CRYPTO_malloc`. The `stacks` and `objects` mechanism controls measure exactly this: a bare "
    "`OPENSSL_sk_new_null`/push/free costs the authority hook calls and the crate none, and a bare "
    "`OBJ_txt2obj` costs the authority hook calls and the crate none. The graph's own node "
    "(24-byte) and tree/levels (64-byte) blocks match in count and size, so the divergence is the "
    "container and object representation, not the policy graph."
)
_CACHE_REASON = (
    "The authority's `X509_free` releases the per-cert policy cache -- `crypto/x509/x_x509.c` "
    "calls `ossl_policy_cache_free(ret->policy_cache)` in both `ASN1_OP_D2I_PRE` and "
    "`ASN1_OP_FREE_POST` -- while the crate withholds that call (`src/x509/x_x509.rs` records the "
    "gap: the `akid`/`crldp`/`policy_cache` releases are not landed), so freeing the leaf releases "
    "the cache's blocks on the authority and leaks them on the crate. The container/object "
    "invisibility compounds it. This is the freeze's recorded authoring gap "
    "(`HANDOFF.md` section 1, `ossl_policy_cache_free` has no caller), measured, not to be fixed in "
    "conversion."
)


def _allocator_divergences(ta: dict, tc: dict) -> list[dict]:
    """The allocator-observable differences, each adjudicated with a measured mechanism."""
    out: list[dict] = []
    for group, key in _COUNT_FIELDS:
        av = (ta.get(group) or {}).get(key)
        cv = (tc.get(group) or {}).get(key)
        if av == cv:
            continue
        reason = _CACHE_REASON if group == "cleanup" else _CONTAINER_REASON
        out.append({
            "field": f"{group}.{key}",
            "class": "ALLOCATION_COUNT",
            "authority": av,
            "candidate": cv,
            "adjudication": "accepted",
            "reason": reason,
        })
    sa = list((ta.get("alloc") or {}).get("sizes") or [])
    sc = list((tc.get("alloc") or {}).get("sizes") or [])
    if sa != sc:
        out.append({
            "field": "alloc.sizes",
            "class": "ALLOC_BLOCK_SIZES",
            "authority": sa,
            "candidate": sc,
            "adjudication": "accepted",
            "reason": _CONTAINER_REASON,
        })
    return out


def compare(a: dict, c: dict) -> dict:
    """Field-by-field comparison of the authority's and the crate's transcripts."""
    ta, tc = a["transcript"], c["transcript"]
    matches: dict[str, bool] = {}
    matches["installed"] = ta.get("installed") == tc.get("installed")
    matches["cases"] = ta.get("cases") == tc.get("cases")
    for k in _BEHAVIOUR_DICTS:
        matches[k] = ta.get(k) == tc.get(k)
    fa, fc = ta.get("fail") or {}, tc.get("fail") or {}
    for k in _FAIL_ANSWER:
        matches[f"fail.{k}"] = fa.get(k) == fc.get(k)
    for group, key in _COUNT_FIELDS:
        matches[f"{group}.{key}"] = (ta.get(group) or {}).get(key) == (tc.get(group) or {}).get(key)
    matches["alloc.sizes"] = list((ta.get("alloc") or {}).get("sizes") or []) == \
        list((tc.get("alloc") or {}).get("sizes") or [])

    divergences = _allocator_divergences(ta, tc)
    # Every behavioural field must match exactly: an adjudication covers only the allocator counts
    # and block sizes, never the return word, the shape, the ordering or the identity.
    behavioural = {k: v for k, v in matches.items() if not _is_allocator_field(k)}
    return {
        "matches": {k: matches[k] for k in sorted(matches)},
        "behavioural_match": all(behavioural.values()),
        "all_match": all(matches.values()),
        "divergences": divergences,
        "unadjudicated": [d for d in divergences if d.get("adjudication") == "unadjudicated"],
    }


def _is_allocator_field(key: str) -> bool:
    if key == "alloc.sizes":
        return True
    for group, sub in _COUNT_FIELDS:
        if key == f"{group}.{sub}":
            return True
    return False


def _allocator_conservation(authority: dict, candidate: dict) -> dict:
    """The allocator conservation evidence, read from the post-cleanup counters and the controls."""
    ta, tc = authority["transcript"], candidate["transcript"]
    aa, ca = ta.get("alloc") or {}, tc.get("alloc") or {}
    ac, cc = ta.get("cleanup") or {}, tc.get("cleanup") or {}
    fa, fc = ta.get("fail") or {}, tc.get("fail") or {}
    sa, sc = list(aa.get("sizes") or []), list(ca.get("sizes") or [])
    census_a, census_c = _graph_block_census(sa), _graph_block_census(sc)
    st_a, st_c = ta.get("stacks") or {}, tc.get("stacks") or {}
    ob_a, ob_c = ta.get("objects") or {}, tc.get("objects") or {}
    return {
        "measured_after_cleanup": True,
        "success_window": {
            "release_call": "X509_policy_tree_free",
            "authority": {"malloc": aa.get("malloc"), "free": aa.get("free"), "sizes_len": len(sa)},
            "candidate": {"malloc": ca.get("malloc"), "free": ca.get("free"), "sizes_len": len(sc)},
            "match": (aa.get("malloc") == ca.get("malloc") and aa.get("free") == ca.get("free")
                      and sa == sc),
            "note": (
                "the counters are read after `X509_policy_tree_free`, so the windows cover the "
                "graph's construction **and** release. The graph's own node (24) and tree/levels "
                "(64) blocks match in count and size; the raw counts and the full size list diverge "
                "by the containers and ASN1 objects the crate does not route through the hook"
            ),
        },
        "graph_block_census": {
            "sizes": list(_GRAPH_BLOCK_SIZES),
            "authority": census_a,
            "candidate": census_c,
            "match": census_a == census_c,
            "note": (
                "the node (24-byte) and tree/levels (64-byte) blocks are the five `pcy_local.h` "
                "structures' own and are the allocations the conversion must conserve; the 32- and "
                "40-byte blocks are dominated by the containers and the ASN1 objects, so they are "
                "recorded but not compared as a fixed census"
            ),
        },
        "failure_window": {
            "release_call": "X509_policy_check (failure path frees the partial tree itself)",
            "authority": {"malloc": fa.get("malloc"), "free": fa.get("free")},
            "candidate": {"malloc": fc.get("malloc"), "free": fc.get("free")},
            "answer": {"authority": {"ret": fa.get("ret"), "tree": fa.get("tree")},
                       "candidate": {"ret": fc.get("ret"), "tree": fc.get("tree")}},
            "answer_match": (fa.get("ret") == fc.get("ret") and fa.get("tree") == fc.get("tree")),
            "note": (
                "the injection refuses the first 24-byte allocation of the window -- the root "
                "anyPolicy node -- so `ossl_policy_level_add_node` propagates NULL and both sides "
                "answer INTERNAL with a NULL tree. The raw counts diverge by the same container and "
                "object invisibility as the success window"
            ),
        },
        "teardown_window": {
            "release_call": "X509_free(leaf)",
            "authority": {"malloc": ac.get("malloc"), "free": ac.get("free")},
            "candidate": {"malloc": cc.get("malloc"), "free": cc.get("free")},
            "note": (
                "read after `X509_free(leaf)`. The authority releases the per-cert policy cache "
                "here (`ossl_policy_cache_free`) and the crate withholds it, so the crate frees "
                "fewer blocks; the container/object invisibility compounds it. This is the freeze's "
                "recorded authoring gap, measured"
            ),
        },
        "mechanism_controls": {
            "claim": (
                "the crate's containers and ASN1 objects are invisible to a caller-installed "
                "`CRYPTO_set_mem_functions` hook, which is what makes the raw counts diverge"
            ),
            "stacks": {
                "operation": "OPENSSL_sk_new_null + push + free",
                "authority": st_a,
                "candidate": st_c,
                "invisible": bool((st_a.get("malloc") or 0) > 0 and (st_c.get("malloc") or 0) == 0),
            },
            "objects": {
                "operation": "OBJ_txt2obj(\"1.2.3.4\", 1) + ASN1_OBJECT_free",
                "authority": ob_a,
                "candidate": ob_c,
                "invisible": bool((ob_a.get("malloc") or 0) > 0 and (ob_c.get("malloc") or 0) == 0),
            },
        },
        "cert_refcount": {
            "authority": ta.get("refcount"),
            "candidate": tc.get("refcount"),
            "match": ta.get("refcount") == tc.get("refcount"),
            "note": (
                "`X509_policy_check` up-refs each non-TA certificate, so the tree holds the leaf at "
                "refcount 2; `X509_policy_tree_free` returns it to 1. Both sides read the same "
                "(1, 2, 1) at the offset the crate asserts (`offset_of!(X509, references) == 192`)"
            ),
        },
        "residual": [
            {
                "field": "alloc.malloc / alloc.sizes (graph window)",
                "class": "ALLOCATION_COUNT",
                "status": "admitted, adjudicated allocator-observable divergence under the bounded "
                          "claim (containers + ASN1 objects not routed through the hook), not "
                          "papered over",
            },
            {
                "field": "cleanup.free (teardown window)",
                "class": "ALLOCATION_COUNT",
                "status": "admitted, adjudicated: the recorded per-cert policy-cache leak in the "
                          "crate's `X509_free` (the freeze's known authoring gap)",
            },
        ],
    }


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
                    "the authority side is the admitted OpenSSL 3.6.4 `X509_policy_check` and its "
                    "`pcy_*.o` graph driven by `courts/phase25/rt_x509_policy_differential.c` under "
                    "a caller-installed allocator; the candidate side is the crate's policy "
                    "differential example driving the same sequence under the crate's "
                    "`CRYPTO_set_mem_functions` seam"
                ),
            },
            "comparison": (
                "the behavioural fields -- the install result, the whole case vector (return word, "
                "explicit flag, tree shape, traversal order), the `get0` identity, the cap, the "
                "certificate refcounts and the failure sequence's answer -- are compared exactly; "
                "the allocator counts and block sizes are compared and the divergence adjudicated "
                "against the measured mechanism controls"
            ),
        },
        "allocator_hook": {
            "installed": True,
            "failure_injection": "one-shot: the first allocation of the node's own size (24 bytes) "
                                 "in a fresh check window answers NULL",
        },
        "allocator_conservation": _allocator_conservation(authority, candidate),
        "authority": authority,
        "candidate": candidate,
        "comparison": cmp_,
        "residual_unsafe_boundary": [
            {
                "boundary": "src/x509/pcy_node.rs: ossl_policy_level_add_node",
                "operation": "CRYPTO_zalloc / CRYPTO_free of the node block through the allocator "
                             "seam",
                "why_unavoidable": (
                    "routing every node allocation through the caller's installed allocator and "
                    "returning the authority's NULL-on-exhaustion is what makes the failure answer "
                    "match; it cannot be expressed without the seam call"
                ),
            },
            {
                "boundary": "src/x509/pcy_tree.rs: tree_init / X509_policy_check",
                "operation": "turning the opaque `*mut OpenSslStack` into `certs`' elements and the "
                             "`*mut X509PolicyTree` into the accessor surface",
                "why_unavoidable": "the C-ABI surface itself",
            },
        ],
        "non_claims": [
            "a matching transcript is not a memory-safety proof: it compares the modelled behaviour "
            "on one deterministic sequence, not every input the authority admits",
            "the allocator counts and block sizes are not compared as an exact match: the crate's "
            "`OPENSSL_sk_*` containers and `ASN1_OBJECT` blocks are not routed through the hook, and "
            "the crate leaks the per-cert policy cache the authority releases, so those divergences "
            "are adjudicated against the measured controls rather than read as graph divergences",
            "the 32- and 40-byte blocks are not compared as a fixed census: they are dominated by "
            "the containers and the ASN1 objects, so only the graph's own 24- and 64-byte blocks are "
            "compared by count and size",
            "the authority's own PEM fixtures "
            "(`test/recipes/80-test_policy_tree_data/{small,large}_policy_tree.pem`) are not driven: "
            "they exercise `openssl verify -policy_check`, an application-level path outside this "
            "entry-point differential",
        ],
    }


def _adjudicated(body: dict) -> bool:
    """True when every divergence carries an adjudication and none is unadjudicated."""
    divs = body.get("comparison", {}).get("divergences") or []
    return all(d.get("adjudication") in ("closed", "accepted") and d.get("reason") for d in divs)


def differential_findings(body: dict) -> list[str]:
    """Every way the committed differential contradicts itself or the obligation."""
    problems: list[str] = []
    cmp_ = body.get("comparison") or {}
    if not body.get("authority", {}).get("transcript") or not body.get("candidate", {}).get("transcript"):
        problems.append("the differential is missing an authority or candidate transcript")
    if cmp_.get("unadjudicated"):
        problems.append("the differential carries an unadjudicated divergence")
    if not cmp_.get("behavioural_match"):
        problems.append("a behavioural field differs (return word, shape, ordering, identity, cap, "
                        "refcounts or the failure answer); an allocator adjudication cannot cover it")
    if not cmp_.get("all_match") and not _adjudicated(body):
        problems.append("an allocator field differs and no adjudication covers it")

    conserved = body.get("allocator_conservation") or {}
    ctl = conserved.get("mechanism_controls") or {}
    if not (ctl.get("stacks") or {}).get("invisible"):
        problems.append("the `stacks` control does not show the crate's container is invisible to "
                        "the hook, so the allocator-count adjudication is unproven")
    if not (ctl.get("objects") or {}).get("invisible"):
        problems.append("the `objects` control does not show the crate's ASN1_OBJECT is invisible to "
                        "the hook, so the allocator-count adjudication is unproven")
    census = conserved.get("graph_block_census") or {}
    if not census.get("match"):
        problems.append("the graph's own block census (node 24, tree/levels 64) does not match")
    if not (conserved.get("failure_window") or {}).get("answer_match"):
        problems.append("the injected-failure answer does not match the authority's INTERNAL")
    if not (conserved.get("cert_refcount") or {}).get("match"):
        problems.append("the certificate refcounts do not match")
    if not body.get("residual_unsafe_boundary"):
        problems.append("the residual unsafe boundary is not recorded")
    if not body.get("non_claims"):
        problems.append("the non-claims are not recorded")
    return problems


def _inputs() -> list:
    return [
        InputRef(name="phase-25-plan", path=REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"),
        InputRef(name="phase25-guard", path=REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"),
        InputRef(name="x509-policy-tree-handoff", path=CAMPAIGN),
        InputRef(name="ms-x509-policy-court-tool", path=TOOL),
        InputRef(name="x509-policy-c-probe", path=C_PROBE),
        InputRef(name="x509-policy-rust-harness", path=RUST_HARNESS),
    ]


def _write_plane(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n",
                    encoding="utf-8")


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _measure() -> int:
    body = build_body()
    auth = resolve_authority(PRODUCTION_AUTHORITY)
    doc = envelope(kind="phase25-x509-policy-differential", authority=auth.id, inputs=_inputs(),
                   body=body, generator=GENERATOR)
    doc["body_hash"] = content_hash(body)
    _write_plane(OUT, doc)
    problems = differential_findings(body)
    c = body["comparison"]
    conserved = body["allocator_conservation"]
    print(f"[ms-x509-policy-court] authority {body['authority']['impl']} vs candidate "
          f"{body['candidate']['impl']}: behavioural_match={c['behavioural_match']}, "
          f"divergences={len(c['divergences'])} (unadjudicated={len(c['unadjudicated'])})")
    print(f"  graph block census match: {conserved['graph_block_census']['match']}; "
          f"failure answer match: {conserved['failure_window']['answer_match']}; "
          f"refcounts match: {conserved['cert_refcount']['match']}")
    print(f"  controls: stacks invisible="
          f"{conserved['mechanism_controls']['stacks']['invisible']}, objects invisible="
          f"{conserved['mechanism_controls']['objects']['invisible']}")
    print(f"  -> {rel(OUT)} all_pass={not problems}")
    for p in problems[:12]:
        print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    if not OUT.is_file():
        print(f"[ms-x509-policy-court] {rel(OUT)} is absent; run --measure")
        return 1
    doc = _load(OUT)
    body = doc.get("body", doc)
    problems = differential_findings(body)
    if problems:
        print(f"[ms-x509-policy-court] check FAILED: {len(problems)} problem(s)")
        for p in problems[:12]:
            print(f"  {p}")
        return 1
    print("[ms-x509-policy-court] check ok: the behavioural fields match exactly, every allocator "
          "divergence is adjudicated against the measured controls, the graph block census and the "
          "failure answer match, and the residual boundary and non-claims are recorded")
    return 0


def _fake_transcript(**over: object) -> dict:
    """A minimal but complete transcript pair for the self-test."""
    base = {
        "impl": "x",
        "installed": 1,
        "cases": [{"name": "single_policy", "ret": 1, "expl": 0, "tree": 1, "levels": 2,
                   "pol": 1, "user": -1, "lc": [1, 1], "order": ["2.5.29.32.0", "1.2.3.4"]}],
        "ident": {"nodes": 2, "parents": 1, "resolved": 1, "stable": 1},
        "alloc": {"malloc": 32, "free": 48, "sizes": [64, 64, 32, 24, 24, 40, 32, 40]},
        "cleanup": {"malloc": 0, "free": 66},
        "fail": {"ret": 0, "tree": 0, "levels": 0, "expl": 0, "malloc": 25, "free": 45},
        "cap": {"ret": 0, "tree": 0},
        "stacks": {"malloc": 2, "free": 2},
        "objects": {"malloc": 3, "free": 4},
        "refcount": {"fresh": 1, "after": 2, "freed": 1},
    }
    base.update(over)
    return base


def self_test() -> int:
    """Prove the comparator catches a behavioural divergence and adjudicates the recorded ones."""
    failures: list[str] = []
    auth = _fake_transcript()
    cand = _fake_transcript(
        impl="y",
        alloc={"malloc": 17, "free": 14, "sizes": [64, 64, 32, 24, 24]},
        cleanup={"malloc": 0, "free": 24},
        fail={"ret": 0, "tree": 0, "levels": 0, "expl": 0, "malloc": 16, "free": 12},
        stacks={"malloc": 0, "free": 0},
        objects={"malloc": 0, "free": 0},
    )
    a = {"transcript": auth, "impl": "openssl-3.6.4"}
    c = {"transcript": cand, "impl": "openssl-rs"}
    ok = compare(a, c)
    if not ok["behavioural_match"]:
        failures.append(f"the comparator mis-reads the allocator divergence as behavioural: {ok['matches']}")
    if ok["all_match"] or ok["unadjudicated"]:
        failures.append(f"the comparator does not adjudicate the allocator divergence: {ok}")
    if not _adjudicated({"comparison": ok}):
        failures.append("the comparator does not adjudicate the allocator divergence")
    # The whole findings pass must accept the adjudicated baseline.
    body = {
        "authority": {"transcript": auth},
        "candidate": {"transcript": cand},
        "comparison": ok,
        "allocator_conservation": _allocator_conservation({"transcript": auth}, {"transcript": cand}),
        "residual_unsafe_boundary": [{"boundary": "x"}],
        "non_claims": ["x"],
    }
    base_problems = differential_findings(body)
    if base_problems:
        failures.append(f"the adjudicated baseline is refused by the findings: {base_problems}")

    # A behavioural difference must be unadjudicated and refused.
    bad = _fake_transcript()
    bad["cases"] = [dict(bad["cases"][0], ret=2)]
    bad_cmp = compare(a, {"transcript": bad, "impl": "openssl-rs"})
    if bad_cmp["behavioural_match"]:
        failures.append(f"the comparator misses a behavioural divergence: {bad_cmp}")
    bad_body = dict(body)
    bad_body["comparison"] = bad_cmp
    if not any("behavioural" in p for p in differential_findings(bad_body)):
        failures.append("the findings do not refuse a behavioural divergence")

    # A missing mechanism control must refuse the adjudication.
    no_ctl = _fake_transcript(
        alloc={"malloc": 17, "free": 14, "sizes": [64, 64, 32, 24, 24]},
        cleanup={"malloc": 0, "free": 24},
        fail={"ret": 0, "tree": 0, "levels": 0, "expl": 0, "malloc": 16, "free": 12},
        stacks={"malloc": 2, "free": 2},
        objects={"malloc": 3, "free": 4},
    )
    no_ctl_cmp = compare(a, {"transcript": no_ctl, "impl": "openssl-rs"})
    no_ctl_body = {
        "authority": {"transcript": auth},
        "candidate": {"transcript": no_ctl},
        "comparison": no_ctl_cmp,
        "allocator_conservation": _allocator_conservation({"transcript": auth},
                                                          {"transcript": no_ctl}),
        "residual_unsafe_boundary": [{"boundary": "x"}],
        "non_claims": ["x"],
    }
    if not any("control" in p for p in differential_findings(no_ctl_body)):
        failures.append("the findings accept an allocator divergence with no invisible control")

    if failures:
        print("[ms-x509-policy-court] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-x509-policy-court] self-test ok: the behavioural fields are compared exactly and a "
          "behavioural difference is refused, the adjudicated allocator divergence passes with both "
          "measured controls, and a missing control refuses the adjudication")
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
