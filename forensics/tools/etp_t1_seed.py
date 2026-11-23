#!/usr/bin/env python3
"""Seed evidence/etp-t1/TRACEABILITY.json from tracked records.

The graph is a static evidence artefact, but it is generated rather than
hand-written: this tool reads the tracked claim inventory, instrument register,
refusal record and queue rows, binds every citation to a Git blob at the named
commit, and writes the graph.  Re-running it over unchanged records reproduces
the committed bytes exactly.

    python3 forensics/tools/etp_t1_seed.py
    python3 forensics/tools/etp_t1_seed.py --output /tmp/TRACEABILITY.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
import closure_discipline  # noqa: E402  (ETP-T10 projection)
S = "21bea318819a56f641b3aa2f25027216b97a1c4d"
# The ETP-T3 analysis candidate.  The refinement nodes cite documents and
# evidence that exist here; the rest of the graph remains bound to S.
A = "794a7c5491e6095992744f1ab624f5183ca3457d"
S0 = "9372bb28b2fbe2f71cf2aa2ab501414d45e87d42"  # ETP-0/ETP-1 claims identity
# The ETP-T4 analysis candidate.  The unsafe-site inventory and axiom register
# describe src/ at this commit; their files do not exist at it yet, so the
# graph declares the three class-8 orphans and settles them when a later commit
# binds the evidence to itself.
T4 = "07b776d688fdd1dcc4e315661894c30e623aed9e"
T4_SITES = "evidence/etp-t4/SAFETY-SITES.json"
T4_AXIOMS = "evidence/etp-t4/AXIOMS.json"
DEFAULT_OUTPUT = REPO / "evidence" / "etp-t1" / "TRACEABILITY.json"

_blob_cache: dict[tuple[str, str], bytes | None] = {}


def git(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-c", "safe.directory=*", "-C", str(REPO), *args],
        capture_output=True, check=False,
    )


def blob(commit: str, path: str) -> bytes | None:
    key = (commit, path)
    if key not in _blob_cache:
        r = git("cat-file", "blob", f"{commit}:{path}")
        _blob_cache[key] = r.stdout if r.returncode == 0 else None
    return _blob_cache[key]


def sha(commit: str, path: str) -> str:
    data = blob(commit, path)
    if data is None:
        raise SystemExit(f"path {path} absent at {commit}")
    return hashlib.sha256(data).hexdigest()


def bound_for(path: str) -> str:
    return S


def worktree_src(path: str, span: str, quote: str, bound: str = T4) -> dict:
    """A source record for a file whose evidence commit is newer than its path.

    The digest is read from the working tree because the file does not exist at
    `bound`; the graph declares the resulting class-8 orphan explicitly and the
    seed's `settling_method` says how to bind it to a later commit.
    """
    data = (REPO / path).read_bytes()
    return {
        "path": path,
        "span": span,
        "quote": quote,
        "quote_kind": "fragment",
        "sha256": hashlib.sha256(data).hexdigest(),
        "bound_commit": bound,
        "settling_method": "re-run with T4 set to the commit that contains this path",
    }


def _output_path() -> Path:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args, _ = parser.parse_known_args()
    return args.output


OUT = _output_path()


def src(path: str, span: str, quote: str, bound: str | None = None,
        quote_kind: str = "fragment") -> dict:
    commit = bound or bound_for(path)
    return {
        "path": path,
        "span": span,
        "quote": quote,
        "quote_kind": quote_kind,
        "sha256": sha(commit, path),
        "bound_commit": commit,
    }


nodes: dict[str, dict] = {}
edges: list[dict] = []
orphans: list[dict] = []


def node(nid: str, ntype: str, title: str, source: dict, **fields) -> None:
    if nid in nodes:
        raise SystemExit(f"duplicate node {nid}")
    entry = {"id": nid, "type": ntype, "title": title, "source": source}
    entry.update(fields)
    nodes[nid] = entry


def edge(src_id: str, etype: str, dst_id: str, basis: str) -> None:
    edges.append({"from": src_id, "type": etype, "to": dst_id, "basis": basis})


def orphan(oid: str, cls: int, nid: str, reason: str, would_close: str) -> None:
    orphans.append({"id": oid, "class": cls, "node": nid, "reason": reason,
                    "would_close": would_close})


# ---------------------------------------------------------------- threats
THREATS = [
    ("THR-01", "operator error", "a mistyped command cannot silently compile on the host; builds are bounded",
     "a correct command with the wrong argument; a receipt written by hand; a test run at the wrong candidate"),
    ("THR-02", "selective publication", "a manifest is self-verifying against a published log",
     "a producer that never publishes the log; the 1,929 court/tmp references; a summary that omits a scope"),
    ("THR-03", "historical revision", "O7's withdrawal is machine-readable; the graduation preserves the adjudication dissent",
     "silent edits to a tracked receipt; force-push outside the repository's control; prose rewritten in place"),
    ("THR-04", "artefact substitution", "a changed DSO or consumer binary is detectable when the digest is recorded",
     "receipts that name paths but not digests; two different DSOs under one build-B name"),
    ("THR-05", "instrument false negative", "a control that does not trigger fails the court",
     "a vacuous control; an instrument insensitive to a defect class it was not challenged on"),
    ("THR-06", "candidate/evidence mismatch", "the b85c freeze records nine artefact digests and two builds",
     "evidence for one candidate cited for another; the tracked install is 32 source-touching commits old"),
    ("THR-07", "dependency compromise", "a changed archive is detected when the digest is pinned and verified",
     "Dropbear and PuTTY signatures are unverified; Dropbear's digest is a first-fetch pin"),
    ("THR-08", "key compromise", "nothing to compromise: no DSSE envelope, Sigstore bundle, Rekor entry or signed manifest is present",
     "no rotation, revocation, expiry or anti-rollback; Addendum A and Addendum B are open"),
]
for nid, name, covers, not_covers in THREATS:
    node(nid, "threat", name,
         src("evidence/etp0/RECEIPT.md", "initial threat model",
             f"adversary class: {name}", quote_kind="paraphrase"),
         adversary_class=name, covers=covers, does_not_cover=not_covers)

# ---------------------------------------------------------------- hazards
# ETP-T2 owns the hazard register.  The graph projects every register hazard as
# a `hazard` node whose scope, input classification and barrier are the ones the
# register records, and whose edges are the register's declared T1 edges.  The
# register is read from the working tree and its digest is recorded in the
# graph, so a register that drifts away from its projection is visible.
HAZARD_REGISTER = REPO / "evidence" / "etp-t2" / "HAZARDS.json"
if not HAZARD_REGISTER.is_file():
    raise SystemExit(f"hazard register {HAZARD_REGISTER} is absent; ETP-T2 is incomplete")
_hazard_bytes = HAZARD_REGISTER.read_bytes()
hazard_register = json.loads(_hazard_bytes)
HAZARD_REGISTER_SHA = hashlib.sha256(_hazard_bytes).hexdigest()

for hazz in hazard_register["hazards"]:
    hid = hazz["id"]
    source = hazz["source"]
    fields = {
        "characterization": hazz["description"],
        "scope": hazz["scope"],
        "trigger_classes": hazz["trigger_classes"],
        "memory_safe_claim": hazz["memory_safe_claim"],
        "barrier": hazz["barrier"],
        "affected_release_claims": hazz["t1_edges"]["release_claims"],
    }
    if "class3_disposition" in hazz:
        fields["class3_disposition"] = hazz["class3_disposition"]
    node(
        hid,
        "hazard",
        hazz["title"],
        src(
            source["path"],
            source["span"],
            source["quote"],
            quote_kind=source.get("quote_kind", "fragment"),
        ),
        **fields,
    )
    for rid in hazz["t1_edges"]["motivates"]:
        edge(hid, "motivates", rid, f"{hid} is the stated hazard behind {rid}")
    for oid in hazz["t1_edges"]["obligations"]:
        edge(hid, "raises", oid, f"{hid} raises the open obligation {oid}")
    for eid in hazz["t1_edges"]["evidence"]:
        edge(hid, "evidenced_by", eid, f"{eid} bears on {hid}; it does not by itself discharge it")

# ETP-T2 HAZ-15: the differential receipt that supports the barrier is in the
# working tree and is bound at the commit that adds it.  It is declared as a
# class-8 orphan below rather than silently presented as settled at `S`.
_HAZ15_EVIDENCE = REPO / "evidence" / "haz-15" / "observables.json"
node(
    "EV-HAZ-15-DIFFERENTIAL",
    "evidence",
    "HAZ-15 external-key PKCS#1 v1.5 differential receipt",
    {
        "path": "evidence/haz-15/observables.json",
        "span": "finding_prefix/finding_postfix",
        "quote": "the content oracle is removed on the return-sign, buffer and error-queue "
                 "axes, while the returned length remains a distinguishing channel",
        "quote_kind": "fragment",
        "sha256": hashlib.sha256(_HAZ15_EVIDENCE.read_bytes()).hexdigest(),
        "bound_commit": "478bf17ec1aa9022a784009a999a10e4eb4c07c4",
        "settling_method": "re-run with the bound commit set to the commit that contains "
                           "this path",
    },
    kind="differential_receipt",
    present=True,
    quality="four ciphertexts against the candidate and the pinned authority, plus a "
            "64-block length population; return value, output bytes, error queue and length "
            "only, no timing measurement",
)

# ---------------------------------------------------------------- requirements
REQUIREMENTS = [
    ("REQ-ABI-01", "The exported C ABI surface is preserved",
     "Every exported symbol and signature and every #[repr(C)] layout that the authority exposes is preserved.",
     "AGENTS.md", "§6", "preserve #[repr(C)] layouts and every exported symbol/signature", True),
    ("REQ-MEM-01", "Ownership adoption discharges a provenance contract",
     "An ownership-adoption constructor is unsafe, states provenance, extent, alignment, initialisation, exclusive ownership and the exact release mechanism, and no safe function can cause an invalid free.",
     "AGENTS.md", "§1", "An ownership-adoption constructor ... MUST be unsafe fn with a # Safety contract.", True),
    ("REQ-MEM-02", "Allocated storage and initialised values are separate states",
     "No reference, initialised read or full destructor is permitted before the type's validity invariants hold; partially initialised objects release only what they acquired.",
     "AGENTS.md", "§2", "Allocated storage and initialized Rust values are separate states.", True),
    ("REQ-MEM-03", "Allocation arithmetic is fallible and checked",
     "Counts, sizes, sums and offsets used for allocation are checked; overflow becomes the failure semantics, not a panic.",
     "AGENTS.md", "§3", "MUST use checked_mul/checked_add and translate overflow to the OpenSSL failure semantics", True),
    ("REQ-PANIC-01", "A panic across the C ABI leaves a defined state",
     "A caught panic does not leave partially mutated state usable: the operation is failure-atomic, rolled back or explicitly poisoned.",
     "AGENTS.md", "§4", "For stateful contexts require one of: failure-atomic mutation, explicit rollback, or a poisoned state", True),
    ("REQ-SEC-01", "Secret-bearing storage is cleansed on every exit path",
     "Cleansing covers the actual secret-bearing storage, including copies, temporaries, partially initialised states and failure paths; release and cleansing are separate.",
     "AGENTS.md", "§5.1", "Cleansing must cover the actual secret-bearing storage, including ... failure paths.", True),
    ("REQ-SEC-02", "Secret-dependent operations preserve constant-time discipline",
     "Secret-dependent operations have no secret-dependent branch, address or early exit, and the intent is preserved under optimisation and checked at the exact artefact.",
     "AGENTS.md", "§5.2", "never introduce secret-dependent branches or early exits", True),
    ("REQ-TIM-01", "Secret-bearing arithmetic fails rather than aborting",
     "Allocation on the secret-bearing path is fallible and returns an error on exhaustion; no unchecked allocation remains on that path.",
     "docs/ETP-TODO.md", "row T1", "Infallible allocations in limbs::rem/limbs::mul; ... still plain Vecs (OBL-BN-ALLOCATOR)", True),
    ("REQ-TIM-02", "Exponentiation, inversion and division are fixed-pattern at public geometry",
     "Modular exponentiation, inversion and division on secret operands use a fixed pattern whose loop count and storage width follow public geometry, with the residual channels stated.",
     "docs/ETP-TODO.md", "row T28", "BN_div ignores BN_FLG_CONSTTIME ... it is a variable-time path on secret operands", True),
    ("REQ-COMPAT-01", "OpenSSH interoperability is cohort- and candidate-bound",
     "An OpenSSH result names its version, tarball digest and candidate; two cohorts are never combined, averaged or carried forward.",
     "docs/OPENSSH-COHORT.md", "the rule", "Two cohorts' results are never combined, averaged, subtracted or carried forward into one another's verdicts", True),
    ("REQ-COMPAT-02", "A consumer closure classifies every reachable edge",
     "Every reachable edge is classified; an omitted edge needs an independently checkable exclusion, and no aggregation hides a blocked row.",
     "docs/ETP-TODO.md", "row ETP-T10", "every omitted edge needs an independently checkable exclusion argument; no aggregation hiding a blocked row", True),
    ("REQ-EVID-01", "A claim never exceeds its evidence",
     "An implementation is not a specification, a test is not a proof, and a summary never stands in for the evidence it summarises.",
     "docs/ETP-TODO.md", "queue rules", "a claim may never exceed its evidence; an implementation is not a specification", False),
    ("REQ-EVID-02", "An instrument demonstrates sensitivity before it is cited",
     "An instrument is admitted with a paired control that fires on the defect class it claims to detect, and its soundness limits are stated.",
     "docs/ETP-TODO.md", "queue rules", "an instrument must demonstrate sensitivity to the defect it claims to detect", False),
    ("REQ-EVID-03", "Evidence is bound to its exact identity and is never fresh by assumption",
     "Historical evidence is never fresh evidence; a candidate change invalidates rather than transfers the result.",
     "docs/ETP-TODO.md", "queue rules", "historical evidence is never fresh evidence", False),
    ("REQ-EVID-04", "Claim axes are orthogonal",
     "No claim axis implies another: verdict, modality, identity and evidence support are independent, and no scalar score combines them.",
     "docs/ETP-CLAIM-ALGEBRA.md", "§1", "a property does not imply a modality; a modality does not imply a verdict", False),
    ("REQ-GRAD-01", "Graduation requires the whole dependency closure",
     "A consumer family is SAFE_COMPATIBLE only when every applicable mechanism in its closure is SAFETY_DISCHARGED and compatibility is confirmed at the exact implementation.",
     "AGENTS.md", "§7", "A family graduates only when every applicable mechanism ... is SAFETY_DISCHARGED", False),
    ("REQ-OMIT-01", "Omission is detectable against a pre-registered population",
     "A producer cannot pass by omitting a failed result; the expected evidence population is frozen before execution and reconciled afterwards.",
     "docs/ETP-TODO.md", "row A17", "a producer cannot PASS by omitting a failed result", False),
    ("REQ-PERF-01", "Performance classifications are disjoint from assurance",
     "MEASURED, AHEAD and FRONTIER_LEADING are performance classifications and never imply SAFE_COMPATIBLE or semantic assurance.",
     "docs/PERFORMANCE-FRONTIER.md", "§10", "These are performance classifications and are disjoint from SAFE_COMPATIBLE", False),
    ("REQ-PERF-02", "A virtualised venue yields only SCOPED_OBSERVATION",
     "A result measured without bare metal and a PMU is labelled SCOPED_OBSERVATION with its venue and is not a frontier result.",
     "docs/PERFORMANCE-FRONTIER.md", "§9.5", "Until that venue exists, results are labelled SCOPED_OBSERVATION with the venue named.", False),
    ("REQ-SPEC-01", "Specifications are independent of the implementation",
     "Specifications and security requirements are never generated by restating the production implementation; one independent hierarchy exists.",
     "docs/FORMAL-REFINEMENT-CERTIFICATION.md", "§9", "Specifications and security requirements are never generated by restating the production implementation.", False),
    ("REQ-REPRO-01", "Independent builds are byte-identical",
     "Two independently initialised clean builds produce byte-identical artefacts, and a reproducible build is not thereby a correct build.",
     "docs/ETP-TODO.md", "row ETP-2", "two independently initialised clean builds; ... no byte-normalisation to manufacture a PASS", False),
    ("REQ-CORR-01", "A cryptographic result is correct or the operation fails",
     "Every cryptographic operation returns the arithmetic result the operation defines or a defined failure; a silent wrong result is not conserved from the authority.",
     "AGENTS.md", "§8", "are results, protocol decisions, secret handling and timing protections correct?", True),
]
for rid, title, statement, path, span, quote, spec_required in REQUIREMENTS:
    node(rid, "requirement", title, src(path, span, quote),
         statement=statement, specification_required=spec_required,
         externally_observable=True)

MOTIVATION = {
    "REQ-ABI-01": ["THR-04", "THR-06"],
    "REQ-COMPAT-01": ["THR-06", "THR-04"],
    "REQ-COMPAT-02": ["THR-02"],
    "REQ-EVID-01": ["THR-02"],
    "REQ-EVID-02": ["THR-05"],
    "REQ-EVID-03": ["THR-03", "THR-06"],
    "REQ-EVID-04": ["THR-02"],
    "REQ-GRAD-01": ["THR-06"],
    "REQ-OMIT-01": ["THR-02"],
    "REQ-PERF-01": ["THR-02"],
    "REQ-PERF-02": ["THR-05"],
    "REQ-SPEC-01": ["THR-02", "THR-03"],
    "REQ-REPRO-01": ["THR-04"],
}
for rid, motivators in MOTIVATION.items():
    for hid in motivators:
        edge(hid, "motivates", rid, f"the hazard/threat is the stated reason for {rid}")

# ---------------------------------------------------------------- implementations
IMPLEMENTATIONS = [
    ("IMP-SECRET-OWNER", "Secret storage owner and cleansing policy", "src/runtime/secret.rs",
     ["REQ-SEC-01", "REQ-MEM-01", "REQ-MEM-02"]),
    ("IMP-ALLOC-SEAM", "Fallible allocation seam", "src/runtime/alloc.rs",
     ["REQ-MEM-03", "REQ-TIM-01"]),
    ("IMP-BN-LIMBS", "Fallible limb arithmetic, constant-pattern ladder, inversion and division", "src/bn/limbs.rs",
     ["REQ-MEM-03", "REQ-SEC-02", "REQ-TIM-01", "REQ-TIM-02"]),
    ("IMP-BN-ARITH", "Constant-time modular addition and exponentiation core", "src/bn/arith.rs",
     ["REQ-SEC-02", "REQ-TIM-02"]),
    ("IMP-BN-BIGNUM", "BIGNUM ownership adoption and fixed-width storage", "src/bn/bignum.rs",
     ["REQ-MEM-01", "REQ-MEM-02", "REQ-TIM-01"]),
    ("IMP-ECDSA", "ECDSA signing pipeline", "src/ec/ecdsa_ossl.rs",
     ["REQ-SEC-01", "REQ-SEC-02", "REQ-TIM-01", "REQ-TIM-02"]),
    ("IMP-RSA", "RSA private operations and CRT", "src/rsa/ossl.rs",
     ["REQ-SEC-01", "REQ-SEC-02", "REQ-TIM-01", "REQ-TIM-02", "REQ-CORR-01"]),
    ("IMP-BN-MONT", "Montgomery domain construction, validation and prepared parameters", "src/bn/mont.rs",
     ["REQ-CORR-01", "REQ-TIM-02"]),
    ("IMP-PANIC-GUARD", "Panic boundary for FFI entry points", "src/ffi/mod.rs",
     ["REQ-PANIC-01"]),
    ("IMP-ABI-SYMBOLS", "Exported library entry points", "src/lib.rs",
     ["REQ-ABI-01"]),
    ("IMP-ABI-LAYOUT", "Shared-library version script", "artifacts/phase2/libcrypto.ld",
     ["REQ-ABI-01"]),
    ("IMP-CLAIM-VALIDATOR", "Claim typing, laws and digest re-derivation", "forensics/tools/etp_claims.py",
     ["REQ-EVID-01", "REQ-EVID-03", "REQ-EVID-04", "REQ-OMIT-01"]),
    ("IMP-INSTR-REGISTER", "Instrument qualification register and controls", "forensics/tools/instrument_qualify.py",
     ["REQ-EVID-02"]),
    ("IMP-RELEASE-GATE", "Release decision over the claim set", "forensics/tools/release_gate.py",
     ["REQ-GRAD-01", "REQ-EVID-01"]),
    ("IMP-CONSUMER-CLOSURE", "Consumer closure classification", "forensics/tools/consumer_closure.py",
     ["REQ-COMPAT-02", "REQ-GRAD-01"]),
    ("IMP-INTEROP", "Four-cell interoperability harness", "courts/phase18/interop/cell.sh",
     ["REQ-COMPAT-01"]),
    ("IMP-BENCH", "Differential benchmark harness", "courts/phase18/timing/bench_api.c",
     ["REQ-PERF-01", "REQ-PERF-02"]),
    ("IMP-BRANCH-AUDIT", "Fail-closed emitted-instruction audit", "courts/phase18/timing/binary_branch_audit.py",
     ["REQ-SEC-02", "REQ-TIM-02"]),
    ("IMP-CI", "Continuous assurance job", ".github/workflows/ci.yml",
     ["REQ-EVID-01", "REQ-EVID-02", "REQ-EVID-03"]),
    ("IMP-REPRO", "Two-build reproducibility recipe", "forensics/tools/build_reproducibility.sh",
     ["REQ-REPRO-01"]),
]
for iid, title, path, reqs in IMPLEMENTATIONS:
    node(iid, "implementation", title, src(path, "file", f"{title}"),
         mechanism=title, location=path)
    for rid in reqs:
        edge(rid, "satisfied_by", iid, f"{iid} is the implementation named for {rid}")

for iid, _title, path, _reqs in IMPLEMENTATIONS:
    aid = "ART-FILE-" + iid.removeprefix("IMP-")
    node(aid, "artefact", f"Tracked file {path}",
         src(path, "file", f"file digest of {path}"),
         kind="file", path=path, digest=sha(S, path), digest_identity=S)
    edge(iid, "realised_by", aid, f"{aid} is the tracked file that realises {iid}")

ARTEFACT_EXTRA = [
    ("ART-DSO-A67305B1", "Candidate distribution DSO a67305b1 (build-id 7cdf5b9c)",
     "docs/ETP-TODO.md", "row T19",
     "a67305b1dcb297b19a12078caf55cb6ad2acdf3dfb332b89c97ee7e1f1d4db34",
     ["IMP-BN-LIMBS", "IMP-ECDSA", "IMP-RSA"],
     "T19 re-measurement at the current candidate; the row does not name the source commit"),
    ("ART-DSO-611E511D", "Authority OpenSSL DSO 611e511d",
     "docs/ETP-TODO.md", "row T21",
     "611e511db4273c4b6b522031fd171efce71b80661bb8310c2a21dfd18ec0efd2",
     ["IMP-BENCH"],
     "authority comparator named in the T21 benchmark"),
    ("ART-OPENSSH-SSH-B85", "OpenSSH ssh binary c2db343d at b85c",
     "evidence/etp0/CLAIMS.json", "claim ETP0-CLM-033 basis",
     "c2db343dfa5135272f2be6960210b3b99af83b9ed181034e976e1c68e98fff8b",
     ["IMP-CONSUMER-CLOSURE"],
     "the consumer binary the b85c closure classifies"),
    ("ART-OPENSSH-SSHD-B85", "OpenSSH sshd binary 8af50952 at b85c",
     "evidence/etp0/CLAIMS.json", "claim ETP0-CLM-033 basis",
     "8af509523ed16f68fe74a75aef923b78e87b047c054ea30fc2aa6d9971485ae1",
     ["IMP-CONSUMER-CLOSURE"],
     "the consumer binary the b85c closure classifies"),
    ("ART-CURL-DSO-FD25", "Admitted install libcrypto.so.3 fd25cc9e",
     "evidence/closure-curl-049.json", "candidate_identity",
     "fd25cc9e6424ea79aaaff05df22b3f6e1d46aa22d5666cfe7589dce95ffd88a9",
     ["IMP-CONSUMER-CLOSURE", "IMP-BN-LIMBS"],
     "the curl closure's admitted install; the working tree may be a descendant"),
    ("ART-PFP1-DSO-596F", "PFP-1 candidate libcrypto.so.3 596f4833",
     "evidence/performance-frontier/campaigns/PFP-1/performance/build-identity.json", "candidate",
     "596f4833e35932da7efff936185dee17dcb56f3b6363f4682300afb741d3c5b9",
     ["IMP-BENCH"],
     "the PFP-1 measured candidate; built under court/tmp"),
]
for aid, title, path, span, digest, impls, note in ARTEFACT_EXTRA:
    node(aid, "artefact", title, src(path, span, note, quote_kind="paraphrase"),
         kind=("consumer_binary" if "OPENSSH" in aid else "dso"),
         digest=digest, digest_identity="recorded candidate", note=note)
    for iid in impls:
        edge(iid, "realised_by", aid, f"{aid} is the shipped artefact for {iid}")

# ---------------------------------------------------------------- typed claims
claims_doc = json.loads((REPO / "evidence/etp/claims.json").read_text())
claims = claims_doc["claims"]
claims_sha = sha(S, "evidence/etp/claims.json")
VERDICT_MAP = {"SUPPORTED": "ESTABLISHED"}
CLAIM_EVIDENCE: dict[tuple, str] = {}
for claim in claims:
    for ev in claim.get("evidence", []):
        key = (ev.get("path"), ev.get("sha256"), ev.get("digest_identity"), ev.get("kind"))
        CLAIM_EVIDENCE.setdefault(key, f"EVD-C{len(CLAIM_EVIDENCE)+1:03d}")

for claim in claims:
    cid = claim["id"]
    state = claim["verdict"]["state"]
    node(cid, "adjudication", f"Typed claim {cid} ({claim['property']})",
         {"path": "evidence/etp/claims.json", "span": cid,
          "quote": claim["verdict"]["basis"][:200], "quote_kind": "fragment",
          "sha256": claims_sha, "bound_commit": S},
         record_kind="typed_claim", property=claim["property"],
         verdict=VERDICT_MAP.get(state, state),
         independence="NOT_CLAIMED",
         authority="ETP-1 claim inventory; the same party produced the cited evidence",
         derived_from=claim.get("derived_from"))

for key, evid in sorted(CLAIM_EVIDENCE.items(), key=lambda kv: kv[1]):
    path, digest, identity, kind = key
    if path is None:
        continue
    if digest is None:
        source = {"path": path, "span": kind or "evidence",
                  "quote": "cited by the ETP-1 claim inventory; absent at the bound commit",
                  "quote_kind": "paraphrase",
                  "sha256": "UNKNOWN", "bound_commit": S0,
                  "settling_method": "produce a tracked evidence file at a named commit and record its sha256"}
    else:
        bound = S0
        if identity == "historical":
            match = re.search(r"read at commit ([0-9a-f]+)", next(
                (e.get("note", "") for c in claims for e in c.get("evidence", [])
                 if e.get("path") == path and e.get("sha256") == digest), ""))
            if match:
                bound = match.group(1)
        source = {"path": path, "span": kind or "evidence",
                  "quote": "cited by the ETP-1 claim inventory",
                  "quote_kind": "paraphrase",
                  "sha256": digest, "bound_commit": bound}
    node(evid, "evidence", f"Evidence {path}", source,
         kind=kind, digest_identity=identity,
         present=path is not None and digest is not None)

for claim in claims:
    cid = claim["id"]
    for ev in claim.get("evidence", []):
        key = (ev.get("path"), ev.get("sha256"), ev.get("digest_identity"), ev.get("kind"))
        evid = CLAIM_EVIDENCE.get(key)
        if evid:
            edge(evid, "assessed_by", cid, f"{cid} cites this record")

CLAIM_REQUIREMENT = {
    "claim-governance": "REQ-EVID-01",
    "compatibility": "REQ-COMPAT-01",
    "timing": "REQ-TIM-02",
    "memory-safety": "REQ-MEM-01",
    "identity": "REQ-EVID-03",
    "reproducibility": "REQ-REPRO-01",
    "consumer-graduation": "REQ-GRAD-01",
}
for claim in claims:
    rid = CLAIM_REQUIREMENT.get(claim["property"])
    if rid:
        edge(rid, "assessed_by", claim["id"],
             f"{claim['id']} is a typed verdict about {rid}'s property")

# ---------------------------------------------------------------- release claims
RELEASE = [
    ("REL-OPENSSH-B85C", "OpenSSH ssh/sshd SAFE_COMPATIBLE graduation at b85c",
     "evidence/SAFE-COMPATIBLE-openssh-b85c.json", "verdict", "SAFE_COMPATIBLE", True,
     ["REQ-COMPAT-01", "REQ-GRAD-01", "REQ-SEC-01", "REQ-SEC-02",
      "REQ-TIM-01", "REQ-TIM-02", "REQ-ABI-01", "REQ-PANIC-01", "REQ-CORR-01"],
     ["ADJ-B85C", "ADJ-ETP5-R1", "ETP0-CLM-030"]),
    ("REL-COHORT-COUNTER-1-33", "Safe-33 cohort counter recorded as 1/33",
     "forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json", "consumers",
     "SAFE_COMPATIBLE", True,
     ["REQ-GRAD-01", "REQ-EVID-01"],
     ["ETP0-CLM-032", "ADJ-ETP5-R2"]),
    ("REL-L7-ATLAS-33-33", "33/33 L7-functional atlas rows",
     "forensics/downstream/runtime-functional-atlas.json", "level counts",
     "ESTABLISHED", False,
     ["REQ-COMPAT-01", "REQ-EVID-01"],
     ["ETP0-CLM-028"]),
    ("REL-CURL-049", "curl consumer is not graduated at 0.0.49",
     "evidence/etp5/REFUSALS.json", "ETP5-R5", "NOT_ESTABLISHED", False,
     ["REQ-COMPAT-02", "REQ-GRAD-01"],
     ["ADJ-ETP5-R5", "ETP0-CLM-029"]),
    ("REL-PERF-PFP0", "Performance baseline classification SCOPED_OBSERVATION",
     "evidence/performance-frontier/campaigns/PFP-0/results.json", "classification",
     "SCOPED_OBSERVATION", False,
     ["REQ-PERF-01", "REQ-PERF-02"], []),
    ("REL-PERF-PFP1", "Prepared Montgomery domain classification SCOPED_OBSERVATION",
     "evidence/performance-frontier/campaigns/PFP-1/performance/results.json", "classification",
     "SCOPED_OBSERVATION", False,
     ["REQ-PERF-01", "REQ-PERF-02"], []),
]
for rid, title, path, span, claimed, independent, reqs, adjudicators in RELEASE:
    node(rid, "release_claim", title, src(path, span, f"recorded verdict: {claimed}",
                                          quote_kind="paraphrase"),
         claimed_verdict=claimed, requires_independent_adjudication=independent,
         scope_requirements=reqs)
    for aid in adjudicators:
        edge(aid, "releases", rid, f"{aid} is the recorded verdict for {rid}")

# ---------------------------------------------------------------- adjudications
node("ADJ-B85C", "adjudication", "Independent adversarial adjudication of b85c",
     src("evidence/b85c-adjudication.json", "verdict",
         "independent adversarial adjudicator; produced none of the b85c source, closures, receipts, instruments or reviews"),
     record_kind="independent_adjudication", verdict="NOT_ESTABLISHED",
     independence="INDEPENDENT",
     authority="independent adversarial adjudicator at the b85c candidate")

refusals = json.loads((REPO / "evidence/etp5/REFUSALS.json").read_text())
for condition in refusals["conditions"]:
    cid = condition["id"]
    node("ADJ-" + cid, "adjudication", f"ETP-5 refusal {cid}",
         src("evidence/etp5/REFUSALS.json", cid, condition["condition"][:200],
             quote_kind="fragment"),
         record_kind="refusal", verdict="REFUSED", independence="SAME_PARTY",
         authority="ETP-5 refusal record; the evidence producer is the refusing party",
         rule=condition["rule"])

# ---------------------------------------------------------------- obligations
obligation_ids: set[str] = set()


def add_obligation(oid, title, source, statement, settled_by, blocks, impls, basis):
    if oid in obligation_ids:
        raise SystemExit(f"duplicate obligation {oid}")
    obligation_ids.add(oid)
    node(oid, "obligation", title, source,
         statement=statement, state="OPEN", settled_by=settled_by,
         blocks_release_claims=blocks)
    for iid in impls:
        edge(iid, "raises", oid, basis)
    for cid in blocks:
        edge(oid, "constrains", cid, basis)


CLAIM_BLOCKS = {
    "ETP0-CLM-030": ["REL-OPENSSH-B85C"],
    "ETP0-CLM-032": ["REL-COHORT-COUNTER-1-33"],
    "ETP0-CLM-028": ["REL-L7-ATLAS-33-33"],
}
claim_obl: dict[str, tuple[dict, str]] = {}
for claim in claims:
    for obl in claim.get("obligations", []):
        claim_obl.setdefault(obl["id"], (obl, claim["id"]))

for oid in sorted(claim_obl):
    obl, owner = claim_obl[oid]
    blocks = CLAIM_BLOCKS.get(owner, [])
    if oid == "OBL-T15-RESOLUTION":
        blocks = ["REL-OPENSSH-B85C", "REL-COHORT-COUNTER-1-33"]
    add_obligation(
        oid, f"Open obligation from the ETP-1 claim inventory: {oid}",
        {"path": "evidence/etp/claims.json", "span": oid,
         "quote": obl["statement"][:200], "quote_kind": "fragment",
         "sha256": claims_sha, "bound_commit": S},
        obl["statement"], obl.get("settled_by", "UNKNOWN"), blocks, [],
        f"{oid} is recorded on typed claim {owner}; its release-claim binding is recorded here")

T_OBLIGATIONS = [
    ("OBL-BN-ALLOCATOR", "T1", "C-ABI bignum::parts clones and the variable-time limbs::{rem,mul} wrappers still allocate infallibly.",
     "Make every remaining allocation on the secret-bearing BN path fallible and return the failure semantics.",
     ["IMP-BN-LIMBS", "IMP-BN-BIGNUM"]),
    ("OBL-T5-RESIDUAL", "T5", "BN_mod_inverse (T7), bases wider than n, mod_exp_core on public inputs and RT-BN remain open.",
     "Close the named residues and run RT-BN at the candidate.", ["IMP-BN-LIMBS", "IMP-BN-ARITH"]),
    ("OBL-T6-RESIDUAL", "T6", "Recombination still reads p/q, revealing zero limbs, carries of at most n+1 limbs and one carry bit, and result-length contexts reveal floor(bitlen/64); RT-RSA NOT RUN.",
     "A fixed-shape recombination and RT-RSA evidence at the candidate.", ["IMP-RSA"]),
    ("OBL-T7-RESIDUAL", "T7", "Even-modulus RSA keygen and FIPS r2^-1 mod 2r1 remain variable-time; limb-count metadata and one authorised no-inverse branch remain.",
     "A domain-correct constant-time inversion for even moduli and the metadata reduction.", ["IMP-BN-LIMBS"]),
    ("OBL-T9-RESIDUAL", "T9", "The presence/bounds test in the staging transfer is a secret-length branch that is stated, not removed.",
     "A public-width read without out-of-bounds or uninitialised spare storage.", ["IMP-BN-LIMBS", "IMP-BN-BIGNUM"]),
    ("OBL-T11-RESIDUAL", "T11", "The blinding factor is released with BN_free rather than cleansed, and there is no runtime timing evidence.",
     "A cleansed blinding release (or recorded authority-parity justification) and timing evidence.", ["IMP-RSA"]),
    ("OBL-T12-RESIDUAL", "T12", "Uncleansed BN_CTX scratch and the absence of an authority differential remain.",
     "Cleansed scratch and a differential court at the candidate.", ["IMP-ECDSA"]),
    ("OBL-T14-RESIDUAL", "T14", "Secret-dependence is not established; the branch audit is a review aid until T16 is validated.",
     "A validated dependence argument for the audited functions.", ["IMP-BRANCH-AUDIT"]),
    ("OBL-T16-RESIDUAL", "T16", "The ladder and inversion reach the BINSEC engine but return unknown; no verdict is claimed.",
     "Resolve the std allocator vtable and the 2 unsolved 64-bit queries.", ["IMP-BN-LIMBS"]),
    ("OBL-T19-RESIDUAL", "T19", "The inverse regression (856 errors / 274 contexts) is unresolved and needs its own analysis.",
     "An explained and resolved inverse count at the candidate.", ["IMP-BN-LIMBS"]),
    ("OBL-T22-RESIDUAL", "T22", "The remaining infallible sites are not yet enumerated.",
     "A complete enumeration of infallible allocation sites with their disposition.", ["IMP-ALLOC-SEAM"]),
    ("OBL-T23-RESIDUAL", "T23", "The transfer window while a result moves into a BIGNUM, plus portability of the two 1 constants, remain.",
     "A cleansed transfer and a portability argument.", ["IMP-SECRET-OWNER", "IMP-BN-BIGNUM"]),
    ("OBL-T24-RESIDUAL", "T24", "The inversion's geometry still follows the operands' normalised limb counts, visible through BN_num_bits.",
     "A public C-ABI width or a CT reduction of an arbitrarily wide secret operand.", ["IMP-BN-LIMBS"]),
    ("OBL-T29-RESIDUAL", "T29", "One allocation per limb operation remains (mul 5147, accumulator 4882, remainder 4882, sub 3612, add 1544, shl 1031 in the census).",
     "The fixed-scratch field workspace the item asks for, re-measured.", ["IMP-BN-LIMBS", "IMP-ECDSA"]),
    ("OBL-T30-RESIDUAL", "T30", "parse_into growth is classified public, growth before SecretBuf adoption is outside the cleansing owner, and no Miri/valgrind ran on the new boundary.",
     "A stated storage invariant for pre-adoption growth and a Miri/valgrind run.", ["IMP-SECRET-OWNER", "IMP-BN-BIGNUM"]),
]
for oid, row, statement, settled, impls in T_OBLIGATIONS:
    add_obligation(
        oid, f"{row} residual: {oid}",
        src("docs/ETP-TODO.md", f"row {row}", statement, quote_kind="paraphrase"),
        statement, settled, [], impls,
        f"{oid} is the named residual of queue row {row}")

QUEUE_OBLIGATIONS = [
    ("OBL-ETP-T2", "ETP-T2", "The security hazard register (fault trees, FMEA, STPA-Sec, attack graphs) is TODO.",
     "A hazard register that distinguishes legal API input, adversarial input and ABI-contract violation.",
     [], []),
    ("OBL-ETP-T15", "ETP-T15", "The OpenSSH b85c graduation and the NOT ESTABLISHED adjudication are unreconciled.",
     "Reconciliation as distinct records with their actual provenance.",
     [], ["REL-OPENSSH-B85C"]),
    ("OBL-C1", "C1", "27 named curl element-7 refusals remain open.",
     "Close or honestly hold each named refusal with a checkable row.",
     ["IMP-CONSUMER-CLOSURE"], ["REL-CURL-049"]),
    ("OBL-C3", "C3", "One frozen census, freeze and closure run at a single identity is TODO.",
     "A frozen census, freeze and closure at one candidate identity.",
     ["IMP-CONSUMER-CLOSURE"], ["REL-CURL-049"]),
    ("OBL-C5", "C5", "Curl L7 replay at the final candidate and element-7 PASS are TODO.",
     "An L7 replay at the final candidate with element-7 PASS.",
     ["IMP-CONSUMER-CLOSURE", "IMP-INTEROP"], ["REL-CURL-049"]),
    ("OBL-FRC-0", "FRC-0", "The independent specification hierarchy is TODO; no specification node exists in the graph.",
     "The FRC-0 specification hierarchy from normative sources.",
     [], []),
    ("OBL-A17-RESIDUAL", "A17", "The pre-registered evidence manifest and signed reconciliation manifest are not implemented.",
     "A frozen expected-evidence manifest and a signed reconciliation closure.",
     ["IMP-CLAIM-VALIDATOR"], ["REL-OPENSSH-B85C", "REL-CURL-049"]),
    ("OBL-PFP-17", "PFP-17", "Independent frontier verification is TODO; no frontier claim is made.",
     "An external party's receipt at the frozen population.",
     ["IMP-BENCH"], []),
]
for oid, item, statement, settled, impls, blocks in QUEUE_OBLIGATIONS:
    add_obligation(
        oid, f"Open queue item {item}: {oid}",
        src("docs/ETP-TODO.md", f"row {item}", statement, quote_kind="paraphrase"),
        statement, settled, blocks, impls,
        f"{oid} is the open state of queue row {item}")

# ETP-T2 hazards whose only honest disposition is an open obligation.
ETP_T2_OBLIGATIONS = [
    ("OBL-RSA-EXTKEY-ORACLE", "ETP-T2 HAZ-15",
     "The authority's external-key PKCS#1 v1.5 substitution is a padding oracle. The candidate "
     "keeps the implicit-rejection arm and keys the synthetic answer with private CRT material "
     "or a per-key RNG secret (the earlier decrypted-block hash is withdrawn as "
     "attacker-computable). The returned length remains a channel: a 2,048-block population "
     "matched every protocol-relevant length at a per-ciphertext probability of order 1/246 "
     "(the 48-byte TLS length matched 9 of 2,048), so the hazard is only partially mitigated "
     "(D-RSA-EXTKEY-ORACLE-1). The first-use secret initialisation no longer holds its side-table "
     "lock across the application-reachable RAND callback; same-thread re-entry is a named "
     "refusal and destruction during initialisation is defined.",
     "Independent adjudication of evidence/haz-15/{observables.json,KDK-CORRECTION.md,"
     "REENTRANCY-AND-LENGTH.md} at the candidate that lands the correction, a consumer replay of "
     "the divergence, and a resolution of the returned-length channel (a fixed-length contract, "
     "or a documented per-consumer obligation).",
     ["REL-OPENSSH-B85C"], ["IMP-RSA"]),
    ("OBL-PANIC-ATOMICITY", "ETP-T2 HAZ-16",
     "guard_ffi prevents a panic from unwinding into C. Three stateful security-relevant "
     "contexts are now failure-atomic (BN_BLINDING_update, BN_BLINDING_create_param, "
     "OPENSSL_sk_pop_free) with unit evidence and revert controls; failure-atomicity, rollback "
     "or poisoning for the remaining mutation candidates is not established.",
     "Failure-atomicity, rollback or poisoning evidence for every stateful FFI context that can "
     "panic, at a named candidate, including the 744 NOT_AUDITED mutation candidates and the "
     "evp/rsa/ec/x509 abort path.",
     ["REL-OPENSSH-B85C"], ["IMP-PANIC-GUARD"]),
    ("OBL-VERIFY-RETURN-POLARITY", "ETP-T2 HAZ-18",
     "EVP_DigestVerifyFinal answers 0 for an invalid signature and -1 for an error, and the C "
     "ABI cannot enforce that a consumer tests exactly 1 for success.",
     "Consumer evidence that every in-scope verification call site distinguishes 1 from 0 and -1.",
     [], ["IMP-ABI-SYMBOLS"]),
]
for oid, item, statement, settled, blocks, impls in ETP_T2_OBLIGATIONS:
    add_obligation(
        oid, f"{item} obligation: {oid}",
        src("docs/ETP-TODO.md", "row ETP-T2", statement, quote_kind="paraphrase"),
        statement, settled, blocks, impls,
        f"{oid} is the open obligation ETP-T2 records for {item}")

B85C_OBLIGATIONS = [
    ("OBL-MECH-EVP-PKEY-PROVIDER", "EVP_PKEY_PROVIDER mechanism is NOT_ESTABLISHED (116 obligations).",
     "Discharge the 116 mechanism obligations or produce an independently checkable exclusion for each."),
    ("OBL-MECH-X509-VERIFY-POLICY", "X509_VERIFY_POLICY mechanism is NOT_ESTABLISHED (122 obligations).",
     "Discharge the 122 mechanism obligations or produce an independently checkable exclusion for each."),
    ("OBL-MECH-RAND-CMS-STORE-KEYFMT", "RAND_CMS_STORE_KEYFMT mechanism is NOT_ESTABLISHED (27 obligations).",
     "Discharge the 27 mechanism obligations or produce an independently checkable exclusion for each."),
    ("OBL-MECH-C-ABI-CONTRACT", "C_ABI_CONTRACT mechanism is NOT_ESTABLISHED (5 obligations).",
     "Establish the five C-ABI obligations at the consumer identity."),
    ("OBL-MECH-BIO", "BIO mechanism is NOT_ESTABLISHED (2 obligations).",
     "Establish the two BIO obligations at the consumer identity."),
    ("OBL-MECH-SSL-SESSION-SCOPED", "SSL_SESSION is SAFETY_DISCHARGED only at a scope whose sslconf-exclusivity precondition is retained and un-discharged.",
     "Establish the caller's exclusive-ownership precondition."),
    ("OBL-MECH-RUNTIME-CONCURRENCY", "RUNTIME_CONCURRENCY's scoped discharge states that no test performs the forbidden release shape; the caller precondition is not established.",
     "A test or argument that establishes the exclusive-ownership precondition."),
    ("OBL-XCUT-CALLBACKS", "The cross-cutting callbacks/reentrancy obligation is NOT_ESTABLISHED.",
     "An audited callback map with per-call-site witnesses."),
    ("OBL-XCUT-ALIASING", "The cross-cutting aliasing/ownership obligation is NOT_ESTABLISHED.",
     "A whole-boundary aliasing argument with negative controls."),
    ("OBL-XCUT-PANIC", "The cross-cutting panic-safety obligation is NOT_ESTABLISHED; there is no failure-atomic, rollback or poison evidence.",
     "Failure-atomicity or poisoning evidence for stateful contexts."),
    ("OBL-XCUT-SECRET", "The cross-cutting secret-memory obligation is NOT_ESTABLISHED; cleansing is unaudited.",
     "An audit of secret-bearing storage and cleansing on failure paths."),
    ("OBL-B54-F1", "B54-F1 (high, open) refutes the NULL-ctx premise of v2i_AUTHORITY_INFO_ACCESS and blocks any SAFE_COMPATIBLE claim including the X509V3 config-decode surface.",
     "Repair the NULL-ctx premise and close B54-F1."),
    ("OBL-B55-F1", "B55-F1 (high, open) blocks v2i_idp and v2i_aaidp, which the b85c closures still record DISCHARGED.",
     "Repair and close B55-F1, and re-measure the two rows."),
]
for oid, statement, settled in B85C_OBLIGATIONS:
    add_obligation(
        oid, f"b85c adjudication obligation: {oid}",
        src("evidence/b85c-adjudication.json", oid, statement, quote_kind="paraphrase"),
        statement, settled, ["REL-OPENSSH-B85C"], [],
        "the independent b85c adjudication records that this item blocks SAFE_COMPATIBLE")

# ---------------------------------------------------------------- extra evidence
EXTRA_EVIDENCE = [
    ("EVD-ETP0-RECEIPT", "ETP-0 baseline and trust-gap receipt", "evidence/etp0/RECEIPT.md",
     "initial threat model", "the threat model and the trust-gap inventory"),
    ("EVD-TRUST-GAPS", "ETP-0 trust-gap inventory (37 gaps)", "evidence/etp0/TRUST-GAPS.json",
     "gaps", "the classified trust-gap inventory"),
    ("EVD-CLAIMS", "ETP-1 typed claim inventory (35 claims)", "evidence/etp/claims.json",
     "claims", "the typed claim inventory"),
    ("EVD-ETP3-INSTRUMENTS", "ETP-3 instrument qualification register (11 instruments)",
     "evidence/etp3/instruments.json", "instruments", "the qualification register"),
    ("EVD-FREEZE-B85C", "b85c candidate freeze", "evidence/FREEZE-b85c.json",
     "freeze_kind", "the frozen candidate identity"),
    ("EVD-CLOSURE-SSH-B85C", "ssh closure at b85c", "evidence/closure-ssh-b85c.json",
     "verdict", "the ssh consumer closure"),
    ("EVD-CLOSURE-SSHD-B85C", "sshd closure at b85c", "evidence/closure-sshd-b85c.json",
     "verdict", "the sshd consumer closure"),
    ("EVD-L7-B85C", "L7 replay at b85c", "evidence/b85-l7-replay.json",
     "workloads", "the L7 compatibility replay"),
    ("EVD-B85C-ADJUDICATION", "b85c independent adjudication", "evidence/b85c-adjudication.json",
     "verdict", "the independent verdict"),
    ("EVD-ETP5-REFUSALS", "ETP-5 refusals (5 conditions)", "evidence/etp5/REFUSALS.json",
     "conditions", "the refusal record"),
    ("EVD-CURL-CLOSURE", "curl closure at 0.0.49", "evidence/closure-curl-049.json",
     "verdict", "the curl consumer closure"),
    ("EVD-ELEMENT7-CLOSED", "curl element-7 closed-set receipt",
     "evidence/element7-curl-049-closedset-receipt.json", "counts",
     "the element-7 closed-set measurement"),
    ("EVD-PFP0-RESULTS", "PFP-0 benchmark reconstruction results",
     "evidence/performance-frontier/campaigns/PFP-0/results.json", "classification",
     "the preregistered benchmark reconstruction"),
    ("EVD-PFP1-RESULTS", "PFP-1 prepared-domain results",
     "evidence/performance-frontier/campaigns/PFP-1/performance/results.json",
     "classification", "the prepared-domain measurement"),
    ("EVD-ETP2-REPRO", "ETP-2 reproducibility result", "evidence/etp2/reproducibility.json",
     "result", "the two-build reproducibility result"),
    ("EVD-OMISSION-RESISTANCE", "A17 omission-resistance half",
     "evidence/etp/OMISSION-RESISTANCE.md", "scope",
     "the claim-algebra half of omission resistance"),
]
EXTRA_TARGETS = {
    "EVD-ETP0-RECEIPT": ["REQ-EVID-01"],
    "EVD-TRUST-GAPS": ["REQ-EVID-01"],
    "EVD-CLAIMS": ["REQ-EVID-01", "REQ-EVID-04"],
    "EVD-ETP3-INSTRUMENTS": ["REQ-EVID-02"],
    "EVD-FREEZE-B85C": ["REQ-COMPAT-01", "REQ-EVID-03"],
    "EVD-CLOSURE-SSH-B85C": ["REQ-COMPAT-01", "REQ-GRAD-01"],
    "EVD-CLOSURE-SSHD-B85C": ["REQ-COMPAT-01", "REQ-GRAD-01"],
    "EVD-L7-B85C": ["REQ-COMPAT-01"],
    "EVD-B85C-ADJUDICATION": ["REQ-GRAD-01"],
    "EVD-ETP5-REFUSALS": ["REQ-GRAD-01", "REQ-EVID-01"],
    "EVD-CURL-CLOSURE": ["REQ-COMPAT-02"],
    "EVD-ELEMENT7-CLOSED": ["REQ-COMPAT-02"],
    "EVD-PFP0-RESULTS": ["REQ-PERF-01", "REQ-PERF-02"],
    "EVD-PFP1-RESULTS": ["REQ-PERF-01", "REQ-PERF-02"],
    "EVD-ETP2-REPRO": ["REQ-REPRO-01"],
    "EVD-OMISSION-RESISTANCE": ["REQ-OMIT-01"],
}
for eid, title, path, span, quote in EXTRA_EVIDENCE:
    node(eid, "evidence", title, src(path, span, quote, quote_kind="paraphrase"),
         kind="record", present=True)
    for rid in EXTRA_TARGETS[eid]:
        edge(rid, "evidenced_by", eid, f"{eid} is cited for {rid}")

for eid, aid in [
    ("EVD-B85C-ADJUDICATION", "ADJ-B85C"),
    ("EVD-FREEZE-B85C", "ADJ-B85C"),
    ("EVD-CLOSURE-SSH-B85C", "ADJ-B85C"),
    ("EVD-CLOSURE-SSHD-B85C", "ADJ-B85C"),
    ("EVD-L7-B85C", "ADJ-B85C"),
    ("EVD-ETP5-REFUSALS", "ADJ-ETP5-R1"),
    ("EVD-ETP5-REFUSALS", "ADJ-ETP5-R2"),
    ("EVD-ETP5-REFUSALS", "ADJ-ETP5-R3"),
    ("EVD-ETP5-REFUSALS", "ADJ-ETP5-R4"),
    ("EVD-ETP5-REFUSALS", "ADJ-ETP5-R5"),
    ("EVD-ETP0-RECEIPT", "ETP0-CLM-030"),
    ("EVD-TRUST-GAPS", "ETP0-CLM-001"),
    ("EVD-CLAIMS", "ETP0-CLM-001"),
    ("EVD-PFP0-RESULTS", "ETP0-CLM-012"),
]:
    edge(eid, "assessed_by", aid, f"{aid} assesses {eid}")

# ---------------------------------------------------------------- instruments
instruments = json.loads((REPO / "evidence/etp3/instruments.json").read_text())
INSTRUMENT_TARGETS = {
    "valgrind-ctgrind": ["REQ-SEC-02", "REQ-TIM-02"],
    "dudect": ["REQ-SEC-02"],
    "binsec-checkct": ["REQ-SEC-02"],
    "timecop-supercop": ["REQ-SEC-02"],
    "perf-pmu": ["REQ-PERF-02"],
    "tsc-smi-fallbacks": ["REQ-PERF-02"],
    "binary-branch-audit": ["REQ-SEC-02", "REQ-TIM-02"],
    "differential-bench-court": ["REQ-PERF-01", "REQ-PERF-02"],
    "alloc-probe": ["REQ-TIM-01"],
    "build-reproducibility": ["REQ-REPRO-01"],
    "etp-claims": ["REQ-EVID-01", "REQ-EVID-04", "REQ-GRAD-01"],
}
for inst in instruments["instruments"]:
    iid = inst["id"]
    status = inst["sensitivity_control"]["status"]
    eid = "EVD-INST-" + iid.upper().replace("-", "_")
    node(eid, "evidence", f"Instrument qualification and control: {inst['name']}",
         src("evidence/etp3/instruments.json", iid,
             "instrument qualification: intended use, limits, version and paired control",
             quote_kind="paraphrase"),
         kind="instrument_result", instrument_id=iid,
         qualification_status=status, version=inst["version_validation"]["observed"],
         intended_use=inst["intended_use"], paths=inst["paths"])
    for rid in INSTRUMENT_TARGETS[iid]:
        edge(rid, "evidenced_by", eid, f"the qualified instrument is the one cited for {rid}")

# ---------------------------------------------------------------- row evidence
ROW_EVIDENCE = [
    ("EVD-ROW-T1", "row T1",
     "Residual: C-ABI bignum::parts clones and the variable-time limbs::{rem,mul} wrappers still allocate infallibly",
     ["IMP-BN-LIMBS", "IMP-BN-BIGNUM"]),
    ("EVD-ROW-T12", "row T12",
     "Open: ... uncleansed BN_CTX scratch, and no authority differential",
     ["IMP-ECDSA"]),
    ("EVD-ROW-T19", "row T19",
     "Candidate DSO a67305b1 (build ID 7cdf5b9c)",
     ["IMP-BN-LIMBS", "IMP-ECDSA", "IMP-RSA"]),
    ("EVD-ROW-T22", "row T22",
     "The remaining infallible sites are not yet enumerated.",
     ["IMP-ALLOC-SEAM"]),
    ("EVD-ROW-T28", "row T28",
     "BN_div now reads BN_FLG_CONSTTIME from both operands and routes a flagged call to limbs::div_rem_ct_fallible",
     ["IMP-BN-LIMBS"]),
    ("EVD-ROW-T29", "row T29",
     "Census after: 22 276 ... Remaining: ... one allocation per limb operation",
     ["IMP-ECDSA"]),
    ("EVD-ROW-T30", "row T30",
     "no Miri/valgrind was run on the new boundary",
     ["IMP-SECRET-OWNER", "IMP-BN-BIGNUM"]),
]
for eid, span, quote, impls in ROW_EVIDENCE:
    node(eid, "evidence", f"Queue status prose {span}",
         src("docs/ETP-TODO.md", span, quote, quote_kind="fragment"),
         kind="queue_status_prose", present=True,
         quality="status prose, not a receipt; it records the row's own state at the bound commit")
    for iid in impls:
        edge(iid, "evidenced_by", eid,
             f"{span} records the current state of {iid}; the row is prose, not a receipt")

# ---------------------------------------------------------------- declared orphans
for req in REQUIREMENTS:
    rid = req[0]
    if req[6]:
        orphan(f"ORPHAN-6:REQ:{rid}", 6, rid, "requirement_without_specification",
               "ETP-T1 does not create the specification; FRC-0 establishes the independent "
               "specification hierarchy, and the requirement is then refined by a specification node.")

orphans.extend([
    {"id": "ORPHAN-1:REQ-SPEC-01", "class": 1, "node": "REQ-SPEC-01",
     "reason": "no_implementation",
     "would_close": "FRC-0 (OBL-FRC-0) produces the specification hierarchy; the implementation "
                    "node is the checker that refuses an implementation-derived specification."},
    {"id": "ORPHAN-3:REL-OPENSSH-B85C", "class": 3, "node": "REL-OPENSSH-B85C",
     "reason": "adjudication_refuses",
     "would_close": "ETP-T15 reconciles the b85c graduation with the independent NOT ESTABLISHED "
                    "verdict and the OBL-MECH-* obligations are discharged; the release claim then "
                    "states the verdict its adjudication supports."},
    {"id": "ORPHAN-3:REL-COHORT-COUNTER-1-33", "class": 3, "node": "REL-COHORT-COUNTER-1-33",
     "reason": "adjudication_refuses+not_independent",
     "would_close": "ETP-T15 resolves the 1/33 vs 0/33 contradiction and an independent adjudication "
                    "records the cohort counter."},
    {"id": "ORPHAN-3:REL-L7-ATLAS-33-33", "class": 3, "node": "REL-L7-ATLAS-33-33",
     "reason": "adjudication_refuses",
     "would_close": "A fresh L7 replay at the claimed candidate (not a carried-forward atlas row) "
                    "and an adjudication that stops at PARTIAL until it exists."},
    {"id": "ORPHAN-3:REL-PERF-PFP0", "class": 3, "node": "REL-PERF-PFP0",
     "reason": "no_adjudication",
     "would_close": "An adjudication of the PFP-0 classification that is not the analyser itself; "
                    "the venue limitation keeps it SCOPED_OBSERVATION regardless."},
    {"id": "ORPHAN-3:REL-PERF-PFP1", "class": 3, "node": "REL-PERF-PFP1",
     "reason": "no_adjudication",
     "would_close": "An adjudication of the PFP-1 classification that is not the analyser itself."},
])

for path in ["court/tmp/t20/NOTES.md", "court/tmp/t21/libcrypto.so.3",
             "forensics/phase7_courts.py"]:
    matches = [eid for eid, n in nodes.items()
               if n["type"] == "evidence" and n["source"]["path"] == path]
    if len(matches) != 1:
        raise SystemExit(f"expected one evidence node for {path}, found {matches}")
    orphans.append({
        "id": f"ORPHAN-8:{matches[0]}:{path}", "class": 8, "node": matches[0],
        "reason": "path_absent",
        "would_close": "Track the artefact (or a content-addressed copy) at the commit the typed "
                       "claim names, or convert the claim's obligation into a tracked replacement.",
    })

orphans.append({
    "id": "ORPHAN-8:EV-HAZ-15-DIFFERENTIAL:evidence/haz-15/observables.json",
    "class": 8,
    "node": "EV-HAZ-15-DIFFERENTIAL",
    "reason": "path_absent",
    "would_close": "Track evidence/haz-15/observables.json at a named commit and re-seed "
                   "with that commit; the barrier then cites a settled evidence identity.",
})

# ---------------------------------------------------------------- refinement
# ETP-T3 owns the refinement architecture.  The six adjacent levels and the five
# edges between them are nodes in this graph so the orphan machinery covers the
# chain.  The obligation and status text projected here is the ETP-T3 record;
# the normative statement of the chain is docs/FORMAL-REFINEMENT-CERTIFICATION.md
# section 3 and docs/REFINEMENT-ARCHITECTURE.md.
REFINEMENT_SOURCE = src(
    "docs/FORMAL-REFINEMENT-CERTIFICATION.md", "§3",
    "Each link is a separate claim with its own evidence, TCB and invalidation rule.",
    bound=A,
)

LEVELS = [
    ("LVL-L1", 1, "abstract specification",
     "The normative statement of the operation, independent of any implementation."),
    ("LVL-L2", 2, "executable reference",
     "An independent executable implementation of the abstract specification."),
    ("LVL-L3", 3, "Rust implementation",
     "The crate under src/, whose safe interior refines the executable reference."),
    ("LVL-L4", 4, "ABI contract",
     "The observable C surface: signatures, ownership, error queue and callback semantics."),
    ("LVL-L5", 5, "machine code",
     "The exact compiled artefact deployed to a consumer."),
    ("LVL-L6", 6, "consumer composition",
     "The loaded DSO in a real consumer, with every reachable call site's precondition."),
]
for lid, rank, name, title in LEVELS:
    node(lid, "refinement_level", f"Level {rank}: {name}", REFINEMENT_SOURCE,
         rank=rank, name=name, description=title)

# The artefact that records every refinement obligation and its status.  It does
# not exist at the graph's bound commits yet, so its own digest is deferred to
# the ETP-T3 evidence commit while the node's source is the tracked document
# that states the chain.
node("ART-RFE-RECORD", "artefact", "ETP-T3 refinement architecture record",
     REFINEMENT_SOURCE,
     kind="refinement_record", path="evidence/etp-t3/REFINEMENT.json",
     digest="UNKNOWN", digest_identity="evidence commit E",
     settling_method="sha256 of evidence/etp-t3/REFINEMENT.json at the ETP-T3 evidence commit")

REFINEMENT_EDGES = [
    ("RFE-1", "LVL-L1", "LVL-L2", "NONE", "UNASSIGNED (ETP-T5 / FRC-1)", None,
     [],
     "OBL-RFE-1",
     "No independent executable reference exists; ETP-T5 is TODO.",
     "A change to the abstract specification, the reference, or the ETP-T5 conformance tool invalidates it.",
     "A proof about the abstract specification says nothing about whether the reference implements it; the reference can be wrong in the same way as any implementation."),
    ("RFE-2", "LVL-L2", "LVL-L3", "NONE", "UNASSIGNED (ETP-T5 differential)", None,
     [],
     "OBL-RFE-2",
     "No differential comparison against an independent executable reference exists; the differential courts compare against the OpenSSL authority, not against a reference derived from the abstract specification.",
     "A change to the reference, the Rust implementation, or the differential harness invalidates it.",
     "Agreement on a finite input population is not a refinement proof; a passing differential court is not evidence about inputs outside the population or about failure behaviour it did not exercise."),
    ("RFE-3", "LVL-L3", "LVL-L4", "PARTIAL",
     "ABI symbol, layout and version-script checks at the candidate",
     "ART-FILE-ABI-LAYOUT",
     ["the exported symbol set and the public layout probes; ownership, error-queue and callback semantics are not established"],
     "OBL-RFE-3",
     "The exported symbol set and public layouts are checked, but ownership, error-queue ordering and callback semantics are not established at the ABI contract.",
     "A change to any exported symbol, #[repr(C)] layout, error path or callback signature invalidates it; the contract must be re-measured at the new candidate.",
     "Checking the exported symbol set and layouts does not establish ownership, error-queue ordering or callback semantics; an ABI match is not a semantic or memory-safety result."),
    ("RFE-4", "LVL-L4", "LVL-L5", "NONE", "UNASSIGNED (ETP-T6 / FRC-4)", None,
     [],
     "OBL-RFE-4",
     "No object-code correspondence exists between the Rust source and the deployed DSO; reproducibility is a build-identity result, not a refinement argument.",
     "A change to the compiler, linker, assembler, target, profile or any build input invalidates it; no result carries across targets.",
     "A proof about the source is not a proof about the binary; build reproducibility shows the binary is deterministic, not that it refines the source, and source-level constant-time intent is not binary timing."),
    ("RFE-5", "LVL-L5", "LVL-L6", "PARTIAL",
     "consumer reachability closure at the loaded DSO",
     "ART-CURL-DSO-FD25",
     ["curl closure at fd25cc9e: 644 reachable files, 7/7 reachable production obligations",
      "ssh closure at b85c: 625 reachable files, 290/290 reachable production obligations"],
     "OBL-RFE-5",
     "The consumer closures classify reachability but do not establish Pre(c) => P at every reachable call site; the b85c graduation is NOT_ESTABLISHED and the curl element-7 refusal population remains open.",
     "A change to the DSO, the loader resolution or the consumer binary invalidates it; the closure is re-run at the new identities.",
     "A reachability classification is not a memory-safety proof and not a SAFE_COMPATIBLE promotion; the closure's own non-claims state that a discharged obligation means an existing receipt covers a site, not that the site's precondition is established."),
]

for eid, src_lvl, dst_lvl, status, discharger, discharge_artefact, population, obl, statement, invalidation, not_established in REFINEMENT_EDGES:
    node(eid, "refinement_edge", f"Refinement edge {src_lvl} -> {dst_lvl}",
         REFINEMENT_SOURCE,
         from_level=src_lvl, to_level=dst_lvl, status=status,
         discharged_by=discharger, discharge_artefact=discharge_artefact,
         bounded_population=population, obligation=obl,
         obligation_artefact="ART-RFE-RECORD",
         obligation_statement=statement,
         invalidation_rule=invalidation,
         does_not_establish=not_established)
    edge(src_lvl, "refines_to", eid, f"{src_lvl} is refined through {eid}")
    edge(eid, "discharges", dst_lvl, f"{eid} produces {dst_lvl}")

    if obl in obligation_ids:
        raise SystemExit(f"duplicate obligation {obl}")
    obligation_ids.add(obl)
    node(obl, "obligation", f"Refinement obligation on {eid}", REFINEMENT_SOURCE,
         statement=statement, state="OPEN",
         settled_by={
             "OBL-RFE-1": "An independent executable reference and a conformance run at a named candidate (ETP-T5, FRC-1).",
             "OBL-RFE-2": "A differential run against that reference over a frozen input population, including failure behaviour (ETP-T5).",
             "OBL-RFE-3": "Ownership, error-queue and callback semantics measured at the ABI contract, with the mechanisms' obligations discharged.",
             "OBL-RFE-4": "Object-code correspondence for the exact artefact, including the reassembly question (ETP-T6, FRC-4).",
             "OBL-RFE-5": "Every reachable consumer call site's precondition established at the loaded DSO identity (ETP-T10), and the ETP-T15 reconciliation closed.",
         }[obl],
         blocks_release_claims=[])
    edge(eid, "obligates", obl, f"{eid} carries the refinement obligation {obl}")
    edge("ART-RFE-RECORD", "raises", obl, f"the refinement record states {obl}")

for eid, _src, _dst, status, _by, _art, _pop, _obl, _st, _inv, _not in REFINEMENT_EDGES:
    if status == "NONE":
        orphan(f"ORPHAN-11:{eid}", 11, eid, "edge_without_discharge",
               "An independent reference, differential run or object-code correspondence is produced at a "
               "named candidate and the edge status is raised to BOUNDED or PARTIAL with the evidence recorded.")

# ---------------------------------------------------------------- ETP-T4 unsafe obligations
t4_document = json.loads((REPO / T4_SITES).read_text(encoding="utf-8"))
t4_axioms = json.loads((REPO / T4_AXIOMS).read_text(encoding="utf-8"))
if t4_document.get("schema") != "openssl-rs/etp/unsafe-sites/1":
    raise SystemExit("ETP-T4 inventory has an unexpected schema")
if t4_axioms.get("schema") != "openssl-rs/etp/axioms/1":
    raise SystemExit("ETP-T4 axiom register has an unexpected schema")
t4_summary = t4_document["summary"]
t4_detail = t4_summary["by_class_detail"]
t4_sites_sha = hashlib.sha256((REPO / T4_SITES).read_bytes()).hexdigest()
t4_axioms_sha = hashlib.sha256((REPO / T4_AXIOMS).read_bytes()).hexdigest()

node("IMP-UNSAFE-SURFACE", "implementation",
     "The crate's unsafe surface, as classified by ETP-T4",
     src("src/lib.rs", "crate root", "the crate under src/ is the implementation whose unsafe sites are classified",
         bound=T4),
     scope="every lexically identified unsafe construct and named raw operation under src/")
node("ART-UNSAFE-SITES", "artefact",
     "ETP-T4 unsafe-site inventory",
     worktree_src(T4_SITES, "sites", "one row per unsafe construct with class, impact, contract and coverage"),
     digest=t4_sites_sha, heuristic=True,
     detail="62,178 site rows and 767 operation rows, generated by forensics/tools/unsafe_obligations.py")
node("EV-ETP-T4-SITES", "evidence",
     "ETP-T4 unsafe-site obligation inventory",
     worktree_src(T4_SITES, "summary", "totals by obligation class, impact, contract state and coverage"),
     bound_artefact="ART-UNSAFE-SITES", record_kind="classification",
     independence="SAME_PARTY",
     authority="the inventory classifies sites; it does not discharge them")
node("EV-ETP-T4-AXIOMS", "evidence",
     "ETP-T4 axiom and admitted-result register",
     worktree_src(T4_AXIOMS, "axioms", "every premise the argument treats as true, with what falsifies it and what checks it"),
     record_kind="axiom_register", independence="SAME_PARTY",
     authority="the register states premises; it does not verify them")
edge("IMP-UNSAFE-SURFACE", "realised_by", "ART-UNSAFE-SITES",
     "the inventory classifies the implementation's unsafe sites")

for klass in t4_document["vocabularies"]["obligation_class"]:
    detail = t4_detail[klass]
    slug = klass.replace("_", "-").upper()
    oid = f"OBL-T4-{slug}"
    node(oid, "obligation", f"ETP-T4 unsafe obligation class {klass}",
         src("docs/UNSAFE.md", "section 2",
             "every unsafe block states which catalogue invariant it relies on and why it holds",
             bound=S),
         statement=(
             f"Every unsafe site of class {klass} has a validity argument or a control that "
             "could fail; a restatement of the operation is not a validity argument."),
         state="OPEN",
         settled_by=(
             "A per-site validity argument or a control that could fail, recorded against the "
             "site in evidence/etp-t4/SAFETY-SITES.json."),
         blocks_release_claims=["REL-OPENSSH-B85C", "REL-L7-ATLAS-33-33"],
         unsafe_site_inventory={
             "class": klass,
             "sites": detail["sites"],
             "contract_argument": detail["contract_argument"],
             "contract_restatement": detail["contract_restatement"],
             "contract_absent": detail["contract_absent"],
             "controlled": detail["controlled"],
             "sites_without_contract_or_control": detail["sites_without_contract_or_control"],
         })
    edge("IMP-UNSAFE-SURFACE", "raises", oid,
         f"the unsafe surface contains sites of class {klass}")
    edge(oid, "evidenced_by", "EV-ETP-T4-SITES",
         f"the inventory records the sites of class {klass}")
    for cid in ("REL-OPENSSH-B85C", "REL-L7-ATLAS-33-33"):
        edge(oid, "constrains", cid,
             f"an unconverted obligation in class {klass} constrains the release claim")
    if detail["sites_without_contract_or_control"] > 0:
        orphan(f"ORPHAN-12:{oid}", 12, oid, "no_contract_or_control",
               "Provide a validity argument or a control that could fail for every uncovered site "
               "in the class and regenerate evidence/etp-t4/SAFETY-SITES.json.")

for nid, path in (
    ("ART-UNSAFE-SITES", T4_SITES),
    ("EV-ETP-T4-SITES", T4_SITES),
    ("EV-ETP-T4-AXIOMS", T4_AXIOMS),
):
    orphan(f"ORPHAN-8:{nid}:{path}", 8, nid, "path_absent",
           "Commit evidence/etp-t4/ and re-run the seed with T4 set to that commit, so the "
           "node is bound to the commit that contains the file.")

# ---------------------------------------------------------------- output
nodes_out = [nodes[k] for k in sorted(nodes)]
edges_out = sorted(edges, key=lambda e: (e["from"], e["type"], e["to"]))
orphans_out = sorted(orphans, key=lambda o: (o["class"], o["id"]))

document = {
    "schema": "openssl-rs/etp/traceability/1",
    "kind": "requirements-traceability-graph",
    "item": "ETP-T1 of docs/ETP-TODO.md",
    "identity": {
        "commit": S,
        "branch": "staging",
        "worktree_state": "clean at S; the ETP-T1 evidence files are untracked until the evidence commit",
        "digest_rule": "sha256 of the Git blob at the node's bound_commit; digests are read from the "
                       "named commit, never from the working tree",
        "evidence_commit": "UNKNOWN",
        "settling_method": "the commit that adds evidence/etp-t1/ and the ETP-T1 row; settled by "
                           "git log -1 --format=%H -- evidence/etp-t1/TRACEABILITY.json",
    },
    "model": {
        "node_types": ["threat", "hazard", "requirement", "specification", "implementation",
                        "artefact", "obligation", "evidence", "adjudication", "release_claim"],
        "edge_types": {
            "motivates": "hazard|threat -> requirement (the hazard is the stated reason for the requirement)",
            "refines": "requirement -> specification (the requirement is refined by an independent specification)",
            "satisfied_by": "requirement|specification -> implementation",
            "realised_by": "implementation -> artefact",
            "raises": "hazard|implementation|artefact -> obligation",
            "evidenced_by": "hazard|requirement|implementation|artefact|obligation|adjudication -> evidence",
            "assessed_by": "evidence|requirement -> adjudication",
            "releases": "adjudication -> release_claim",
            "constrains": "obligation -> release_claim",
        },
        "direction": "every edge points from the provider to the candidate along the trace direction; "
                     "a cycle in this direction is a circular support claim",
        "cardinality": {
            "requirement": "at least one satisfied_by implementation (class 1); "
                           "specification_required=true requires at least one refining specification (class 6)",
            "implementation": "at least one realised_by artefact (class 2)",
            "specification": "at least one reachable implementation (class 6)",
            "release_claim": "at least one releases adjudication (class 3), independent where required",
            "obligation": "every blocks_release_claims target must have a constrains edge (class 5)",
            "evidence": "one source path and bound commit; a digest that disagrees is class 4",
            "hazard": "a scope naming one API family and one input class, a non-empty trigger "
                      "class set, at least one motivates edge, an affected_release_claims list "
                      "derived from its requirements and obligations, and a barrier state; "
                      "a contract-violation trigger forbids a memory-safety claim",
            "node": "one source path that exists at its bound commit (class 8)",
            "unsafe obligation": "an unsafe-site inventory whose sites_without_contract_or_control "
                                 "count is zero; a positive count is class 12",
        },
    },
    "etp_t4": {
        "candidate": T4,
        "inventory": {"path": T4_SITES, "sha256": t4_sites_sha},
        "axioms": {"path": T4_AXIOMS, "sha256": t4_axioms_sha},
        "scanner": {
            "path": t4_document["identity"]["scanner"],
            "sha256": t4_document["identity"]["scanner_sha256"],
            "heuristic": True,
        },
        "source_tree_sha256": t4_document["identity"]["source_tree_sha256"],
        "settling_method": "re-run forensics/tools/unsafe_obligations.py inventory and this "
                           "seed at the evidence commit; the class-8 orphans settle there",
    },
    "hazard_register": {
        "path": "evidence/etp-t2/HAZARDS.json",
        "sha256": HAZARD_REGISTER_SHA,
        "settling_method": "sha256 of the register file the graph projects; the register is the "
                           "ETP-T2 deliverable and the graph projects its hazard entries",
    },
    "tool": {
        "path": "forensics/tools/traceability.py",
        "digest_at_S": "UNKNOWN",
        "settling_method": "the tool does not exist at S; its digest is recorded by the evidence commit E",
    },
    "nodes": nodes_out,
    "edges": edges_out,
    "orphans": orphans_out,
    "non_claims": [
        "The graph records what the tracked records state; it does not establish that a requirement is met.",
        "An edge means the cited record states the relation; it is not a proof of the relation.",
        "A specification node's independence is a claim about provenance, not about correctness.",
        "The orphan machinery detects the twelve named omissions only; it does not detect stale evidence, "
        "an incorrect measurement or a false claim that cites a real record.",
        "MC/DC and structural coverage are not measured for this graph; the coverage gap is recorded in "
        "docs/REQUIREMENTS-TRACEABILITY.md and is not a pass.",
        "An ETP-T4 obligation node records a class-level inventory, not a per-site proof; a class "
        "with uncovered sites is class 12, and a covered class is not thereby SAFETY_DISCHARGED.",
    ],
}

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(document, indent=2, sort_keys=False) + "\n", encoding="utf-8")
print(f"wrote {OUT}: {len(nodes_out)} nodes, {len(edges_out)} edges, {len(orphans_out)} orphans")
