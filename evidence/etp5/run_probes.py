#!/usr/bin/env python3
"""ETP-5 refusal probes.

Each probe is a schema-typed claim (or claim set) that types a *promotion* a
consumer of the historical records could attempt, or types the record exactly
as it stands.  The probes are fed to the hardened validator in
`forensics/tools/etp_claims.py`; the observed refusals are the evidence.

Nothing here promotes a claim.  A probe that the validator accepts is recorded
as an accepted probe, not as a pass for the underlying claim: an accepted
promotion is a finding about the machinery, and the finding is listed in
`evidence/etp5/REFUSALS.json`.

Run from the repository root:

    python3 evidence/etp5/run_probes.py

Writes `evidence/etp5/probes/*.json` and `evidence/etp5/PROBE-RESULTS.json`.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "forensics" / "tools"))

import etp_claims as etp  # noqa: E402

OUT = Path(__file__).resolve().parent
PROBES = OUT / "probes"

CLAIMS = json.loads((ROOT / "evidence/etp/claims.json").read_text())
SOURCE_IDENTITY = CLAIMS["source_identity"]
DERIVED_FROM = CLAIMS["derived_from"]

B85_SOURCE = "17042ccf29bc39df638c63e69d3be6c6f965eef7"
B85_DSO = "06b5f3384e3480c694ef2735c84b845311e1b86152026c26e50853f89f618f71"
B85_SSL = "1901de061d9d9793849b8c2d2b73847c7feb61339708062aea064a95f0e60b2b"
B85_SSH = "c2db343dfa5135272f2be6960210b3b99af83b9ed181034e976e1c68e98fff8b"
B85_SSHD = "8af509523ed16f68fe74a75aef923b78e87b047c054ea30fc2aa6d9971485ae1"
B85_TOOL = "3e86a74dbbe9095ca98ef3b8d889ec67a9447e59ef1caceecaa72152202988a1"

B_HOST = "3c3a68c1baeb304adf2fc3af827e49b14529556008429bd11dda784a2c6cdfd1"
B_COURT = "ee7fa27c79f5a679d5b229429d53dc7c3b510695db9c74d11b4b6783a735ebe9"
CURL_CRYPTO = "fd25cc9e6424ea79aaaff05df22b3f6e1d46aa22d5666cfe7589dce95ffd88a9"
CURL_SSL = "648f8caecda245d2186813fb67ceadedd798b9ce609c8b041a84f195946c5f68"


def sha(path: str) -> str:
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def ev(eid: str, path: str, kind: str = "record", identity: str = "E", digest: str | None = None,
       present: object = True, reconstructable: object = "partial", note: str | None = None) -> dict:
    entry = {
        "id": eid,
        "path": path,
        "kind": kind,
        "sha256": digest if digest is not None else sha(path),
        "digest_identity": identity,
        "present": present,
        "reconstructable": reconstructable,
    }
    if note:
        entry["note"] = note
    return entry


def obligation(oid: str, statement: str, settled_by: str, evidence: list[str],
               blocks: list[str]) -> dict:
    return {
        "id": oid,
        "statement": statement,
        "state": "OPEN",
        "blocks": blocks,
        "settled_by": settled_by,
        "evidence": evidence,
    }


def claim(**kw) -> dict:
    body = {
        "id": kw["id"],
        "property": kw["property"],
        "interpretation": kw["interpretation"],
        "quantification": kw.get("quantification") or {
            "kind": "universal",
            "population": kw["population"],
            "population_size": None,
            "measure": {"form": "count", "value": kw["measure"], "aggregation": "forbidden"},
        },
        "scope": {
            "kind": kw.get("scope_kind", "record"),
            "subject": kw["subject"],
            "venue": kw.get("venue"),
            "locations": kw["locations"],
            "excludes": [],
        },
        "threat_model": {
            "adversary": kw.get(
                "adversary",
                "candidate/evidence mismatch: a verdict attributed to an identity the record does not bind",
            ),
            "observation_model": kw.get(
                "observation",
                "the historical records are read at their own digests; no new measurement is claimed",
            ),
            "out_of_scope": ["behaviour outside the cited records"],
        },
        "identity": {
            "source": {
                "candidate": kw["candidate"],
                "commit": kw.get("commit"),
                "binding": kw.get("binding", "exact"),
                "tree_sha256": None,
            },
            "build": {
                "toolchain": kw.get("toolchain"),
                "profile": kw.get("profile"),
                "target": kw.get("target"),
            },
            "artefacts": kw.get("artefacts", []),
        },
        "authority": {
            "kind": kw.get("authority_kind", "machine-record"),
            "name": kw["authority"],
            "version": kw.get("authority_version"),
            "path": kw["authority_path"],
        },
        "target": {"kind": kw.get("target_kind", "record"), "name": kw["target"], "path": kw["target_path"]},
        "assumptions": kw.get("assumptions", []),
        "evidence": kw["evidence"],
        "tcb": [
            {"component": "Git object store", "trusted_for": "the tracked bytes and commit identities cited", "verified": False},
            {"component": "court/venue", "trusted_for": "execution of any cited procedure", "verified": False},
        ],
        "obligations": kw.get("obligations", []),
        "invalidation": {
            "depends_on": [{"kind": "path", "id": e["path"]} for e in kw["evidence"] if e.get("path")],
            "rationale": "a change to any cited record invalidates this claim conservatively",
        },
        "modality": kw["modality"],
        "reproduction": {"status": "NOT_ATTEMPTED", "procedure": None, "at": None},
        "verdict": {"state": kw["verdict"], "basis": kw["basis"]},
    }
    if kw.get("closure") is not None:
        body["closure"] = kw["closure"]
    if kw.get("contradiction") is not None:
        body["contradiction"] = kw["contradiction"]
    if kw.get("derived_from") is not None:
        body["derived_from"] = kw["derived_from"]
    return body


def document(claims: list[dict]) -> dict:
    return {
        "schema": "openssl-rs/etp/claims/v1",
        "kind": "etp-typed-claims",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_identity": SOURCE_IDENTITY,
        "derived_from": DERIVED_FROM,
        "claims": claims,
    }


# ---------------------------------------------------------------------------
# Probe definitions
# ---------------------------------------------------------------------------

SAFE_FILE = "evidence/SAFE-COMPATIBLE-openssh-b85c.json"
SSH_CLOSURE = "evidence/closure-ssh-b85c.json"
SSHD_CLOSURE = "evidence/closure-sshd-b85c.json"
FREEZE = "evidence/FREEZE-b85c.json"
ADJUDICATION = "evidence/b85c-adjudication.json"
STATUS = "forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json"
PROGRESS = "forensics/memory-safety/campaign/safe-c33/PROGRESS.md"
STATUS_OCT = "forensics/memory-safety/campaign/safe-c33/STATUS-2026-10-20.md"
O7 = "courts/phase18/interop/RECEIPT-o7.json"
O7_BB = "courts/phase18/interop/RECEIPT-o7-BB.json"
O4 = "courts/phase18/interop/RECEIPT-o4.json"
O5 = "courts/phase18/interop/RECEIPT-o5.json"
O11B = "courts/phase18/interop/MANIFEST-o11-B.json"
O7_AB = "courts/phase18/interop/RECEIPT-o7-AB.json"
CURL_CLOSURE = "evidence/closure-curl-049.json"
E7_TRIAGE = "evidence/element7-curl-049-triage.json"
E7_LAST34 = "evidence/element7-curl-049-last34-notes.md"

WITHDRAWN_O7_SHA = "2ee7ee4d8fb3b909cc007a14d9dabf511fb90bb2f8f2f32d92b893004e8bd0a0"

OPENSSH_SUBJECT = "OpenSSH ssh and sshd"
OPENSSH_CANDIDATE = "b85c, source_head 17042ccf2"
OPENSSH_ARTEFACTS = [
    {"label": "freeze", "sha256": "b08131b1ca7849a3e7f801b87f427774df346366344a2b24bd8207fcb847ec4e", "path": FREEZE},
    {"label": "libcrypto.so.3", "sha256": B85_DSO, "path": None},
    {"label": "libssl.so.3", "sha256": B85_SSL, "path": None},
    {"label": "ssh", "sha256": B85_SSH, "path": None},
    {"label": "sshd", "sha256": B85_SSHD, "path": None},
    {"label": "consumer_closure.py", "sha256": B85_TOOL, "path": None},
]


def p1_openssh_graduation_promotion() -> dict:
    evidence = [
        ev("EV-01", SAFE_FILE),
        ev("EV-02", SSH_CLOSURE),
        ev("EV-03", SSHD_CLOSURE),
        ev("EV-04", FREEZE),
        ev("EV-05", ADJUDICATION),
    ]
    return document([
        claim(
            id="ETP5-CLM-001",
            property="consumer-graduation",
            interpretation="Promote ssh and sshd to SAFE_COMPATIBLE at b85c on the strength of the graduation record alone.",
            population="two consumer binaries, one admitted cohort family",
            measure="2 binaries; graduation record says 290/290 discharged",
            subject=OPENSSH_SUBJECT,
            venue="b85c frozen artefacts",
            locations=[SAFE_FILE, SSH_CLOSURE, SSHD_CLOSURE, FREEZE, ADJUDICATION],
            candidate=OPENSSH_CANDIDATE,
            commit=B85_SOURCE,
            artefacts=OPENSSH_ARTEFACTS,
            authority="evidence/SAFE-COMPATIBLE-openssh-b85c.json",
            authority_path=SAFE_FILE,
            target="OpenSSH consumer graduation record",
            target_path=SAFE_FILE,
            evidence=evidence,
            obligations=[
                obligation(
                    "OBL-ETP5-OPENSSH-CONTRADICTION",
                    "The two closure receipts the graduation cites record verdict.safe_compatible=false; "
                    "evidence/FREEZE-b85c.json records the L7 replay as not graduated and safe_compatible=false; "
                    "evidence/b85c-adjudication.json records NOT ESTABLISHED. The graduation cannot be promoted "
                    "while these records stand.",
                    "Withdraw the SAFE_COMPATIBLE label or record a policy that a principal risk acceptance overrides "
                    "the AGENTS.md section 7 criteria; reconciliation is ETP-T15.",
                    ["EV-01", "EV-02", "EV-03", "EV-04", "EV-05"],
                    ["verdict", "graduation"],
                )
            ],
            closure={
                "dependencies": [
                    SSH_CLOSURE,
                    SSHD_CLOSURE,
                    FREEZE,
                    ADJUDICATION,
                ],
                "unresolved_dependencies": [
                    "closure-ssh-b85c: verdict.safe_compatible=false",
                    "closure-sshd-b85c: verdict.safe_compatible=false",
                    "FREEZE-b85c: L7 replay not_graduated, safe_compatible=false",
                    "b85c-adjudication: NOT ESTABLISHED",
                ],
                "complete": False,
            },
            modality="PROOF_OBLIGATIONS_DISCHARGED",
            verdict="SAFE_COMPATIBLE",
            basis="The promotion a consumer of the graduation record alone would read.",
        )
    ])


def p2_openssh_two_records() -> dict:
    graduation = claim(
        id="ETP5-CLM-002",
        property="consumer-graduation",
        interpretation="Type the b85c graduation record as its own record, at its own provenance.",
        population="two consumer binaries",
        measure="SAFE_COMPATIBLE per the graduation record",
        subject=OPENSSH_SUBJECT,
        venue="graduation record at source_head 17042ccf2",
        locations=[SAFE_FILE],
        candidate=OPENSSH_CANDIDATE,
        commit=B85_SOURCE,
        artefacts=OPENSSH_ARTEFACTS,
        authority="evidence/SAFE-COMPATIBLE-openssh-b85c.json",
        authority_path=SAFE_FILE,
        target="OpenSSH consumer graduation record",
        target_path=SAFE_FILE,
        evidence=[ev("EV-01", SAFE_FILE)],
        closure={"dependencies": [SAFE_FILE], "unresolved_dependencies": [], "complete": True},
        modality="PROOF_OBLIGATIONS_DISCHARGED",
        verdict="SAFE_COMPATIBLE",
        basis="What the graduation record asserts about itself.",
    )
    adjudication = claim(
        id="ETP5-CLM-003",
        property="consumer-graduation",
        interpretation="Type the independent b85c adjudication as its own record, at its own provenance.",
        population="two consumer binaries",
        measure="NOT ESTABLISHED per the adjudication",
        subject=OPENSSH_SUBJECT,
        venue="adjudication at head bfa39a6c3 over evidence source head 17042ccf2",
        locations=[ADJUDICATION],
        candidate=OPENSSH_CANDIDATE,
        commit=B85_SOURCE,
        artefacts=OPENSSH_ARTEFACTS,
        authority="evidence/b85c-adjudication.json",
        authority_path=ADJUDICATION,
        target="OpenSSH consumer graduation adjudication",
        target_path=ADJUDICATION,
        evidence=[ev("EV-01", ADJUDICATION)],
        obligations=[
            obligation(
                "OBL-ETP5-ADJUDICATION-SETTLE",
                "The adjudication records NOT ESTABLISHED: five of seven mechanisms are NOT_ESTABLISHED and all four "
                "cross-cutting obligations are NOT_ESTABLISHED.",
                "Reconcile the two records under ETP-T15, or establish the five NOT_ESTABLISHED mechanisms.",
                ["EV-01"],
                ["verdict", "graduation"],
            )
        ],
        modality="INSTRUMENTED",
        verdict="NOT_ESTABLISHED",
        basis="What the independent adjudication asserts about itself.",
    )
    return document([graduation, adjudication])


def p3_counter_single_source() -> dict:
    return document([
        claim(
            id="ETP5-CLM-004",
            property="consumer-graduation",
            interpretation="Type the Safe-33 cohort counter contradiction with both statements sourced from the one file that carries both.",
            population="33 admitted cohort families",
            measure="1/33 and 0/33 both recorded in one file",
            scope_kind="ledger",
            subject="Safe-33 cohort counter",
            venue="ledger",
            locations=[STATUS],
            candidate="b85c graduation",
            commit="1e7c221f0",
            artefacts=[{"label": "CAMPAIGN-STATUS.json", "sha256": sha(STATUS), "path": STATUS}],
            authority="forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json",
            authority_path=STATUS,
            target="Safe-33 cohort counter",
            target_path=STATUS,
            evidence=[ev("EV-01", STATUS)],
            obligations=[
                obligation(
                    "OBL-ETP5-COUNTER",
                    "consumers.safe_compatible is 1 and safe_compatible_graduation.verdict is SAFE_COMPATIBLE, while "
                    "the same file's consumers.note says SAFE_COMPATIBLE remains 0/33 and non_claims[0] says the "
                    "counter remains 0/33.",
                    "Reconcile the counter and the non-claim in one ledger edit (ETP-T15).",
                    ["EV-01"],
                    ["verdict", "graduation"],
                )
            ],
            contradiction={
                "parties": [
                    {
                        "id": "counter-field",
                        "source": STATUS,
                        "assertion": "consumers.safe_compatible = 1 and safe_compatible_graduation.verdict = SAFE_COMPATIBLE",
                        "asserted_verdict": "SAFE_COMPATIBLE",
                        "evidence": [STATUS],
                    },
                    {
                        "id": "note-and-non-claim",
                        "source": STATUS,
                        "assertion": "consumers.note says SAFE_COMPATIBLE remains 0/33 and non_claims[0] says the counter remains 0/33",
                        "asserted_verdict": "REFUTED",
                        "evidence": [STATUS],
                    },
                ],
                "resolution_owner": "ETP-T15",
            },
            modality="DOCUMENTED",
            verdict="CONTRADICTED",
            basis="Both contradictory statements are in CAMPAIGN-STATUS.json.",
        )
    ])


def p3b_counter_promotion() -> dict:
    families = json.loads((ROOT / STATUS).read_text())["consumers"]["l7_families"]
    return document([
        claim(
            id="ETP5-CLM-005",
            property="consumer-graduation",
            interpretation="Promote the Safe-33 cohort counter to SAFE_COMPATIBLE on the 1/33 reading.",
            population="33 admitted cohort families",
            measure="1 of 33 graduated",
            quantification={
                "kind": "enumerated",
                "population": "the 33 admitted cohort families",
                "population_size": len(families),
                "members": sorted(families),
                "measure": {"form": "ratio", "value": "1/33 while consumers.note says 0/33", "aggregation": "forbidden"},
            },
            scope_kind="ledger",
            subject="Safe-33 cohort counter",
            venue="ledger",
            locations=[STATUS],
            candidate="b85c graduation",
            commit="1e7c221f0",
            artefacts=[{"label": "CAMPAIGN-STATUS.json", "sha256": sha(STATUS), "path": STATUS}],
            authority="forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json",
            authority_path=STATUS,
            target="Safe-33 cohort counter",
            target_path=STATUS,
            evidence=[ev("EV-01", STATUS)],
            obligations=[
                obligation(
                    "OBL-ETP5-COUNTER",
                    "The same file's consumers.note says SAFE_COMPATIBLE remains 0/33 and non_claims[0] says the "
                    "counter remains 0/33; the 32 other cohort families are L7-functional, not SAFE_COMPATIBLE.",
                    "Reconcile the counter in one ledger edit and graduate only families whose whole dependency "
                    "closure is SAFETY_DISCHARGED (ETP-T15).",
                    ["EV-01"],
                    ["verdict", "graduation"],
                )
            ],
            closure={
                "dependencies": sorted(families),
                "unresolved_dependencies": ["32 of 33 families are not SAFE_COMPATIBLE"],
                "complete": False,
            },
            modality="PROOF_OBLIGATIONS_DISCHARGED",
            verdict="SAFE_COMPATIBLE",
            basis="The 1/33 reading promoted over the 0/33 statement in the same file.",
        )
    ])


def p4_withdrawn(identity: str, digest: str, eid: str, verdict: str) -> dict:
    return document([
        claim(
            id=eid,
            property="compatibility",
            interpretation="Type the first O7 four-cell result as a claim over the bytes at its own revision.",
            population="four cells, two builds",
            measure="four cells reported; withdrawal record present",
            subject="O7 first four-cell interoperability result",
            venue="revision cc2e5fa32",
            locations=[O7],
            candidate="pre-fix host build",
            commit="cc2e5fa32",
            authority="courts/phase18/interop/RECEIPT-o7.json",
            authority_path=O7,
            target="O7 first four-cell result",
            target_path=O7,
            evidence=[ev("EV-01", O7, identity=identity, digest=digest,
                         note="revision at cc2e5fa32 carries status WITHDRAWN and withdrawn: true")],
            modality="TESTED" if verdict == "ESTABLISHED" else "DOCUMENTED",
            verdict=verdict,
            basis=(
                "A consumer that reads the withdrawn revision's four cells as a current result."
                if verdict == "ESTABLISHED"
                else "The revision declares itself withdrawn; the verdict preserves that."
            ),
        )
    ])


def p5_identity_split() -> dict:
    # `candidates` is the only carrier the pre-scan recognises for a claim that
    # names two candidate identities. The closed schema has no such field, so
    # the probe also records the schema refusal that accompanies it.
    doc = document([
        claim(
            id="ETP5-CLM-009",
            property="identity",
            interpretation="Bind build B to both DSO digests the tracked interop records name, as one identity.",
            population="build B across O4/O5/O11 and O7",
            measure="two DSO digests: 3c3a68c1 and ee7fa27c",
            subject="OpenSSH build B",
            venue="interop records",
            locations=[O4, O5, O11B, O7_AB, O7_BB],
            candidate="B = 3c3a68c1",
            commit=None,
            artefacts=[
                {"label": "B-host", "sha256": B_HOST, "path": None},
                {"label": "B-court", "sha256": B_COURT, "path": None},
            ],
            authority="courts/phase18/interop/RECEIPT-o4.json",
            authority_path=O4,
            target="OpenSSH build B",
            target_path=O4,
            evidence=[ev("EV-01", O4), ev("EV-02", O5), ev("EV-03", O11B), ev("EV-04", O7_AB), ev("EV-05", O7_BB)],
            obligations=[
                obligation(
                    "OBL-ETP5-BUILD-B-SPLIT",
                    "O4, O5 and the O11 B manifest bind build B to libcrypto 3c3a68c1 (host build); the O7 matrix "
                    "and its per-cell B receipts bind build B to libcrypto ee7fa27c (court rebuild). No tracked "
                    "record joins the two digests to one archive and one toolchain.",
                    "One build record naming the source commit, archive digest, toolchain and both DSO digests, or "
                    "a rebuild of both in one venue from the O2 pins.",
                    ["EV-01", "EV-02", "EV-03", "EV-04", "EV-05"],
                    ["identity", "verdict"],
                )
            ],
            modality="TESTED",
            verdict="PARTIAL",
            basis="The two populations are recorded; their relationship is not.",
        )
    ])
    doc["claims"][0]["identity"]["source"]["candidates"] = [B_HOST, B_COURT]
    return doc


def p6_curl_element7_closed() -> dict:
    return document([
        claim(
            id="ETP5-CLM-010",
            property="memory-safety",
            interpretation="Read the element-7 refusal population as closed because no tracked run currently reports a refusal.",
            population="curl element-7 target-bounded reachable sites",
            measure="no current run reports a refusal",
            subject="curl element-7 refusal population",
            venue="tracked curl closure and repair records",
            locations=[CURL_CLOSURE, E7_TRIAGE, E7_LAST34],
            candidate="curl 0.0.49, install libcrypto fd25cc9e",
            commit=None,
            artefacts=[
                {"label": "libcrypto.so.3", "sha256": CURL_CRYPTO, "path": None},
                {"label": "libssl.so.3", "sha256": CURL_SSL, "path": None},
            ],
            authority="evidence/closure-curl-049.json",
            authority_path=CURL_CLOSURE,
            target="curl element-7 refusal population",
            target_path=E7_TRIAGE,
            evidence=[ev("EV-01", CURL_CLOSURE), ev("EV-02", E7_TRIAGE), ev("EV-03", E7_LAST34)],
            modality="TESTED",
            verdict="ESTABLISHED",
            basis="A consumer that equates absence of a tracked failure with closure.",
        )
    ])


def p6b_curl_graduation_promotion() -> dict:
    return document([
        claim(
            id="ETP5-CLM-011",
            property="consumer-graduation",
            interpretation="Promote curl to SAFE_COMPATIBLE while element 7 reports FAIL.",
            population="one consumer family",
            measure="closure ACCEPTED; element 7 FAIL; 27 named refusals after the repair batches",
            subject="curl consumer family",
            venue="curl 0.0.49 closure and element-7 records",
            locations=[CURL_CLOSURE, E7_TRIAGE, E7_LAST34],
            candidate="curl 0.0.49, install libcrypto fd25cc9e",
            commit=None,
            artefacts=[
                {"label": "libcrypto.so.3", "sha256": CURL_CRYPTO, "path": None},
                {"label": "libssl.so.3", "sha256": CURL_SSL, "path": None},
            ],
            authority="evidence/closure-curl-049.json",
            authority_path=CURL_CLOSURE,
            target="curl consumer family",
            target_path=CURL_CLOSURE,
            evidence=[ev("EV-01", CURL_CLOSURE), ev("EV-02", E7_TRIAGE), ev("EV-03", E7_LAST34)],
            obligations=[
                obligation(
                    "OBL-ETP5-CURL-ELEMENT7",
                    "evidence/element7-curl-049-triage.json records predicate_element_7 established=false, status FAIL "
                    "(449 reachable unresolved, 219 target-bounded); the repair notes record 27 named rows still "
                    "refused and a full closure NOT_RUN. Element 7 is not closed.",
                    "A full closure run at a frozen identity that establishes element 7, or a bounded contract for "
                    "every remaining refusal with its own witness.",
                    ["EV-02", "EV-03"],
                    ["verdict", "graduation"],
                )
            ],
            closure={
                "dependencies": [CURL_CLOSURE, E7_TRIAGE, E7_LAST34],
                "unresolved_dependencies": ["element 7 FAIL: 27 named refusals remain; full closure NOT_RUN"],
                "complete": False,
            },
            modality="PROOF_OBLIGATIONS_DISCHARGED",
            verdict="SAFE_COMPATIBLE",
            basis="The promotion a consumer of the 27-row repair notes could attempt.",
        )
    ])


def p6c_curl_element7_typed() -> dict:
    closure = claim(
        id="ETP5-CLM-012",
        property="compatibility",
        interpretation="Type the curl-049 closure record's own verdict, which is ACCEPTED with safe_compatible false.",
        population="curl reachable files",
        measure="644 reachable files; 7 obligations discharged; safe_compatible false",
        subject="curl consumer closure",
        venue="curl 0.0.49",
        locations=[CURL_CLOSURE],
        candidate="curl 0.0.49, install libcrypto fd25cc9e",
        commit=None,
        artefacts=[{"label": "libcrypto.so.3", "sha256": CURL_CRYPTO, "path": None}],
        authority="evidence/closure-curl-049.json",
        authority_path=CURL_CLOSURE,
        target="curl consumer closure",
        target_path=CURL_CLOSURE,
        evidence=[ev("EV-01", CURL_CLOSURE)],
        obligations=[
            obligation(
                "OBL-ETP5-CURL-CLOSURE-NOT-GRADUATED",
                "verdict.state is ACCEPTED but verdict.safe_compatible is false; ACCEPTED is a closure-predicate "
                "result, not a graduation.",
                "Establish every applicable mechanism and element 7, then adjudicate SAFE_COMPATIBLE.",
                ["EV-01"],
                ["verdict", "graduation"],
            )
        ],
        modality="TESTED",
        verdict="PARTIAL",
        basis="The record's own safe_compatible=false.",
    )
    element7 = claim(
        id="ETP5-CLM-013",
        property="memory-safety",
        interpretation="Type element 7 exactly as the triage and the repair notes record it.",
        population="curl element-7 target-bounded reachable sites",
        measure="FAIL; 219 target-bounded at triage; 27 named refusals after the repairs; full closure NOT_RUN",
        subject="curl element-7 refusal population",
        venue="curl 0.0.49",
        locations=[E7_TRIAGE, E7_LAST34],
        candidate="curl 0.0.49, install libcrypto fd25cc9e",
        commit=None,
        artefacts=[{"label": "libcrypto.so.3", "sha256": CURL_CRYPTO, "path": None}],
        authority="evidence/element7-curl-049-triage.json",
        authority_path=E7_TRIAGE,
        target="curl element-7 refusal population",
        target_path=E7_TRIAGE,
        evidence=[ev("EV-01", E7_TRIAGE), ev("EV-02", E7_LAST34)],
        obligations=[
            obligation(
                "OBL-ETP5-CURL-ELEMENT7",
                "established=false, status FAIL; 27 named rows remain refused; no full closure run after the tool "
                "changes.",
                "A full closure run at a frozen identity, or a bounded contract with a witness for each refusal.",
                ["EV-01", "EV-02"],
                ["verdict", "graduation"],
            )
        ],
        modality="INSTRUMENTED",
        verdict="NOT_ESTABLISHED",
        basis="The triage's own established=false.",
    )
    return document([closure, element7])


def p3c_counter_two_established() -> dict:
    def counter(eid: str, value: str, basis: str) -> dict:
        return claim(
            id=eid,
            property="consumer-graduation",
            interpretation=f"Type the counter reading {value} as an established fact.",
            population="33 admitted cohort families",
            measure=f"counter = {value}",
            scope_kind="ledger",
            subject="Safe-33 cohort counter",
            venue="ledger",
            locations=[STATUS],
            candidate="b85c graduation",
            commit="1e7c221f0",
            artefacts=[{"label": "CAMPAIGN-STATUS.json", "sha256": sha(STATUS), "path": STATUS}],
            authority="forensics/memory-safety/campaign/safe-c33/CAMPAIGN-STATUS.json",
            authority_path=STATUS,
            target="Safe-33 cohort counter",
            target_path=STATUS,
            evidence=[ev("EV-01", STATUS)],
            modality="DOCUMENTED",
            verdict="ESTABLISHED",
            basis=basis,
        )
    return document([
        counter(
            "ETP5-CLM-014",
            "1/33",
            "consumers.safe_compatible = 1 and safe_compatible_graduation.verdict = SAFE_COMPATIBLE",
        ),
        counter(
            "ETP5-CLM-015",
            "0/33",
            "consumers.note says SAFE_COMPATIBLE remains 0/33 and non_claims[0] says the counter remains 0/33",
        ),
    ])


PROBE_BUILDERS = {
    "p1-openssh-graduation-promotion": p1_openssh_graduation_promotion,
    "p2-openssh-two-records": p2_openssh_two_records,
    "p3-counter-single-source": p3_counter_single_source,
    "p3b-counter-promotion": p3b_counter_promotion,
    "p3c-counter-two-established": p3c_counter_two_established,
    "p4a-withdrawn-o7-historical-accepted": lambda: p4_withdrawn(
        "historical", WITHDRAWN_O7_SHA, "ETP5-CLM-006", "ESTABLISHED"),
    "p4b-withdrawn-o7-current-identity": lambda: p4_withdrawn(
        "E", WITHDRAWN_O7_SHA, "ETP5-CLM-007", "ESTABLISHED"),
    "p4c-withdrawn-o7-nonpromotion": lambda: p4_withdrawn(
        "historical", WITHDRAWN_O7_SHA, "ETP5-CLM-008", "WITHDRAWN"),
    "p5-build-b-identity-split": p5_identity_split,
    "p6-curl-element7-closed": p6_curl_element7_closed,
    "p6b-curl-graduation-promotion": p6b_curl_graduation_promotion,
    "p6c-curl-element7-typed": p6c_curl_element7_typed,
}


def main() -> int:
    PROBES.mkdir(parents=True, exist_ok=True)
    schema = etp.load_json(etp.DEFAULT_SCHEMA)
    results = {"schema": "openssl-rs/etp5/probe-results/v1",
               "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "validator": "forensics/tools/etp_claims.py",
               "validator_sha256": sha("forensics/tools/etp_claims.py"),
               "probes": []}
    for name, builder in PROBE_BUILDERS.items():
        doc = builder()
        path = PROBES / f"{name}.json"
        path.write_text(json.dumps(doc, indent=1) + "\n")
        refusals = etp.validate_document(doc, schema, repo_root=etp.REPO_ROOT)
        entry = {
            "probe": name,
            "document": str(path.relative_to(ROOT)),
            "claims": [c["id"] for c in doc["claims"]],
            "valid": not refusals,
            "refusal_count": len(refusals),
            "refusals": refusals,
        }
        # A probe that validates can still be run through the algebra, so the
        # observed meet is recorded alongside the refusal result.
        if not refusals:
            entry["conjoin"] = etp.conjoin(doc["claims"])
            entry["contradictions"] = etp.contradiction_conflicts(doc["claims"])
        results["probes"].append(entry)
        print(f"{name}: refusals={len(refusals)} "
              + ", ".join(sorted({r['rule'] for r in refusals})))

    # Two additional algebra runs over the committed record.
    doc = etp.load_json(etp.DEFAULT_CLAIMS)
    committed_refusals = etp.validate_document(doc, schema, repo_root=etp.REPO_ROOT)
    results["committed_record"] = {
        "document": "evidence/etp/claims.json",
        "claims": len(doc["claims"]),
        "validate_refusals": len(committed_refusals),
        "conjoin": etp.conjoin(doc["claims"]),
        "contradictions": etp.contradiction_conflicts(doc["claims"]),
    }
    results["invalidate"] = {}
    for changed in (B_HOST, B_COURT):
        results["invalidate"][changed] = etp.invalidated_claims(doc["claims"], [changed])

    (OUT / "PROBE-RESULTS.json").write_text(json.dumps(results, indent=1) + "\n")
    print("committed claims:", len(doc["claims"]), "refusals:", len(committed_refusals),
          "conjoin:", results["committed_record"]["conjoin"]["verdict"])
    for changed in (B_HOST, B_COURT):
        print("invalidate", changed[:12], "->",
              len(results["invalidate"][changed]["invalidated"]), "claims")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
