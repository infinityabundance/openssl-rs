#!/usr/bin/env python3
"""openssl-rs — the exposure / data-flow classification (Phase 25.7).

Phase 25 is the memory-safety stratum (`docs/RELEASE_GATES.md` section 1,
`docs/PHASE-25-MEMORY-SAFETY-SUBPHASES.md`). 25.1 enumerates the compiler-derived unsafe
operations, 25.2 records the non-Rust trusted computing base, 25.3 gives every site an obligation,
25.4 models the ownership/allocation/callback machinery, 25.5 maps every site to the OpenSSL public
compatibility roots the Phase-22 reachability atlas reaches it from, and 25.6 maps it to the Phase-24
downstream population that reaches it. This subphase is 25.7:

  * it gives **every** compiler-derived unsafe site exactly one class from the closed
    `memory_safety_schemas.EXPOSURE_CLASSES`; and
  * for the sites that can consume externally controlled lengths, bytes or indices it records the
    **attacker-input routes** from a wire/file/config/CLI surface to a raw pointer read/write, a
    manual allocation or an index/length arithmetic, with the **buffer-operation census** that says
    where the buffer, the pointer, the length and the capacity come from.

The classification is derived, never typed
------------------------------------------
Every class comes from committed evidence and the rule that turns it into a class is recorded in the
plane's own `rule`:

  * the **census** (`artifacts/phase25/source-census.json`) is the site's context — its file, its
    module, its operation kind and its compiler-derived context;
  * the **25.5 crosswalk** (`artifacts/phase25/phase22-crosswalk.json`) is the site's authority
    translation unit and the public compatibility roots that reach it, or the `evidence_missing`
    residual that says the atlas could not resolve the module to an authority unit;
  * the **25.6 crosswalk** (`artifacts/phase25/phase24-crosswalk.json`) is the site's downstream
    state (runtime-observed or not);
  * the **25.4 ownership planes** (`artifacts/phase25/ownership-planes.json`) are the manual
    allocation sites, so a `CRYPTO_malloc` site is a buffer operation even though its operation kind
    is a function call.

The exposure precedence, recorded in `rule.exposure_precedence`, is a review ordering — most
specific externally reachable class first — and it is **not** a probability. The two members the
brief names that the 25.0 schema did not carry (`TOOLING_ONLY` and `LOCAL_FILE_INPUT_REACHABLE`) are
added to the schema by this subphase and recorded as a correction in the plan (§4.5).

The risk tier records the consequence of the class, and an unknown is not a non-exposed site. The
risk tiers are S0 (a genuinely non-exposed site), `SU` (unknown exposure — a site whose exposure the
committed evidence does not establish) and S1-S4 (the externally reachable ranking). A site classed
`UNKNOWN_REACHABILITY` is tier **`SU`**, never S0: an unknown is not the lowest priority, and it
stays eligible for high-priority investigation until evidence narrows it. `SU` was added to
`memory_safety_schemas.RISK_TIERS` in the third 25.7 correction recorded in the plan (§4).

Network reachability needs an entry semantics, not a static edge
----------------------------------------------------------------
The Phase-22 compatibility closure leaves its `protocol` family **unpopulated** — "no plane in
22.1-22.13 observes the TLS/DTLS/QUIC externally observable wire or state". A static edge, therefore,
can never justify `NETWORK_SERVER_REACHABLE` or `NETWORK_CLIENT_REACHABLE` here. A wire-parser class
is assigned only when the site's committed module or authority unit is the parser an inbound peer
drives (`ssl/record`, `ssl/statem`, `ssl/quic`, `ssl/d1_*`, `crypto/http`, `crypto/quic_vlint`), and
the justification that rule produces is stored per class-route in `.justifications`, so a remote
class with no justification is a finding rather than a silent assertion. This is recorded as a
residual, never hidden: the class is grounded in the parser's role, and the atlas's own protocol
family is named as unpopulated.

Attacker-input reachability, and the buffer-operation census
-----------------------------------------------------------
For sites that are externally reachable **and** a raw pointer access or a manual allocation, the
plane records the routes (TLS records, DTLS datagrams, QUIC packets, DER, PEM, PKCS#7/#8/#12, CMS,
OCSP, CMP, X.509 certificates, configuration files, provider parameters, CLI files/input, STORE
URIs) whose committed parser prefix matches the site's file or authority unit, and a buffer-operation
record naming where the buffer, the pointer, the length and the capacity come from. The route and
buffer rules are `rule.attacker_routes` and `rule.buffer_operations`; a field the committed evidence
does not measure is recorded `NOT_MEASURED` rather than guessed.

The length-boundary plan is a plan, not a result
------------------------------------------------
`.length_boundary_plan` fixes, per applicable buffer operation, the generic boundary cases
(`len = 0, 1, capacity-1, capacity, capacity+1, large, near an integer boundary`). It is marked
`PLANNED_NOT_EXECUTED` (`executed: false`): **execution belongs to the dynamic subphases 25.9-25.12**,
and this plane records the plan only.

A pure derivation, so it executes nothing
-----------------------------------------
It reads committed planes and writes a derived plane; it runs no compiler, no tool and no probe, so
`forensics/memory-safety/container.json` lists it `metadata_only` and the Docker-only guard admits it
on any host (it still calls the guard first, so the rule is never optional).

Outputs
-------
  artifacts/phase25/exposure.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
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
)

# The census (for the site universe and its ordered id lists) and the lossless columnar codec every
# Phase-25 artefact is stored in. Imported after `atlas_common` so `sys.path` is set.
import ms_census  # noqa: E402
import ms_codec  # noqa: E402

# The Docker-only execution guard, called first. This tool executes nothing -- it derives a plane
# from committed planes -- so the manifest lists it `metadata_only` and the guard admits it on any
# host exactly as `ms_phase24_crosswalk.py` is.
import phase25_guard  # noqa: E402

# The schema and its closed vocabularies. Imported, never restated.
import memory_safety_schemas as schemas  # noqa: E402

OUT = REPO_ROOT / "artifacts" / "phase25" / "exposure.json"
GENERATOR = "forensics/tools/ms_exposure.py"
TOOL = REPO_ROOT / "forensics" / "tools" / "ms_exposure.py"
SCHEMAS = REPO_ROOT / "forensics" / "tools" / "memory_safety_schemas.py"
GUARD = REPO_ROOT / "forensics" / "tools" / "phase25_guard.py"
PLAN = REPO_ROOT / "docs" / "PHASE-25-MEMORY-SAFETY-SUBPHASES.md"
MANIFEST = REPO_ROOT / "forensics" / "memory-safety" / "container.json"

# 25.1's compiler-backed source census: the primary unit and the site context.
CENSUS = REPO_ROOT / "artifacts" / "phase25" / "source-census.json"

# 25.5's Phase-22 reachability crosswalk: the site -> authority-unit -> roots resolution.
PHASE22_CROSSWALK = REPO_ROOT / "artifacts" / "phase25" / "phase22-crosswalk.json"

# 25.6's Phase-24 downstream crosswalk: the site's downstream state.
PHASE24_CROSSWALK = REPO_ROOT / "artifacts" / "phase25" / "phase24-crosswalk.json"

# 25.4's ownership planes: the manual allocation sites, so a `CRYPTO_malloc` site is a buffer
# operation even though its operation kind is a function call.
OWNERSHIP_PLANES = REPO_ROOT / "artifacts" / "phase25" / "ownership-planes.json"

CENSUS_REL = rel(CENSUS)
PHASE22_CROSSWALK_REL = rel(PHASE22_CROSSWALK)
PHASE24_CROSSWALK_REL = rel(PHASE24_CROSSWALK)
OWNERSHIP_PLANES_REL = rel(OWNERSHIP_PLANES)


# --------------------------------------------------------------------------------------------
# the closed tables the classification applies (authored rules, applied to committed evidence)
# --------------------------------------------------------------------------------------------

# The raw memory-access operation kinds. A site whose compiler-derived operation kind is one of
# these is a buffer operation; so is a manual allocation site (25.4), whose kind is a function call.
MEMORY_ACCESS_KINDS: frozenset[str] = frozenset({
    "RAW_POINTER_DEREFERENCE",
    "RAW_POINTER_READ",
    "RAW_POINTER_WRITE",
    "UNALIGNED_ACCESS",
})

# The kinds that write memory (a write is a review priority above a read). A manual allocation writes.
WRITE_KINDS: frozenset[str] = frozenset({
    "RAW_POINTER_DEREFERENCE",
    "RAW_POINTER_WRITE",
    "UNALIGNED_ACCESS",
})

# The manual-allocation roles of 25.4 that allocate. `FREE`/`CLEAR_FREE`/`SECURE_FREE` deallocate and
# are not a buffer origin; the four allocator roles are.
ALLOCATOR_ROLES: frozenset[str] = frozenset({"ALLOC", "REALLOC", "SECURE_ALLOC",
                                             "RUST_RETURN_OWNERSHIP", "RUST_TRANSFER"})

# The route transports. A wire transport carries an entry semantics -- the parser is driven by an
# inbound peer -- so it may establish a network exposure class; the other transports establish a
# data-flow route without a remote claim.
NETWORK_TRANSPORTS: frozenset[str] = frozenset({"NETWORK_SERVER", "NETWORK_CLIENT"})

# The test/tooling module prefixes. A site only in one of these is `TEST_ONLY`/`TOOLING_ONLY` and is
# not a memory-safety exposure in the claimed profile. This candidate ships no such first-party file
# with a compiler-derived unsafe site, so both counts are recorded as zero rather than assumed.
TEST_PREFIXES: tuple[str, ...] = (
    "tests/", "test/", "benches/", "examples/", "fuzz/", "src/tests/", "src/test_support",
)
TOOLING_PREFIXES: tuple[str, ...] = (
    "tools/", "xtask/", "src/tools/", "build.rs",
)

# The exposure precedence, most specific externally reachable class first. `TEST_ONLY`/`TOOLING_ONLY`
# are decided first (a site only in a test or a tool is not in the claimed profile), then the
# route-established classes, then the root-established ones, then the unresolved residual. The order
# is a review ordering, never a probability. `UNKNOWN_REACHABILITY` sits last, before the witnessed
# `UNREACHABLE_PROFILE`: a site whose mapping the committed evidence does not resolve is reviewed, but
# it is neither promoted to an external class nor read as an unreachability claim.
EXPOSURE_PRECEDENCE: tuple[str, ...] = (
    "TEST_ONLY",
    "TOOLING_ONLY",
    "NETWORK_SERVER_REACHABLE",
    "NETWORK_CLIENT_REACHABLE",
    "CONFIG_REACHABLE",
    "LOCAL_FILE_INPUT_REACHABLE",
    "CLI_INPUT_REACHABLE",
    "DOWNSTREAM_RUNTIME_OBSERVED",
    "LOCAL_API_REACHABLE",
    "INTERNAL_REACHABLE",
    "UNKNOWN_REACHABILITY",
    "UNREACHABLE_PROFILE",
)

# The exclusion-witness kinds. `UNREACHABLE_PROFILE` is awarded only to a site that carries one of
# these, recorded on the site as `w`, so an unreachability claim is never silently produced by a
# missing mapping. `committed_exclusion_residual` is a Phase-22 crosswalk residual that names an
# explicit exclusion rather than missing evidence; `no_reachable_root` is a resolved authority unit
# no root family in the committed closure reaches.
WITNESS_KINDS: tuple[str, ...] = (
    "committed_exclusion_residual",
    "no_reachable_root",
)

# The Phase-22 crosswalk residual classes that name an explicit exclusion (the site is off the
# atlas's scope) rather than missing evidence. Drawn from `memory_safety_schemas.RESIDUAL_CLASSES`,
# never restated: the self-test asserts membership. A residual here is a justified exclusion witness;
# every other residual (`evidence_missing`, `unclassified_unsafe_site`) is missing evidence, which
# establishes nothing about reachability.
EXCLUSION_RESIDUALS: frozenset[str] = frozenset({"out_of_scope"})

# The attacker-input routes. Each names the externally controlled input, the transport that carries
# it, the exposure its entry semantics establishes (or `None` when it establishes only a data-flow
# route and the class comes from the roots), the committed module/authority-unit prefixes that are the
# parser, and the entry semantics that justifies a remote claim.
ROUTES: tuple[dict, ...] = (
    {
        "route": "TLS_RECORD",
        "input": "TLS record bytes",
        "transport": "NETWORK_SERVER",
        "exposure": "NETWORK_SERVER_REACHABLE",
        "files": ("src/ssl/record/", "src/ssl/statem/statem.rs", "src/ssl/statem/statem_lib.rs",
                  "src/ssl/statem/statem_srvr", "src/ssl/statem/extensions_srvr",
                  "src/ssl/statem/extensions_cust.rs", "src/ssl/t1_lib.rs", "src/ssl/t1_trce.rs",
                  "src/ssl/tls13_enc.rs"),
        "units": ("ssl/record/", "ssl/statem/statem.c", "ssl/statem/statem_lib.c",
                  "ssl/statem/statem_srvr.c", "ssl/statem/extensions_srvr.c",
                  "ssl/statem/extensions_cust.c", "ssl/t1_lib.c", "ssl/t1_trce.c",
                  "ssl/tls13_enc.c"),
        "entry": ("a TLS record is read from the peer's socket by the record layer and driven through "
                  "the state machine; the parser is the wire entry point a network peer reaches "
                  "without authenticating"),
    },
    {
        "route": "TLS_CLIENT_STATE",
        "input": "TLS server handshake messages",
        "transport": "NETWORK_CLIENT",
        "exposure": "NETWORK_CLIENT_REACHABLE",
        "files": ("src/ssl/statem/statem_clnt", "src/ssl/statem/extensions_clnt"),
        "units": ("ssl/statem/statem_clnt.c", "ssl/statem/extensions_clnt.c"),
        "entry": ("the client-side state machine parses the server's handshake messages; the parser "
                  "is driven by an inbound peer, and the client role is claimed rather than the "
                  "server one"),
    },
    {
        "route": "DTLS_DATAGRAM",
        "input": "DTLS datagrams",
        "transport": "NETWORK_SERVER",
        "exposure": "NETWORK_SERVER_REACHABLE",
        "files": ("src/ssl/d1_lib.rs", "src/ssl/d1_srtp.rs"),
        "units": ("ssl/d1_lib.c", "ssl/d1_srtp.c"),
        "entry": ("a DTLS datagram arrives from an unauthenticated peer and is parsed by the d1 "
                  "layer; the datagram path is the wire entry point"),
    },
    {
        "route": "QUIC_PACKET",
        "input": "QUIC packets",
        "transport": "NETWORK_SERVER",
        "exposure": "NETWORK_SERVER_REACHABLE",
        "files": ("src/ssl/quic/", "src/quic_vlint.rs"),
        "units": ("ssl/quic/", "crypto/quic_vlint.c"),
        "entry": ("a QUIC packet and its variable-length integers arrive from the peer; the QUIC "
                  "transport and the varint codec are the wire entry point"),
    },
    {
        "route": "HTTP_RESPONSE",
        "input": "HTTP response (OCSP/CRL/CMP fetch)",
        "transport": "NETWORK_CLIENT",
        "exposure": "NETWORK_CLIENT_REACHABLE",
        "files": ("src/http/",),
        "units": ("crypto/http/",),
        "entry": ("the HTTP client fetches an OCSP/CRL/CMP response from a remote server and parses "
                  "it; the response is an inbound peer's bytes"),
    },
    {
        "route": "CONFIGURATION_FILE",
        "input": "configuration file text",
        "transport": "CONFIG",
        "exposure": "CONFIG_REACHABLE",
        "files": ("src/runtime/conf/",),
        "units": ("crypto/conf/", "crypto/provider_conf"),
        "entry": ("an OpenSSL configuration file is parsed by the conf module and its directives "
                  "drive the library; the file is externally controlled"),
    },
    {
        "route": "DER",
        "input": "DER-encoded ASN.1",
        "transport": "LOCAL_FILE",
        "exposure": "LOCAL_FILE_INPUT_REACHABLE",
        "files": ("src/asn1/", "src/asn1_dsa.rs", "src/der_writer.rs"),
        "units": ("crypto/asn1/", "crypto/asn1_dsa.c", "crypto/der_writer.c"),
        "entry": ("the ASN.1/DER decoder parses externally controlled byte strings"),
    },
    {
        "route": "PEM",
        "input": "PEM text",
        "transport": "LOCAL_FILE",
        "exposure": "LOCAL_FILE_INPUT_REACHABLE",
        "files": ("src/pem/",),
        "units": ("crypto/pem/",),
        "entry": ("a PEM block is read from a file or stream and base64-decoded; the text is "
                  "externally controlled"),
    },
    {
        "route": "PKCS7",
        "input": "PKCS#7 input",
        "transport": "LOCAL_FILE",
        "exposure": "LOCAL_FILE_INPUT_REACHABLE",
        "files": ("src/pkcs7/",),
        "units": ("crypto/pkcs7/",),
        "entry": ("a PKCS#7 structure is decoded from externally controlled bytes"),
    },
    {
        "route": "PKCS8",
        "input": "PKCS#8 private key",
        "transport": "LOCAL_FILE",
        "exposure": "LOCAL_FILE_INPUT_REACHABLE",
        "files": ("src/pkcs12/p12_p8", "src/pem/pem_pk8"),
        "units": ("crypto/pem/pem_pk8.c",),
        "entry": ("a PKCS#8 private key is decoded from externally controlled bytes"),
    },
    {
        "route": "PKCS12",
        "input": "PKCS#12 input",
        "transport": "LOCAL_FILE",
        "exposure": "LOCAL_FILE_INPUT_REACHABLE",
        "files": ("src/pkcs12/",),
        "units": ("crypto/pkcs12/",),
        "entry": ("a PKCS#12 container is decoded from externally controlled bytes"),
    },
    {
        "route": "CMS",
        "input": "CMS input",
        "transport": "LOCAL_FILE",
        "exposure": "LOCAL_FILE_INPUT_REACHABLE",
        "files": ("src/cms/",),
        "units": ("crypto/cms/",),
        "entry": ("a CMS structure is decoded from externally controlled bytes"),
    },
    {
        "route": "OCSP",
        "input": "OCSP request/response",
        "transport": "LOCAL_FILE",
        "exposure": "LOCAL_FILE_INPUT_REACHABLE",
        "files": ("src/ocsp/",),
        "units": ("crypto/ocsp/",),
        "entry": ("an OCSP request or response is decoded from externally controlled bytes"),
    },
    {
        "route": "CMP",
        "input": "CMP/CRMF message",
        "transport": "LOCAL_FILE",
        "exposure": "LOCAL_FILE_INPUT_REACHABLE",
        "files": ("src/cmp/", "src/crmf/"),
        "units": ("crypto/cmp/", "crypto/crmf/"),
        "entry": ("a CMP or CRMF message is decoded from externally controlled bytes"),
    },
    {
        "route": "X509_CERTIFICATE",
        "input": "X.509 certificate/CRL",
        "transport": "LOCAL_FILE",
        "exposure": "LOCAL_FILE_INPUT_REACHABLE",
        "files": ("src/x509/",),
        "units": ("crypto/x509/",),
        "entry": ("an X.509 certificate, CRL or extension is decoded from externally controlled "
                  "bytes; the network delivery of a chain is not claimed here because the atlas does "
                  "not record it"),
    },
    {
        "route": "STORE_URI",
        "input": "STORE URI and its payload",
        "transport": "LOCAL_FILE",
        "exposure": "LOCAL_FILE_INPUT_REACHABLE",
        "files": ("src/store/",),
        "units": ("crypto/store/",),
        "entry": ("a STORE URI is resolved and its payload loaded from an externally supplied "
                  "location"),
    },
    {
        "route": "PROVIDER_PARAMETERS",
        "input": "provider parameters",
        "transport": "IN_PROCESS",
        "exposure": None,
        "files": ("src/params/", "src/provider/", "src/param_build"),
        "units": ("crypto/params", "crypto/param_build", "crypto/provider_", "providers/"),
        "entry": ("provider parameters are supplied by an in-process caller; no external transport "
                  "is claimed, so the exposure comes from the roots"),
    },
    {
        "route": "CLI_INPUT",
        "input": "CLI files/input",
        "transport": "CLI",
        "exposure": None,
        "files": ("src/apps/",),
        "units": ("apps/",),
        "entry": ("the openssl CLI parses command-line files and arguments; 25.5 does not resolve the "
                  "apps modules to an authority unit, so with no resolved site the route carries no "
                  "attributable operation and is recorded at zero"),
    },
)

ROUTE_ORDER: tuple[str, ...] = tuple(r["route"] for r in ROUTES)
ROUTE_BY_NAME: dict[str, dict] = {r["route"]: r for r in ROUTES}

# The operation primitive a buffer-operation record names.
OPERATION_NAMES: dict[str, str] = {
    "RAW_POINTER_DEREFERENCE": "raw_pointer_dereference",
    "RAW_POINTER_READ": "raw_pointer_read",
    "RAW_POINTER_WRITE": "raw_pointer_write",
    "UNALIGNED_ACCESS": "unaligned_access",
}
MANUAL_ALLOCATION = "manual_allocation"

# The buffer-operation fields the census records, and the ones the committed evidence does not
# measure (they are `NOT_MEASURED` rather than guessed; the dynamic subphases own them).
BUFFER_OPERATION_FIELDS: tuple[str, ...] = (
    "operation", "buffer_origin", "pointer_origin", "length_origin", "capacity_origin",
    "bounds_validation", "integer_conversion_path", "copy_primitive", "provenance", "attacker_routes",
)
NOT_MEASURED = "NOT_MEASURED"

# The generic length-boundary plan. It is a plan, never a result: execution belongs to 25.9-25.12.
LENGTH_BOUNDARY_CASES: tuple[dict, ...] = (
    {"case": "len = 0", "description": "an empty input must not read or write; a zero length is "
     "the degenerate bound every allocator and copy must accept"},
    {"case": "len = 1", "description": "the smallest non-empty input; a one-byte read or write "
     "must stay inside a one-byte buffer"},
    {"case": "len = capacity - 1", "description": "one below capacity: the largest input that "
     "leaves a spare byte, and the case a `>=`/`>` inversion passes"},
    {"case": "len = capacity", "description": "exactly full: the largest input that fits without a "
     "further allocation"},
    {"case": "len = capacity + 1", "description": "one over capacity: the first input that must "
     "grow or be rejected, and the off-by-one a length check must catch"},
    {"case": "len = large", "description": "a large length well inside the type's range, to "
     "exercise the allocator and the copy rather than the empty case"},
    {"case": "len near an integer boundary", "description": "a length at or next to an integer "
     "boundary (2**31-1, 2**32, SIZE_MAX, INT_MAX), where a length arithmetic wraps or truncates"},
)
INTEGER_BOUNDARIES: tuple[str, ...] = (
    "INT_MAX (2**31-1)", "UINT_MAX (2**32-1)", "INT64_MAX (2**63-1)", "SIZE_MAX",
)

NON_CLAIMS: tuple[str, ...] = (
    "exposure is a reachability claim over the admitted profile, not a campaign result, and the "
    "length-boundary plan is not executed evidence: a class says the committed evidence reaches the "
    "site's surface, and the plan records the cases the dynamic subphases (25.9-25.12) will run, "
    "never a run that happened",
    "a network class is a claim about an entry semantics, not a wire observation: the Phase-22 "
    "closure leaves its `protocol` family unpopulated, so the class is grounded in the site's "
    "committed parser role (the module or authority unit the peer drives), and it is recorded as a "
    "residual rather than hidden",
    "an attacker-input route is a rule over committed module and authority-unit identities, not a "
    "dynamic taint result: it names the parser an input format reaches and the memory operation, and "
    "it makes no claim about a specific value that flowed at run time",
    "the exposure precedence is a review ordering, not a probability: the classes are ordered by how "
    "specific and how externally reachable they are, and a class is not a likelihood",
    "the risk tiers (S0, SU, S1-S4) are a review priority, not a probability and not a "
    "vulnerability count: a tier orders the sites a reviewer reads first, and an unsafe site is not "
    "a defect; an unknown exposure is SU and is not read as the lowest priority",
    "the buffer-operation census records only the fields the committed evidence measures; the length "
    "origin, the integer-conversion path and the copy primitive are `NOT_MEASURED` here, because the "
    "census does not observe a data flow, and they are the dynamic subphases' subject",
)


# --------------------------------------------------------------------------------------------
# small pure helpers
# --------------------------------------------------------------------------------------------

def _load(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"[ms-exposure] {rel(path)} is absent")
    return json.loads(path.read_text(encoding="utf-8"))


def load_authority() -> dict:
    """The committed planes this plane reads, loaded once so the generator and the court share bytes.

    Each artefact's columnar body is decoded here (the census supplies the ordered id lists the
    others reference by index), so every reader sees the same record view.
    """
    census_doc = _load(CENSUS)
    census_body = ms_census.decode_body(census_doc.get("body", census_doc))
    refs = ms_codec.refs_from_census(census_body)

    def decoded(path: Path) -> dict:
        doc = _load(path)
        return {**doc, "body": ms_codec.decode_body(doc.get("body", doc), refs)}

    return {
        "census": {**census_doc, "body": census_body},
        "phase22_crosswalk": decoded(PHASE22_CROSSWALK),
        "phase24_crosswalk": decoded(PHASE24_CROSSWALK),
        "ownership_planes": decoded(OWNERSHIP_PLANES),
    }


def _body(doc: dict) -> dict:
    return doc.get("body", doc)


def _alloc_sites(own_body: dict) -> dict:
    """`site_id -> allocation row` for the manual allocation sites (25.4)."""
    out: dict = {}
    for a in own_body.get("allocation_sites") or []:
        sid = str(a.get("site_id"))
        if a.get("role") in ALLOCATOR_ROLES:
            out[sid] = a
    return out


def _is_test(file: str) -> bool:
    return file.startswith(TEST_PREFIXES)


def _is_tooling(file: str) -> bool:
    return file.startswith(TOOLING_PREFIXES)


def _matches(prefixes: tuple[str, ...], value: str | None) -> bool:
    return bool(value) and value.startswith(prefixes)


def _route_matches(route: dict, file: str, unit: str | None) -> bool:
    """Whether the committed module or authority unit is the parser this route names.

    A route is keyed on either identity because the candidate's own module (the census context) and
    the authority translation unit it transcribes (the 25.5 resolution) name the same parser from the
    two sides, and a route matches when either says so.
    """
    return _matches(tuple(route["files"]), file) or _matches(tuple(route["units"]), unit)


def _matched_routes(file: str, unit: str | None) -> list[str]:
    return [r["route"] for r in ROUTES if _route_matches(r, file, unit)]


def _is_buffer_op(kind: str, sid: str, alloc: dict) -> bool:
    return kind in MEMORY_ACCESS_KINDS or sid in alloc


def _writes(kind: str, sid: str, alloc: dict) -> bool:
    return kind in WRITE_KINDS or sid in alloc


def _primitive(kind: str, sid: str, alloc: dict) -> str:
    if kind in OPERATION_NAMES:
        return OPERATION_NAMES[kind]
    if sid in alloc:
        return MANUAL_ALLOCATION
    return "other"


def _exclusion_witness(entry: dict | None, roots: set) -> dict | None:
    """A justified exclusion witness, or `None` when the evidence only shows a missing mapping.

    A missing Phase-22 mapping (`evidence_missing`, `unclassified_unsafe_site`) establishes nothing
    about reachability, so it is **never** a witness: the site is `UNKNOWN_REACHABILITY`, not
    `UNREACHABLE_PROFILE`. `UNREACHABLE_PROFILE` is awarded only for a witness derived from committed
    evidence: a crosswalk residual that names an explicit exclusion (`out_of_scope`), or a resolved
    authority unit whose roots the committed closure leaves empty (provably off every reachable
    path). The witness is recorded on the site so the claim is auditable, never inferred.
    """
    if entry and entry.get("residual") in EXCLUSION_RESIDUALS:
        return {
            "kind": "committed_exclusion_residual",
            "residual": str(entry.get("residual")),
            "reason": ("the Phase-22 crosswalk records the site's module out of the atlas's scope, "
                       "an explicit exclusion rather than a missing mapping"),
            "evidence": [PHASE22_CROSSWALK_REL],
        }
    if entry is None or entry.get("residual"):
        # An unresolved site, or one with no crosswalk entry at all: the mapping is missing, which
        # is missing evidence, not an exclusion. Never a witness.
        return None
    if not set(roots or []):
        return {
            "kind": "no_reachable_root",
            "reason": ("the Phase-22 closure resolves the site's authority unit and no root family "
                       "reaches it, so it is provably off every reachable path"),
            "evidence": [PHASE22_CROSSWALK_REL],
        }
    return None


def _witness_problems(w) -> list[str]:
    """Every way an exclusion witness fails to justify `UNREACHABLE_PROFILE`."""
    if w is None:
        return ["carries no justified exclusion witness"]
    if not isinstance(w, dict):
        return [f"carries a malformed exclusion witness {w!r}"]
    problems: list = []
    if w.get("kind") not in WITNESS_KINDS:
        problems.append(f"its exclusion witness kind {w.get('kind')!r} is not in the closed "
                        f"vocabulary")
    if not w.get("reason"):
        problems.append("its exclusion witness records no reason")
    if not w.get("evidence"):
        problems.append("its exclusion witness cites no evidence")
    return problems


# --------------------------------------------------------------------------------------------
# the derivation
# --------------------------------------------------------------------------------------------

_DERIVE_CACHE: dict = {}


def derive_cached(census_body: dict, authority: dict) -> dict:
    """`derive` memoised by the identity of its two arguments (pure and deterministic)."""
    key = (id(census_body), id(authority))
    if key not in _DERIVE_CACHE:
        _DERIVE_CACHE[key] = derive(census_body, authority)
    return _DERIVE_CACHE[key]


def derive(census_body: dict, authority: dict) -> dict:
    """The whole classification, derived: sites, inverse views, routes, buffer ops, counts."""
    pcw = _body(authority["phase22_crosswalk"])
    p24 = _body(authority["phase24_crosswalk"])
    own = _body(authority["ownership_planes"])
    xw_sites = pcw.get("sites") or {}
    ds_sites = p24.get("sites") or {}
    alloc = _alloc_sites(own)

    risk_rank = {t: i for i, t in enumerate(schemas.RISK_TIERS)}
    census_sites = list(census_body.get("sites") or [])
    census_ids = [str(s["site_id"]) for s in census_sites]

    sites: dict = {}
    justifications: dict = {}
    buffer_ops: dict = {}
    routed: dict = defaultdict(list)
    by_exposure = defaultdict(list)

    def justification(jid: str, cls: str, reason: str, evidence: list, routes: list,
                      transport: str | None) -> str:
        rec = justifications.get(jid)
        if rec is None:
            justifications[jid] = {
                "class": cls,
                "reason": reason,
                "evidence": evidence,
                "routes": routes,
                "transport": transport,
                "network": transport in NETWORK_TRANSPORTS,
                "site_count": 0,
            }
        justifications[jid]["site_count"] += 1
        return jid

    for s in census_sites:
        sid = str(s["site_id"])
        file = str(s["file"])
        kind = str(s["operation_kind"])
        entry = xw_sites.get(sid)
        unresolved = (not entry) or bool(entry.get("residual"))
        unit = None if unresolved else entry.get("unit")
        roots = set() if unresolved else set(entry.get("roots") or [])
        state = (ds_sites.get(sid) or {}).get("state")
        witness = None

        matched = _matched_routes(file, unit)

        # The class, by the recorded precedence. `TEST_ONLY`/`TOOLING_ONLY` are decided first, then
        # the route-established classes, then the root-established ones, then the residual. A site
        # the committed evidence does not resolve is `UNKNOWN_REACHABILITY`; `UNREACHABLE_PROFILE` is
        # awarded only with a justified exclusion witness, never for a missing mapping.
        if _is_test(file):
            cls = "TEST_ONLY"
        elif _is_tooling(file):
            cls = "TOOLING_ONLY"
        elif any(ROUTE_BY_NAME[r]["transport"] == "NETWORK_SERVER" for r in matched):
            cls = "NETWORK_SERVER_REACHABLE"
        elif any(ROUTE_BY_NAME[r]["transport"] == "NETWORK_CLIENT" for r in matched):
            cls = "NETWORK_CLIENT_REACHABLE"
        elif any(ROUTE_BY_NAME[r]["exposure"] == "CONFIG_REACHABLE" for r in matched):
            cls = "CONFIG_REACHABLE"
        elif any(ROUTE_BY_NAME[r]["exposure"] == "LOCAL_FILE_INPUT_REACHABLE" for r in matched):
            cls = "LOCAL_FILE_INPUT_REACHABLE"
        elif unresolved:
            witness = _exclusion_witness(entry, roots)
            cls = "UNREACHABLE_PROFILE" if witness is not None else "UNKNOWN_REACHABILITY"
        elif "cli" in roots:
            cls = "CLI_INPUT_REACHABLE"
        elif state == "DOWNSTREAM_RUNTIME_OBSERVED":
            cls = "DOWNSTREAM_RUNTIME_OBSERVED"
        elif roots & {"binary-abi", "source-api", "modules"}:
            cls = "LOCAL_API_REACHABLE"
        elif "callbacks" in roots:
            cls = "INTERNAL_REACHABLE"
        else:
            witness = _exclusion_witness(entry, roots)
            cls = "UNREACHABLE_PROFILE" if witness is not None else "UNKNOWN_REACHABILITY"

        external = cls in schemas.EXTERNALLY_REACHABLE_EXPOSURE
        buf = _is_buffer_op(kind, sid, alloc)
        writes = _writes(kind, sid, alloc)
        net = cls in ("NETWORK_SERVER_REACHABLE", "NETWORK_CLIENT_REACHABLE")

        # The risk tier, recorded as a review priority. A site whose exposure the committed
        # evidence does not establish is SU (unknown exposure), never S0: an unknown is not a
        # non-exposed site, and it stays eligible for high-priority investigation until evidence
        # narrows it. S0 is a genuinely non-exposed site; S1-S4 rank the externally reachable sites.
        if cls == "UNKNOWN_REACHABILITY":
            tier = "SU"
        elif not external:
            tier = "S0"
        elif net and buf and writes:
            tier = "S4"
        elif net and buf:
            tier = "S3"
        elif buf:
            tier = "S2"
        else:
            tier = "S1"

        rec: dict = {"e": cls, "r": tier}
        if cls == "UNREACHABLE_PROFILE":
            # The exclusion witness is recorded on the site, so an unreachability claim is auditable
            # and a witness-less one is a finding rather than a silent assertion.
            rec["w"] = witness

        # The attacker-input routes are recorded for a site that is externally reachable and is a
        # buffer operation -- the security-relevant half. The routes are the matched routes whose
        # committed parser prefix reaches it.
        site_routes = sorted(set(matched)) if (external and buf) else []
        if site_routes:
            rec["a"] = site_routes
            for rname in site_routes:
                routed[rname].append(sid)

        # The justification, for every externally reachable site. The id names the class and the
        # route (network/local-file), the root (cli/api/internal) or the downstream observation that
        # establishes it, so a remote class with no justification is a finding.
        if external:
            if cls == "NETWORK_SERVER_REACHABLE":
                rname = next((r for r in site_routes
                              if ROUTE_BY_NAME[r]["transport"] == "NETWORK_SERVER"),
                             next(r for r in matched
                                  if ROUTE_BY_NAME[r]["transport"] == "NETWORK_SERVER"))
                rec["j"] = justification(
                    f"j:{cls}:{rname}", cls,
                    f"the site's committed parser ({rname}) is the {ROUTE_BY_NAME[rname]['input']} "
                    f"entry point a network peer drives: {ROUTE_BY_NAME[rname]['entry']}",
                    [PHASE22_CROSSWALK_REL, CENSUS_REL], [rname], "NETWORK_SERVER")
            elif cls == "NETWORK_CLIENT_REACHABLE":
                rname = next((r for r in site_routes
                              if ROUTE_BY_NAME[r]["transport"] == "NETWORK_CLIENT"),
                             next(r for r in matched
                                  if ROUTE_BY_NAME[r]["transport"] == "NETWORK_CLIENT"))
                rec["j"] = justification(
                    f"j:{cls}:{rname}", cls,
                    f"the site's committed parser ({rname}) is the {ROUTE_BY_NAME[rname]['input']} "
                    f"entry point a network peer drives: {ROUTE_BY_NAME[rname]['entry']}",
                    [PHASE22_CROSSWALK_REL, CENSUS_REL], [rname], "NETWORK_CLIENT")
            elif cls == "CONFIG_REACHABLE":
                rec["j"] = justification(
                    "j:CONFIG_REACHABLE:CONFIGURATION_FILE", cls,
                    "the site's committed parser is the configuration-file parser: "
                    + ROUTE_BY_NAME["CONFIGURATION_FILE"]["entry"],
                    [PHASE22_CROSSWALK_REL, CENSUS_REL], ["CONFIGURATION_FILE"], "CONFIG")
            elif cls == "LOCAL_FILE_INPUT_REACHABLE":
                rname = next((r for r in site_routes
                              if ROUTE_BY_NAME[r]["exposure"] == "LOCAL_FILE_INPUT_REACHABLE"),
                             next(r for r in matched
                                  if ROUTE_BY_NAME[r]["exposure"] == "LOCAL_FILE_INPUT_REACHABLE"))
                rec["j"] = justification(
                    f"j:{cls}:{rname}", cls,
                    f"the site's committed parser ({rname}) consumes {ROUTE_BY_NAME[rname]['input']}, "
                    f"an externally controlled input: {ROUTE_BY_NAME[rname]['entry']}",
                    [PHASE22_CROSSWALK_REL, CENSUS_REL], [rname], "LOCAL_FILE")
            elif cls == "CLI_INPUT_REACHABLE":
                rec["j"] = justification(
                    "j:CLI_INPUT_REACHABLE:cli-root", cls,
                    "the Phase-22 compatibility closure's `cli` root reaches the site's authority "
                    "unit (the CLI's dispatch surface), so an externally controlled CLI input "
                    "reaches it",
                    [PHASE22_CROSSWALK_REL], ["cli"], "CLI")
            elif cls == "DOWNSTREAM_RUNTIME_OBSERVED":
                rec["j"] = justification(
                    "j:DOWNSTREAM_RUNTIME_OBSERVED:phase24-runtime", cls,
                    "the committed 25.6 crosswalk records a measured downstream consumer that reaches "
                    "the site's surface at a functional level, so an external program reaches it at "
                    "run time (for the measured workload only)",
                    [PHASE24_CROSSWALK_REL], [], None)
            elif cls == "LOCAL_API_REACHABLE":
                root = next((r for r in ("binary-abi", "source-api", "modules") if r in roots),
                            "binary-abi")
                rec["j"] = justification(
                    f"j:LOCAL_API_REACHABLE:{root}", cls,
                    f"the Phase-22 compatibility closure's `{root}` root reaches the site's authority "
                    f"unit, so an in-process caller of the public {root} surface reaches it",
                    [PHASE22_CROSSWALK_REL], [root], None)
            elif cls == "INTERNAL_REACHABLE":
                rec["j"] = justification(
                    "j:INTERNAL_REACHABLE:callbacks-root", cls,
                    "only the Phase-22 compatibility closure's `callbacks` root reaches the site's "
                    "authority unit (no public root does), so it is reachable only from an internal "
                    "callback",
                    [PHASE22_CROSSWALK_REL], ["callbacks"], None)

        # The buffer-operation census, for externally reachable buffer operations.
        if external and buf:
            origin = (ROUTE_BY_NAME[site_routes[0]]["input"] if site_routes
                      else _origin_without_route(cls))
            a = alloc.get(sid) or {}
            buffer_ops[sid] = {
                "operation": _primitive(kind, sid, alloc),
                "buffer_origin": origin,
                "pointer_origin": f"{s.get('function')} @ {file}:{s.get('line')}",
                "length_origin": NOT_MEASURED,
                "capacity_origin": str(a.get("size_expr")) if a.get("size_expr") else NOT_MEASURED,
                "bounds_validation": NOT_MEASURED,
                "integer_conversion_path": NOT_MEASURED,
                "copy_primitive": NOT_MEASURED,
                "provenance": file,
                "attacker_routes": site_routes,
            }

        sites[sid] = rec
        by_exposure[cls].append(sid)

    # The inverse exposure view: per class the count and the bounded top sites, recomputed from the
    # site map, never typed.
    by_exposure_out: dict = {}
    for cls in schemas.EXPOSURE_CLASSES:
        ids = sorted(by_exposure.get(cls, []))
        top = sorted(ids, key=lambda x: (risk_rank.get(sites[x]["r"], len(risk_rank)), x))[:20]
        by_exposure_out[cls] = {"count": len(ids), "top_sites": top}

    # The attacker-input routes: per route its input, transport, exposure and the reachable sites.
    routes_out: dict = {}
    for r in ROUTES:
        ids = sorted(routed.get(r["route"], []))
        routes_out[r["route"]] = {
            "input": r["input"],
            "transport": r["transport"],
            "exposure": r["exposure"],
            "entry": r["entry"],
            "count": len(ids),
            "sites": ids,
        }

    # The residuals: the protocol family the Phase-22 atlas leaves unpopulated (the network classes'
    # grounding), and the sites 25.5 could not resolve.
    residuals: list = [{
        "residual_id": "rx:" + content_hash("exposure|phase22_protocol_family_unpopulated")[:16],
        "subject": "the Phase-22 `protocol` root family",
        "class": "evidence_missing",
        "disposition": "preserved",
        "detail": ("the committed Phase-22 compatibility closure leaves its `protocol` family "
                   "unpopulated -- 'no plane in 22.1-22.13 observes the TLS/DTLS/QUIC externally "
                   "observable wire or state' -- so a network exposure class is grounded in the "
                   "site's committed parser role and the entry semantics it names, never in a "
                   "Phase-22 root; recorded rather than left as a silent assertion"),
        "evidence": [PHASE22_CROSSWALK_REL, CENSUS_REL],
    }]
    no_unit = sum(1 for sid in census_ids
                  if (xw_sites.get(sid) is None or xw_sites.get(sid, {}).get("residual")))
    if no_unit:
        residuals.append({
            "residual_id": "rx:" + content_hash("exposure|no_authority_unit")[:16],
            "subject": "census sites with no Phase-22 authority unit",
            "class": "evidence_missing",
            "disposition": "open",
            "detail": ("the site's containing module transcribes no authority translation unit, so "
                       "the site's exposure is `UNKNOWN_REACHABILITY` in the claimed profile: a "
                       "missing mapping is evidence the atlas cannot resolve the site, not evidence "
                       "the profile cannot reach it, so it is recorded and never dropped, never "
                       "defaulted to a root and never read as `UNREACHABLE_PROFILE`"),
            "evidence": [PHASE22_CROSSWALK_REL, CENSUS_REL],
            "site_count": no_unit,
        })

    classes = Counter(rec["e"] for rec in sites.values())
    tiers = Counter(rec["r"] for rec in sites.values())
    counts = {
        "census_sites": len(census_ids),
        "sites_classified": len(sites),
        "sites_by_exposure": {c: classes.get(c, 0) for c in schemas.EXPOSURE_CLASSES},
        "sites_by_risk_tier": {t: tiers.get(t, 0) for t in schemas.RISK_TIERS},
        "externally_reachable": sum(1 for rec in sites.values()
                                    if rec["e"] in schemas.EXTERNALLY_REACHABLE_EXPOSURE),
        "network_reachable": sum(classes.get(c, 0) for c in
                                 ("NETWORK_SERVER_REACHABLE", "NETWORK_CLIENT_REACHABLE")),
        "unreachable_profile": classes.get("UNREACHABLE_PROFILE", 0),
        "sites_unknown_reachability": classes.get("UNKNOWN_REACHABILITY", 0),
        "test_only": classes.get("TEST_ONLY", 0),
        "tooling_only": classes.get("TOOLING_ONLY", 0),
        "routed_sites": sum(1 for rec in sites.values() if rec.get("a")),
        "attacker_routes": len(ROUTES),
        "attacker_routes_with_sites": sum(1 for v in routes_out.values() if v["count"]),
        "buffer_operations": len(buffer_ops),
        "justifications": len(justifications),
        "residuals": len(residuals),
    }

    return {
        "sites": sites,
        "justifications": justifications,
        "by_exposure": by_exposure_out,
        "attacker_routes": routes_out,
        "buffer_operations": buffer_ops,
        "counts": counts,
        "residuals": residuals,
    }


def _origin_without_route(cls: str) -> str:
    return {
        "CLI_INPUT_REACHABLE": "in-process caller buffer (CLI-driven)",
        "LOCAL_API_REACHABLE": "in-process caller buffer",
        "DOWNSTREAM_RUNTIME_OBSERVED": "in-process caller buffer",
    }.get(cls, NOT_MEASURED)


def _length_boundary_plan(d: dict) -> dict:
    """The recorded length-boundary plan, per applicable buffer operation, never executed."""
    per_operation: dict = {}
    for sid, rec in sorted(d["buffer_operations"].items()):
        per_operation.setdefault(rec["operation"], set()).add(sid)
    per_op = {op: sorted(ids) for op, ids in sorted(per_operation.items())}
    return {
        "status": "PLANNED_NOT_EXECUTED",
        "executed": False,
        "note": ("a recorded plan only: no case below has been run here, and execution belongs to the "
                 "dynamic subphases 25.9-25.12 (Miri, ASan/MSan, TSan, Kani)"),
        "cases": [dict(c) for c in LENGTH_BOUNDARY_CASES],
        "integer_boundaries": list(INTEGER_BOUNDARIES),
        "applies_to": sorted(per_op),
        "per_operation": {op: len(ids) for op, ids in per_op.items()},
        "per_operation_sites": per_op,
    }


def _rule(authority: dict) -> dict:
    pcw = _body(authority["phase22_crosswalk"])
    p24 = _body(authority["phase24_crosswalk"])
    return {
        "authority": {
            "kind": "committed-phase25-planes",
            "paths": [CENSUS_REL, PHASE22_CROSSWALK_REL, PHASE24_CROSSWALK_REL,
                      OWNERSHIP_PLANES_REL],
            "declaration": ("the committed 25.1 census is the site context, the committed 25.5 "
                            "crosswalk the authority unit and public roots, the committed 25.6 "
                            "crosswalk the downstream state and the committed 25.4 ownership planes "
                            "the manual allocation sites; the class is derived from them and no site "
                            "context is typed"),
        },
        "exposure_classes": list(schemas.EXPOSURE_CLASSES),
        "externally_reachable_exposure": sorted(schemas.EXTERNALLY_REACHABLE_EXPOSURE),
        "exposure_precedence": list(EXPOSURE_PRECEDENCE),
        "exclusion_witness_kinds": list(WITNESS_KINDS),
        "exclusion_residuals": sorted(EXCLUSION_RESIDUALS),
        "exposure_rule": (
            "every census site gets exactly one class: TEST_ONLY/TOOLING_ONLY when its file is a "
            "test/tooling module; else NETWORK_SERVER_REACHABLE/NETWORK_CLIENT_REACHABLE when its "
            "committed module or authority unit is a wire-parser route (an entry semantics, not a "
            "static edge); else CONFIG_REACHABLE for the configuration-file parser; else "
            "LOCAL_FILE_INPUT_REACHABLE for a local-file/format parser; else CLI_INPUT_REACHABLE when "
            "the cli root reaches the unit; else DOWNSTREAM_RUNTIME_OBSERVED when 25.6 observed it at "
            "a functional level; else LOCAL_API_REACHABLE for the binary-abi/source-api/modules "
            "roots; else INTERNAL_REACHABLE for the callbacks root alone; else UNKNOWN_REACHABILITY "
            "when the 25.5 mapping leaves the site unresolved, never UNREACHABLE_PROFILE -- a missing "
            "mapping is not evidence of unreachability; UNREACHABLE_PROFILE is awarded only to a site "
            "that carries a justified exclusion witness (`w`), a committed exclusion residual or a "
            "resolved authority unit no root reaches"
        ),
        "network_entry_semantics": (
            "a network class needs a justified entry semantics, never a static edge: the Phase-22 "
            "closure leaves its `protocol` family unpopulated, so NETWORK_SERVER_REACHABLE/"
            "NETWORK_CLIENT_REACHABLE are assigned only when the site's committed module or authority "
            "unit is the parser an inbound peer drives, and the justification is stored per "
            "class-route in `.justifications`"
        ),
        "attacker_routes": {
            "rule": (
                "a route is recorded for a site that is externally reachable and is a buffer "
                "operation (a raw pointer access, or a manual allocation); the route matches when the "
                "site's committed module or authority unit starts with the parser prefix the route "
                "names"
            ),
            "vocabulary": [r["route"] for r in ROUTES],
            "inputs": {r["route"]: r["input"] for r in ROUTES},
            "transports": {r["route"]: r["transport"] for r in ROUTES},
        },
        "justification_rule": (
            "every externally reachable site carries a `j` justification id whose record names the "
            "class, the route/root and the entry semantics; a network class's justification must name "
            "a network route, so a remote class with no justification is a finding"
        ),
        "buffer_operations": {
            "rule": (
                "a buffer operation is a raw pointer access (RAW_POINTER_READ/WRITE/DEREFERENCE, "
                "UNALIGNED_ACCESS) or a manual 25.4 allocation site; its record names the buffer "
                "origin (the route input or the exposure), the pointer origin (function @ file:line), "
                "the capacity origin (the allocation size expression) and the provenance, and records "
                "`NOT_MEASURED` for the fields the census does not observe"
            ),
            "fields": list(BUFFER_OPERATION_FIELDS),
            "not_measured": [f for f in BUFFER_OPERATION_FIELDS
                             if f in ("length_origin", "bounds_validation",
                                      "integer_conversion_path", "copy_primitive")],
        },
        "risk_tier_rule": (
            "S0 a genuinely non-exposed site; SU (unknown exposure) a site whose exposure the "
            "committed evidence does not establish, ordered above S0 so it stays eligible for "
            "high-priority investigation until evidence narrows it -- an unknown is not the lowest "
            "priority; S1 externally reachable, not a buffer operation; S2 externally reachable "
            "buffer operation; S3 network-reachable buffer operation; S4 network-reachable buffer "
            "operation that writes. A review priority, never a probability"
        ),
        "length_boundary_plan_rule": (
            "per applicable buffer operation, the generic cases len = 0, 1, capacity-1, capacity, "
            "capacity+1, large and near an integer boundary are recorded as a plan; the plan is "
            "marked PLANNED_NOT_EXECUTED and execution belongs to 25.9-25.12"
        ),
        "site_disposition": (
            "every census site is present in `.sites` with exactly one class and one risk tier; an "
            "externally reachable site carries a `j` justification and, when it is a buffer "
            "operation, its attacker routes; a site is never dropped"
        ),
        "sort_key": ("sites by id; routes in the recorded route order; buffer operations by site; "
                     "every list sorted"),
    }


def _property_findings(d: dict) -> list:
    c = d["counts"]
    network_top = sorted(
        d["by_exposure"]["NETWORK_SERVER_REACHABLE"]["top_sites"]
        + d["by_exposure"]["NETWORK_CLIENT_REACHABLE"]["top_sites"])[:3]
    routed_routes = sorted((v["count"], r) for r, v in d["attacker_routes"].items())
    top_routes = ", ".join(f"{r}={n}" for n, r in reversed(routed_routes[-3:]) if n)
    return [
        f"{c['sites_classified']} census site(s) carry exactly one exposure class: "
        f"{c['network_reachable']} are network-reachable ({c['sites_by_exposure'].get('NETWORK_SERVER_REACHABLE', 0)} server, "
        f"{c['sites_by_exposure'].get('NETWORK_CLIENT_REACHABLE', 0)} client), "
        f"{c['externally_reachable']} are externally reachable, {c['unreachable_profile']} are "
        f"`UNREACHABLE_PROFILE` and {c['sites_unknown_reachability']} carry "
        f"`UNKNOWN_REACHABILITY`. Every unreachable site carries a justified exclusion witness; an "
        f"unknown is the site whose 25.5 mapping is missing, and an unknown is not a zero and not an "
        f"unreachability claim",
        f"{c['routed_sites']} site(s) are attacker-input reachable across "
        f"{c['attacker_routes_with_sites']} of {c['attacker_routes']} route(s); the largest are "
        f"{top_routes or 'none'}. The routes are a rule over committed parser identities, not a "
        f"dynamic taint result",
        f"{c['buffer_operations']} externally reachable buffer operation(s) are censused by buffer "
        f"origin, pointer origin and capacity origin; the length origin, the integer-conversion path "
        f"and the copy primitive are `NOT_MEASURED` and are the dynamic subphases' subject",
        f"the risk tiers are a review priority: "
        + ", ".join(f"{t}={c['sites_by_risk_tier'].get(t, 0)}" for t in schemas.RISK_TIERS)
        + f"; an unknown exposure is SU, not S0, so {c['sites_unknown_reachability']} unknown "
          f"site(s) stay eligible for high-priority investigation; {len(network_top)} network "
          f"site(s) are named as the review head",
        f"the Phase-22 closure's `protocol` family is unpopulated, so a network class is grounded in "
        f"the parser's committed role (the module or authority unit the peer drives) and is recorded "
        f"as an `evidence_missing` residual, never read as a wire observation",
    ]


def build_body(census_body: dict, authority: dict) -> dict:
    """The classification body: the rule, the sites, the inverse views, counts and the plan."""
    d = derive_cached(census_body, authority)
    return {
        "rule": _rule(authority),
        "sites": d["sites"],
        "by_exposure": d["by_exposure"],
        "attacker_routes": d["attacker_routes"],
        "buffer_operations": d["buffer_operations"],
        "justifications": d["justifications"],
        "length_boundary_plan": _length_boundary_plan(d),
        "counts": d["counts"],
        "residuals": d["residuals"],
        "findings": _property_findings(d),
        "non_claims": list(NON_CLAIMS),
    }


# --------------------------------------------------------------------------------------------
# the pure checks: what the court runs over the committed artefact
# --------------------------------------------------------------------------------------------

def exposure_findings(body: dict, census_body: dict, authority: dict) -> list:
    """Every way the committed classification contradicts the census or the committed planes.

    Pure over `body` and the committed planes: it checks that every census site has exactly one
    class; that every externally reachable site has a justification (a network class one that names a
    network route); that every attacker route's sites are named and equal the derivation; that the
    inverse view reproduces; that the buffer operations equal the derivation; that the boundary plan
    is marked unexecuted; and that the counts, sites, justifications and residuals equal the
    derivation.
    """
    problems: list = []
    # The committed classification is columnar on disk; re-derive the views the checks read (a fresh
    # measurement passes the views, for which decoding is a no-op).
    census_body = ms_census.decode_body(census_body)
    refs = ms_codec.refs_from_census(census_body)
    body = ms_codec.decode_body(body, refs)
    d = derive_cached(census_body, authority)
    census_ids = [str(s["site_id"]) for s in (census_body.get("sites") or [])]

    sites = body.get("sites") or {}
    justifications = body.get("justifications") or {}

    # 1. The census site ids are unique and every one has a class.
    if len(set(census_ids)) != len(census_ids):
        problems.append("the census carries a duplicate site_id, so a class is ambiguous")
    for sid in sorted(set(census_ids) - set(sites)):
        problems.append(f"the census site {sid} has no exposure class (dropped)")
    for sid in sorted(set(sites) - set(census_ids)):
        problems.append(f"the classification names {sid}, which is not a census site")

    # 2. Exactly one class and one risk tier per site, and every externally reachable site has a
    #    justification (a network class one that names a network route).
    for sid in sorted(set(census_ids) & set(sites)):
        rec = sites[sid]
        cls = rec.get("e")
        if cls not in schemas.EXPOSURE_CLASSES:
            problems.append(f"{sid}: the exposure class {cls!r} is not in the closed vocabulary")
            continue
        if rec.get("r") not in schemas.RISK_TIERS:
            problems.append(f"{sid}: the risk tier {rec.get('r')!r} is not in the risk-tier "
                            f"vocabulary (S0, SU, S1-S4)")
        if cls == "UNKNOWN_REACHABILITY" and rec.get("r") != "SU":
            problems.append(f"{sid}: is UNKNOWN_REACHABILITY but its risk tier is "
                            f"{rec.get('r')!r}, not SU -- an unknown is not a non-exposed site and "
                            f"must not be read as the lowest priority")
        if cls != "UNKNOWN_REACHABILITY" and rec.get("r") == "SU":
            problems.append(f"{sid}: is {cls}, not UNKNOWN_REACHABILITY, but carries the "
                            f"unknown-exposure tier SU")
        external = cls in schemas.EXTERNALLY_REACHABLE_EXPOSURE
        jid = rec.get("j")
        if external and not jid:
            problems.append(f"{sid}: is {cls} (externally reachable) but has no justification")
            continue
        if not external and jid:
            problems.append(f"{sid}: is {cls} (not externally reachable) but carries a justification")
        if external:
            jrec = justifications.get(jid)
            if jrec is None:
                problems.append(f"{sid}: the justification {jid!r} is not recorded")
            else:
                if jrec.get("class") != cls:
                    problems.append(f"{sid}: the justification {jid!r} names class "
                                    f"{jrec.get('class')!r}, not {cls!r}")
                if cls in ("NETWORK_SERVER_REACHABLE", "NETWORK_CLIENT_REACHABLE") \
                        and not jrec.get("network"):
                    problems.append(f"{sid}: is {cls} but its justification {jid!r} names no "
                                    f"network route")
        # An unreachability claim is carried only by a justified exclusion witness recorded on the
        # site; a witness-less `UNREACHABLE_PROFILE` (a missing mapping dressed as unreachability) is
        # caught here, and a witness on any other class is caught too.
        if cls == "UNREACHABLE_PROFILE":
            problems += [f"{sid}: is UNREACHABLE_PROFILE but {p}" for p in _witness_problems(rec.get("w"))]
        elif "w" in rec:
            problems.append(f"{sid}: is {cls}, not UNREACHABLE_PROFILE, but carries an exclusion "
                            f"witness")

    # 3. Every attacker route's sites are named and equal the derivation, and every routed site
    #    names its routes.
    routes = body.get("attacker_routes") or {}
    if sorted(routes) != sorted(ROUTE_ORDER):
        problems.append("the attacker-route vocabulary is not the recorded route order")
    for rname in ROUTE_ORDER:
        rec = routes.get(rname) or {}
        want = sorted(sid for sid in d["sites"] if rname in (d["sites"][sid].get("a") or []))
        if sorted(rec.get("sites") or []) != want or rec.get("count") != len(want):
            problems.append(f"the attacker route {rname} names {rec.get('count')!r} site(s), the "
                            f"derivation has {len(want)}")
    for sid in sorted(set(census_ids) & set(sites)):
        a = sites[sid].get("a") or []
        want = d["sites"][sid].get("a") or []
        if sorted(a) != sorted(want):
            problems.append(f"{sid}: the attacker routes {a} are not the derived routes {want}")

    # 4. The inverse exposure view reproduces from the forward map.
    want_by = d["by_exposure"]
    for cls, rec in want_by.items():
        got = (body.get("by_exposure") or {}).get(cls) or {}
        if got.get("count") != rec["count"]:
            problems.append(f"the inverse exposure view for {cls} records {got.get('count')!r} "
                            f"site(s), the derivation has {rec['count']}")
        if sorted(got.get("top_sites") or []) != sorted(rec["top_sites"]):
            problems.append(f"the inverse exposure view for {cls} names a different top-site set")

    # 5. The buffer operations equal the derivation.
    if (body.get("buffer_operations") or {}) != d["buffer_operations"]:
        problems.append("the committed `buffer_operations` is not the derived `buffer_operations`")

    # 6. The length-boundary plan is a plan, never executed.
    plan = body.get("length_boundary_plan") or {}
    if plan.get("executed") is not False:
        problems.append("the length-boundary plan is marked executed (it is a plan, not a result)")
    if plan.get("status") != "PLANNED_NOT_EXECUTED":
        problems.append(f"the length-boundary plan status {plan.get('status')!r} is not "
                        f"PLANNED_NOT_EXECUTED")
    if not plan.get("cases"):
        problems.append("the length-boundary plan names no boundary case")
    if not plan.get("per_operation"):
        problems.append("the length-boundary plan names no applicable buffer operation")

    # 7. Every plane equals its derivation.
    for key in ("sites", "by_exposure", "attacker_routes", "buffer_operations", "justifications",
                "counts", "residuals"):
        if body.get(key) != d[key]:
            problems.append(f"the committed `{key}` is not the derived `{key}`")

    # 8. The rule names the committed inputs, not a typed context.
    paths = ((body.get("rule") or {}).get("authority") or {}).get("paths") or []
    for want in (CENSUS_REL, PHASE22_CROSSWALK_REL, PHASE24_CROSSWALK_REL):
        if want not in paths:
            problems.append(f"the classification rule does not name its committed authority {want}")

    # 9. Every residual validates against the residual schema.
    for r in body.get("residuals") or []:
        problems += [f"residual[{r.get('residual_id')}]: {p}" for p in schemas.validate("residual", r)]

    return problems


def exposure_sensitivity_control(body: dict, census_body: dict, authority: dict) -> dict:
    """Seed the mutations and require each caught, with specificity holding.

    Each is a distinct way the classification could lie: a remote class with no justification; an
    attacker route that names a site the derivation does not reach; the inverse exposure view
    disagreeing with the forward map; a length-boundary plan marked executed; a dropped site; a typed
    count; an unresolved site promoted to `UNREACHABLE_PROFILE` with no witness; an unresolved site
    promoted to an external class; and an unknown-reachability site assigned the non-exposed tier
    S0.
    """
    # The committed classification is columnar on disk; the mutations below index its records, so
    # decode once (a fresh measurement passes the views, for which decoding is a no-op).
    census_body = ms_census.decode_body(census_body)
    refs = ms_codec.refs_from_census(census_body)
    body = ms_codec.decode_body(body, refs)
    baseline = exposure_findings(body, census_body, authority)
    result: dict = {"baseline_findings": len(baseline), "honest": not baseline,
                    "specificity_holds": False, "mutations": {}}

    def check(label: str, mutated: dict, marker: str) -> bool:
        found = exposure_findings(mutated, census_body, authority)
        caught = any(marker in f for f in found)
        result["mutations"][label] = {"caught": caught, "findings": len(found),
                                      "delta": len(found) - len(baseline), "marker": marker}
        return caught

    def clone() -> dict:
        return json.loads(json.dumps(body))

    network = sorted(sid for sid, rec in body["sites"].items()
                     if rec.get("e") == "NETWORK_SERVER_REACHABLE")
    routed = sorted(sid for sid, rec in body["sites"].items() if rec.get("a"))
    unknown = sorted(sid for sid, rec in body["sites"].items()
                     if rec.get("e") == "UNKNOWN_REACHABILITY")
    any_site = sorted(body["sites"])[0]
    classes = sorted(body["by_exposure"])

    # m1: a remote class with no justification -- a non-network site promoted to a network class,
    #     with the justification dropped.
    def remote_without_justification() -> dict:
        b = clone()
        sid = next(s for s in sorted(body["sites"])
                   if body["sites"][s].get("e") not in
                   ("NETWORK_SERVER_REACHABLE", "NETWORK_CLIENT_REACHABLE"))
        b["sites"][sid]["e"] = "NETWORK_SERVER_REACHABLE"
        b["sites"][sid].pop("j", None)
        return b

    m1 = check("remote_class_without_justification", remote_without_justification(),
               "has no justification")

    # m2: an attacker route that names a site the derivation does not reach.
    def route_with_no_path() -> dict:
        b = clone()
        rname = sorted(b["attacker_routes"])[0]
        bogus = next(s for s in sorted(body["sites"])
                     if rname not in (body["sites"][s].get("a") or []))
        b["attacker_routes"][rname]["sites"] = sorted(
            (b["attacker_routes"][rname]["sites"] or []) + [bogus])
        b["attacker_routes"][rname]["count"] += 1
        return b

    m2 = check("attacker_route_with_no_path", route_with_no_path(),
               "the derivation has")

    # m3: the inverse exposure view disagreeing with the forward map.
    def inverse_disagrees() -> dict:
        b = clone()
        c = classes[0]
        b["by_exposure"][c]["count"] += 1
        return b

    m3 = check("inverse_view_disagrees", inverse_disagrees(), "the derivation has")

    # m4: a length-boundary plan marked executed.
    def plan_executed() -> dict:
        b = clone()
        b["length_boundary_plan"]["executed"] = True
        return b

    m4 = check("boundary_plan_marked_executed", plan_executed(), "marked executed")

    # m5: a census site silently dropped.
    def drop_site() -> dict:
        b = clone()
        b["sites"].pop(routed[0] if routed else any_site, None)
        return b

    m5 = check("site_dropped", drop_site(), "has no exposure class")

    # m6: a typed count.
    def typed_count() -> dict:
        b = clone()
        b["counts"]["network_reachable"] += 1
        return b

    m6 = check("typed_count", typed_count(), "not the derived `counts`")

    # m7: an unresolved site promoted to `UNREACHABLE_PROFILE` with no witness. A missing mapping is
    #     not an unreachability claim, so this must be caught by the witness requirement.
    def unresolved_to_unreachable_without_witness() -> dict:
        b = clone()
        sid = unknown[0] if unknown else any_site
        b["sites"][sid]["e"] = "UNREACHABLE_PROFILE"
        b["sites"][sid].pop("w", None)
        return b

    m7 = check("unresolved_to_unreachable_without_witness",
               unresolved_to_unreachable_without_witness(), "no justified exclusion witness")

    # m8: an unresolved site promoted to an external class, with no route justification. An unknown
    #     is not an external reachability claim, so this must be caught.
    def unresolved_to_external_class() -> dict:
        b = clone()
        sid = unknown[0] if unknown else any_site
        b["sites"][sid]["e"] = "NETWORK_SERVER_REACHABLE"
        b["sites"][sid].pop("j", None)
        b["sites"][sid].pop("w", None)
        return b

    m8 = check("unresolved_to_external_class", unresolved_to_external_class(),
               "has no justification")

    # m9: an unknown-reachability site assigned the non-exposed tier S0. An unknown is not a
    #     non-exposed site, so this must be caught rather than read as the lowest priority.
    def unknown_to_s0() -> dict:
        b = clone()
        sid = unknown[0] if unknown else any_site
        b["sites"][sid]["r"] = "S0"
        return b

    m9 = check("unknown_exposure_assigned_s0", unknown_to_s0(), "not SU")

    result["specificity_holds"] = bool(m1 and m2 and m3 and m4 and m5 and m6 and m7 and m8 and m9
                                       and not baseline)
    result["caught"] = sum(1 for v in result["mutations"].values() if v["caught"])
    result["seeded"] = len(result["mutations"])
    return result


# --------------------------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------------------------

def _synth_authority() -> dict:
    """A tiny, self-consistent set of planes: a wire parser, a format parser, an unresolved file and
    a committed exclusion (a witnessed `UNREACHABLE_PROFILE`)."""
    census = {"sites": [
        {"site_id": "us-tls-1", "file": "src/ssl/record/rec.rs", "line": 10, "function": "read_rec",
         "operation_kind": "RAW_POINTER_READ"},
        {"site_id": "us-tls-2", "file": "src/ssl/record/rec.rs", "line": 20, "function": "write_rec",
         "operation_kind": "RAW_POINTER_WRITE"},
        {"site_id": "us-pem-1", "file": "src/pem/pem_lib.rs", "line": 30, "function": "pem_read",
         "operation_kind": "RAW_POINTER_DEREFERENCE"},
        {"site_id": "us-api-1", "file": "src/bn/bn_lib.rs", "line": 40, "function": "bn_alloc",
         "operation_kind": "UNSAFE_FUNCTION_CALL"},
        {"site_id": "us-un-1", "file": "src/apps/x.rs", "line": 50, "function": "main_like",
         "operation_kind": "RAW_POINTER_READ"},
        {"site_id": "us-ex-1", "file": "src/generated/tables.rs", "line": 60, "function": "gen",
         "operation_kind": "RAW_POINTER_READ"},
    ]}
    phase22 = {"body": {"sites": {
        "us-tls-1": {"unit": "ssl/record/rec_layer_s3.c", "roots": ["binary-abi", "source-api",
                                                                    "callbacks", "cli",
                                                                    "configuration", "modules"]},
        "us-tls-2": {"unit": "ssl/record/rec_layer_s3.c", "roots": ["binary-abi", "source-api",
                                                                    "callbacks", "cli",
                                                                    "configuration", "modules"]},
        "us-pem-1": {"unit": "crypto/pem/pem_lib.c", "roots": ["binary-abi", "source-api", "cli"]},
        "us-api-1": {"unit": "crypto/bn/bn_lib.c", "roots": ["source-api"]},
        "us-un-1": {"module": "src/apps/x.rs", "residual": "evidence_missing"},
        "us-ex-1": {"module": "src/generated/tables.rs", "residual": "out_of_scope"},
    }}}
    phase24 = {"body": {"sites": {
        "us-tls-1": {"state": "NOT_OBSERVED"},
        "us-tls-2": {"state": "NOT_OBSERVED"},
        "us-pem-1": {"state": "DOWNSTREAM_RUNTIME_OBSERVED"},
        "us-api-1": {"state": "NOT_OBSERVED"},
        "us-un-1": {"state": "NOT_OBSERVED"},
        "us-ex-1": {"state": "NOT_OBSERVED"},
    }}}
    ownership = {"body": {"allocation_sites": [
        {"site_id": "us-api-1", "role": "ALLOC", "allocator": "CRYPTO_malloc",
         "size_expr": "size_of::<Bignum>()"},
    ]}}
    return {
        "census": census,
        "phase22_crosswalk": phase22,
        "phase24_crosswalk": phase24,
        "ownership_planes": ownership,
    }


def self_test() -> int:
    """Prove the metadata-only admission holds, the derivation is clean and the control is honest."""
    failures: list = []

    admission = phase25_guard.evaluate(entry_point="ms_exposure.py", env={}, dockerenv=False)
    if not admission["admitted"] or admission["venue"] != "metadata-only":
        failures.append("ms_exposure.py is not admitted as a metadata-only generator on a host")

    authority = _synth_authority()
    census = authority.pop("census")
    body = build_body(census, authority)
    baseline = exposure_findings(body, census, authority)
    if baseline:
        failures.append(f"the synthetic classification body is not clean: {baseline[:4]}")
    c = body["counts"]
    if c["sites_by_exposure"]["NETWORK_SERVER_REACHABLE"] != 2:
        failures.append(f"the synthetic network-server count is wrong: {c['sites_by_exposure']}")
    if c["sites_by_exposure"]["LOCAL_FILE_INPUT_REACHABLE"] != 1:
        failures.append(f"the synthetic local-file count is wrong: {c['sites_by_exposure']}")
    if c["sites_by_exposure"]["LOCAL_API_REACHABLE"] != 1:
        failures.append(f"the synthetic local-api count is wrong: {c['sites_by_exposure']}")
    if c["sites_by_exposure"]["UNREACHABLE_PROFILE"] != 1:
        failures.append(f"the synthetic unreachable count is wrong: {c['sites_by_exposure']}")
    if c["sites_unknown_reachability"] != 1:
        failures.append(f"the synthetic unknown-reachability count is wrong: {c['sites_by_exposure']}")
    if body["sites"]["us-un-1"].get("r") != "SU":
        failures.append(f"the synthetic unknown-reachability site is not tier SU: "
                        f"{body['sites']['us-un-1'].get('r')!r}")
    if body["sites"]["us-ex-1"].get("r") != "S0":
        failures.append(f"the synthetic witnessed-unreachable site is not tier S0: "
                        f"{body['sites']['us-ex-1'].get('r')!r}")
    witness = body["sites"]["us-ex-1"].get("w")
    if not isinstance(witness, dict) or witness.get("kind") != "committed_exclusion_residual":
        failures.append(f"the synthetic committed-exclusion witness is not recorded: {witness}")
    if "w" in body["sites"]["us-un-1"]:
        failures.append("an unresolved site carries an exclusion witness")
    if not EXCLUSION_RESIDUALS <= set(schemas.RESIDUAL_CLASSES):
        failures.append("an exclusion residual is not in the schema residual vocabulary")
    if c["routed_sites"] != 3 or c["attacker_routes_with_sites"] < 2:
        failures.append(f"the synthetic route counts are wrong: {c}")
    if c["buffer_operations"] != 4:
        failures.append(f"the synthetic buffer-operation count is wrong: {c['buffer_operations']}")
    if body["length_boundary_plan"]["executed"] is not False:
        failures.append("the synthetic length-boundary plan is marked executed")
    control = exposure_sensitivity_control(body, census, authority)
    if not control["specificity_holds"] or control["caught"] != control["seeded"]:
        failures.append(f"the sensitivity control is not honest: {control}")

    if failures:
        print("[ms-exposure] self-test FAILED")
        for f in failures:
            print(f"  {f}")
        return 1
    print("[ms-exposure] self-test ok: the guard admits it as metadata-only; the synthetic "
          "classification is clean (2 network-server, 1 local-file, 1 local-api, 1 witnessed "
          "unreachable at tier S0, 1 unknown-reachability at tier SU; 3 routed sites, 4 buffer "
          "operations, an unexecuted boundary plan); and every seeded mutation (a remote class with "
          "no justification, an attacker route with no path, an inverse view that disagrees, an "
          "executed boundary plan, a dropped site, a typed count, an unresolved site promoted to "
          "unreachable with no witness, an unresolved site promoted to an external class, and an "
          "unknown-reachability site assigned tier S0) is caught with specificity holding")
    return 0


# --------------------------------------------------------------------------------------------
# entry points
# --------------------------------------------------------------------------------------------

def _write_plane(path: Path, doc: dict) -> None:
    """Write the plane compactly, key-sorted and deterministic."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


def _inputs() -> list:
    return [
        InputRef(name="phase-25-plan", path=PLAN),
        InputRef(name="memory-safety-schemas", path=SCHEMAS),
        InputRef(name="phase25-guard", path=GUARD),
        InputRef(name="phase25-container-manifest", path=MANIFEST),
        InputRef(name="ms-exposure-tool", path=TOOL),
        InputRef(name="source-census", path=CENSUS),
        InputRef(name="phase22-crosswalk", path=PHASE22_CROSSWALK),
        InputRef(name="phase24-crosswalk", path=PHASE24_CROSSWALK),
        InputRef(name="ownership-planes", path=OWNERSHIP_PLANES),
    ]


def _measure() -> int:
    """Derive the classification from the committed planes and write it."""
    census_body = ms_census.decode_body(_body(_load(CENSUS)))
    refs = ms_codec.refs_from_census(census_body)
    authority = load_authority()
    body = build_body(census_body, authority)
    problems = exposure_findings(body, census_body, authority)

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    encoded = ms_codec.encode_body(body, refs)
    doc = envelope(kind="phase25-exposure", authority=auth.id, inputs=_inputs(),
                   body=encoded, generator=GENERATOR)
    doc["body_hash"] = content_hash(encoded)
    _write_plane(OUT, doc)

    c = body["counts"]
    print("[ms-exposure] sites by exposure: "
          + ", ".join(f"{k}={v}" for k, v in sorted(c["sites_by_exposure"].items())))
    print(f"  externally reachable: {c['externally_reachable']}; network-reachable: "
          f"{c['network_reachable']}; routed sites: {c['routed_sites']}; buffer operations: "
          f"{c['buffer_operations']}")
    print("  sites by risk tier: "
          + ", ".join(f"{t}={c['sites_by_risk_tier'].get(t, 0)}" for t in schemas.RISK_TIERS))
    print("  attacker routes: "
          + ", ".join(f"{r}={v['count']}" for r, v in sorted(body["attacker_routes"].items())))
    print(f"  -> {rel(OUT)} all_pass={not problems} (findings={len(body['findings'])}, "
          f"residuals={len(body['residuals'])})")
    if problems:
        for p in problems[:24]:
            print(f"    {p}")
    return 0 if not problems else 1


def _check() -> int:
    """Re-run the pure checks over the committed classification, without a compiler."""
    if not OUT.is_file():
        print(f"[ms-exposure] {rel(OUT)} is absent; run --measure")
        return 1
    body = _body(_load(OUT))
    census_body = _body(_load(CENSUS))
    authority = load_authority()
    problems = exposure_findings(body, census_body, authority)
    if problems:
        print(f"[ms-exposure] check FAILED: {len(problems)} problem(s)")
        for p in problems[:24]:
            print(f"  {p}")
        return 1
    c = body["counts"]
    print(f"[ms-exposure] check ok: {c['sites_classified']} site(s) classified, "
          f"{c['network_reachable']} network-reachable, {c['routed_sites']} routed, "
          f"{c['buffer_operations']} buffer operation(s), {len(body['residuals'])} residual(s); "
          f"every check holds")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--measure", action="store_true",
                    help="derive artifacts/phase25/exposure.json from the committed inputs")
    ap.add_argument("--check", action="store_true",
                    help="re-run the pure checks over the committed classification")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the metadata-only admission and the control is honest")
    args = ap.parse_args(argv)

    # The Docker-only execution guard, called first. This tool executes nothing, so the manifest
    # lists it `metadata_only` and the guard admits it on any host.
    phase25_guard.require_admitted()

    if args.self_test:
        return self_test()
    if args.check:
        return _check()
    # The default action is the derivation (and `--measure` names it): `evidence_determinism.py`
    # regenerates every generator with no flags and compares the bytes.
    return _measure()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
