#!/usr/bin/env python3
"""location_fidelity.py -- truthful locations for Rust, FFI and binary findings.

The normative document is `docs/LOCATION-FIDELITY.md`. This module implements the
per-class rules it states, projects a native location record into the one location
the record supports, and refuses every fabrication the document names.

What this module does
---------------------
* `project(record)` builds the most precise location the native record actually
  contains, and refuses a record that is internally inconsistent. It never adds a
  line, a column, an extent, an address or a call site that the record lacks.
* `check(record, emission)` validates an already-built emission against the same
  record and returns a stable refusal code for each fabrication class, so a
  consumer can tell *which* substitution happened.
* `scan_sarif(document)` checks an A1 emission for the location policy the A1
  profile fixed (line-only source regions, byte-offset binary regions, no
  `endLine`/`endColumn`/`charOffset`, record-level findings without locations) and
  for the A4 refinements. It does not change the A1 profile; it holds an emission
  to it.
* `verify_instances(document, repo_root)` re-projects every recorded instance,
  re-reads the tracked provenance it cites, and applies each recorded mutation to
  confirm that the named refusal fires.

What this module does not do
----------------------------
It does not analyse source or machine code, decide that a finding is true, or
recover a location the native record does not contain. A compiler's expansion
stack, a monomorphised instance's source line, an inlined callee's boundary and a
dynamic call's runtime target are unavailable by construction unless a record
carries them; this module records the absence rather than filling it. It does not
weaken `docs/SARIF-PROFILE.md` §7: no emission rule is relaxed and the A1
population is scanned unchanged.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

MODEL_ID = "a4/v1"
CLASS_SCHEMA = "openssl-rs/a4/classes/1"
INSTANCE_SCHEMA = "openssl-rs/a4/instances/1"

# --------------------------------------------------------------------------
# Refusals. A code is stable: a document, receipt or test cites it verbatim.
# --------------------------------------------------------------------------

R_UNKNOWN_CLASS = "LF_REFUSED_UNKNOWN_CLASS"
R_MISSING_SUBJECT = "LF_REFUSED_MISSING_SUBJECT"
R_MISSING_ARTIFACT_DIGEST = "LF_REFUSED_MISSING_ARTIFACT_DIGEST"
R_MISSING_SYMBOL = "LF_REFUSED_MISSING_SYMBOL"
R_MISSING_ADDRESS = "LF_REFUSED_MISSING_ADDRESS"
R_FABRICATED_LINE = "LF_REFUSED_FABRICATED_LINE"
R_DEFINITION_AS_INSTANCE = "LF_REFUSED_DEFINITION_AS_INSTANCE"
R_MACHINE_CODE_LINE = "LF_REFUSED_MACHINE_CODE_LINE"
R_COLUMN_NOT_EMITTED = "LF_REFUSED_COLUMN_NOT_EMITTED"
R_UNRECORDED_EXTENT = "LF_REFUSED_UNRECORDED_EXTENT"
R_FILE_NOT_IN_CANDIDATE = "LF_REFUSED_FILE_NOT_IN_CANDIDATE"
R_INLINED_CALL_SITE = "LF_REFUSED_INLINED_CALL_SITE"
R_UNRECORDED_CALL_SITE = "LF_REFUSED_UNRECORDED_CALL_SITE"
R_FABRICATED_CALL_SITE = "LF_REFUSED_FABRICATED_CALL_SITE"
R_FABRICATED_ADDRESS = "LF_REFUSED_FABRICATED_ADDRESS"
R_FABRICATED_SYMBOL = "LF_REFUSED_FABRICATED_SYMBOL"
R_RECORD_CONDITION_WITH_LOCATION = "LF_REFUSED_RECORD_CONDITION_WITH_LOCATION"
R_EMISSION_INVALID = "LF_REFUSED_EMISSION_INVALID"
R_INSTANCE = "LF_REFUSED_INSTANCE"
R_PROVENANCE = "LF_REFUSED_PROVENANCE"

# code -> (short description, what a reader would wrongly conclude)
REFUSALS = {
    R_UNKNOWN_CLASS: (
        "the class is not one of the eight registered location classes",
        "that the record's class has no rule, so any location it carries might be "
        "the truthful one",
    ),
    R_MISSING_SUBJECT: (
        "the record names neither a source path nor a binary artefact",
        "that a location was verified when no subject was verified",
    ),
    R_MISSING_ARTIFACT_DIGEST: (
        "a binary finding names no artefact digest",
        "that the bytes examined are the candidate's bytes (Article 2)",
    ),
    R_MISSING_SYMBOL: (
        "a symbol-only finding names no symbol",
        "that a symbol location exists when the record names none",
    ),
    R_MISSING_ADDRESS: (
        "a binary finding records neither an address nor a byte offset",
        "that a machine-code location exists when none was recorded",
    ),
    R_FABRICATED_LINE: (
        "the emitted line is not the line the native record carries",
        "that the defect is at a line no native record identifies, so a reader "
        "may review, patch or suppress the wrong code, or conclude the finding is "
        "absent because that line does not exist",
    ),
    R_DEFINITION_AS_INSTANCE: (
        "a definition site (macro body, generic body) is presented as an "
        "instantiation's own location",
        "that each instantiation has its own line at the shared definition, so a "
        "per-instance defect is reported at a line that only contains the shared "
        "body, and fixing that line is read as fixing one instance",
    ),
    R_MACHINE_CODE_LINE: (
        "a machine-code finding carries a source line",
        "that the emitted instruction has a source line, when the record records "
        "an address only; a reader would mark up a source line the compiler may "
        "not have emitted the instruction from, particularly after inlining",
    ),
    R_COLUMN_NOT_EMITTED: (
        "a column is emitted as a SARIF column",
        "a token-level precision the record does not state, with an unstated unit",
    ),
    R_UNRECORDED_EXTENT: (
        "an end line, column, offset, length or byte extent not present in the "
        "native record is emitted",
        "that the tool observed the whole range, statement or symbol, so a "
        "diff, suppression or patch is scoped to bytes nobody examined",
    ),
    R_FILE_NOT_IN_CANDIDATE: (
        "the location names a file the candidate identity does not contain",
        "that the finding applies to this candidate, when the record came from "
        "another candidate or a path that no longer exists (Article 2)",
    ),
    R_INLINED_CALL_SITE: (
        "an inlined finding is presented as if it had a distinct call site or "
        "callee symbol",
        "that a call exists in the binary, so a breakpoint, patch or suppression "
        "is placed where no instruction calls the inlined body, and a fix at the "
        "reported call site does not change the inlined code",
    ),
    R_UNRECORDED_CALL_SITE: (
        "a dynamic or indirect call has no recorded call-site offset",
        "that the dispatch's location is known when only its target set or its "
        "containing function is known",
    ),
    R_FABRICATED_CALL_SITE: (
        "the emitted call-site offset is not the one the record carries",
        "that the instruction at an invented offset is the dispatch, so the "
        "wrong instruction is read as the call",
    ),
    R_FABRICATED_ADDRESS: (
        "the emitted address is not the address the record carries",
        "that a resolved target was observed when the record establishes no such "
        "target",
    ),
    R_FABRICATED_SYMBOL: (
        "a symbol name is emitted although the record names none",
        "that the binary has that symbol and that the finding is inside it",
    ),
    R_RECORD_CONDITION_WITH_LOCATION: (
        "a record-level condition is given a code location",
        "that the condition is a property of a file or instruction, when it is a "
        "property of the record, so a reader hunts for code that carries no defect",
    ),
    R_EMISSION_INVALID: (
        "the emission differs from the one the record supports in a way no "
        "narrower refusal names",
        "that the emission is the projection of the record when it is not",
    ),
    R_INSTANCE: (
        "a recorded A4 instance failed its own projection or control",
        "that the instance supports the rule it is cited for",
    ),
    R_PROVENANCE: (
        "the tracked provenance an instance cites cannot be read or does not "
        "carry the expected native fields",
        "that the instance is bound to the native record it names",
    ),
}


class Refusal(Exception):
    """A refusal to emit or accept a location. Carries a stable code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# The eight classes.
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ClassRule:
    id: str
    title: str
    subjects: tuple[str, ...]
    truthful: str
    unavailable: tuple[str, ...]
    never_emit: tuple[str, ...]
    precision: tuple[str, ...]
    instance_ids: tuple[str, ...] = ()
    occurrence: str = "present"

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "subjects": list(self.subjects),
            "truthful": self.truthful,
            "unavailable": list(self.unavailable),
            "never_emit": list(self.never_emit),
            "precision": list(self.precision),
            "instanceIds": list(self.instance_ids),
            "occurrence": self.occurrence,
        }


CLASSES: tuple[ClassRule, ...] = (
    ClassRule(
        id="inline-macro-expansion",
        title="Inline macro expansion at an invocation site",
        subjects=("source", "binary"),
        truthful=(
            "The span the compiler assigned to the tokens that carry the finding. "
            "A block written at the invocation belongs to the invocation line; a "
            "token written in the macro body belongs to the definition line. When "
            "the record carries an expansion origin, emit it as expansion "
            "metadata; the invocation line alone is a complete source location for "
            "an invocation-site token."
        ),
        unavailable=(
            "the expansion call stack when the record does not carry it",
            "hygiene context",
            "a token-level mapping between body and invocation tokens",
            "a binary address unless the record records one",
        ),
        never_emit=(
            "the macro definition line substituted for an invocation-site finding",
            "a synthesized expansion origin or line",
            "a column as a SARIF column",
        ),
        precision=("line", "symbol-only", "byte-offset-in-artifact", "function-offset-and-extent"),
        instance_ids=("L1-cmp-ctx-cb-to-ptr",),
    ),
    ClassRule(
        id="macro-rules-derive-output",
        title="macro_rules! or derive output (generated items)",
        subjects=("source", "binary"),
        truthful=(
            "For a macro_rules! body the compiler attributes generated tokens to "
            "the definition line, with an expansion origin only where the record "
            "supplies one. Each invocation is a separate instantiation with its own "
            "generated name and no distinct source line. A derive-generated item "
            "has no source file or line of its own; the attribute's line locates "
            "the input, not the generated code."
        ),
        unavailable=(
            "a per-instantiation source line",
            "the expansion origin when unrecorded",
            "the location of derive-generated items",
            "the number of instantiations unless the record counts them",
        ),
        never_emit=(
            "the definition line as each instantiation's own line",
            "a line for each derived impl",
            "a synthesized expansion stack",
            "an extent over generated code the record does not measure",
        ),
        precision=("definition-site", "symbol-only", "byte-offset-in-artifact", "function-offset-and-extent"),
        instance_ids=("L2-define-new-free",),
    ),
    ClassRule(
        id="monomorphised-generic",
        title="Monomorphised generic instance",
        subjects=("source", "binary"),
        truthful=(
            "For source, the generic definition line is the shared body and is not "
            "any instance's own line. For a binary finding, the mangled or "
            "demangled instantiation symbol and its offset are the location; the "
            "generic definition is background, never the instance's address."
        ),
        unavailable=(
            "a per-instantiation source line",
            "the type arguments unless the symbol is demangled",
            "a distinct source extent for each instance",
        ),
        never_emit=(
            "the generic definition line as the instance's line",
            "a type-argument-specific line",
            "a symbol the record does not name",
        ),
        precision=("generic-definition-body", "symbol-only", "byte-offset-in-artifact", "function-offset-and-extent"),
        instance_ids=("L3-md32-update",),
    ),
    ClassRule(
        id="dynamic-dispatch",
        title="Trait-object or dynamic dispatch call",
        subjects=("source", "binary"),
        truthful=(
            "The call site the record carries, with the static target set it "
            "establishes. A trait method's definition is shared by every dynamic "
            "call and is not the call's location. In a binary, the containing "
            "function's offset plus the call-site offset is the whole location."
        ),
        unavailable=(
            "the runtime target unless the record resolves it",
            "the receiver's concrete type",
            "the callee's source line",
            "the trait definition's applicability to this call",
        ),
        never_emit=(
            "the trait method's definition line as the call's location",
            "a single resolved target the record does not establish",
            "a call site the record does not carry",
        ),
        precision=("line", "call-site-offset-in-artifact", "symbol-only"),
        instance_ids=("L4-bsearch-dyn-call",),
    ),
    ClassRule(
        id="no-mangle-export",
        title="#[no_mangle] C ABI export",
        subjects=("source", "binary"),
        truthful=(
            "For source, the Rust declaration line is truthful for the export "
            "declaration. For a binary finding, the exported symbol name is the "
            "identity and the DSO plus address is the location. The export "
            "declaration line is never the address of the machine code."
        ),
        unavailable=(
            "a line or column for the machine-code occurrence",
            "the caller, unless the record records one",
            "the export's Rust signature in the binary beyond the symbol name",
        ),
        never_emit=(
            "a source line for a machine-code finding at the export",
            "a symbol the record does not name",
            "a definition site substituted for an address",
        ),
        precision=("line", "function-offset-and-extent", "byte-offset-in-artifact", "symbol-only"),
        instance_ids=("L5-cmp-ctx-export",),
    ),
    ClassRule(
        id="indirect-function-pointer-call",
        title="Indirect call through a function pointer",
        subjects=("source", "binary"),
        truthful=(
            "The DSO, the containing function's offset and the offset of the "
            "instruction that performs the indirect call. If the record resolves "
            "the pointer's provenance, the provenance is emitted verbatim; the "
            "callee is not a location the record establishes unless it names one."
        ),
        unavailable=(
            "the callee when unresolved",
            "a source line for the call site",
            "the callee's definition line",
            "an instruction extent unless the record measures one",
        ),
        never_emit=(
            "a line or column",
            "one target presented as resolved when the record records a set or a "
            "contract",
            "a definition site in place of the call-site offset",
        ),
        precision=("call-site-offset-in-artifact", "symbol-only"),
        instance_ids=("L6-store-loader-closefn",),
    ),
    ClassRule(
        id="inlined-optimised-code",
        title="Inlined function in optimised code",
        subjects=("source", "binary"),
        truthful=(
            "The enclosing out-of-line symbol and the offset of the inlined code "
            "inside it. The inlined body has no symbol and no call site of its own. "
            "A source line for the body is truthful as source text; it does not "
            "become a binary location."
        ),
        unavailable=(
            "a symbol for the inlined function",
            "a distinct call site",
            "the boundary between inlined body and caller",
            "a per-copy source line from the binary",
        ),
        never_emit=(
            "an inlined result presented with a distinct call site",
            "a symbol that does not exist",
            "a call-site offset that is not an instruction boundary",
            "the callee's source line as the binary location",
        ),
        precision=("function-offset-and-extent", "byte-offset-in-artifact", "line"),
        instance_ids=("L7-store-close-it", "L7-compress-staged"),
    ),
    ClassRule(
        id="binary-symbol-only",
        title="Function reached only through a binary symbol",
        subjects=("binary",),
        truthful=(
            "The DSO, the exported symbol name and the address or byte offset the "
            "record carries. Where the record also carries an extent, emit both "
            "lengths equally. A source definition may be cited as background but is "
            "not the binary occurrence's location, and symbol presence establishes "
            "no reachability."
        ),
        unavailable=(
            "a source line for the binary occurrence",
            "the call path",
            "reachability from an entry point, which symbol presence does not "
            "establish",
            "an extent when the record records none",
        ),
        never_emit=(
            "a source location presented as the binary finding's location",
            "a call site the record does not carry",
            "a reachability claim derived from symbol presence",
        ),
        precision=("symbol-only", "function-offset-and-extent", "byte-offset-in-artifact"),
        instance_ids=("L8-bn-mod-inverse",),
    ),
)

BY_ID = {rule.id: rule for rule in CLASSES}


def classes_document() -> dict:
    return {
        "schema": CLASS_SCHEMA,
        "model": MODEL_ID,
        "classes": [rule.as_dict() for rule in CLASSES],
        "refusals": [
            {"code": code, "description": description, "consequence": consequence}
            for code, (description, consequence) in REFUSALS.items()
        ],
        "a1PolicyChange": "none",
    }


# --------------------------------------------------------------------------
# Record inspection helpers.
# --------------------------------------------------------------------------

SOURCE_ORIGINS = {
    "direct",
    "invocation-span",
    "expanded-token",
    "macro-definition",
    "generic-definition",
    "inlined-caller",
    "symbol",
    "none",
}
INSTANTIATION_ORIGINS = {"direct", "invocation-span", "expanded-token"}


def _rule(record: dict) -> ClassRule:
    class_id = record.get("class")
    if class_id not in BY_ID:
        raise Refusal(R_UNKNOWN_CLASS, f"class {class_id!r} is not registered")
    return BY_ID[class_id]


def _subject(record: dict) -> dict:
    subject = record.get("subject")
    if not isinstance(subject, dict):
        raise Refusal(R_MISSING_SUBJECT, "record has no subject object")
    if subject.get("kind") not in {"source", "binary", "record"}:
        raise Refusal(
            R_MISSING_SUBJECT, f"subject kind {subject.get('kind')!r} is not a location kind"
        )
    if subject["kind"] in {"source", "binary"} and not isinstance(subject.get("uri"), str):
        raise Refusal(R_MISSING_SUBJECT, "subject has no uri")
    return subject


def _native(record: dict) -> dict:
    native = record.get("native")
    return native if isinstance(native, dict) else {}


def _artifact_location(subject: dict) -> dict:
    digest = subject.get("digest")
    if not isinstance(digest, str) or not digest:
        raise Refusal(R_MISSING_ARTIFACT_DIGEST, f"{subject.get('uri')!r} has no digest")
    scope = subject.get("digestScope")
    algorithm = subject.get("algorithm")
    if not scope or not algorithm:
        raise Refusal(
            R_MISSING_ARTIFACT_DIGEST,
            f"{subject.get('uri')!r} has no digestScope/algorithm pair",
        )
    return {
        "uri": subject["uri"],
        "digest": digest,
        "digestScope": scope,
        "algorithm": algorithm,
    }


def _check_candidate_file(subject: dict) -> None:
    files = subject.get("candidateFiles")
    if files is None:
        return
    if not isinstance(files, list):
        raise Refusal(R_FILE_NOT_IN_CANDIDATE, "candidateFiles is not a list")
    if subject["uri"] not in files:
        raise Refusal(
            R_FILE_NOT_IN_CANDIDATE,
            f"{subject['uri']!r} is not in the candidate's file set",
        )


def _source_location(rule: ClassRule, native: dict, subject: dict) -> dict:
    _check_candidate_file(subject)
    line = native.get("line")
    origin = native.get("lineOrigin") or "none"
    if origin not in SOURCE_ORIGINS:
        raise Refusal(R_EMISSION_INVALID, f"lineOrigin {origin!r} is not registered")
    symbol = native.get("symbol")
    limitations: list[str] = []

    if line is None or origin == "symbol":
        if not symbol:
            return {
                "class": rule.id,
                "precision": "none",
                "location": None,
                "properties": {
                    "locationPrecision": "none",
                    "lineInfoAvailable": False,
                    "extentRecorded": False,
                    "instantiationLineRecorded": False,
                    "nativeLineOrigin": origin,
                },
                "limitations": ["the record records no source line and no symbol"],
            }
        return {
            "class": rule.id,
            "precision": "symbol-only",
            "location": {
                "logicalLocations": [{"kind": "function", "name": symbol}],
            },
            "properties": {
                "locationPrecision": "symbol-only",
                "lineInfoAvailable": False,
                "extentRecorded": False,
                "instantiationLineRecorded": False,
                "nativeLineOrigin": origin,
            },
            "limitations": [
                "the record names a symbol and no source line; no line is derived "
                "from the symbol"
            ],
        }

    precision = "line"
    if rule.id == "macro-rules-derive-output" and origin == "macro-definition":
        precision = "definition-site"
        limitations.append(
            "the line is the macro definition's; the record does not carry a "
            "per-instantiation line"
        )
    elif rule.id == "monomorphised-generic" and origin == "generic-definition":
        precision = "generic-definition-body"
        limitations.append(
            "the line is the shared generic body's; no instance has its own line"
        )
    elif rule.id == "inline-macro-expansion":
        if origin == "invocation-span":
            precision = "line"
        elif origin == "expanded-token":
            precision = "line"
            limitations.append("the line is the span of the expanded token")
        else:
            precision = "definition-site"
            limitations.append(
                "the record carries the macro definition site, not an invocation "
                "span; no invocation line is invented"
            )

    properties = {
        "locationPrecision": precision,
        "lineInfoAvailable": True,
        "extentRecorded": False,
        "instantiationLineRecorded": origin in INSTANTIATION_ORIGINS,
        "nativeLineOrigin": origin,
        "expansionOriginRecorded": bool(native.get("expansionOrigin")),
    }
    if native.get("expansionOrigin"):
        properties["expansionOrigin"] = native["expansionOrigin"]
    column = native.get("column")
    if column is not None:
        properties["column"] = int(column)
        properties["columnUnit"] = native.get("columnUnit") or "not-recorded"
        limitations.append(
            "the recorded column is preserved as a native field and is not "
            "emitted as a SARIF column; its unit is the recorded one"
        )
    if native.get("symbol"):
        properties["nativeSymbol"] = native["symbol"]

    return {
        "class": rule.id,
        "precision": precision,
        "location": {
            "physicalLocation": {
                "artifactLocation": {"uri": subject["uri"]},
                "region": {"startLine": int(line)},
            }
        },
        "properties": properties,
        "limitations": limitations,
    }


def _binary_location(rule: ClassRule, native: dict, subject: dict) -> dict:
    _check_candidate_file(subject)
    artifact = _artifact_location(subject)
    symbol = native.get("symbol")
    address = native.get("address")
    offset = native.get("byteOffset")
    call_site = native.get("callSite")
    byte_length = native.get("byteLength")
    extent_recorded = bool(native.get("extentRecorded"))
    kind = native.get("addressKind") or "instruction"
    if kind not in {"function", "instruction"}:
        raise Refusal(R_EMISSION_INVALID, f"addressKind {kind!r} is not registered")

    if rule.id == "binary-symbol-only" and address is None and offset is None:
        if not symbol:
            raise Refusal(R_MISSING_SYMBOL, "symbol-only finding carries no symbol")
        return {
            "class": rule.id,
            "precision": "symbol-only",
            "location": {
                "physicalLocation": {"artifactLocation": artifact},
                "logicalLocations": [{"kind": "function", "name": symbol}],
            },
            "properties": {
                "locationPrecision": "symbol-only",
                "lineInfoAvailable": False,
                "extentRecorded": False,
                "nativeLineOrigin": "symbol",
            },
            "limitations": [
                "the record names a binary symbol and no address; symbol presence "
                "establishes no reachability"
            ],
        }

    if address is None:
        if offset is None:
            raise Refusal(R_MISSING_ADDRESS, "binary finding has no address or offset")
        address = offset
    if offset is None:
        offset = address

    properties: dict[str, Any] = {
        "lineInfoAvailable": False,
        "nativeLineOrigin": "symbol" if native.get("lineOrigin") in (None, "symbol") else native["lineOrigin"],
    }
    limitations: list[str] = []

    if rule.id in {"indirect-function-pointer-call", "dynamic-dispatch"}:
        if call_site is None:
            raise Refusal(
                R_UNRECORDED_CALL_SITE,
                f"{rule.id} finding carries no call-site offset",
            )
        address_object = {"absoluteAddress": int(address), "kind": kind}
        region = {"byteOffset": int(call_site)}
        precision = "call-site-offset-in-artifact"
        properties["callSite"] = int(call_site)
        if symbol:
            address_object["name"] = symbol
        limitations.append(
            "the location is the containing function's offset plus the call-site "
            "offset; the runtime target is not a recorded location"
        )
        # The recorded function extent is the container's; the call itself has no
        # recorded extent, so none is emitted.
        extent_recorded = False
    elif rule.id == "inlined-optimised-code":
        inlined_into = native.get("inlinedInto")
        if not inlined_into:
            raise Refusal(
                R_INLINED_CALL_SITE,
                "inlined finding does not name the enclosing symbol",
            )
        if call_site is not None:
            raise Refusal(
                R_INLINED_CALL_SITE,
                "an inlined finding carries a call site it does not have",
            )
        address_object = {"absoluteAddress": int(address), "kind": "function"}
        if inlined_into:
            address_object["name"] = inlined_into
        region = {"byteOffset": int(offset)}
        if extent_recorded and byte_length is not None:
            address_object["length"] = int(byte_length)
            region["byteLength"] = int(byte_length)
            precision = "function-offset-and-extent"
        else:
            precision = "byte-offset-in-artifact"
        properties["inlinedInto"] = inlined_into
        limitations.append(
            "the inlined body has no symbol and no call site; the location is the "
            "enclosing out-of-line symbol"
        )
    else:
        if kind == "function" and offset != address:
            raise Refusal(
                R_FABRICATED_ADDRESS,
                "function address and byte offset disagree",
            )
        address_object = {"absoluteAddress": int(address), "kind": kind}
        region = {"byteOffset": int(offset)}
        precision = "byte-offset-in-artifact"
        if extent_recorded and byte_length is not None:
            address_object["length"] = int(byte_length)
            region["byteLength"] = int(byte_length)
            precision = "function-offset-and-extent"
        if symbol:
            address_object["name"] = symbol
        limitations.append(
            "the location is a byte offset in the named artefact; offsets are not "
            "stable across builds"
        )

    physical: dict[str, Any] = {
        "artifactLocation": artifact,
        "region": region,
        "address": address_object,
    }
    location: dict[str, Any] = {"physicalLocation": physical}
    if symbol:
        location["logicalLocations"] = [{"kind": "function", "name": symbol}]

    properties.update(
        {
            "locationPrecision": precision,
            "extentRecorded": bool(extent_recorded and byte_length is not None),
            "instantiationLineRecorded": False,
        }
    )
    return {
        "class": rule.id,
        "precision": precision,
        "location": location,
        "properties": properties,
        "limitations": limitations,
    }


def project(record: dict) -> dict:
    """Build the most precise truthful location the native record supports."""

    rule = _rule(record)
    subject = _subject(record)
    native = _native(record)

    if subject["kind"] == "record" or native.get("recordCondition"):
        for field in ("line", "byteOffset", "address", "callSite"):
            if native.get(field) is not None:
                raise Refusal(
                    R_RECORD_CONDITION_WITH_LOCATION,
                    f"record condition carries a {field}",
                )
        return {
            "class": rule.id,
            "precision": "record-condition",
            "location": None,
            "properties": {
                "locationKind": "record-condition",
                "locationPrecision": "record-condition",
                "lineInfoAvailable": False,
                "extentRecorded": False,
                "instantiationLineRecorded": False,
                "nativeLineOrigin": "none",
            },
            "limitations": [
                "the finding is a condition of the record; the record names no "
                "code location"
            ],
        }

    if subject["kind"] == "source":
        if "source" not in rule.subjects:
            raise Refusal(
                R_EMISSION_INVALID, f"{rule.id} is not registered for a source subject"
            )
        return _source_location(rule, native, subject)

    if "binary" not in rule.subjects:
        raise Refusal(
            R_EMISSION_INVALID, f"{rule.id} is not registered for a binary subject"
        )
    return _binary_location(rule, native, subject)


# --------------------------------------------------------------------------
# Checking an emission against the record that supports it.
# --------------------------------------------------------------------------

TEXT_KEYS = ("startLine", "startColumn", "endLine", "endColumn", "charOffset", "charLength")


def _contains_key(value: Any, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_contains_key(v, key) for v in value.values())
    if isinstance(value, list):
        return any(_contains_key(v, key) for v in value)
    return False


def _find_value(value: Any, key: str) -> Any:
    if isinstance(value, dict):
        if key in value:
            return value[key]
        for child in value.values():
            found = _find_value(child, key)
            if found is not _MISSING:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_value(child, key)
            if found is not _MISSING:
                return found
    return _MISSING


_MISSING = object()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _check_text_policy(rule: ClassRule, native: dict, emission: dict) -> None:
    location = emission.get("location")
    if location is None:
        return
    if _contains_key(location, "startColumn"):
        raise Refusal(
            R_COLUMN_NOT_EMITTED,
            "a column is emitted as a SARIF column; A1 preserves it as a native field",
        )
    for key in ("endLine", "endColumn", "charOffset", "charLength"):
        if _contains_key(location, key):
            raise Refusal(
                R_UNRECORDED_EXTENT,
                f"{key} is emitted; the native record does not carry it",
            )
    if _contains_key(location, "startLine") and emission.get("properties", {}).get(
        "lineInfoAvailable"
    ) is False:
        raise Refusal(
            R_MACHINE_CODE_LINE,
            "a result marked lineInfoAvailable=false carries a startLine",
        )
    precision = emission.get("properties", {}).get("locationPrecision")
    if precision in {
        "byte-offset-in-artifact",
        "function-offset-and-extent",
        "call-site-offset-in-artifact",
        "symbol-only",
    } and _contains_key(location, "startLine"):
        raise Refusal(
            R_MACHINE_CODE_LINE,
            f"a {precision} location carries a source line",
        )


def _check_source(record: dict, native: dict, subject: dict, emission: dict) -> None:
    _check_candidate_file(subject)
    location = emission.get("location")
    if location is None:
        if native.get("line") is not None and native.get("lineOrigin") != "symbol":
            raise Refusal(R_FABRICATED_LINE, "the record carries a line and none is emitted")
        return
    start_line = _find_value(location, "startLine")
    origin = native.get("lineOrigin") or "none"
    if start_line is not _MISSING:
        if native.get("line") is None:
            definition = native.get("definitionLine")
            if definition is not None and start_line == definition:
                raise Refusal(
                    R_DEFINITION_AS_INSTANCE,
                    f"line {start_line} is the definition line, not the record's line",
                )
            raise Refusal(
                R_FABRICATED_LINE, f"line {start_line} emitted but the record carries none"
            )
        if origin == "symbol":
            raise Refusal(R_FABRICATED_LINE, "a line is derived from a symbol")
        if int(start_line) != int(native["line"]):
            definition = native.get("definitionLine")
            if definition is not None and int(start_line) == int(definition):
                raise Refusal(
                    R_DEFINITION_AS_INSTANCE,
                    f"line {start_line} is the definition line; the record's line is "
                    f"{native['line']}",
                )
            raise Refusal(
                R_FABRICATED_LINE,
                f"line {start_line} emitted; the record carries {native['line']}",
            )
    properties = emission.get("properties") or {}
    if properties.get("instantiationLineRecorded") and origin not in INSTANTIATION_ORIGINS:
        raise Refusal(
            R_DEFINITION_AS_INSTANCE,
            f"instantiationLineRecorded is true but lineOrigin is {origin!r}",
        )
    if origin == "generic-definition" and properties.get("instantiationLineRecorded"):
        raise Refusal(
            R_DEFINITION_AS_INSTANCE,
            "a generic definition line is presented as an instance's own line",
        )
    if origin == "macro-definition" and properties.get("instantiationLineRecorded"):
        raise Refusal(
            R_DEFINITION_AS_INSTANCE,
            "a macro definition line is presented as an instance's own line",
        )


def _check_binary(record: dict, native: dict, subject: dict, emission: dict) -> None:
    _check_candidate_file(subject)
    artifact = _artifact_location(subject)
    location = emission.get("location")
    if location is None:
        raise Refusal(R_FABRICATED_LINE, "a binary finding is emitted with no location")
    physical = location.get("physicalLocation")
    if not isinstance(physical, dict):
        raise Refusal(R_EMISSION_INVALID, "binary emission has no physicalLocation")
    emitted_artifact = physical.get("artifactLocation") or {}
    if emitted_artifact.get("uri") != artifact["uri"]:
        raise Refusal(
            R_FILE_NOT_IN_CANDIDATE,
            f"emitted uri {emitted_artifact.get('uri')!r} is not the record's "
            f"{artifact['uri']!r}",
        )
    if emitted_artifact.get("digest") != artifact["digest"]:
        raise Refusal(
            R_MISSING_ARTIFACT_DIGEST,
            "the emitted artefact digest is not the record's",
        )

    region = physical.get("region") or {}
    address = physical.get("address") or {}
    native_address = native.get("address")
    if native_address is None:
        native_address = native.get("byteOffset")
    emitted_address = address.get("absoluteAddress")
    if emitted_address is not None and native_address is not None:
        if int(emitted_address) != int(native_address):
            raise Refusal(
                R_FABRICATED_ADDRESS,
                f"address {emitted_address} emitted; the record carries {native_address}",
            )
    if emitted_address is None and native_address is not None and not (
        location.get("logicalLocations") and _find_value(location, "startLine") is _MISSING
    ):
        raise Refusal(R_MISSING_ADDRESS, "no address is emitted for an address-bearing record")

    byte_length = region.get("byteLength")
    if byte_length is not None:
        recorded = native.get("byteLength")
        if not native.get("extentRecorded") or recorded is None:
            raise Refusal(
                R_UNRECORDED_EXTENT,
                f"byteLength {byte_length} emitted but the record records no extent",
            )
        if int(byte_length) != int(recorded):
            raise Refusal(
                R_UNRECORDED_EXTENT,
                f"byteLength {byte_length} emitted; the record carries {recorded}",
            )
        if address.get("length") is not None and int(address["length"]) != int(byte_length):
            raise Refusal(
                R_UNRECORDED_EXTENT,
                "address.length and region.byteLength disagree",
            )

    symbol = native.get("symbol")
    emitted_symbol = address.get("name")
    if emitted_symbol is not None and emitted_symbol != symbol:
        raise Refusal(
            R_FABRICATED_SYMBOL,
            f"symbol {emitted_symbol!r} emitted; the record carries {symbol!r}",
        )

    rule_id = emission.get("class")
    if rule_id in {"indirect-function-pointer-call", "dynamic-dispatch"}:
        call_site = native.get("callSite")
        if call_site is None:
            raise Refusal(R_UNRECORDED_CALL_SITE, "the record carries no call site")
        if region.get("byteOffset") is None:
            raise Refusal(R_UNRECORDED_CALL_SITE, "the emission carries no call-site offset")
        if int(region["byteOffset"]) != int(call_site):
            raise Refusal(
                R_FABRICATED_CALL_SITE,
                f"call site {region['byteOffset']} emitted; the record carries {call_site}",
            )
    if rule_id == "inlined-optimised-code":
        if native.get("callSite") is not None:
            raise Refusal(R_INLINED_CALL_SITE, "the record carries a call site")
        if _find_value(location, "callSite") is not _MISSING:
            raise Refusal(R_INLINED_CALL_SITE, "an inlined emission carries a call site")
        properties = emission.get("properties") or {}
        if properties.get("inlinedInto") != native.get("inlinedInto"):
            raise Refusal(
                R_INLINED_CALL_SITE,
                "the emitted inlinedInto is not the record's enclosing symbol",
            )
        if address.get("kind") != "function":
            raise Refusal(
                R_INLINED_CALL_SITE,
                "an inlined finding must name the enclosing function",
            )


def check(record: dict, emission: dict) -> None:
    """Accept an emission only if the native record supports it exactly."""

    rule = _rule(record)
    subject = _subject(record)
    native = _native(record)
    if emission.get("class") != rule.id:
        raise Refusal(
            R_EMISSION_INVALID,
            f"emission class {emission.get('class')!r} is not the record's {rule.id!r}",
        )
    _check_text_policy(rule, native, emission)

    if subject["kind"] == "record" or native.get("recordCondition"):
        if emission.get("location") is not None:
            raise Refusal(
                R_RECORD_CONDITION_WITH_LOCATION,
                "a record-level finding carries a location",
            )
    elif subject["kind"] == "source":
        _check_source(record, native, subject, emission)
    else:
        _check_binary(record, native, subject, emission)

    expected = project(record)
    if _canonical(emission) != _canonical(expected):
        raise Refusal(
            R_EMISSION_INVALID,
            "the emission is not the projection of the native record",
        )


# --------------------------------------------------------------------------
# The A1 emission scan.
# --------------------------------------------------------------------------

BINARY_PRECISIONS = {
    "byte-offset-in-artifact",
    "function-offset-and-extent",
    "call-site-offset-in-artifact",
}


def scan_sarif(document: dict) -> list[dict]:
    """Return the location-policy violations in an A1 SARIF document."""

    violations: list[dict] = []
    if document.get("version") != "2.1.0":
        violations.append(
            {"run": None, "result": None, "ruleId": None, "code": "LF_SARIF_VERSION"}
        )
    for run_index, run in enumerate(document.get("runs") or []):
        artifacts = run.get("artifacts") or []
        artifact_uris = {
            (artifact.get("location") or {}).get("uri") for artifact in artifacts
        }
        for result_index, result in enumerate(run.get("results") or []):
            props = ((result.get("properties") or {}).get("a1") or {})
            precision = props.get("locationPrecision")
            line_info = props.get("lineInfoAvailable")
            locations = result.get("locations") or []

            def add(code: str, detail: str = "") -> None:
                violations.append(
                    {
                        "run": run_index,
                        "result": result_index,
                        "ruleId": result.get("ruleId"),
                        "code": code,
                        "detail": detail,
                    }
                )

            if props.get("locationKind") == "record-condition" or precision == "record-condition":
                if locations:
                    add("LF_SARIF_RECORD_CONDITION_LOCATION")
                continue
            if not locations:
                continue

            for location_index, location in enumerate(locations):
                physical = location.get("physicalLocation") or {}
                region = physical.get("region") or {}
                address = physical.get("address") or {}
                artifact_uri = (physical.get("artifactLocation") or {}).get("uri")
                where = f"location {location_index}"
                if artifact_uri is not None and artifact_uri not in artifact_uris:
                    add("LF_SARIF_ARTIFACT_UNLISTED", f"{where}: {artifact_uri}")
                for key in ("startColumn", "endColumn", "endLine", "charOffset", "charLength"):
                    if key in region:
                        add("LF_SARIF_EXTENT_EMITTED", f"{where}: {key}")
                if "startLine" in region and "byteOffset" in region:
                    add("LF_SARIF_MIXED_REGION", where)
                if precision in BINARY_PRECISIONS:
                    if "startLine" in region:
                        add("LF_SARIF_BINARY_LINE", where)
                    if "byteOffset" not in region:
                        add("LF_SARIF_BINARY_NO_OFFSET", where)
                    if "absoluteAddress" not in address:
                        add("LF_SARIF_BINARY_NO_ADDRESS", where)
                    if precision == "function-offset-and-extent":
                        if "byteLength" not in region:
                            add("LF_SARIF_EXTENT_NOT_RECORDED", where)
                        elif address.get("length") != region.get("byteLength"):
                            add("LF_SARIF_EXTENT_DISAGREES", where)
                        if props.get("extentRecorded", props.get("functionExtentRecorded")) is not True:
                            add("LF_SARIF_EXTENT_NOT_RECORDED", f"{where}: property")
                    elif "byteLength" in region:
                        add("LF_SARIF_EXTENT_NOT_RECORDED", f"{where}: unrecorded")
                elif precision == "line":
                    if set(region) != {"startLine"}:
                        add("LF_SARIF_LINE_SHAPE", f"{where}: {sorted(region)}")
                    if line_info is False:
                        add("LF_SARIF_BINARY_LINE", where)
                else:
                    add("LF_SARIF_UNKNOWN_PRECISION", repr(precision))
                if line_info is False and "startLine" in region:
                    add("LF_SARIF_BINARY_LINE", where)
    return violations


# --------------------------------------------------------------------------
# Instance verification.
# --------------------------------------------------------------------------

_INDEX = "sites"


def _decode_site_row(document: dict, row_index: int) -> dict:
    sites = document.get(_INDEX)
    if not isinstance(sites, dict):
        raise Refusal(R_PROVENANCE, "record has no indexed sites table")
    columns = sites.get("columns") or []
    tables = sites.get("tables") or {}
    vocabulary = sites.get("vocabularies") or {}
    rows = sites.get("rows") or []
    if row_index < 0 or row_index >= len(rows):
        raise Refusal(R_PROVENANCE, f"row {row_index} is out of range")
    decoded = {}
    for column, value in zip(columns, rows[row_index]):
        if column in tables:
            decoded[column] = tables[column][value]
        elif column in vocabulary:
            decoded[column] = vocabulary[column][value]
        else:
            decoded[column] = value
    return decoded


def _resolve_pointer(document: Any, pointer: str) -> Any:
    if not pointer.startswith("/"):
        raise Refusal(R_PROVENANCE, f"pointer {pointer!r} is not absolute")
    node = document
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(node, list):
            node = node[int(token)]
        elif isinstance(node, dict):
            node = node[token]
        else:
            raise Refusal(R_PROVENANCE, f"pointer {pointer!r} does not resolve")
    return node


def _check_expect(actual: Any, expect: dict, where: str) -> None:
    if not isinstance(actual, dict):
        raise Refusal(R_PROVENANCE, f"{where} is not an object")
    for key, value in expect.items():
        if key not in actual:
            raise Refusal(R_PROVENANCE, f"{where} has no field {key!r}")
        if actual[key] != value:
            raise Refusal(
                R_PROVENANCE,
                f"{where}.{key} is {actual[key]!r}, expected {value!r}",
            )


def _verify_provenance(instance: dict, repo_root: Path) -> int:
    raw = instance.get("provenance")
    if raw is None:
        raise Refusal(R_PROVENANCE, f"{instance.get('id')}: no provenance")
    entries = raw if isinstance(raw, list) else [raw]
    for provenance in entries:
        _verify_one_provenance(instance, provenance, repo_root)
    return len(entries)


def _verify_one_provenance(instance: dict, provenance: dict, repo_root: Path) -> None:
    if not isinstance(provenance, dict):
        raise Refusal(R_PROVENANCE, f"{instance.get('id')}: provenance is not an object")
    kind = provenance.get("kind")
    if kind == "source-line":
        path = repo_root / provenance["path"]
        if not path.is_file():
            raise Refusal(R_PROVENANCE, f"source {provenance['path']} is absent")
        raw_bytes = path.read_bytes()
        recorded = provenance.get("recordSha256")
        if recorded is not None and hashlib.sha256(raw_bytes).hexdigest() != recorded:
            raise Refusal(
                R_PROVENANCE,
                f"{provenance['path']} does not have the recorded digest",
            )
        lines = raw_bytes.decode("utf-8").splitlines()
        line = int(provenance["line"])
        if line < 1 or line > len(lines):
            raise Refusal(R_PROVENANCE, f"{provenance['path']}:{line} is out of range")
        if provenance.get("contains") and provenance["contains"] not in lines[line - 1]:
            raise Refusal(
                R_PROVENANCE,
                f"{provenance['path']}:{line} does not contain "
                f"{provenance['contains']!r}",
            )
        return
    path = repo_root / provenance["path"]
    if not path.is_file():
        raise Refusal(R_PROVENANCE, f"provenance file {provenance['path']} is absent")
    raw = path.read_bytes()
    recorded = provenance.get("recordSha256")
    if recorded is not None:
        digest = hashlib.sha256(raw).hexdigest()
        if digest != recorded:
            raise Refusal(
                R_PROVENANCE,
                f"{provenance['path']} is {digest}, the instance records {recorded}",
            )
    document = json.loads(raw.decode("utf-8"))
    if kind == "indexed-site-row":
        actual = _decode_site_row(document, int(provenance["row"]))
        where = f"{provenance['path']} row {provenance['row']}"
    elif kind == "json-pointer":
        actual = _resolve_pointer(document, provenance["pointer"])
        where = f"{provenance['path']} {provenance['pointer']}"
    else:
        raise Refusal(R_PROVENANCE, f"unknown provenance kind {kind!r}")
    if provenance.get("expect") is not None:
        _check_expect(actual, provenance["expect"], where)
    if "expectContains" in provenance:
        needle = provenance["expectContains"]
        if not isinstance(actual, str) or needle not in actual:
            raise Refusal(
                R_PROVENANCE, f"{where} does not contain {needle!r}"
            )
    if "expectEquals" in provenance:
        if actual != provenance["expectEquals"]:
            raise Refusal(
                R_PROVENANCE, f"{where} is not {provenance['expectEquals']!r}"
            )


def _apply_mutation(emission: dict, mutation: dict) -> dict:
    mutated = json.loads(json.dumps(emission))
    node: Any = mutated
    tokens = mutation["path"].split(".")
    for token in tokens[:-1]:
        if isinstance(node, list):
            node = node[int(token)]
        else:
            if token not in node:
                node[token] = {}
            node = node[token]
    last = tokens[-1]
    if mutation["op"] == "set":
        if isinstance(node, list):
            node[int(last)] = mutation["value"]
        else:
            node[last] = mutation["value"]
    elif mutation["op"] == "delete":
        if isinstance(node, list):
            del node[int(last)]
        else:
            node.pop(last, None)
    else:
        raise Refusal(R_INSTANCE, f"unknown mutation op {mutation['op']!r}")
    return mutated


def verify_instances(document: dict, repo_root: Path) -> dict:
    """Verify every recorded instance, its provenance and its controls."""

    if document.get("model") != MODEL_ID:
        raise Refusal(R_INSTANCE, f"instances model {document.get('model')!r}")
    total_instances = 0
    total_mutations = 0
    total_provenance = 0
    by_class: dict[str, int] = {}
    for instance in document.get("instances") or []:
        identifier = instance.get("id")
        record = instance.get("nativeRecord")
        if not isinstance(record, dict):
            raise Refusal(R_INSTANCE, f"{identifier}: no nativeRecord")
        expected = project(record)
        if _canonical(expected) != _canonical(instance.get("emitted")):
            raise Refusal(
                R_INSTANCE,
                f"{identifier}: the recorded emission is not the projection of the record",
            )
        check(record, instance["emitted"])
        _verify_provenance(instance, repo_root)
        total_provenance += len(
            instance["provenance"]
            if isinstance(instance.get("provenance"), list)
            else [instance.get("provenance")]
        )
        by_class[record["class"]] = by_class.get(record["class"], 0) + 1
        total_instances += 1
        for mutation in instance.get("mutations") or []:
            mutated = _apply_mutation(instance["emitted"], mutation)
            try:
                check(record, mutated)
            except Refusal as refusal:
                if refusal.code != mutation.get("refusal"):
                    raise Refusal(
                        R_INSTANCE,
                        f"{identifier}: mutation {mutation.get('path')} refused as "
                        f"{refusal.code}, expected {mutation.get('refusal')}",
                    )
            else:
                raise Refusal(
                    R_INSTANCE,
                    f"{identifier}: mutation {mutation.get('path')} was accepted",
                )
            total_mutations += 1
    return {
        "model": MODEL_ID,
        "instances": total_instances,
        "provenance": total_provenance,
        "mutations": total_mutations,
        "byClass": by_class,
    }


# --------------------------------------------------------------------------
# Optional observation check (symbol table / disassembly).
# --------------------------------------------------------------------------

def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _symbol_table(dso: Path) -> dict[str, tuple[int, int]]:
    completed = subprocess.run(
        ["nm", "-C", "--defined-only", "--format=posix", str(dso)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if completed.returncode != 0:
        raise Refusal(R_INSTANCE, f"nm failed on {dso}")
    table: dict[str, tuple[int, int]] = {}
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1] in {"t", "T"}:
            try:
                table[parts[0]] = (int(parts[2], 16), int(parts[3], 16))
            except ValueError:
                continue
    return table


def verify_observations(document: dict, artefact_root: Path) -> dict:
    """Re-run the recorded symbol observations when the artefact is present."""

    checked = 0
    not_run = 0
    for instance in document.get("instances") or []:
        for observation in instance.get("observations") or []:
            artefact = observation.get("artefact") or {}
            path = artefact_root / Path(artefact.get("path", "")).name
            expected_digest = artefact.get("sha256")
            if not path.is_file() or not expected_digest:
                not_run += 1
                continue
            if _sha256_file(path) != expected_digest:
                raise Refusal(
                    R_INSTANCE,
                    f"{artefact['path']} does not have the recorded digest",
                )
            table = _symbol_table(path)
            if observation.get("kind") == "symbol":
                entry = table.get(observation["symbol"])
                if entry is None:
                    raise Refusal(
                        R_INSTANCE, f"symbol {observation['symbol']!r} is absent"
                    )
                address, size = entry
                if address != int(observation["address"], 16):
                    raise Refusal(
                        R_INSTANCE,
                        f"symbol {observation['symbol']!r} is at {address:#x}, "
                        f"recorded {observation['address']}",
                    )
                if size != int(observation["size"]):
                    raise Refusal(
                        R_INSTANCE,
                        f"symbol {observation['symbol']!r} has size {size}, "
                        f"recorded {observation['size']}",
                    )
            elif observation.get("kind") == "symbol-absent":
                needle = observation["symbol"]
                for name in table:
                    if needle in name:
                        raise Refusal(
                            R_INSTANCE,
                            f"symbol matching {needle!r} is present as {name!r}",
                        )
            elif observation.get("kind") == "instruction":
                start = int(observation["offset"], 16)
                length = len(observation["bytes"].split())
                completed = subprocess.run(
                    [
                        "objdump",
                        "-d",
                        f"--start-address={start:#x}",
                        f"--stop-address={start + length:#x}",
                        str(path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if completed.returncode != 0:
                    raise Refusal(R_INSTANCE, f"objdump failed on {path}")
                body = completed.stdout
                if observation["bytes"] not in body or observation["text"] not in body:
                    raise Refusal(
                        R_INSTANCE,
                        f"instruction at {observation['offset']} is not "
                        f"{observation['bytes']!r} {observation['text']!r}",
                    )
            checked += 1
    return {"checked": checked, "not_run": not_run}


# --------------------------------------------------------------------------
# CLI.
# --------------------------------------------------------------------------

def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("classes", help="print the class registry")

    project_parser = subparsers.add_parser("project", help="project one native record")
    project_parser.add_argument("record", type=Path)

    check_parser = subparsers.add_parser("check", help="check an emission against a record")
    check_parser.add_argument("record", type=Path)
    check_parser.add_argument("emission", type=Path)

    scan_parser = subparsers.add_parser("scan-sarif", help="hold an A1 emission to the policy")
    scan_parser.add_argument("sarif", type=Path)

    verify_parser = subparsers.add_parser("verify-instances", help="verify recorded instances")
    verify_parser.add_argument("instances", type=Path)
    verify_parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    verify_parser.add_argument(
        "--observe",
        type=Path,
        metavar="ARTEFACT_ROOT",
        help="re-run symbol observations against artefacts in this directory",
    )

    args = parser.parse_args(argv)

    if args.command == "classes":
        print(json.dumps(classes_document(), indent=1, sort_keys=True))
        return 0

    if args.command == "project":
        try:
            print(json.dumps(project(_read_json(args.record)), indent=1, sort_keys=True))
        except Refusal as refusal:
            print(str(refusal), file=sys.stderr)
            return 2
        return 0

    if args.command == "check":
        try:
            check(_read_json(args.record), _read_json(args.emission))
        except Refusal as refusal:
            print(str(refusal), file=sys.stderr)
            return 2
        print("accepted")
        return 0

    if args.command == "scan-sarif":
        violations = scan_sarif(_read_json(args.sarif))
        print(json.dumps({"violations": violations}, indent=1, sort_keys=True))
        return 1 if violations else 0

    if args.command == "verify-instances":
        document = _read_json(args.instances)
        try:
            report = verify_instances(document, args.repo_root)
        except Refusal as refusal:
            print(str(refusal), file=sys.stderr)
            return 2
        if args.observe is not None:
            try:
                report["observations"] = verify_observations(document, args.observe)
            except Refusal as refusal:
                print(str(refusal), file=sys.stderr)
                return 2
        else:
            report["observations"] = "NOT_RUN: no --observe artefact root"
        print(json.dumps(report, indent=1, sort_keys=True))
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
