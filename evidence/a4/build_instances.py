#!/usr/bin/env python3
"""Build the A4 class and instance records from the tracked native evidence.

The native location records are not invented here. Each instance cites the exact
tracked bytes it is derived from (a record digest), the native row or JSON pointer,
and the fields that pointer must carry. `location_fidelity.verify_instances`
re-reads those bytes and refuses an instance whose provenance has moved.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "forensics" / "tools"))

import location_fidelity as lf  # noqa: E402

SAFETY = "evidence/etp-t4/SAFETY-SITES.json"
TIMING = "evidence/timing-bn-findings.json"
CURL = "evidence/closure-curl-049.json"
SSH = "evidence/closure-ssh-b86.json"


def _sha256(relpath: str) -> str:
    return hashlib.sha256((REPO_ROOT / relpath).read_bytes()).hexdigest()


SHA = {relpath: _sha256(relpath) for relpath in (SAFETY, TIMING, CURL, SSH)}
SOURCE_SHA = {
    relpath: _sha256(relpath)
    for relpath in (
        "src/cmp/cmp_ctx.rs",
        "src/asn1/string.rs",
        "src/digest/md32.rs",
        "src/runtime/bsearch.rs",
        "src/store/store_lib.rs",
    )
}

LIB = "libcrypto.so.3"
LIB_DIGEST = "fd25cc9e6424ea79aaaff05df22b3f6e1d46aa22d5666cfe7589dce95ffd88a9"
ARTEFACT = {
    "path": "artifacts/phase2/install/lib/libcrypto.so.3",
    "sha256": LIB_DIGEST,
}


def site(row: int, expect: dict) -> dict:
    return {
        "kind": "indexed-site-row",
        "path": SAFETY,
        "recordSha256": SHA[SAFETY],
        "row": row,
        "expect": expect,
    }


def pointer(path: str, pointer_text: str, expect: dict | None = None, **extra) -> dict:
    entry = {
        "kind": "json-pointer",
        "path": path,
        "recordSha256": SHA[path],
        "pointer": pointer_text,
    }
    if expect is not None:
        entry["expect"] = expect
    entry.update(extra)
    return entry


def source_line(path: str, line: int, contains: str) -> dict:
    return {
        "kind": "source-line",
        "path": path,
        "recordSha256": SOURCE_SHA[path],
        "line": line,
        "contains": contains,
    }


def symbol(name: str, address: int, size: int) -> dict:
    return {
        "kind": "symbol",
        "artefact": ARTEFACT,
        "symbol": name,
        "address": hex(address),
        "size": size,
    }


def symbol_absent(name: str) -> dict:
    return {"kind": "symbol-absent", "artefact": ARTEFACT, "symbol": name}


def instruction(offset: int, text: str, byte_text: str) -> dict:
    return {
        "kind": "instruction",
        "artefact": ARTEFACT,
        "offset": hex(offset),
        "text": text,
        "bytes": byte_text,
    }


def source_subject(path: str) -> dict:
    return {"kind": "source", "uri": path, "candidateFiles": [path]}


def binary_subject() -> dict:
    return {
        "kind": "binary",
        "uri": LIB,
        "digest": LIB_DIGEST,
        "digestScope": "artifact",
        "algorithm": "sha-256",
        "candidateFiles": [LIB],
    }


def instance(identifier: str, class_id: str, record: dict, provenance, observations, mutations, note):
    record = {"class": class_id, **record}
    emitted = lf.project(record)
    for mutation in mutations:
        mutated = lf._apply_mutation(emitted, mutation)
        try:
            lf.check(record, mutated)
        except lf.Refusal as refusal:
            if refusal.code != mutation["refusal"]:
                raise SystemExit(
                    f"{identifier}: {mutation['path']} refused as {refusal.code}, "
                    f"expected {mutation['refusal']}"
                )
        else:
            raise SystemExit(f"{identifier}: {mutation['path']} was accepted")
    return {
        "id": identifier,
        "class": class_id,
        "status": "real",
        "note": note,
        "nativeRecord": record,
        "provenance": provenance,
        "observations": observations,
        "emitted": emitted,
        "mutations": mutations,
    }


INSTANCES = [
    instance(
        "L1-cmp-ctx-cb-to-ptr",
        "inline-macro-expansion",
        {
            "subject": source_subject("src/cmp/cmp_ctx.rs"),
            "native": {
                "line": 759,
                "lineOrigin": "invocation-span",
                "column": 5,
                "columnUnit": "not-recorded",
                "symbol": "OSSL_CMP_CTX_set_certConf_cb",
                "expansionOrigin": "cb_to_ptr!",
                "definitionLine": 738,
            },
        },
        [
            site(
                7182,
                {
                    "path": "src/cmp/cmp_ctx.rs",
                    "line": 759,
                    "column": 5,
                    "kind": "unsafe_block",
                    "symbol": "OSSL_CMP_CTX_set_certConf_cb",
                    "class": "callback_reentrancy_edge",
                },
            ),
            source_line("src/cmp/cmp_ctx.rs", 759, "cb_to_ptr!(cb)"),
            source_line("src/cmp/cmp_ctx.rs", 738, "f as *const () as *mut c_void"),
        ],
        [symbol("OSSL_CMP_CTX_set_certConf_cb", 0x27ABD0, 0x77)],
        [
            {
                "op": "set",
                "path": "location.physicalLocation.region.startLine",
                "value": 738,
                "refusal": lf.R_DEFINITION_AS_INSTANCE,
                "why": "the macro-body definition line substituted for the invocation span",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.region.startLine",
                "value": 760,
                "refusal": lf.R_FABRICATED_LINE,
                "why": "a line adjacent to the record",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.region.startColumn",
                "value": 5,
                "refusal": lf.R_COLUMN_NOT_EMITTED,
                "why": "the recorded column emitted as a SARIF column",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.region.endLine",
                "value": 759,
                "refusal": lf.R_UNRECORDED_EXTENT,
                "why": "an end line the record does not carry",
            },
        ],
        "The unsafe block is written at the invocation (cmp_ctx.rs:759); the cast "
        "belongs to the macro body (cmp_ctx.rs:738). The record carries the "
        "invocation span, so 759 is truthful and 738 is the definition site.",
    ),
    instance(
        "L2-define-new-free",
        "macro-rules-derive-output",
        {
            "subject": source_subject("src/asn1/string.rs"),
            "native": {
                "line": 562,
                "lineOrigin": "macro-definition",
                "column": 13,
                "columnUnit": "not-recorded",
                "symbol": "file:string",
            },
        },
        [
            site(
                4029,
                {
                    "path": "src/asn1/string.rs",
                    "line": 562,
                    "column": 13,
                    "kind": "unsafe_block",
                    "symbol": "file:string",
                    "class": "delegated_unsafe_contract",
                },
            ),
            source_line("src/asn1/string.rs", 546, "macro_rules! define_new_free"),
            source_line("src/asn1/string.rs", 567, "define_new_free!("),
        ],
        [symbol("ASN1_OCTET_STRING_free", 0x2680F0, 0x72)],
        [
            {
                "op": "set",
                "path": "properties.instantiationLineRecorded",
                "value": True,
                "refusal": lf.R_DEFINITION_AS_INSTANCE,
                "why": "the definition line presented as an instantiation's own line",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.region.startLine",
                "value": 569,
                "refusal": lf.R_FABRICATED_LINE,
                "why": "one invocation's line substituted for the shared definition",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.region.startColumn",
                "value": 13,
                "refusal": lf.R_COLUMN_NOT_EMITTED,
                "why": "the recorded column emitted as a SARIF column",
            },
        ],
        "One lexical row at string.rs:562 stands for every generated *_free "
        "function; the generated export ASN1_OCTET_STRING_free is a separate "
        "binary symbol with no line of its own. The class also covers derive "
        "output, but no derive-generated finding occurs in the tree.",
    ),
    instance(
        "L3-md32-update",
        "monomorphised-generic",
        {
            "subject": binary_subject(),
            "native": {
                "address": 0x1B4D20,
                "byteOffset": 0x1B4D20,
                "byteLength": 0xA5,
                "extentRecorded": True,
                "addressKind": "function",
                "symbol": "openssl_rs::digest::md32::update::<openssl_rs::digest::md4::Md4Ctx>",
            },
        },
        [
            site(
                13997,
                {
                    "path": "src/digest/md32.rs",
                    "line": 118,
                    "column": 12,
                    "kind": "unsafe_fn",
                    "symbol": "update",
                    "class": "callback_reentrancy_edge",
                },
            ),
            pointer(TIMING, "/candidate/libcrypto/sha256", expectEquals=LIB_DIGEST),
        ],
        [symbol("openssl_rs::digest::md32::update::<openssl_rs::digest::md4::Md4Ctx>", 0x1B4D20, 0xA5)],
        [
            {
                "op": "set",
                "path": "location.physicalLocation.region.startLine",
                "value": 118,
                "refusal": lf.R_MACHINE_CODE_LINE,
                "why": "the generic definition line emitted for the machine-code instance",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.region.byteLength",
                "value": 0xA6,
                "refusal": lf.R_UNRECORDED_EXTENT,
                "why": "an extent one byte past the recorded symbol size",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.address.absoluteAddress",
                "value": 0x1B4E90,
                "refusal": lf.R_FABRICATED_ADDRESS,
                "why": "the Md5 instance's address substituted for the Md4 instance",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.address.name",
                "value": "update",
                "refusal": lf.R_FABRICATED_SYMBOL,
                "why": "the generic source name substituted for the mangled instance",
            },
        ],
        "One source row at md32.rs:118 covers the generic body; the binary has six "
        "separate update and six finalize instantiations. The instance location is "
        "the mangled symbol and its recorded extent.",
    ),
    instance(
        "L4-bsearch-dyn-call",
        "dynamic-dispatch",
        {
            "subject": binary_subject(),
            "native": {
                "address": 0x3F54E0,
                "callSite": 0x3F551C,
                "addressKind": "function",
                "symbol": "openssl_rs::runtime::bsearch::ossl_bsearch",
            },
        },
        [
            source_line("src/runtime/bsearch.rs", 85, "c = cmp(i);"),
            pointer(
                CURL,
                "/precision/classes/field",
                expect={"mechanism": "object-field dispatch (callback or method pointer)"},
            ),
        ],
        [
            symbol("openssl_rs::runtime::bsearch::ossl_bsearch", 0x3F54E0, 0xC8),
            instruction(0x3F551C, "call   *%r13", "41 ff d5"),
        ],
        [
            {
                "op": "set",
                "path": "location.physicalLocation.region.startLine",
                "value": 85,
                "refusal": lf.R_MACHINE_CODE_LINE,
                "why": "the trait-object call's source line emitted for the binary call",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.region.byteOffset",
                "value": 0x3F551D,
                "refusal": lf.R_FABRICATED_CALL_SITE,
                "why": "an offset inside the call instruction",
            },
            {
                "op": "delete",
                "path": "location.physicalLocation.region.byteOffset",
                "refusal": lf.R_UNRECORDED_CALL_SITE,
                "why": "the recorded call-site offset removed",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.address.absoluteAddress",
                "value": 0x3F54E1,
                "refusal": lf.R_FABRICATED_ADDRESS,
                "why": "an address inside the enclosing function",
            },
        ],
        "The call at bsearch.rs:85 goes through `&mut dyn FnMut`; the emitted code "
        "loads the method pointer from 0x20(%rcx) and performs `call *%r13` at "
        "ossl_bsearch+0x3c. Reachability of this function is not claimed.",
    ),
    instance(
        "L5-cmp-ctx-export",
        "no-mangle-export",
        {
            "subject": binary_subject(),
            "native": {
                "address": 0x27ABD0,
                "byteOffset": 0x27ABD0,
                "byteLength": 0x77,
                "extentRecorded": True,
                "addressKind": "function",
                "symbol": "OSSL_CMP_CTX_set_certConf_cb",
            },
        },
        [
            site(
                7180,
                {
                    "path": "src/cmp/cmp_ctx.rs",
                    "line": 748,
                    "column": 1,
                    "kind": "export",
                    "symbol": "OSSL_CMP_CTX_set_certConf_cb",
                    "class": "abi_export",
                },
            ),
            source_line("src/cmp/cmp_ctx.rs", 748, "#[no_mangle]"),
        ],
        [symbol("OSSL_CMP_CTX_set_certConf_cb", 0x27ABD0, 0x77)],
        [
            {
                "op": "set",
                "path": "location.physicalLocation.region.startLine",
                "value": 748,
                "refusal": lf.R_MACHINE_CODE_LINE,
                "why": "the export declaration line emitted for the machine code",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.region.byteLength",
                "value": 0x78,
                "refusal": lf.R_UNRECORDED_EXTENT,
                "why": "an extent one byte past the recorded symbol size",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.address.absoluteAddress",
                "value": 0x27AC50,
                "refusal": lf.R_FABRICATED_ADDRESS,
                "why": "the neighbouring export's address",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.address.name",
                "value": "OSSL_CMP_CTX_set_http_cb",
                "refusal": lf.R_FABRICATED_SYMBOL,
                "why": "a different export's name",
            },
        ],
        "The export declaration is at cmp_ctx.rs:748 and the machine code is at "
        "libcrypto.so.3+0x27abd0, size 0x77. The declaration line is not the "
        "machine-code location.",
    ),
    instance(
        "L6-store-loader-closefn",
        "indirect-function-pointer-call",
        {
            "subject": binary_subject(),
            "native": {
                "address": 0x36EEE0,
                "callSite": 0x36F8D3,
                "addressKind": "function",
                "symbol": "OSSL_STORE_open_ex",
            },
        },
        [
            pointer(
                CURL,
                "/precision/residual_sites/109",
                expect={
                    "dso": LIB,
                    "function": "0x36eee0",
                    "call_site": "0x36f8d3",
                    "reason": "external ABI contract witness: OsslStoreLoader.closefn (offset 0x50)",
                    "class": "ABI_CONTRACT_STORE_LOADER",
                    "text": "call   *%rax",
                },
            ),
            source_line("src/store/store_lib.rs", 666, "closefn"),
        ],
        [
            symbol("OSSL_STORE_open_ex", 0x36EEE0, 0xA87),
            instruction(0x36F8D3, "call   *%rax", "ff d0"),
        ],
        [
            {
                "op": "set",
                "path": "location.physicalLocation.region.startLine",
                "value": 666,
                "refusal": lf.R_MACHINE_CODE_LINE,
                "why": "the source call line emitted for the binary call site",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.region.byteOffset",
                "value": 0x36F8D4,
                "refusal": lf.R_FABRICATED_CALL_SITE,
                "why": "an offset inside the call instruction",
            },
            {
                "op": "delete",
                "path": "location.physicalLocation.region.byteOffset",
                "refusal": lf.R_UNRECORDED_CALL_SITE,
                "why": "the recorded call-site offset removed",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.address.absoluteAddress",
                "value": 0x36EEE1,
                "refusal": lf.R_FABRICATED_ADDRESS,
                "why": "an address inside the enclosing function",
            },
        ],
        "The closure record's residual row 109 names the DSO, the containing "
        "function 0x36eee0, the call site 0x36f8d3 and the provenance "
        "OsslStoreLoader.closefn. A1 emits exactly this location and no line.",
    ),
    instance(
        "L7-store-close-it",
        "inlined-optimised-code",
        {
            "subject": binary_subject(),
            "native": {
                "address": 0x36EEE0,
                "byteOffset": 0x36EEE0,
                "byteLength": 0xA87,
                "extentRecorded": True,
                "addressKind": "function",
                "symbol": "OSSL_STORE_open_ex",
                "inlinedInto": "OSSL_STORE_open_ex",
            },
        },
        [
            site(
                51766,
                {
                    "path": "src/store/store_lib.rs",
                    "line": 666,
                    "column": 32,
                    "kind": "unsafe_block",
                    "symbol": "ossl_store_close_it",
                    "class": "delegated_unsafe_contract",
                },
            ),
            pointer(
                SSH,
                "/graph/limits/0",
                expectContains="inlined callees have no out-of-line function node",
            ),
            pointer(
                SSH,
                "/precision/abi_contract_bounded/external_call_sites/contracts/"
                "ABI_CONTRACT_STORE_LOADER/citation/6",
                expectContains="the inlined `ossl_store_close_it`",
            ),
        ],
        [
            symbol_absent("ossl_store_close_it"),
            symbol("OSSL_STORE_open_ex", 0x36EEE0, 0xA87),
        ],
        [
            {
                "op": "set",
                "path": "location.physicalLocation.callSite",
                "value": 0x36F8D3,
                "refusal": lf.R_INLINED_CALL_SITE,
                "why": "an inlined finding given a call site it does not have",
            },
            {
                "op": "set",
                "path": "properties.inlinedInto",
                "value": "ossl_store_close_it",
                "refusal": lf.R_INLINED_CALL_SITE,
                "why": "the inlined callee presented as the enclosing symbol",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.region.startLine",
                "value": 666,
                "refusal": lf.R_MACHINE_CODE_LINE,
                "why": "the inlined body's source line emitted for the binary code",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.region.byteLength",
                "value": 0xA88,
                "refusal": lf.R_UNRECORDED_EXTENT,
                "why": "an extent one byte past the enclosing symbol",
            },
        ],
        "ossl_store_close_it has no symbol in the candidate DSO; its code is inside "
        "OSSL_STORE_open_ex. The closure record states the inlining and attributes "
        "the call site to the caller. No separate call site exists.",
    ),
    instance(
        "L7-compress-staged",
        "inlined-optimised-code",
        {
            "subject": binary_subject(),
            "native": {
                "address": 0x1B55C0,
                "byteOffset": 0x1B55C0,
                "byteLength": 0x10D,
                "extentRecorded": True,
                "addressKind": "function",
                "symbol": "openssl_rs::digest::md32::finalize::<openssl_rs::digest::md4::Md4Ctx>",
                "inlinedInto": "openssl_rs::digest::md32::finalize::<openssl_rs::digest::md4::Md4Ctx>",
            },
        },
        [
            site(
                14016,
                {
                    "path": "src/digest/md32.rs",
                    "line": 220,
                    "column": 1,
                    "kind": "unsafe_fn",
                    "symbol": "compress_staged",
                    "class": "callback_reentrancy_edge",
                },
            ),
        ],
        [
            symbol_absent("compress_staged"),
            symbol("openssl_rs::digest::md32::finalize::<openssl_rs::digest::md4::Md4Ctx>", 0x1B55C0, 0x10D),
        ],
        [
            {
                "op": "set",
                "path": "location.physicalLocation.callSite",
                "value": 0x1B5600,
                "refusal": lf.R_INLINED_CALL_SITE,
                "why": "an inlined generic given a call site it does not have",
            },
            {
                "op": "set",
                "path": "properties.inlinedInto",
                "value": "openssl_rs::digest::md32::compress_staged::<openssl_rs::digest::md4::Md4Ctx>",
                "refusal": lf.R_INLINED_CALL_SITE,
                "why": "a symbol that the candidate DSO does not contain",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.region.startLine",
                "value": 220,
                "refusal": lf.R_MACHINE_CODE_LINE,
                "why": "the inlined body's source line emitted for the binary code",
            },
        ],
        "compress_staged is private and generic and has no symbol in the candidate "
        "DSO; its only callers are the finalize instantiations. Its code is located "
        "only through the enclosing finalize symbol.",
    ),
    instance(
        "L8-bn-mod-inverse",
        "binary-symbol-only",
        {
            "subject": binary_subject(),
            "native": {
                "address": 0x3CF4A0,
                "byteOffset": 0x3CF4A0,
                "byteLength": 1137,
                "extentRecorded": True,
                "addressKind": "function",
                "symbol": "BN_mod_inverse",
            },
        },
        [
            pointer(
                TIMING,
                "/primitives/BN_mod_inverse",
                expect={
                    "libcrypto_offset": "0x3cf4a0",
                    "size": 1137,
                    "dynsym_name": "BN_mod_inverse@@OPENSSL_3.0.0",
                    "got_slot": "0x896880 (R_X86_64_GLOB_DAT)",
                },
            ),
            pointer(TIMING, "/candidate/libcrypto/sha256", expectEquals=LIB_DIGEST),
        ],
        [symbol("BN_mod_inverse", 0x3CF4A0, 1137)],
        [
            {
                "op": "set",
                "path": "location.physicalLocation.region.startLine",
                "value": 1,
                "refusal": lf.R_MACHINE_CODE_LINE,
                "why": "a source line emitted for a machine-code finding",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.region.byteLength",
                "value": 1138,
                "refusal": lf.R_UNRECORDED_EXTENT,
                "why": "an extent one byte past the recorded size",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.address.absoluteAddress",
                "value": 0x3CF4A1,
                "refusal": lf.R_FABRICATED_ADDRESS,
                "why": "an address inside the function",
            },
            {
                "op": "set",
                "path": "location.physicalLocation.address.name",
                "value": "BN_mod_exp_mont_consttime",
                "refusal": lf.R_FABRICATED_SYMBOL,
                "why": "another exported symbol's name",
            },
        ],
        "The tracking record names the DSO digest, the dynsym name, the offset, the "
        "size and the GOT slot. The source definition exists but is not the binary "
        "occurrence's location, and symbol presence establishes no reachability.",
    ),
]


def main() -> int:
    classes = lf.classes_document()
    instances = {
        "schema": lf.INSTANCE_SCHEMA,
        "model": lf.MODEL_ID,
        "candidate": {
            "libcrypto": {"uri": LIB, "sha256": LIB_DIGEST},
            "source": {
                relpath: digest for relpath, digest in sorted(SOURCE_SHA.items())
            },
        },
        "classes": [rule.id for rule in lf.CLASSES],
        "instances": INSTANCES,
        "nonClaims": [
            "an instance records the truthful location rule and its native "
            "provenance; it is not a claim that the finding is true or reachable",
            "the symbol and instruction observations are bound to the named "
            "artefact digest and are re-checked only where that artefact exists",
            "no derive-generated finding occurs in the tree; the derive half of "
            "the macro_rules!/derive class is stated as a rule without an instance",
        ],
    }
    out = REPO_ROOT / "evidence" / "a4"
    out.mkdir(parents=True, exist_ok=True)
    (out / "CLASSES.json").write_text(
        json.dumps(classes, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "INSTANCES.json").write_text(
        json.dumps(instances, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    report = lf.verify_instances(instances, REPO_ROOT)
    print(json.dumps(report, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
