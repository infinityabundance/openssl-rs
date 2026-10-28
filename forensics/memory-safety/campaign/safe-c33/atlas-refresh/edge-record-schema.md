# Edge provenance record schema (v1)

`forensics/tools/consumer_closure.py` now emits one record per indirect site it
classifies. The record is the tool's account of **what it proved** versus
**what it approximated**.

Schema: `openssl-rs/campaign/safe-c33/edge-record/v1`

## Fields

| field | meaning |
|---|---|
| `edge_id` | semantic id: `defining_function::operation_kind::ordinal` |
| `semantic_identity.source_operation` | the indirect instruction text |
| `semantic_identity.operation_kind` | `call` / `jmp` |
| `semantic_identity.defining_function` | the containing function |
| `semantic_identity.call_site_role` | `method-store-slot`, `in-image-data-slot`, `argument-callback`, `abi-contract-dispatch`, `unresolved-dispatch`, `value-flow` |
| `semantic_identity.provenance_chain` | per target: `store-writer` -> `argument` -> `relocation` / `code-materialised` (lea) / `thunk` / `field-slot` / `abi-contract` / `resolver` |
| `semantic_identity.artifact_local_witness` | module, function/site address, and an explicit note that the address is **not** the identity |
| `disposition` | `PROVED_TARGET_SET`, `CONTRACT_BOUNDED`, `UNRESOLVED` |
| `target_set` | admitted targets when `PROVED_TARGET_SET`; empty otherwise |
| `witness_id` | required when `CONTRACT_BOUNDED` |
| `missing_property` | required when `UNRESOLVED` |
| `exclusions[]` | each `{target, reason, evidence}` |
| `exclusion_accounting` | candidate / admitted / excluded / unaccounted target sets |

## Exclusion reasons (all checkable)

`not-in-reachable-set`, `no-reachable-writer`, `provenance-unbounded`,
`declared-name-absent`, `non-image-value`.

Each reason requires evidence fields; a free-text reason is not a reason:

| reason | required evidence |
|---|---|
| `not-in-reachable-set` | `reachable_set_member`, `symbol` |
| `no-reachable-writer` | `writer`, `derived_targets` |
| `provenance-unbounded` | `failure` |
| `declared-name-absent` | `declared_name`, `present` |
| `non-image-value` | `value` |

## Refusal rule

`validate_edge_records` recomputes
`candidate_targets - admitted_targets - exclusion_targets`. For a derivation
that claims complete candidate enumeration, any remainder is an unrecorded
target. Such a defect, an exclusion with an unknown/absent reason, or an
exclusion without its required evidence produces
`EDGE_RECORD_EXCLUSION_UNSOUND`, and `build_receipt` refuses the closure rather
than emitting it.

The self-test injects an exclusion with no reason and asserts that refusal
(`python3 forensics/tools/consumer_closure.py --self-test`).
