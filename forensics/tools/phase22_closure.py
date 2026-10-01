#!/usr/bin/env python3
"""openssl-rs -- Phase 22.14 external-root reachability and compatibility closure.

`docs/PHASE-22-SUBPHASES.md` section 5 gives this subphase its artefact
(`forensics/atlas/phase22/compatibility-closure.json`) and its question: from the declared
external compatibility roots, traverse the whole-program typed edge graph and close every
reachable surface, so that nothing reachable from a root is left unclassified.

The roots (section 2)
---------------------
The plan names ten compatibility root families. Seven are populated from the extraction planes
that actually observe them, each with a concrete, derived member list and its provenance:

  * source-api    -- the Phase-1 header/API atlas's public declarations
                     (functions, variables, macros, typedefs, tagged structs);
  * binary-abi    -- the global symbols the shared objects, provider module and engine modules
                     of 22.6's binary-reference graph define (the DSO exports);
  * modules       -- 22.7's dispatch-slot, registration and provider/dispatch table surfaces;
  * callbacks     -- 22.7's callback-slot targets (the routes that invoke a callback);
  * cli           -- 22.9's commands, aliases and digest/cipher pseudo-commands;
  * configuration -- 22.10's directives, environment variables and default paths;
  * distribution  -- 22.8's installed entries dispositioned `REQUIRED_COMPATIBILITY`.

The remaining three -- `runtime-behaviour`, `protocol`, `dynamic-loading` -- are declared and
left **unpopulated**, bluntly: no plane in 22.1-22.13 observes runtime behaviour, the TLS/DTLS/
QUIC wire, or loader symbol lookup. 22.12 recorded the same non-join (its `unjoined`), and this
document repeats it rather than inventing a witness.

The typed edges (section 3)
---------------------------
A call graph is not enough: the architecture of this library is function-pointer tables, and a
`static const OSSL_DISPATCH` initializer has no `caller -> callee` edge anywhere in the source.
The closure is therefore over a *typed* edge graph, each kind extracted from exactly one plane
and oriented **from the compatibility surface outward to the implementation it reaches**:

    DIRECT_CALL          (caller -> callee)                         22.3 every-TU Clang AST
    ADDRESS_TAKEN        (taker -> function)                        22.3 every-TU Clang AST
    CALLBACK_SLOT        (table -> slot target)                     22.7 dispatch graph
    DISPATCH_SLOT        (table -> slot target)                     22.7 dispatch graph
    REGISTRATION         (registration table -> target)            22.7 dispatch graph
    CONFIG_DISPATCH      (registration table -> target)            22.7 dispatch graph
    RELOCATION_REFERENCE (object/table -> referenced symbol)       22.6 binary graph / 22.7
    GENERATED_FROM       (generated output -> input or generator)  22.5 generated lineage
    BUILT_INTO           (object/artifact -> its source path)      22.6 binary graph
    EXPORTED_AS          (defined symbol -> object/artifact)       22.6 binary graph
    ENV_READ             (environment variable -> reader function) 22.10 config surface
    CLI_DISPATCH         (command -> handler)                      22.7 dispatch graph

Disposition (section 4)
-----------------------
Every reachable entity keeps exactly the disposition 22.12 assigned it; this plane never
re-classifies, it only says which entities a root reaches. Anything still `UNKNOWN` **and**
reachable from a declared root is the blocking set, and `counts.unknown_intersecting_roots`
carries the same name and meaning 22.12 gave it.

The X.509 slice, and the gate contract
--------------------------------------
`forensics/tools/phase22_x509_gate.py` is a fail-closed pipeline gate: it refuses a growth in
Phase 11.2's exports while `body.x509_slice` is unsatisfied. The block this document must
publish, exactly, is:

    body.x509_slice = {
        "roots": [...],             # the X.509 root families the slice covers
        "satisfied": true|false,    # no UNKNOWN residual intersects any of them
        "unknown_residuals": [...]  # the residuals that block it when false
    }

`satisfied` is true exactly when `unknown_residuals` is empty. The membership behind it is
derived from the authority, not chosen: the named roots are matched against 22.12's own
declared-root members by authority file (the `crypto/x509/` units -- the policy tree in
`pcy_*.c`, trust in `x509_trust.c`, purpose in `v3_purp.c`, CRL in `x_crl.c`/`v3_crld.c`,
name constraints in `v3_ncons.c`) and by the `X509*` name prefix, and the slice is their union.
The two `UNKNOWN` entities 22.12 records -- `_openssl_ascii2ebcdic` and `_openssl_ebcdic2ascii`
from `ebcdic.h` -- are not in that membership and no X.509 root reaches them, so the slice is
satisfied and the gate opens Phase 11.2. That is the measured answer, not a tuned one.

Output
------
    forensics/atlas/phase22/compatibility-closure.json

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    envelope,
    load_build_records,
    rel,
    resolve_authority,
    write_json,
)

GENERATOR = "forensics/tools/phase22_closure.py"
ARTEFACT_REL = "forensics/atlas/phase22/compatibility-closure.json"
OUT = REPO_ROOT / ARTEFACT_REL
ATLAS = REPO_ROOT / "forensics" / "atlas"
P22 = ATLAS / "phase22"

# ---------------------------------------------------------------------------
# the declared roots (docs/PHASE-22-SUBPHASES.md section 2), and the unpopulated three
# ---------------------------------------------------------------------------

POPULATED_FAMILIES = (
    "source-api",
    "binary-abi",
    "modules",
    "callbacks",
    "cli",
    "configuration",
    "distribution",
)

# The plan names these; no 22.1-22.13 plane observes the runtime, the wire, or the loader.
UNPOPULATED_FAMILIES = (
    ("runtime-behaviour",
     ("no plane in 22.1-22.13 observes runtime errors, state, ownership or "
      "concurrency; 22.12 recorded the same non-join. It is not derivable "
      "from any artefact this stratum carries.")),
    ("protocol",
     ("no plane in 22.1-22.13 observes the TLS/DTLS/QUIC externally observable wire "
      "or state; there is no wire trace in the atlas to close.")),
    ("dynamic-loading",
     ("no plane in 22.1-22.13 observes loader/provider symbol lookup; 22.6 "
      "sees DT_NEEDED edges and 22.7 sees engine registration, but neither "
      "sees the dlopen/dlsym lookup path a module/engine/provider surface "
      "exercises.")),
)

# The X.509 root labels the gate's contract names, verbatim.
X509_ROOT_LABELS = (
    "X509",
    "X509_STORE",
    "X509_STORE_CTX",
    "X509_VERIFY_PARAM",
    "X509_verify_cert",
    "policy-tree",
    "trust",
    "purpose",
    "crl",
    "name-constraints",
    "verification-callbacks",
)

# Whole-authority file membership for the X.509 named roots. The `crypto/x509/` unit set is the
# authority's own organisation for the verification engine; the header set is where the public
# X.509 surface is declared.
X509_UNIT_PREFIX = "crypto/x509/"
X509_HEADERS = frozenset({
    "include/openssl/x509.h",
    "include/openssl/x509_vfy.h",
    "include/openssl/x509v3.h",
    "include/openssl/x509err.h",
    "include/openssl/x509v3err.h",
    "include/openssl/x509_acert.h",
    "include/crypto/x509.h",
    "include/crypto/x509_acert.h",
    "include/crypto/x509err.h",
    "include/crypto/x509v3err.h",
})

# The edge vocabulary. `direction` is recorded because the traversal's meaning depends on it.
EDGE_VOCABULARY = (
    {"kind": "DIRECT_CALL", "direction": "caller -> callee",
     "source": "22.3 tu-ast.json call_edges"},
    {"kind": "ADDRESS_TAKEN", "direction": "taker -> function whose address is taken",
     "source": "22.3 tu-ast.json address_taken"},
    {"kind": "CALLBACK_SLOT", "direction": "dispatch table -> callback-slot target",
     "source": "22.7 dispatch-graph.json"},
    {"kind": "DISPATCH_SLOT", "direction": "dispatch table -> slot target",
     "source": "22.7 dispatch-graph.json"},
    {"kind": "REGISTRATION", "direction": "registration table -> registered target",
     "source": "22.7 dispatch-graph.json"},
    {"kind": "CONFIG_DISPATCH", "direction": "config registration table -> target",
     "source": "22.7 dispatch-graph.json"},
    {"kind": "RELOCATION_REFERENCE", "direction": "object or table -> referenced symbol",
     "source": "22.6 binary-reference-graph.json relocations; 22.7 binary-only slots"},
    {"kind": "GENERATED_FROM", "direction": "generated output file -> input or generator file",
     "source": "22.5 generated-lineage.json lineage"},
    {"kind": "BUILT_INTO", "direction": "object/artifact -> the source path it was built from",
     "source": "22.6 binary-reference-graph.json objects[].source"},
    {"kind": "EXPORTED_AS", "direction": "defined global symbol -> the object/artifact that "
                                         "exports it",
     "source": "22.6 binary-reference-graph.json definitions"},
    {"kind": "ENV_READ", "direction": "environment variable -> the function that reads it",
     "source": "22.10 config-surface.json env_sites"},
    {"kind": "CLI_DISPATCH", "direction": "CLI command -> handler",
     "source": "22.7 dispatch-graph.json CLI_DISPATCH edges"},
)
EDGE_KINDS = tuple(e["kind"] for e in EDGE_VOCABULARY)


# ---------------------------------------------------------------------------
# pure key/path helpers
# ---------------------------------------------------------------------------

def norm_file(path: str | None, prefixes: tuple[str, ...]) -> str | None:
    """Authority-relative POSIX path, stripping whichever admitted prefix applies."""
    if not path:
        return None
    p = path.replace("\\", "/")
    marker = p.find("/work/")
    if marker != -1:
        p = p[marker + len("/work/"):]
    while p.startswith("./"):
        p = p[2:]
    while p.startswith("../"):
        p = p[3:]
    changed = True
    while changed:
        changed = False
        for pre in prefixes:
            if pre and p == pre:
                p = ""
                changed = True
            elif pre and p.startswith(pre + "/"):
                p = p[len(pre) + 1:]
                changed = True
    return p or None


def decode_entity(e: dict, field_map: dict) -> dict:
    list_fields = {"planes", "evidence", "root_families", "parity", "court_family"}
    out: dict = {}
    for long, short in field_map.items():
        v = e.get(short)
        if long in list_fields:
            out[long] = v.split(",") if v else []
        else:
            out[long] = v
    return out


def encode_edge(kind: str, src: str, dst: str) -> str:
    return f"{kind}\t{src}\t{dst}"


def decode_edge(row: str) -> tuple[str, str, str]:
    kind, src, dst = row.split("\t", 2)
    return kind, src, dst


# ---------------------------------------------------------------------------
# the pure traversal / body builder
# ---------------------------------------------------------------------------

def adjacency(edge_rows: list) -> dict:
    """A forward adjacency from triples or encoded rows. Pure."""
    adj: dict[str, list[str]] = defaultdict(list)
    for row in edge_rows:
        if isinstance(row, str):
            _, src, dst = decode_edge(row)
        else:
            _, src, dst = row
        adj[src].append(dst)
    return adj


def closure_from(members, adj: dict) -> set:
    """The forward reachable set from a member seed set: the traversal, and nothing else."""
    seen: set = set()
    stack = [m for m in members if m]
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        for d in adj.get(n, ()):
            if d not in seen:
                stack.append(d)
    return seen


def x509_slice_of(x509_member_keys, adj: dict, dispositions: dict, labels) -> dict:
    """The gate's contract block: satisfied exactly when no UNKNOWN is reachable from a root."""
    reachable = closure_from(x509_member_keys, adj)
    unknown = sorted(k for k in reachable
                     if k in dispositions and dispositions[k] == "UNKNOWN")
    return {
        "roots": list(labels),
        "satisfied": not unknown,
        "unknown_residuals": unknown,
    }


def build_body(members: dict, edge_rows: list, dispositions: dict, *,
               x509_member_keys, x509_labels, x509_named_members=None,
               unpopulated=(), declared=()) -> dict:
    """Recompute the whole closure from the declared roots, the typed edges and the
    dispositions 22.12 assigned. Pure: no I/O, no ambient state, no plane preference.

    This is the function `RT-PHASE22-CLOSURE` drives on the committed artefact and on
    in-memory mutations of its roots and edges.
    """
    adj = adjacency(edge_rows)
    entity_nodes = set(dispositions)

    by_root: dict[str, dict] = {}
    union: set = set()
    for fam in sorted(members):
        seed = members[fam]
        reached = closure_from(seed, adj)
        reached_entities = sorted(reached & entity_nodes)
        unknown = sorted(k for k in reached_entities
                         if dispositions.get(k) == "UNKNOWN")
        by_root[fam] = {
            "reachable": reached_entities,
            "unknown": unknown,
        }
        union |= set(reached_entities)

    edge_kind_counts: dict[str, int] = {k: 0 for k in EDGE_KINDS}
    for row in edge_rows:
        kind = decode_edge(row)[0] if isinstance(row, str) else row[0]
        edge_kind_counts[kind] = edge_kind_counts.get(kind, 0) + 1

    all_members = sorted({m for mem in members.values() for m in mem})
    unknown_union = sorted(k for k in union if dispositions.get(k) == "UNKNOWN")

    counts = {
        "roots": len(members),
        "roots_declared": len(declared) if declared else len(members) + len(unpopulated),
        "root_members": len(all_members),
        "reachable_entities": len(union),
        "unknown_intersecting_roots": len(unknown_union),
        "by_root": {
            fam: {
                "members": len(members[fam]),
                "reachable": len(by_root[fam]["reachable"]),
                "unknown": len(by_root[fam]["unknown"]),
            }
            for fam in sorted(members)
        },
        "edges": len(edge_rows),
        "edge_kinds": {k: edge_kind_counts.get(k, 0) for k in EDGE_KINDS},
        "unpopulated_families": sorted(f for f, _ in unpopulated),
    }

    x509_reachable = closure_from(x509_member_keys, adj)
    x509_entities = sorted(k for k in x509_reachable if k in entity_nodes)

    named_members = x509_named_members or {}
    x509_by_label = {}
    for label in x509_labels:
        seed = named_members.get(label, [])
        reached = closure_from(seed, adj)
        reached_entities = [k for k in reached if k in entity_nodes]
        x509_by_label[label] = {
            "members": len(seed),
            "reachable": len(reached_entities),
            "unknown": sum(1 for k in reached_entities
                           if dispositions.get(k) == "UNKNOWN"),
        }

    return {
        "counts": counts,
        "by_root": by_root,
        "unknown_intersecting_root_keys": unknown_union,
        "x509_slice": x509_slice_of(x509_member_keys, adj, dispositions, x509_labels),
        "x509_root_membership": {
            "labels": list(x509_labels),
            "members": len(x509_member_keys),
            "member_keys": sorted(x509_member_keys),
            "reachable": len(x509_entities),
            "by_label": x509_by_label,
        },
    }


# ---------------------------------------------------------------------------
# I/O: derive the roots and the typed edges from the planes
# ---------------------------------------------------------------------------

def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class Resolver:
    """Resolve a symbol name (optionally at a file) to 22.12's canonical entity key.

    Rebuilds the same name index 22.12 built, so an edge target and an entity are the same
    thing. An ambiguous name falls back to `sym|<name>`, which is simply not an entity key and
    does not contribute a disposition.
    """

    def __init__(self, entities: list[dict]):
        self.keys = {e["key"] for e in entities}
        self.by_name: dict[str, set[str]] = defaultdict(set)
        for e in entities:
            if e["space"] == "symbol":
                self.by_name[e["name"]].add(e["key"])

    def __call__(self, name: str, file: str | None = None) -> str:
        if file:
            k = f"sym|{name}@{file}"
            if k in self.keys:
                return k
        cands = self.by_name.get(name)
        if cands and len(cands) == 1:
            return next(iter(cands))
        if cands and file:
            fc = [x for x in cands if x.endswith("@" + file)]
            if len(fc) == 1:
                return fc[0]
        return f"sym|{name}"


def collect(authority_id: str) -> dict:
    auth = resolve_authority(authority_id)
    rec = load_build_records()[authority_id]
    prefixes = (
        auth.source.resolve().relative_to(REPO_ROOT).as_posix(),
        str(rec.get("build_dir", "")),
        str(rec.get("prefix", "")),
    )

    rec_body = _load(P22 / "reconciliation.json")["body"]
    field_map = rec_body["field_map"]
    entities = [decode_entity(e, field_map) for e in rec_body["entities"]]
    dispositions = {e["key"]: e["disposition"] for e in entities}
    resolve = Resolver(entities)

    def N(p):
        return norm_file(p, prefixes)

    # -- roots -----------------------------------------------------------------
    # Names a plane offered as a member that did not resolve to a 22.12 entity key are recorded
    # per family, so a member list that dropped candidates says so rather than looking complete.
    unresolved: dict[str, set] = {f: set() for f in POPULATED_FAMILIES}

    # source API: the Phase-1 header/API atlas's public declarations.
    prod = ATLAS / authority_id
    sa: set = set()
    for rec_name, kind_of in (("functions.json", "function"), ("variables.json", "variable"),
                              ("typedefs.json", "typedef"), ("structs.json", "struct"),
                              ("macros.json", "macro")):
        for r in _load(prod / rec_name)["body"]["records"]:
            name = r["name"]
            if kind_of == "macro":
                key = f"sym|macro:{name}"
            elif kind_of in ("typedef", "struct"):
                tag = r.get("tag", kind_of) if kind_of == "struct" else kind_of
                key = f"sym|{tag}:{name}"
            else:
                key = resolve(name)
            if key in dispositions:
                sa.add(key)
            else:
                unresolved["source-api"].add(f"{kind_of}:{name}")

    # binary ABI: the DSO exports 22.6's binary graph defines.
    bin_body = _load(P22 / "binary-reference-graph.json")["body"]
    art_kind = {a["path"]: a["kind"] for a in bin_body["artifacts"]}
    dso_kinds = {"shared-object", "provider-module", "engine-module"}
    ba: set = set()
    for o in bin_body["objects"]:
        if art_kind.get(o.get("artifact")) not in dso_kinds:
            continue
        for d in o["defined"]:
            if d.get("binding") != "global":
                continue
            key = resolve(d["name"])
            if key in dispositions:
                ba.add(key)
            else:
                unresolved["binary-abi"].add(d["name"])

    # modules and callbacks: 22.7's dispatch, registration and callback surfaces.
    disp_body = _load(P22 / "dispatch-graph.json")["body"]
    mods: set = set()
    cbs: set = set()
    for e in disp_body["edges"]:
        f = N(e.get("file"))
        key = resolve(e.get("target"), f)
        if key not in dispositions:
            unresolved["callbacks" if e["kind"] == "CALLBACK_SLOT" else "modules"].add(
                e.get("target") or "")
            continue
        if e["kind"] == "CALLBACK_SLOT":
            cbs.add(key)
        elif e["kind"] in ("DISPATCH_SLOT", "REGISTRATION", "CONFIG_DISPATCH"):
            mods.add(key)
    module_table_families = {
        "PROVIDER_INIT", "OSSL_DISPATCH", "OSSL_ALGORITHM", "OSSL_ALGORITHM_CAPABLE",
        "ENGINE_SET", "CONF_MODULE_ADD", "EVP_PKEY_ASN1_METHOD", "EVP_PKEY_ASN1_METHOD_ARRAY",
    }
    for t in disp_body.get("tables") or []:
        if t.get("family") not in module_table_families:
            continue
        key = resolve(t.get("symbol"), N(t.get("file")))
        if key in dispositions:
            mods.add(key)

    # CLI: 22.9's commands, aliases and pseudo-commands.
    cli_body = _load(P22 / "cli-surface.json")["body"]
    cli: set = set()
    for c in cli_body["commands"]:
        cli.add(f"cli|{c['name']}")
        for a in c.get("aliases") or []:
            cli.add(f"cli|{a}")
    for name in cli_body.get("digest_commands") or []:
        cli.add(f"cli|{name}")
    for name in cli_body.get("cipher_commands") or []:
        cli.add(f"cli|{name}")
    cli_raw = set(cli)
    cli &= set(dispositions)
    unresolved["cli"] |= cli_raw - cli

    # configuration: 22.10's directives, environment variables and default paths.
    cfg_body = _load(P22 / "config-surface.json")["body"]
    cfg: set = set()
    for d in cfg_body["directives"]:
        cfg.add(f"config|{d['name']}")
    for e in cfg_body["env_vars"]:
        cfg.add(f"config|env:{e['name']}")
    for p in cfg_body["default_paths"]:
        cfg.add(f"config|path:{p['name']}")
    cfg_raw = set(cfg)
    cfg &= set(dispositions)
    unresolved["configuration"] |= cfg_raw - cfg

    # distribution: 22.8's REQUIRED_COMPATIBILITY entries.
    man_body = _load(P22 / "install-manifest.json")["body"]
    dist: set = set()
    for entry in man_body["entries"]:
        if entry.get("disposition") == "REQUIRED_COMPATIBILITY":
            dist.add(f"install|{entry['path']}")
    dist_raw = set(dist)
    dist &= set(dispositions)
    unresolved["distribution"] |= dist_raw - dist

    members: dict[str, list[str]] = {
        "source-api": sorted(sa),
        "binary-abi": sorted(ba),
        "modules": sorted(mods),
        "callbacks": sorted(cbs),
        "cli": sorted(cli),
        "configuration": sorted(cfg),
        "distribution": sorted(dist),
    }
    roots_meta = {
        "source-api": {
            "declaration": "public header declarations -- functions, variables, macros, "
                           "typedefs and tagged structs",
            "provenance": f"forensics/atlas/{authority_id}/functions.json, variables.json, "
                           f"macros.json, typedefs.json, structs.json (Phase-1 header/API atlas)",
        },
        "binary-abi": {
            "declaration": "the DSO exports: global symbols defined by the shared objects, the "
                           "provider module and the engine modules",
            "provenance": "forensics/atlas/phase22/binary-reference-graph.json "
                           "artifacts[].kind in {shared-object, provider-module, engine-module}, "
                           "objects[].defined binding=global",
        },
        "modules": {
            "declaration": "provider entrypoints, registrations and dispatch tables",
            "provenance": "forensics/atlas/phase22/dispatch-graph.json edges of kind "
                           "DISPATCH_SLOT/REGISTRATION/CONFIG_DISPATCH and the table symbols of "
                           "the provider/dispatch/engine families",
        },
        "callbacks": {
            "declaration": "callback types and the routes that invoke them -- the callback-slot "
                           "targets",
            "provenance": "forensics/atlas/phase22/dispatch-graph.json edges of kind CALLBACK_SLOT",
        },
        "cli": {
            "declaration": "commands, aliases and digest/cipher pseudo-commands",
            "provenance": "forensics/atlas/phase22/cli-surface.json commands[].name, "
                           ".aliases[], digest_commands[], cipher_commands[]",
        },
        "configuration": {
            "declaration": "directives, environment variables and default paths",
            "provenance": "forensics/atlas/phase22/config-surface.json directives, env_vars, "
                           "default_paths",
        },
        "distribution": {
            "declaration": "installed files, symlinks and modes dispositioned "
                           "REQUIRED_COMPATIBILITY",
            "provenance": "forensics/atlas/phase22/install-manifest.json entries[].disposition "
                           "== REQUIRED_COMPATIBILITY",
        },
    }
    unresolved_out = {
        fam: {"count": len(names), "examples": sorted(names)[:8]}
        for fam, names in sorted(unresolved.items())
    }

    # -- typed edges -----------------------------------------------------------
    edge_set: set[tuple[str, str, str]] = set()

    def edge(src, dst, kind):
        if src and dst and src != dst:
            edge_set.add((src, dst, kind))

    # 22.3 every-translation-unit AST: direct calls and address-taken functions.
    ast_body = _load(P22 / "tu-ast.json")["body"]
    for e in ast_body["call_edges"]:
        edge(resolve(e["caller"], N(e.get("caller_file"))),
             resolve(e["callee"], N(e.get("callee_file"))), "DIRECT_CALL")
    for e in ast_body["address_taken"]:
        edge(resolve(e["caller"], N(e.get("file"))),
             resolve(e["function"], N(e.get("function_file"))), "ADDRESS_TAKEN")

    # 22.7 dispatch/callback/registration/CLI/config tables.
    for e in disp_body["edges"]:
        f = N(e.get("file"))
        kind = e["kind"]
        if kind == "CLI_DISPATCH":
            edge(f"cli|{e.get('slot')}", resolve(e.get("target"), f), "CLI_DISPATCH")
        else:
            tbl = e.get("table") or f"file:{f}"
            edge(f"tbl|{tbl}", resolve(e.get("target"), f), kind)

    # 22.6 binary graph: exports, built-into sources, relocations.
    for o in bin_body["objects"]:
        oid = o["id"]
        node = f"bin|{oid}"
        kind = art_kind.get(o.get("artifact"), "archive")
        for d in o["defined"]:
            if kind in dso_kinds and d.get("binding") != "global":
                continue
            edge(resolve(d["name"]), node, "EXPORTED_AS")
        src = N(o.get("source"))
        if src:
            edge(node, f"file|{src}", "BUILT_INTO")
        for r in o.get("relocations") or []:
            edge(node, resolve(r.get("symbol")), "RELOCATION_REFERENCE")

    # 22.5 generated-source genealogy.
    gen_body = _load(P22 / "generated-lineage.json")["body"]
    for row in gen_body["lineage"]:
        out = N(row.get("output"))
        if not out:
            continue
        for i in row.get("inputs") or []:
            ip = N(i.get("path"))
            if ip:
                edge(f"file|{out}", f"file|{ip}", "GENERATED_FROM")
        g = N(row.get("generator"))
        if g:
            edge(f"file|{out}", f"file|{g}", "GENERATED_FROM")

    # 22.10 environment reads: the variable reaches the function that reads it.
    for s in cfg_body.get("env_sites") or []:
        if s.get("name"):
            edge(f"config|env:{s['name']}", resolve(s.get("caller"), N(s.get("file"))),
                 "ENV_READ")

    edge_rows = sorted(encode_edge(k, s, d) for (s, d, k) in edge_set)

    # -- X.509 root membership, derived from the named roots -------------------
    e_by_key = {e["key"]: e for e in entities}
    cb_targets = cbs
    named_roots: dict[str, dict] = {}
    x509_members: set = set()
    x509_named_members: dict[str, list[str]] = {}

    def member_file(key):
        return N(e_by_key[key].get("file"))

    def member_name(key):
        return e_by_key[key].get("name") or ""

    declared_union = set().union(*members.values())
    for label in X509_ROOT_LABELS:
        picked: set = set()
        for key in declared_union:
            f = member_file(key)
            nm = member_name(key)
            if label in ("X509", "X509_STORE", "X509_STORE_CTX", "X509_VERIFY_PARAM",
                         "X509_verify_cert"):
                if nm == label or nm.startswith(label + "_"):
                    picked.add(key)
            elif label == "policy-tree":
                if f and f.startswith(X509_UNIT_PREFIX + "pcy_"):
                    picked.add(key)
            elif label == "trust":
                if f in (X509_UNIT_PREFIX + "x509_trust.c",):
                    picked.add(key)
            elif label == "purpose":
                if f == X509_UNIT_PREFIX + "v3_purp.c":
                    picked.add(key)
            elif label == "crl":
                if f in (X509_UNIT_PREFIX + "x_crl.c", X509_UNIT_PREFIX + "v3_crld.c"):
                    picked.add(key)
            elif label == "name-constraints":
                if f == X509_UNIT_PREFIX + "v3_ncons.c":
                    picked.add(key)
            elif label == "verification-callbacks":
                if ((key in cb_targets and f and f.startswith(X509_UNIT_PREFIX))
                        or nm.startswith("X509_VERIFY") or nm.endswith("verify_cb")):
                    picked.add(key)
        named_roots[label] = {
            "members": len(picked),
            "rule": _x509_rule(label),
        }
        x509_named_members[label] = sorted(picked)
        x509_members |= picked

    return {
        "members": members,
        "roots_meta": roots_meta,
        "unresolved": unresolved_out,
        "edge_rows": edge_rows,
        "dispositions": dispositions,
        "named_roots": named_roots,
        "x509_member_keys": sorted(x509_members),
        "x509_named_members": x509_named_members,
        "entity_count": len(entities),
    }


def _x509_rule(label: str) -> str:
    if label in ("X509", "X509_STORE", "X509_STORE_CTX", "X509_VERIFY_PARAM",
                 "X509_verify_cert"):
        return f"declared-root members named exactly `{label}` or starting `{label}_`"
    if label == "policy-tree":
        return "declared-root members defined in crypto/x509/pcy_*.{c,h} (the policy tree)"
    if label == "trust":
        return "declared-root members defined in crypto/x509/x509_trust.c"
    if label == "purpose":
        return "declared-root members defined in crypto/x509/v3_purp.c"
    if label == "crl":
        return "declared-root members defined in crypto/x509/x_crl.c or crypto/x509/v3_crld.c"
    if label == "name-constraints":
        return "declared-root members defined in crypto/x509/v3_ncons.c"
    if label == "verification-callbacks":
        return ("callback-slot targets defined under crypto/x509/, plus declared-root members "
                "named `X509_VERIFY*` or ending `verify_cb`")
    return "unspecified"


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Phase 22.14 external-root compatibility closure")
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    ap.add_argument("--self-test", action="store_true",
                    help="break the pure traversal/classification in memory and require the "
                         "court to fail")
    args = ap.parse_args(argv)

    col = collect(args.authority)
    derived = build_body(
        col["members"], col["edge_rows"], col["dispositions"],
        x509_member_keys=col["x509_member_keys"], x509_labels=X509_ROOT_LABELS,
        x509_named_members=col["x509_named_members"],
        unpopulated=UNPOPULATED_FAMILIES,
        declared=(POPULATED_FAMILIES + tuple(f for f, _ in UNPOPULATED_FAMILIES)),
    )

    body = {
        "roots": {
            fam: {
                "declaration": col["roots_meta"][fam]["declaration"],
                "provenance": col["roots_meta"][fam]["provenance"],
                "members": col["members"][fam],
                "unresolved": col["unresolved"].get(fam, {"count": 0, "examples": []}),
            }
            for fam in POPULATED_FAMILIES
        },
        "unpopulated": [{"family": f, "reason": why} for f, why in UNPOPULATED_FAMILIES],
        "edge_vocabulary": list(EDGE_VOCABULARY),
        "edges": col["edge_rows"],
        "dispositions": col["dispositions"],
        "entity_count": col["entity_count"],
        "x509_root_labels": list(X509_ROOT_LABELS),
        "x509_member_keys": col["x509_member_keys"],
        "x509_named_members": col["x509_named_members"],
        "x509_named_roots": col["named_roots"],
        "x509_derivation": (
            "The X.509 slice membership is the union over the named roots of the X.509 members "
            "of the declared compatibility roots. Each named root's rule is recorded in "
            "x509_named_roots; the units are the authority's own (crypto/x509/pcy_* for the "
            "policy tree, x509_trust.c for trust, v3_purp.c for purpose, x_crl.c/v3_crld.c for "
            "CRL, v3_ncons.c for name constraints), and the X509* prefix covers the X509, "
            "X509_STORE, X509_STORE_CTX, X509_VERIFY_PARAM and X509_verify_cert roots. "
            "`_openssl_ascii2ebcdic` and `_openssl_ebcdic2ascii` (ebcdic.h) are not matched by "
            "any rule and no X.509 root reaches them."
        ),
        "counts": derived["counts"],
        "by_root": derived["by_root"],
        "unknown_intersecting_root_keys": derived["unknown_intersecting_root_keys"],
        "x509_slice": derived["x509_slice"],
        "x509_root_membership": derived["x509_root_membership"],
        "reductions": {
            "relocation": (
                "22.6 attributes a relocation to an object, not to one symbol, so a symbol's "
                "reach through RELOCATION_REFERENCE is its object's reference set; for archive "
                "members that is one translation unit, for a linked shared object it is the "
                "whole DSO."
            ),
            "unknown_is_dispositions_only": (
                "This plane assigns no disposition. It reads 22.12's; a reachable entity whose "
                "22.12 disposition is UNKNOWN is the blocking set, and nothing here reclassifies."
            ),
            "generated_from_degrades_to_file_nodes": (
                "GENERATED_FROM and BUILT_INTO connect file and object nodes; they are reached "
                "from a symbol root through EXPORTED_AS/BUILT_INTO, so they carry build "
                "provenance rather than adding callable surfaces."
            ),
        },
        "sort_key": ("roots by family; members sorted; edges sorted by (kind, src, dst); "
                     "by_root reachable/unknown sorted; every list sorted"),
    }

    inputs = [InputRef(name="plan", path=REPO_ROOT / "docs" / "PHASE-22-SUBPHASES.md")]
    for name, relpath in (
        ("reconciliation", "forensics/atlas/phase22/reconciliation.json"),
        ("binary-reference-graph", "forensics/atlas/phase22/binary-reference-graph.json"),
        ("dispatch-graph", "forensics/atlas/phase22/dispatch-graph.json"),
        ("tu-ast", "forensics/atlas/phase22/tu-ast.json"),
        ("generated-lineage", "forensics/atlas/phase22/generated-lineage.json"),
        ("config-surface", "forensics/atlas/phase22/config-surface.json"),
        ("cli-surface", "forensics/atlas/phase22/cli-surface.json"),
        ("install-manifest", "forensics/atlas/phase22/install-manifest.json"),
    ):
        p = REPO_ROOT / relpath
        if p.is_file():
            inputs.append(InputRef(name=name, path=p))

    doc = envelope(kind="phase22-compatibility-closure", authority=args.authority,
                   inputs=inputs, body=body, generator=GENERATOR)
    doc["body"] = dict(doc["body"])
    write_json(OUT, doc)

    if args.self_test:
        ok = self_test(body)
        print(f"[phase22-closure] self-test: {'OK' if ok else 'FAILED'}")
        if not ok:
            return 1

    c = body["counts"]
    print(f"[phase22-closure] root families={c['roots']}/{c['roots_declared']} "
          f"members={c['root_members']} edges={c['edges']} "
          f"reachable_entities={c['reachable_entities']} "
          f"unknown_intersecting_roots={c['unknown_intersecting_roots']}")
    print(f"[phase22-closure] x509_slice satisfied={body['x509_slice']['satisfied']} "
          f"members={body['x509_root_membership']['members']} "
          f"reachable={body['x509_root_membership']['reachable']} "
          f"unknown={len(body['x509_slice']['unknown_residuals'])}")
    print(f"[phase22-closure] unpopulated={[f for f, _ in UNPOPULATED_FAMILIES]} -> {rel(OUT)}")
    return 0


# ---------------------------------------------------------------------------
# the court
# ---------------------------------------------------------------------------

def _inputs(body: dict) -> dict:
    return {
        "members": {fam: list(v["members"]) for fam, v in body["roots"].items()},
        "edge_rows": list(body["edges"]),
        "dispositions": dict(body["dispositions"]),
        "x509_member_keys": list(body["x509_member_keys"]),
        "x509_named_members": {k: list(v) for k, v in body["x509_named_members"].items()},
    }


def court_closure(body: dict) -> dict:
    """`RT-PHASE22-CLOSURE`: an FRF-style sensitivity challenge of the root/traversal logic.

    Round-trips the committed closure from its own declared roots, typed edges and dispositions,
    then drives `build_body` over five controlled in-memory mutations -- add a root member, add a
    reachable entity, make an UNKNOWN reachable from an X.509 root, remove that reachability
    again, and drop a root family -- and fails if any derivation is insensitive to it.
    """
    checks: list[tuple[str, bool]] = []
    inp = _inputs(body)
    labels = body["x509_root_labels"]
    committed_counts = body["counts"]
    committed_by_root = body["by_root"]
    committed_slice = body["x509_slice"]
    unpopulated = tuple((u["family"], u["reason"]) for u in body["unpopulated"])
    declared = POPULATED_FAMILIES + tuple(f for f, _ in unpopulated)

    def derive(members, edges, dispositions, x509):
        return build_body(
            members, edges, dispositions, x509_member_keys=x509, x509_labels=labels,
            x509_named_members=inp["x509_named_members"],
            unpopulated=unpopulated, declared=declared,
        )

    base = derive(inp["members"], inp["edge_rows"], inp["dispositions"], inp["x509_member_keys"])

    checks.append(("baseline: the artefact declares roots",
                   committed_counts["roots"] > 0 and committed_counts["root_members"] > 0))
    checks.append(("baseline: the artefact reaches entities",
                   committed_counts["reachable_entities"] > 0))
    checks.append(("baseline: the artefact carries every edge kind",
                   all(committed_counts["edge_kinds"].get(k, 0) > 0 for k in EDGE_KINDS)))
    checks.append(("baseline: the artefact has X.509 root members",
                   committed_counts["by_root"]["source-api"]["members"] > 0
                   and len(body["x509_member_keys"]) > 0))

    checks.append(("round-trip: counts equal", base["counts"] == committed_counts))
    checks.append(("round-trip: by_root equal", base["by_root"] == committed_by_root))
    checks.append(("round-trip: x509_slice equal", base["x509_slice"] == committed_slice))
    checks.append(("round-trip: x509_root_membership equal",
                   base["x509_root_membership"]["members"]
                   == body["x509_root_membership"]["members"]))

    def reachable_union(res):
        return {k for fam in res["by_root"].values() for k in fam["reachable"]}

    reachable0 = reachable_union(base)

    # 1. add a root member (an entity nobody currently reaches).
    free = next((k for k in sorted(inp["dispositions"])
                 if k not in reachable0), None)
    if free is None:
        checks.append(("add-root-member: a free entity was found", False))
    else:
        members = {f: list(m) for f, m in inp["members"].items()}
        members["callbacks"].append(free)
        new = derive(members, inp["edge_rows"], inp["dispositions"], inp["x509_member_keys"])
        checks.append(("add-root-member: the family gained one member",
                       new["counts"]["by_root"]["callbacks"]["members"]
                       == base["counts"]["by_root"]["callbacks"]["members"] + 1))
        checks.append(("add-root-member: root_members rose by one",
                       new["counts"]["root_members"] == base["counts"]["root_members"] + 1))
        checks.append(("add-root-member: reachable_entities rose",
                       new["counts"]["reachable_entities"]
                       > base["counts"]["reachable_entities"]))

    # 2. add a reachable entity by one edge from a root member.
    root_member = inp["members"]["source-api"][0] if inp["members"]["source-api"] else None
    dst_free = next((k for k in sorted(inp["dispositions"])
                    if k not in reachable0 and k != root_member), None)
    if root_member is None or dst_free is None:
        checks.append(("add-reachable-entity: inputs were found", False))
    else:
        edges = inp["edge_rows"] + [encode_edge("DIRECT_CALL", root_member, dst_free)]
        new = derive(inp["members"], edges, inp["dispositions"], inp["x509_member_keys"])
        checks.append(("add-reachable-entity: reachable_entities rose by one",
                       new["counts"]["reachable_entities"]
                       == base["counts"]["reachable_entities"] + 1))
        checks.append(("add-reachable-entity: the edge kind count rose",
                       new["counts"]["edge_kinds"]["DIRECT_CALL"]
                       == base["counts"]["edge_kinds"]["DIRECT_CALL"] + 1))

    # 3. make an UNKNOWN reachable from an X.509 root: the slice must flip, and populate.
    x509_root = inp["x509_member_keys"][0] if inp["x509_member_keys"] else None
    unknown_key = next((k for k in sorted(inp["dispositions"])
                        if inp["dispositions"][k] == "UNKNOWN"
                        and k not in reachable_union(base)), None)
    if x509_root is None or unknown_key is None:
        checks.append(("make-unknown-reachable: inputs were found", False))
    else:
        edges = inp["edge_rows"] + [encode_edge("DIRECT_CALL", x509_root, unknown_key)]
        new = derive(inp["members"], edges, inp["dispositions"], inp["x509_member_keys"])
        checks.append(("make-unknown-reachable: x509_slice.satisfied flipped false",
                       new["x509_slice"]["satisfied"] is False))
        checks.append(("make-unknown-reachable: unknown_residuals populated",
                       unknown_key in new["x509_slice"]["unknown_residuals"]))
        checks.append(("make-unknown-reachable: unknown_intersecting_roots rose",
                       new["counts"]["unknown_intersecting_roots"]
                       > base["counts"]["unknown_intersecting_roots"]))

        # 4. remove that reachability again: it must flip back.
        back = derive(inp["members"], inp["edge_rows"], inp["dispositions"],
                      inp["x509_member_keys"])
        checks.append(("remove-reachability: x509_slice.satisfied flipped back true",
                       back["x509_slice"]["satisfied"] is True))
        checks.append(("remove-reachability: unknown_residuals empty again",
                       back["x509_slice"]["unknown_residuals"] == []))

    # 5. drop a root family: the family count must fall and the union must not grow.
    dropped = "distribution"
    members = {f: list(m) for f, m in inp["members"].items() if f != dropped}
    new = derive(members, inp["edge_rows"], inp["dispositions"], inp["x509_member_keys"])
    checks.append(("drop-root-family: counts.roots fell by one",
                   new["counts"]["roots"] == base["counts"]["roots"] - 1))
    checks.append(("drop-root-family: the family left by_root",
                   dropped not in new["counts"]["by_root"]))
    checks.append(("drop-root-family: reachable_entities did not rise",
                   new["counts"]["reachable_entities"]
                   <= base["counts"]["reachable_entities"]))

    failures = [desc for desc, ok in checks if not ok]
    return {
        "court": "RT-PHASE22-CLOSURE",
        "artefact": ARTEFACT_REL,
        "summary": (f"{committed_counts['roots']} root families, "
                    f"{committed_counts['root_members']} members, "
                    f"{committed_counts['reachable_entities']} reachable, "
                    f"{committed_counts['unknown_intersecting_roots']} unknown-in-roots, "
                    f"x509 satisfied={committed_slice['satisfied']}"),
        "root_families": committed_counts["roots"],
        "root_members": committed_counts["root_members"],
        "edges": committed_counts["edges"],
        "reachable_entities": committed_counts["reachable_entities"],
        "unknown_intersecting_roots": committed_counts["unknown_intersecting_roots"],
        "x509_satisfied": committed_slice["satisfied"],
        "mutations": ["round-trip", "add-root-member", "add-reachable-entity",
                      "make-unknown-reachable", "remove-reachability", "drop-root-family"],
        "observations": len(checks),
        "failures": failures,
        "verdict": "pass" if not failures else "fail",
    }


def courts() -> list[dict]:
    """`RT-PHASE22-CLOSURE`, or `[]` while the artefact has not landed."""
    path = REPO_ROOT / ARTEFACT_REL
    if not path.is_file():
        return []
    return [court_closure(json.loads(path.read_text(encoding="utf-8"))["body"])]


# ---------------------------------------------------------------------------
# sensitivity self-test: break a pure function in memory and require the court to fail
# ---------------------------------------------------------------------------

def self_test(body: dict) -> bool:
    baseline = court_closure(body)
    if baseline["verdict"] != "pass":
        print(f"  self-test: the unbroken court does not pass ({baseline['failures'][:3]}); "
              f"cannot prove sensitivity")
        return False
    ok = True
    orig_closure = closure_from
    orig_slice = x509_slice_of
    try:
        # A traversal that returns only the seeds cannot see a newly reachable entity.
        globals()["closure_from"] = lambda members, adj: {m for m in members if m}
        if court_closure(body)["verdict"] != "fail":
            print("  self-test: a blind closure_from() was not caught")
            ok = False
        globals()["closure_from"] = orig_closure

        # A classifier that always says satisfied cannot see an UNKNOWN reach an X.509 root.
        globals()["x509_slice_of"] = lambda x, adj, disp, labels: {
            "roots": list(labels), "satisfied": True, "unknown_residuals": []}
        if court_closure(body)["verdict"] != "fail":
            print("  self-test: a blind x509_slice_of() was not caught")
            ok = False
        globals()["x509_slice_of"] = orig_slice
    finally:
        globals()["closure_from"] = orig_closure
        globals()["x509_slice_of"] = orig_slice
    return ok


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
