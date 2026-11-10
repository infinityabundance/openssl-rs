#!/usr/bin/env python3
"""Extension-slot callback enumeration completeness gate.

The obligation queue is built from the V1 census' ``UNSAFE_FN_DEF`` blockers.
A callback that is *registered in an extension-method row* but absent from that
census is invisible to the queue: it is neither DISCHARGED nor BLOCKED.  This
gate enumerates registrations by **slot**, not by function-name prefix, binds
each registered callback to the dispatcher path that can invoke it, classifies
its reachability against a pinned candidate closure, and fails unless every
registration is either:

* present in the obligation inventory (any status), or
* ``PROVEN_EXCLUDED`` with an explicit, written closed-world assumption.

An ``UNRESOLVED`` classification is always a failure.  ``REACHABLE_BOUND``
callbacks that are absent from the inventory are reported in the enrolment
list.  The gate is deterministic: stable ordering, no timestamps, no absolute
paths in the payload.

Source parsing is deliberately *syntactic and slot-driven*.  It does not match
callbacks by name prefix: any identifier assigned to a slot field is a
registration, whatever its name, and a function may be registered in several
slots or rows.

Usage::

    python3 forensics/tools/callback_enumeration_gate.py \
        --root /work \
        --closure evidence/closure-ssh-b52-applied.json \
        --out-dir forensics/memory-safety/campaign/safe-c33/atlas-refresh

Controls use ``--root`` pointed at a fixture tree, ``--inventory`` pointed at a
fixture inventory, and ``--overrides`` to inject a classification.  Overrides
are test-only and are recorded verbatim in the report; they are not used for an
authoritative run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

SLOT_FIELDS = ("i2s", "s2i", "i2v", "v2i", "i2r", "r2i")
AUX_SLOT_FIELDS = ("it", "ext_free", "d2i", "i2d", "ext_new")
GATED_SLOTS = frozenset(SLOT_FIELDS) | {"it", "ext_free"}

REACHABLE = "REACHABLE_BOUND"
EXCLUDED = "PROVEN_EXCLUDED"
UNRESOLVED = "UNRESOLVED"

BASIS_EDGE = "edge-witness"
BASIS_MODULE = "module-name-match"
BASIS_UNIQUE = "unique-name-match"
BASIS_DISPATCH = "dispatcher-row-binding"
BASIS_ORDER = (BASIS_EDGE, BASIS_MODULE, BASIS_UNIQUE, BASIS_DISPATCH)
BASIS_VOCABULARY = frozenset(BASIS_ORDER)

CLOSED_WORLD_ASSUMPTION = (
    "Closed-world assumption CE-1 (pinned-consumer reachability): a "
    "source-defined callback is not reachable from this consumer family when "
    "(a) its defining file is absent from the closure's reachable_files, "
    "(b) its name is absent from reachable_functions, (c) no row that installs "
    "it is present in STANDARD_EXTS or otherwise referenced from a reachable "
    "file, and (d) no reachable function calls it directly. Evidence for this "
    "registration: {evidence}. Limit: this assumes the closure's file list, "
    "static-table extraction and direct-call extraction are complete; indirect "
    "targets not modelled by the closure (e.g. arbitrary runtime-built tables) "
    "are outside the assumption and would demote it to UNRESOLVED."
)

NON_CLAIMS = [
    "The gate proves inventory-vs-source agreement for the registrations this "
    "parser can see; it does not prove that every registration in the source "
    "was parsed (macro-generated rows and build-script-generated source are "
    "outside the parser).",
    "REACHABLE_BOUND is a bound, not a proof. edge-witness records a concrete "
    "source call-graph edge from a caller that is itself reachable-bound; "
    "module-name-match and unique-name-match rest only on the closure's "
    "converged MAY-bound reachable_functions set (unresolved-site-bound/v1, "
    "whose own contract says monotonicity is not completeness); "
    "dispatcher-row-binding records a STANDARD_EXTS row plus a reachable "
    "dispatcher and states that no callback symbol was found in the reachable "
    "set.",
    "PROVEN_EXCLUDED carries the written closed-world assumption CE-1; it is "
    "a scoped reachability claim about the pinned consumer family, not a "
    "property of the callback in general.",
    "The gate does not adjudicate whether an inventoried callback is safe, and "
    "it does not change any obligation status.",
]


# --------------------------------------------------------------------------
# Rust source masking / structural helpers
# --------------------------------------------------------------------------

def mask_rust(text: str) -> str:
    """Replace comments and string literals with spaces, preserving newlines.

    This is not a lexer; it is enough to keep braces, commas and field colons
    inside comments/strings from confusing the structural scanners.  Character
    literals are left alone (a brace in a char literal is not usable Rust in
    the constructs we scan).
    """
    out = list(text)
    n = len(text)
    i = 0
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            if j < 0:
                j = n
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if text[k] != "\n":
                    out[k] = " "
            i = j
        elif c == "r" and i + 1 < n and text[i + 1] in '#"':
            # raw string r"..." / r#"..."#
            j = i + 1
            hashes = 0
            while j < n and text[j] == "#":
                hashes += 1
                j += 1
            if j < n and text[j] == '"':
                close = '"' + "#" * hashes
                end = text.find(close, j + 1)
                end = n if end < 0 else end + len(close)
                for k in range(i, end):
                    if text[k] != "\n":
                        out[k] = " "
                i = end
            else:
                i += 1
        elif c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            for k in range(i, min(j, n)):
                if text[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


def match_brace(masked: str, open_pos: int) -> int:
    depth = 0
    for i in range(open_pos, len(masked)):
        ch = masked[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(masked) - 1


def match_paren(masked: str, open_pos: int) -> int:
    depth = 0
    for i in range(open_pos, len(masked)):
        ch = masked[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
    return len(masked) - 1


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


DECL_RE = re.compile(
    r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:(?P<kind>static|const)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:|"
    r"(?:const\s+)?(?:unsafe\s+)?(?:extern\s+)?(?:async\s+)?"
    r"(?:fn)\s+(?P<fname>[A-Za-z_][A-Za-z0-9_]*)\s*[\(<])"
)

FN_DEF_RE = re.compile(
    r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:unsafe\s+)?"
    r"(?:extern\s+)?(?:async\s+)?fn\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*[\(<]"
)

SLOT_PREFIX_DEF_RE = re.compile(
    r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?unsafe\s+extern\s+fn\s+"
    r"((?:s2i|i2s|i2r|i2v|r2i|v2i)_[A-Za-z0-9_]+)"
)


def depth_map(masked: str) -> list[int]:
    depth = 0
    out = [0] * (len(masked) + 1)
    for i, ch in enumerate(masked):
        out[i] = depth
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
    out[len(masked)] = depth
    return out


def test_spans(masked: str) -> list[tuple[int, int]]:
    spans = []
    for m in re.finditer(r"#\[cfg\(test\)\]", masked):
        brace = masked.find("{", m.end())
        if brace < 0:
            continue
        spans.append((brace, match_brace(masked, brace)))
    return spans


def in_spans(pos: int, spans: list[tuple[int, int]]) -> bool:
    return any(a <= pos <= b for a, b in spans)


def declarations(masked: str, depths: list[int]) -> list[dict]:
    decls = []
    for m in DECL_RE.finditer(masked):
        name = m.group("name") or m.group("fname")
        kind = m.group("kind") or "fn"
        decls.append({
            "name": name,
            "kind": kind,
            "pos": m.start(),
            "depth": depths[m.start()],
        })
    decls.sort(key=lambda d: d["pos"])
    return decls


def enclosing_decl(decls: list[dict], pos: int, depth: int) -> dict | None:
    best = None
    for d in decls:
        if d["pos"] >= pos:
            break
        if d["depth"] <= depth:
            best = d
    return best


def enclosing_fn(decls: list[dict], pos: int, depth: int) -> str | None:
    for d in reversed(decls):
        if d["pos"] >= pos:
            continue
        if d["depth"] <= depth and d["kind"] == "fn":
            return d["name"]
    return None


def def_line_for(masked: str, name: str) -> int | None:
    pat = re.compile(
        r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:unsafe\s+)?"
        r"(?:extern\s+)?(?:async\s+)?fn\s+"
        + re.escape(name) + r"\s*[\(<]"
    )
    m = pat.search(masked)
    return line_of(masked, m.start()) if m else None


# --------------------------------------------------------------------------
# v0/v1 Rust symbol demangling (name-level reachability)
# --------------------------------------------------------------------------

def symbol_name(sym: str) -> str:
    """Return the symbol part of a closure entry ``module:addr:name``."""
    parts = sym.split(":")
    return parts[-1] if len(parts) >= 2 else sym


def demangle_segments(sym: str) -> list[str]:
    """Best-effort rustc v0/legacy path segments for a mangled symbol.

    Only used to turn closure reachable-function entries into
    ``(module-stem, function-name)`` pairs.  Failure is not fatal: the caller
    falls back to the raw last segment.
    """
    raw = symbol_name(sym)
    # Strip common optimisation suffixes.
    for marker in (".llvm.", ".constprop.", ".isra.", ".part."):
        if marker in raw:
            raw = raw.split(marker, 1)[0]
    if raw.startswith("_R"):
        body = raw[2:]
        segs = []
        i = 0
        n = len(body)
        while i < n:
            m = re.match(r"(\d+)", body[i:])
            if m:
                length = int(m.group(1))
                start = i + len(m.group(1))
                ident = body[start:start + length]
                if len(ident) == length and re.fullmatch(
                        r"[A-Za-z_][A-Za-z0-9_]*", ident):
                    segs.append(ident)
                    i = start + length
                    continue
            i += 1
        if segs:
            return segs
    if raw.startswith("_ZN"):
        body = raw[3:]
        segs = []
        i = 0
        n = len(body)
        while i < n:
            m = re.match(r"(\d+)", body[i:])
            if not m:
                break
            length = int(m.group(1))
            start = i + len(m.group(1))
            ident = body[start:start + length]
            if len(ident) != length:
                break
            if not re.fullmatch(r"17h[0-9a-f]{16}", ident):
                segs.append(ident)
            i = start + length
        if segs:
            return segs
    return [raw]


# --------------------------------------------------------------------------
# Registration parsing
# --------------------------------------------------------------------------

ROW_LITERAL_RE = re.compile(r"\bX509V3ExtMethod\s*\{")
VALUE_SKIP = {
    "None", "Some", "ptr", "null_mut", "c_void", "I2dOfVoid", "D2iOfVoid",
}


def callback_from_value(value: str) -> str | None:
    value = value.strip()
    if not value or value.startswith("None"):
        return None
    # as_i2r(i2r_X) / as_free(X) / Some(X) / bare X: the callback is the last
    # identifier in the expression.
    ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", value)
    ids = [x for x in ids if x not in VALUE_SKIP]
    if not ids:
        return None
    return ids[-1]


def split_fields(body: str) -> list[tuple[str, str]]:
    """Split a struct-literal body into top-level ``field: value`` pairs."""
    fields = []
    parts = []
    depth = 0
    start = 0
    for i, ch in enumerate(body):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(body[start:i])
            start = i + 1
    parts.append(body[start:])
    for part in parts:
        text = part.strip()
        if ":" not in text:
            # Rust field-init shorthand: ``v2i,`` means ``v2i: v2i``.
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text):
                fields.append((text, text))
            continue
        name, _, value = text.partition(":")
        name = name.strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            fields.append((name, value.strip()))
    return fields


def static_initializer(masked: str, decl: dict) -> str:
    """Return a static/const initializer text (after ``=``, before ``;``)."""
    eq = masked.find("=", decl["pos"])
    if eq < 0:
        return ""
    depth = 0
    for i in range(eq + 1, len(masked)):
        ch = masked[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch == ";" and depth == 0:
            return masked[eq + 1:i]
    return masked[eq + 1:]


def fn_params_for(masked: str, decl: dict) -> tuple[list[str], dict[str, str]]:
    """Return the ordered parameter names and their declared types."""
    name = decl["name"]
    m = re.search(r"\bfn\s+" + re.escape(name) + r"\s*\(",
                  masked[decl["pos"]:])
    if not m:
        return [], {}
    open_pos = decl["pos"] + m.end() - 1
    close = match_paren(masked, open_pos)
    params_text = masked[open_pos + 1:close]
    names = []
    types = {}
    depth = 0
    start = 0
    parts = []
    for i, ch in enumerate(params_text):
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>" and depth > 0:
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(params_text[start:i])
            start = i + 1
    parts.append(params_text[start:])
    for part in parts:
        if ":" not in part:
            continue
        pname, _, ptype = part.partition(":")
        pname = pname.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", pname):
            continue
        names.append(pname)
        types[pname] = ptype.strip()
    return names, types


def split_args(text: str) -> list[str]:
    """Split a call's argument text at top-level commas."""
    parts = []
    depth = 0
    start = 0
    for i, ch in enumerate(text):
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>" and depth > 0:
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(text[start:i].strip())
            start = i + 1
    tail = text[start:].strip()
    if tail or parts:
        parts.append(tail)
    return parts


def find_call_sites(masked_files: dict[str, str], spans: dict, decls: dict,
                    depths: dict, fname: str,
                    def_file: str) -> list[dict]:
    """Find calls to a row constructor and the static/index that hosts them."""
    sites = []
    pat = re.compile(r"\b" + re.escape(fname) + r"\s*\(")
    for path, m in masked_files.items():
        for hit in pat.finditer(m):
            if in_spans(hit.start(), spans[path]):
                continue
            if re.search(r"\bfn\s+$", m[max(0, hit.start() - 24):hit.start()]):
                continue
            open_pos = m.find("(", hit.start())
            close = match_paren(m, open_pos)
            args = split_args(m[open_pos + 1:close])
            container = enclosing_decl(decls[path], hit.start(),
                                       depths[path][hit.start()])
            if container and container["kind"] in ("static", "const"):
                init = static_initializer(m, container)
                before = m[container["pos"]:hit.start()]
                # The array case is where the constructor is called per element.
                index = len(re.findall(r"\b" + re.escape(fname) + r"\s*\(",
                                       before))
                is_array = bool(re.search(
                    r"\[\s*(?:X509V3ExtMethod|\[)",
                    m[container["pos"]:m.find("=", container["pos"])]))
                row_name = (f"{container['name']}[{index}]" if is_array
                            else container["name"])
                instances = [{
                    "name": container["name"],
                    "file": path,
                    "line": line_of(m, container["pos"]),
                    "index": (index if is_array else None),
                }]
            else:
                row_name = f"callsite:{path}:{line_of(m, hit.start())}"
                instances = []
            sites.append({
                "row": row_name,
                "file": path,
                "line": line_of(m, hit.start()),
                "instances": instances,
                "args": args,
            })
    return sites


def parse_source(files: dict[str, str]) -> dict:
    """Parse all extension-method registrations from ``files``.

    Returns rows (one per struct literal / construction site), registrations
    (one per non-None slot) and per-file masks used by later call-site scans.
    """
    masked_files = {p: mask_rust(t) for p, t in files.items()}
    spans = {p: test_spans(m) for p, m in masked_files.items()}
    depths = {p: depth_map(m) for p, m in masked_files.items()}
    decls = {p: declarations(m, depths[p]) for p, m in masked_files.items()}

    # Helper-constructor instances: statics whose RHS calls a const fn.
    helper_instances: dict[str, list[dict]] = defaultdict(list)
    for path, m in masked_files.items():
        for d in decls[path]:
            if d["kind"] not in ("static", "const"):
                continue
            init = static_initializer(m, d)
            for call in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", init):
                helper = call.group(1)
                if helper in ("Some", "X509V3ExtMethod", "StandardExts"):
                    continue
                helper_instances[helper].append({
                    "name": d["name"],
                    "file": path,
                    "line": line_of(m, d["pos"]),
                })

    rows = []
    for path, m in masked_files.items():
        for lit in ROW_LITERAL_RE.finditer(m):
            pre = m[max(0, lit.start() - 24):lit.start()]
            if re.search(r"(?:struct|impl\s+[^;{]*\bfor)\s*$", pre):
                continue
            # A return type / type annotation is not a literal.
            if re.search(r"(?:->|:)\s*$", pre):
                continue
            brace = m.find("{", lit.start())
            end = match_brace(m, brace)
            body = m[brace + 1:end]
            depth = depths[path][lit.start()]
            container = enclosing_decl(decls[path], lit.start(), depth)
            is_test = in_spans(lit.start(), spans[path])

            if container and container["kind"] in ("static", "const"):
                siblings = [
                    x for x in rows
                    if x["container"] == container["name"]
                    and x["file"] == path
                ]
                row_name = container["name"]
                init = static_initializer(m, container)
                is_array = bool(
                    "[" in init.split("=", 1)[0]
                    or re.search(r"\[\s*X509V3ExtMethod",
                                 m[container["pos"]:lit.start()]))
                index = len(siblings) if is_array else None
                instances = [{
                    "name": container["name"],
                    "file": path,
                    "line": line_of(m, container["pos"]),
                    "index": index,
                }]
                if is_array:
                    row_name = f"{container['name']}[{index}]"
            elif container and container["kind"] == "fn":
                row_name = f"fn:{container['name']}"
                index = None
                instances = list(helper_instances.get(container["name"], []))
                if not instances:
                    # A row built inside a non-constructor function: record
                    # the function as the construction site; call sites are
                    # resolved later as direct references.
                    instances = []
            else:
                row_name = f"<anonymous>:{path}:{line_of(m, lit.start())}"
                index = None
                instances = []

            slots = {}
            for field, value in split_fields(body):
                if field not in GATED_SLOTS and field not in AUX_SLOT_FIELDS:
                    continue
                cb = callback_from_value(value)
                slots[field] = {
                    "value": value,
                    "callback": cb,
                    "gated": field in GATED_SLOTS,
                }

            rows.append({
                "row": row_name,
                "file": path,
                "line": line_of(m, lit.start()),
                "container": container["name"] if container else None,
                "container_kind": container["kind"] if container else "unknown",
                "instances": instances,
                "slots": slots,
                "test_only": is_test,
            })

    # Rows whose slot is installed through a constructor parameter: the
    # literal alone shows only the parameter name.  Resolve each call site and
    # emit one variant registration per call, carrying the caller's argument.
    fn_params = {}
    for path, m in masked_files.items():
        for d in decls[path]:
            if d["kind"] == "fn":
                fn_params[(path, d["name"])] = fn_params_for(m, d)

    expanded = []
    for row in rows:
        if row["container_kind"] != "fn":
            expanded.append(row)
            continue
        names, _types = fn_params.get(
            (row["file"], row["container"]), ([], {}))
        param_slots = {
            slot: info for slot, info in row["slots"].items()
            if info["callback"] in names
        }
        if not param_slots:
            expanded.append(row)
            continue
        sites = find_call_sites(masked_files, spans, decls, depths,
                                row["container"], row["file"])
        if not sites:
            row["constructor_params_unresolved"] = sorted(param_slots)
            expanded.append(row)
            continue
        for site in sites:
            slots = {}
            for slot, info in row["slots"].items():
                if slot in param_slots:
                    pname = info["callback"]
                    idx = names.index(pname)
                    arg = site["args"][idx] if idx < len(site["args"]) else ""
                    slots[slot] = {
                        "value": arg,
                        "callback": callback_from_value(arg),
                        "gated": info["gated"],
                    }
                else:
                    slots[slot] = dict(info)
            expanded.append({
                "row": site["row"],
                "file": site["file"],
                "line": site["line"],
                "container": row["container"],
                "container_kind": "helper-call",
                "constructor": row["container"],
                "instances": site["instances"],
                "slots": slots,
                "test_only": row["test_only"],
            })
    rows = expanded

    # Definition map (production only).
    definitions: dict[str, list[dict]] = defaultdict(list)
    for path, m in masked_files.items():
        for d in FN_DEF_RE.finditer(m):
            pos = d.start()
            if in_spans(pos, spans[path]):
                continue
            name = d.group(1)
            prefix = m[pos:d.start(1)]
            definitions[name].append({
                "file": path,
                "line": line_of(m, pos),
                "pos": pos,
                "unsafe": bool(re.search(r"\bunsafe\b", prefix)),
            })

    slot_prefix_definitions = []
    for path, m in masked_files.items():
        for d in SLOT_PREFIX_DEF_RE.finditer(m):
            if in_spans(d.start(), spans[path]):
                continue
            slot_prefix_definitions.append({
                "callback": d.group(1),
                "file": path,
                "line": line_of(m, d.start()),
                "unsafe": True,
            })
    slot_prefix_definitions.sort(
        key=lambda x: (x["file"], x["line"], x["callback"]))

    registrations = []
    for row in rows:
        for slot, info in sorted(row["slots"].items()):
            cb = info["callback"]
            if not cb:
                continue
            defs = definitions.get(cb, [])
            same_file = [d for d in defs if d["file"] == row["file"]]
            reg = {
                "row": row["row"],
                "row_file": row["file"],
                "row_line": row["line"],
                "row_instances": row["instances"],
                "slot": slot,
                "gated": info["gated"],
                "value": info["value"],
                "callback": cb,
                "callback_definitions": defs,
                "callback_definition": (
                    [x for x in same_file if x.get("unsafe")]
                    or [x for x in defs if x.get("unsafe")]
                    or same_file or defs or [None])[0],
                "source_defined": bool(defs),
                "unsafe_fn": any(x.get("unsafe") for x in defs),
                "test_only": row["test_only"],
            }
            registrations.append(reg)
    return {
        "files": masked_files,
        "spans": spans,
        "depths": depths,
        "decls": decls,
        "rows": rows,
        "registrations": registrations,
        "definitions": definitions,
        "slot_prefix_definitions": slot_prefix_definitions,
    }


# --------------------------------------------------------------------------
# Dispatcher and registry bindings
# --------------------------------------------------------------------------

DISPATCHER_SLOTS = {
    "X509V3_EXT_print": {"i2s", "i2r"},
    "X509V3_EXT_print_fp": {"i2s", "i2r"},
    "do_ext_nconf": {"v2i", "s2i", "r2i"},
    "X509V3_EXT_i2d": {"i2v", "i2d"},
    "X509V3_EXT_d2i": {"d2i"},
}
TABLE_DISPATCHERS = {
    "i2s": ["X509V3_EXT_print"],
    "i2r": ["X509V3_EXT_print", "X509V3_EXT_print_fp"],
    "s2i": ["do_ext_nconf"],
    "v2i": ["do_ext_nconf"],
    "r2i": ["do_ext_nconf"],
    "i2v": ["X509V3_EXT_i2d"],
    "it": ["X509V3_EXT_print", "X509V3_EXT_d2i"],
    "ext_free": ["X509V3_EXT_print", "X509V3_EXT_d2i"],
    "d2i": ["X509V3_EXT_d2i"],
    "i2d": ["X509V3_EXT_i2d"],
    "ext_new": ["X509V3_EXT_d2i"],
}


def parse_standard_exts(masked_files: dict[str, str]) -> list[dict]:
    entries = []
    for path, m in masked_files.items():
        for d in re.finditer(r"\bSTANDARD_EXTS\s*:\s*[^=]+=", m):
            start = d.end()
            idx = m.find("[", start)
            if idx < 0:
                continue
            # Bracket matching for the array literal.
            depth = 0
            close = len(m) - 1
            for i in range(idx, len(m)):
                if m[i] == "[":
                    depth += 1
                elif m[i] == "]":
                    depth -= 1
                    if depth == 0:
                        close = i
                        break
            body = m[idx + 1:close]
            for e in re.finditer(
                    r"&\s*crate::([A-Za-z0-9_:]+)(?:\[(\d+)\])?", body):
                item = e.group(1)
                modname = item.rsplit("::", 1)[0] if "::" in item else ""
                name = item.rsplit("::", 1)[-1]
                entries.append({
                    "module": modname,
                    "name": name,
                    "index": int(e.group(2)) if e.group(2) is not None else None,
                    "file": path,
                    "line": line_of(m, idx + 1 + e.start()),
                    "text": e.group(0),
                })
    return entries


def module_parts(path: str) -> tuple[str, ...]:
    p = path
    if p.startswith("src/"):
        p = p[len("src/"):]
    p = p.rsplit(".", 1)[0]
    parts = tuple(p.split("/"))
    if parts and parts[-1] == "mod":
        parts = parts[:-1]
    return parts


def table_entry_matches(entry: dict, instance: dict, path: str) -> bool:
    parts = module_parts(path)
    if not parts:
        return False
    modname = entry["module"]
    if not modname.endswith("::".join(parts)):
        return False
    if entry["name"] != instance["name"]:
        return False
    if entry["index"] is not None:
        return instance.get("index") == entry["index"]
    return instance.get("index") is None


def build_inventory(obligations: list[dict]) -> dict:
    by_identity = set()
    by_item = defaultdict(list)
    for o in obligations:
        if o.get("kind") != "UNSAFE_FN_DEF":
            continue
        if o.get("partition", "production") != "production":
            continue
        file = o.get("file")
        item = o.get("item")
        if not file or not item:
            continue
        by_identity.add((file, item))
        by_item[item].append({
            "id": o.get("id"),
            "file": file,
            "line": o.get("line"),
            "status": o.get("status"),
            "stable_id": o.get("stable_id"),
        })
    return {"identity": by_identity, "by_item": dict(by_item), "count": len(by_identity)}


# --------------------------------------------------------------------------
# Reachability classification
# --------------------------------------------------------------------------

def load_reachable(closure: dict) -> dict:
    rf = closure.get("graph", {}).get("closure", {}).get("reachable_functions", [])
    reachable_files = set(closure.get("graph", {}).get("reachable_files", []))
    names = set()
    qualified = set()
    symbols_by_name = defaultdict(list)
    for sym in rf:
        segs = demangle_segments(sym)
        if not segs:
            continue
        name = segs[-1]
        names.add(name)
        symbols_by_name[name].append(sym)
        if len(segs) >= 2:
            qualified.add((segs[-2], name))
    return {
        "files": reachable_files,
        "names": names,
        "qualified": qualified,
        "symbols_by_name": dict(symbols_by_name),
        "count": len(rf),
    }


def source_definitions_by_name(parsed: dict) -> dict:
    return {name: defs for name, defs in parsed["definitions"].items()}


def definition_key(name: str, d: dict) -> tuple[str, int, str]:
    """Per-definition identity: (file, definition line, item)."""
    return (d["file"], d["line"], name)


def definition_reachability(cb: str, d: dict, parsed: dict,
                            reach: dict) -> dict:
    """Membership evidence for one *definition*, never for a bare name."""
    defs = parsed["definitions"].get(cb, [])
    parts = module_parts(d["file"])
    stem = parts[-1] if parts else ""
    if (stem, cb) in reach["qualified"]:
        syms = reach["symbols_by_name"].get(cb, [])
        exact = [x for x in syms if cb in x]
        return {
            "reachable": True,
            "basis": BASIS_MODULE,
            "evidence": {"file": d["file"], "module": stem,
                         "symbols": exact[:3], "may_bound": True,
                         "proof": False},
        }
    # A name-only closure hit is accepted only when the source defines the
    # name once; with two definitions it cannot identify which one is meant.
    if len(defs) == 1 and cb in reach["names"]:
        return {
            "reachable": True,
            "basis": BASIS_UNIQUE,
            "evidence": {"file": defs[0]["file"],
                         "symbols": reach["symbols_by_name"].get(cb, [])[:3],
                         "may_bound": True, "proof": False},
        }
    if defs and cb in reach["names"]:
        return {
            "reachable": False,
            "basis": "ambiguous-name-match",
            "evidence": {"definitions": defs,
                         "symbols": reach["symbols_by_name"].get(cb, [])[:3]},
        }
    return {"reachable": False, "basis": "absent-from-reachable-functions"}


def resolve_callee_keys(name: str, caller_file: str,
                        parsed: dict) -> list[tuple[str, int, str]]:
    """Resolve a call to ``name`` to definition identities.

    Same-file resolution wins; otherwise a globally unique definition wins.
    An ambiguous cross-file call is not attributed to either definition.
    """
    defs = parsed["definitions"].get(name, [])
    if not defs:
        return []
    same = [d for d in defs if d["file"] == caller_file]
    if len(same) == 1:
        return [definition_key(name, same[0])]
    if len(defs) == 1:
        return [definition_key(name, defs[0])]
    return []


def enclosing_fn_decl_key(path: str, pos: int, parsed: dict):
    """Return (definition key, bare name) of the enclosing function."""
    decls = parsed["decls"][path]
    depth = parsed["depths"][path][pos]
    for d in reversed(decls):
        if d["pos"] < pos and d["depth"] <= depth and d["kind"] == "fn":
            line = line_of(parsed["files"][path], d["pos"])
            key = (path, line, d["name"])
            if key in parsed.get("definition_keys", set()):
                return key, d["name"]
            return None, d["name"]
    return None, None


def compute_callback_reach(parsed: dict, reach: dict
                           ) -> set[tuple[str, int, str]]:
    """Per-definition direct-call closure from closure-reachable seeds.

    Nodes are (file, definition line, item).  A helper may not appear in the
    closure's reachable-function set yet be called directly by a callback that
    is reachable-bound; this propagates such edges without collapsing two
    same-named definitions into one result.
    """
    universe = {d["callback"] for d in parsed.get("slot_prefix_definitions", [])}
    universe.update(r["callback"] for r in parsed["registrations"])
    nodes = {}
    for name in sorted(universe):
        for d in parsed["definitions"].get(name, []):
            nodes[definition_key(name, d)] = d
    parsed["definition_keys"] = set(nodes)

    edges: dict[tuple[str, int, str], set[tuple[str, int, str]]] = defaultdict(set)
    edge_sites: dict[tuple[str, int, str], dict] = defaultdict(dict)
    for key in sorted(nodes):
        d = nodes[key]
        name = key[2]
        path = d["file"]
        m = parsed["files"].get(path)
        if not m or "pos" not in d:
            continue
        brace = m.find("{", d["pos"])
        if brace < 0:
            continue
        end = match_brace(m, brace)
        body = m[brace:end]
        for other in universe:
            if other == name:
                continue
            hit = re.search(r"\b" + re.escape(other) + r"\s*\(", body)
            if not hit:
                continue
            site = f"{path}:{line_of(m, brace + hit.start())}"
            for target in resolve_callee_keys(other, path, parsed):
                edges[key].add(target)
                edge_sites[key].setdefault(target, site)

    seeds = {
        key for key, d in nodes.items()
        if definition_reachability(key[2], d, parsed, reach)["reachable"]
    }
    reachable = set(seeds)
    frontier = set(seeds)
    while frontier:
        nxt = set()
        for n in frontier:
            nxt.update(edges.get(n, ()))
        nxt -= reachable
        reachable |= nxt
        frontier = nxt
    parsed["callback_edges"] = {key: sorted(v) for key, v in edges.items()}
    parsed["callback_edge_sites"] = {
        key: dict(v) for key, v in edge_sites.items()
    }
    parsed["callback_reachable_keys"] = sorted(reachable)
    return reachable


def direct_calls(cb: str, parsed: dict, reach: dict,
                 reachable_keys: set | None = None,
                 target_key: tuple[str, int, str] | None = None) -> list[dict]:
    """Call sites that resolve to one specific definition of ``cb``."""
    calls = []
    pat = re.compile(r"\b" + re.escape(cb) + r"\s*\(")
    for path, m in parsed["files"].items():
        for hit in pat.finditer(m):
            if in_spans(hit.start(), parsed["spans"][path]):
                continue
            if re.search(r"\bfn\s+$", m[max(0, hit.start() - 24):hit.start()]):
                continue
            if target_key is not None:
                matches = resolve_callee_keys(cb, path, parsed)
                if target_key not in matches:
                    continue
            caller_key, caller_name = enclosing_fn_decl_key(
                path, hit.start(), parsed)
            if target_key is not None and caller_key == target_key:
                continue
            closure_hit = bool(caller_name and caller_name in reach["names"])
            bound_hit = bool(caller_key and reachable_keys
                             and caller_key in reachable_keys)
            calls.append({
                "file": path,
                "line": line_of(m, hit.start()),
                "site": f"{path}:{line_of(m, hit.start())}",
                "caller": caller_name,
                "caller_key": list(caller_key) if caller_key else None,
                "callee": cb,
                "callee_key": list(target_key) if target_key else None,
                "caller_reachable_closure_name": closure_hit,
                "caller_reachable_call_bound": bound_hit,
                "caller_reachable": closure_hit or bound_hit,
            })
    return calls


def is_file_reachable(path: str, reach: dict) -> bool:
    return path in reach["files"]


def row_references(cb: str, parsed: dict, reach: dict) -> list[dict]:
    """Find references to a callback outside its own definition/registration.

    Used to refuse PROVEN_EXCLUDED when an otherwise-unreachable row is
    address-taken from a reachable file.
    """
    refs = []
    pat = re.compile(r"\b" + re.escape(cb) + r"\b")
    for path, m in parsed["files"].items():
        for hit in pat.finditer(m):
            if in_spans(hit.start(), parsed["spans"][path]):
                continue
            refs.append({
                "file": path,
                "line": line_of(m, hit.start()),
                "file_reachable": is_file_reachable(path, reach),
            })
    return refs


# --------------------------------------------------------------------------
# Gate
# --------------------------------------------------------------------------

def stable_callback_key(reg: dict) -> str:
    d = reg.get("callback_definition") or {}
    return f"{d.get('file', reg['row_file'])}::{reg['callback']}"


def build_gate(root: str, closure: dict, parsed: dict, overrides: dict,
               reach: dict, standard_exts: list[dict]) -> dict:
    inventory = build_inventory(closure.get("obligations", []))
    cb_reach = compute_callback_reach(parsed, reach)
    dispatcher_reachable = {}
    for disp in sorted(DISPATCHER_SLOTS):
        dispatcher_reachable[disp] = disp in reach["names"]

    table_keys = set()
    for e in standard_exts:
        table_keys.add((e["module"], e["name"], e["index"]))
    table_by_name = defaultdict(list)
    for e in standard_exts:
        table_by_name[e["name"]].append(e)

    reg_results = []
    for reg in parsed["registrations"]:
        cb = reg["callback"]
        d = reg.get("callback_definition") or {}
        def_file = d.get("file", reg["row_file"])
        def_line = d.get("line", reg["row_line"])

        # METHOD-table binding: does any instance of this row appear in
        # STANDARD_EXTS?
        bindings = []
        instances = reg.get("row_instances") or []
        if not instances and reg["row"].split("[")[0] is not None:
            instances = [{
                "name": reg["row"].split("[")[0],
                "file": reg["row_file"],
                "line": reg["row_line"],
            }]
        for inst in instances:
            matched = [
                e for e in table_by_name.get(inst["name"], [])
                if table_entry_matches(e, inst, inst["file"])
            ]
            for e in matched:
                for disp in TABLE_DISPATCHERS.get(reg["slot"], []):
                    bindings.append({
                        "dispatcher": disp,
                        "dispatcher_reachable": dispatcher_reachable.get(disp, False),
                        "kind": "method-table",
                        "method_table": "STANDARD_EXTS",
                        "evidence": f"{e['file']}:{e['line']} {e['text']}",
                    })

        # Source-level direct callers, resolved to *this* definition.
        def_key = (def_file, def_line, cb)
        calls = direct_calls(cb, parsed, reach, cb_reach, def_key)
        reachable_calls = sorted(
            [c for c in calls if c["caller_reachable"]],
            key=lambda c: (not c["caller_reachable_closure_name"], c["site"]))
        reachr = definition_reachability(
            cb, {"file": def_file, "line": def_line}, parsed, reach)
        inv_hit = (def_file, cb) in inventory["identity"]

        # Classification (conservative).  basis is exactly one of the four
        # reachability bases for REACHABLE_BOUND; non-reachable records carry
        # an explicit non-reachability basis instead.
        classification = None
        assumption = ""
        basis = ""
        if reachable_calls:
            classification = REACHABLE
            basis = BASIS_EDGE
            evidence = {"witness": reachable_calls[0],
                        "witnesses": reachable_calls[:4]}
        elif reachr["reachable"]:
            classification = REACHABLE
            basis = reachr["basis"]
            evidence = reachr.get("evidence", {})
        elif any(b["dispatcher_reachable"] for b in bindings):
            classification = REACHABLE
            basis = BASIS_DISPATCH
            evidence = {
                "bindings": [b for b in bindings
                             if b["dispatcher_reachable"]][:4],
                "callback_symbol_in_reachable_set": False,
                "note": ("table binding only; no callback symbol was found in "
                         "the closure reachable set"),
            }
        elif def_key in cb_reach:
            classification = REACHABLE
            basis = BASIS_EDGE
            incoming = [
                (caller, site)
                for caller, callees in parsed.get("callback_edges", {}).items()
                if def_key in callees and caller in cb_reach
                for site in [parsed.get("callback_edge_sites", {})
                             .get(caller, {}).get(def_key)]
            ]
            witness = None
            if incoming:
                caller, site = incoming[0]
                witness = {
                    "caller": list(caller),
                    "callee": list(def_key),
                    "site": site,
                    "caller_reachable_call_bound": True,
                }
            evidence = {"witness": witness,
                        "note": "direct-call closure witness"}
        else:
            # PROVEN_EXCLUDED only under the full closed-world conditions.
            file_reach = is_file_reachable(def_file, reach)
            refs = row_references(cb, parsed, reach)
            reachable_refs = [r for r in refs if r["file_reachable"]]
            if (not file_reach and not reachr["reachable"]
                    and not reachable_calls and not bindings
                    and not reachable_refs):
                classification = EXCLUDED
                basis = "closed-world-ce-1"
                evidence = {
                    "file_reachable": False,
                    "reachable_functions_hit": False,
                    "method_table_binding": False,
                    "direct_reachable_caller": False,
                    "reachable_row_references": 0,
                    "definition_file": def_file,
                }
                assumption = CLOSED_WORLD_ASSUMPTION.format(
                    evidence=(f"defining file {def_file} is not in reachable_files; "
                              f"{cb} is not in reachable_functions; no STANDARD_EXTS "
                              f"row installs it; no reachable caller names it"))
            else:
                classification = UNRESOLVED
                basis = "unresolved"
                evidence = {
                    "file_reachable": file_reach,
                    "reachable_functions_basis": reachr["basis"],
                    "method_table_binding": bool(bindings),
                    "direct_calls": calls[:4],
                    "reachable_row_references": reachable_refs[:4],
                }

        # Test-only overrides (control harness only).
        key = stable_callback_key(reg)
        if key in overrides:
            ov = overrides[key]
            classification = ov.get("classification", classification)
            assumption = ov.get("assumption", assumption)
            basis = "control-override"
            evidence = {"override": ov}
            if classification == EXCLUDED and not assumption.strip():
                assumption = ""

        reg_results.append({
            "registration_id": f"{def_file}::{cb}::{reg['row']}::{reg['slot']}",
            "registration_kind": "slot-registration",
            "callback": cb,
            "callback_file": def_file,
            "callback_line": def_line,
            "definition_key": list(def_key),
            "slot": reg["slot"],
            "gated": reg["gated"],
            "row": reg["row"],
            "row_file": reg["row_file"],
            "row_line": reg["row_line"],
            "row_instances": instances,
            "source_defined": reg["source_defined"],
            "unsafe_fn": reg.get("unsafe_fn", False),
            "test_only": reg["test_only"],
            "in_inventory": inv_hit,
            "inventory_rows": inventory["by_item"].get(cb, []),
            "dispatcher_bindings": bindings,
            "dispatcher_binding_status": ("bound" if bindings else "none-found"),
            "direct_callers": calls[:8],
            "classification": classification,
            "basis": basis,
            "classification_basis": basis,
            "classification_evidence": evidence,
            "assumption": assumption,
            "override": key in overrides,
        })


    # Definition-coverage cross-check.  A callback can be invisible for a
    # second reason: it is named like a slot callback but no row installs it.
    # The 114-definition measurement in the B52 finding includes these, so
    # account for them explicitly rather than silently dropping them.
    registered_keys = {
        (r["callback_file"], r["callback"]) for r in reg_results
        if r["source_defined"]
    }
    for d in parsed.get("slot_prefix_definitions", []):
        key = (d["file"], d["callback"])
        if key in registered_keys:
            continue
        cb = d["callback"]
        def_file = d["file"]
        def_line = d["line"]
        def_key = (def_file, def_line, cb)
        calls = direct_calls(cb, parsed, reach, cb_reach, def_key)
        reachable_calls = sorted(
            [c for c in calls if c["caller_reachable"]],
            key=lambda c: (not c["caller_reachable_closure_name"], c["site"]))
        reachr = definition_reachability(
            cb, {"file": def_file, "line": def_line}, parsed, reach)
        inv_hit = (def_file, cb) in inventory["identity"]
        file_reach = is_file_reachable(def_file, reach)
        assumption = ""
        if reachable_calls:
            classification = REACHABLE
            basis = BASIS_EDGE
            evidence = {"definition_only": True,
                        "witness": reachable_calls[0],
                        "witnesses": reachable_calls[:4]}
        elif reachr["reachable"]:
            classification = REACHABLE
            basis = reachr["basis"]
            evidence = {"definition_only": True,
                        "reachable": reachr.get("evidence", {})}
        elif def_key in cb_reach:
            classification = REACHABLE
            basis = BASIS_EDGE
            incoming = [
                (caller, site)
                for caller, callees in parsed.get("callback_edges", {}).items()
                if def_key in callees and caller in cb_reach
                for site in [parsed.get("callback_edge_sites", {})
                             .get(caller, {}).get(def_key)]
            ]
            witness = None
            if incoming:
                caller, site = incoming[0]
                witness = {
                    "caller": list(caller),
                    "callee": list(def_key),
                    "site": site,
                    "caller_reachable_call_bound": True,
                }
            evidence = {"definition_only": True, "witness": witness,
                        "note": "direct-call closure witness"}
        elif not file_reach:
            classification = EXCLUDED
            basis = "closed-world-ce-1-definition-only"
            evidence = {
                "definition_only": True,
                "file_reachable": False,
                "reachable_functions_hit": False,
                "direct_reachable_caller": False,
            }
            assumption = CLOSED_WORLD_ASSUMPTION.format(
                evidence=(f"unregistered helper {cb}: defining file {def_file} "
                          f"is not in reachable_files; no reachable caller names it"))
        else:
            classification = UNRESOLVED
            basis = "unresolved"
            evidence = {
                "definition_only": True,
                "file_reachable": file_reach,
                "reachable_functions_basis": reachr["basis"],
                "direct_calls": calls[:4],
            }
        if classification != EXCLUDED:
            assumption = ""
        reg = {"callback": cb,
               "callback_definition": {"file": def_file, "line": def_line},
               "row_file": def_file}
        okey = stable_callback_key(reg)
        if okey in overrides:
            ov = overrides[okey]
            classification = ov.get("classification", classification)
            assumption = ov.get("assumption", assumption)
            basis = "control-override"
            evidence = {"override": ov}
            if classification == EXCLUDED and not assumption.strip():
                assumption = ""
        reg_results.append({
            "registration_id": f"{def_file}::{cb}::<definition-only>",
            "registration_kind": "definition-only",
            "callback": cb,
            "callback_file": def_file,
            "callback_line": def_line,
            "definition_key": list(def_key),
            "slot": cb.split("_", 1)[0],
            "gated": True,
            "row": None,
            "row_file": def_file,
            "row_line": def_line,
            "row_instances": [],
            "source_defined": True,
            "unsafe_fn": True,
            "test_only": False,
            "in_inventory": inv_hit,
            "inventory_rows": inventory["by_item"].get(cb, []),
            "dispatcher_bindings": [],
            "direct_callers": calls[:8],
            "classification": classification,
            "basis": basis,
            "classification_basis": basis,
            "classification_evidence": evidence,
            "assumption": assumption,
            "override": okey in overrides,
        })

    # Aggregate to unique source-defined gated callbacks.
    callbacks = {}
    for r in reg_results:
        if (not r["gated"] or not r["source_defined"]
                or not r["unsafe_fn"] or r["test_only"]):
            continue
        key = (r["callback_file"], r["callback_line"], r["callback"])
        agg = callbacks.get(key)
        if agg is None:
            agg = {
                "callback": r["callback"],
                "file": r["callback_file"],
                "line": r["callback_line"],
                "in_inventory": r["in_inventory"],
                "inventory_rows": r["inventory_rows"],
                "classifications": [],
                "bases": [],
                "registrations": [],
                "registration_kinds": [],
            }
            callbacks[key] = agg
        agg["classifications"].append(r["classification"])
        agg["bases"].append(r["basis"])
        agg["registration_kinds"].append(r["registration_kind"])
        agg["registrations"].append({
            "row": r["row"],
            "slot": r["slot"],
            "registration_id": r["registration_id"],
            "registration_kind": r["registration_kind"],
        })

    def aggregate_class(cs: list[str]) -> str:
        if REACHABLE in cs:
            return REACHABLE
        if UNRESOLVED in cs:
            return UNRESOLVED
        if EXCLUDED in cs:
            return EXCLUDED
        return UNRESOLVED

    missing = []
    excluded_without_assumption = []
    unresolved = []
    in_inventory = []
    for key in sorted(callbacks):
        c = callbacks[key]
        cls = aggregate_class(c["classifications"])
        assumptions = [
            r["assumption"] for r in reg_results
            if (r["callback_file"], r["callback_line"], r["callback"]) == key
            and r["classification"] == EXCLUDED and r["assumption"].strip()
        ]
        c["classification"] = cls
        c["basis"] = next((b for b in BASIS_ORDER if b in c["bases"]),
                          c["bases"][0] if c["bases"] else "unresolved")
        c["assumptions"] = sorted(set(assumptions))
        if c["in_inventory"]:
            in_inventory.append(c)
            continue
        if cls == EXCLUDED:
            if not c["assumptions"]:
                excluded_without_assumption.append(c)
            continue
        if cls == UNRESOLVED:
            unresolved.append(c)
        missing.append(c)

    # Ensure excluded-without-assumption is a failure even if also missing.
    missing_ids = {(c["file"], c["line"], c["callback"]) for c in missing}
    for c in excluded_without_assumption:
        if (c["file"], c["line"], c["callback"]) not in missing_ids:
            missing.append(c)

    missing.sort(key=lambda c: (c["file"], c["line"] or 0, c["callback"]))
    unresolved.sort(key=lambda c: (c["file"], c["line"] or 0, c["callback"]))
    excluded_without_assumption.sort(
        key=lambda c: (c["file"], c["line"] or 0, c["callback"]))
    in_inventory.sort(key=lambda c: (c["file"], c["line"] or 0, c["callback"]))

    counts = Counter(c["classification"] for c in callbacks.values())
    reg_counts = Counter(r["classification"] for r in reg_results
                         if r["gated"] and r["source_defined"]
                         and r["unsafe_fn"] and not r["test_only"])
    basis_counts = Counter(
        r["basis"] for r in reg_results
        if r["gated"] and r["source_defined"] and r["unsafe_fn"]
        and not r["test_only"] and r["basis"] in BASIS_VOCABULARY)
    callback_basis_counts = Counter(
        c["basis"] for c in callbacks.values() if c["basis"] in BASIS_VOCABULARY)

    enrolment = []
    for c in missing:
        if c["classification"] != REACHABLE:
            continue
        enrolment.append({
            "file": c["file"],
            "line": c["line"],
            "kind": "UNSAFE_FN_DEF",
            "item": c["callback"],
            "partition": "production",
            "reason": ("extension-slot callback is REACHABLE_BOUND from the "
                       "pinned consumer family and absent from the obligation "
                       "queue (neither DISCHARGED nor BLOCKED); enrolled BLOCKED "
                       "pending site-scoped adjudication "
                       "(callback-enumeration-gate)"),
            "requested_status": "BLOCKED",
            "queue_status": "absent",
            "id": f"V1:{c['file']}:{c['line']}:UNSAFE_FN_DEF",
            "stable_id": f"{c['file']}::UNSAFE_FN_DEF::{c['callback']}",
            "mechanism": "X509_VERIFY_POLICY",
            "registrations": c["registrations"],
            "registration_kinds": sorted(set(c["registration_kinds"])),
            "gate_provenance": {
                "gate": "callback-enumeration-completeness",
                "classification": c["classification"],
            },
        })

    # Inventory accounting: every inventoried callback the source enumeration
    # sees is accounted for, and a slot-named unsafe definition that the
    # inventory carries may not disappear from the enumeration.
    gate_keys = {(c["file"], c["callback"]) for c in callbacks.values()}
    inventory_accounted = [
        c for c in callbacks.values() if c["in_inventory"]
    ]
    inventory_unaccounted = [
        c for c in inventory_accounted
        if (c["file"], c["line"], c["callback"])
        in {(x["file"], x["line"], x["callback"]) for x in missing}
    ]
    extern_slot_names = {
        d["callback"] for d in parsed.get("slot_prefix_definitions", [])
    }
    slot_prefix_inventory = {
        (f, i) for (f, i) in inventory["identity"]
        if re.match(r"^(?:s2i|i2s|i2r|i2v|r2i|v2i)_", i)
        and i in extern_slot_names
    }
    slot_prefix_not_seen = sorted(slot_prefix_inventory - gate_keys)
    # A slot-prefixed inventory item with no source definition at all is a lost
    # callback (not an internal `unsafe fn` helper, which is still defined).
    slot_prefix_lost_definition = sorted(
        (f, i) for (f, i) in inventory["identity"]
        if re.match(r"^(?:s2i|i2s|i2r|i2v|r2i|v2i)_", i)
        and i not in parsed["definitions"]
    )
    inventory_accounting = {
        "inventory_callbacks_accounted": len(inventory_accounted),
        "unaccounted": [
            f'{c["file"]}::{c["line"]}::{c["callback"]}'
            for c in inventory_unaccounted
        ],
        "slot_prefix_inventory_not_seen": [
            f"{f}::{i}" for f, i in slot_prefix_not_seen
        ],
        "slot_prefix_inventory_without_source_definition": [
            f"{f}::{i}" for f, i in slot_prefix_lost_definition
        ],
        "unit": ("distinct inventory callbacks accounted for by the source "
                 "enumeration; entries are file-qualified"),
    }

    pass_gate = (not missing and not unresolved
                 and not excluded_without_assumption
                 and not inventory_unaccounted
                 and not slot_prefix_not_seen
                 and not slot_prefix_lost_definition)
    return {
        "registration_results": reg_results,
        "callbacks": [callbacks[k] for k in sorted(callbacks)],
        "missing": missing,
        "unresolved": unresolved,
        "excluded_without_assumption": excluded_without_assumption,
        "in_inventory": in_inventory,
        "counts": {
            REACHABLE: counts.get(REACHABLE, 0),
            EXCLUDED: counts.get(EXCLUDED, 0),
            UNRESOLVED: counts.get(UNRESOLVED, 0),
        },
        "registration_counts": {
            REACHABLE: reg_counts.get(REACHABLE, 0),
            EXCLUDED: reg_counts.get(EXCLUDED, 0),
            UNRESOLVED: reg_counts.get(UNRESOLVED, 0),
        },
        "basis_counts": {b: basis_counts.get(b, 0) for b in BASIS_ORDER},
        "callback_basis_counts": {
            b: callback_basis_counts.get(b, 0) for b in BASIS_ORDER
        },
        "enrolment": enrolment,
        "missing_entry_count": len(missing),
        "missing_distinct_name_count": len({c["callback"] for c in missing}),
        "missing_count_unit": ("entries are per file-qualified callback "
                               "definition; distinct_names counts callback names"),
        "inventory_accounting": inventory_accounting,
        "pass": pass_gate,
        "exit_code": 0 if pass_gate else 1,
    }


# --------------------------------------------------------------------------
# I/O
# --------------------------------------------------------------------------

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_sources(root: str) -> dict[str, str]:
    files = {}
    src = os.path.join(root, "src")
    for dirpath, _dirnames, filenames in os.walk(src):
        for name in sorted(filenames):
            if not name.endswith(".rs"):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            with open(full, "r", encoding="utf-8", errors="replace") as f:
                files[rel] = f.read()
    return dict(sorted(files.items()))


def git_head(root: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", root, "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True)
        return out.stdout.strip()
    except Exception:
        return None


def src_tree_unchanged(root: str, base_commit: str | None) -> bool | None:
    if not base_commit:
        return None
    try:
        out = subprocess.run(
            ["git", "-C", root, "diff", "--quiet", base_commit, "--", "src"],
            capture_output=True)
        return out.returncode == 0
    except Exception:
        return None


def write_json(path: str, payload: dict) -> bytes:
    data = json.dumps(payload, indent=1, sort_keys=True,
                      ensure_ascii=False).encode("utf-8") + b"\n"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return data


def write_manifest(out_dir: str, name: str, manifest: dict) -> tuple[bytes, dict]:
    """Write the manifest, splitting by slot when it exceeds the context budget.

    Returns (index_bytes, split_info).  The index is always ``name``; when
    split, it names every part with a sha256 so a reader can verify the parts
    without loading the whole set.
    """
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, name)
    full = json.dumps(manifest, indent=1, sort_keys=True,
                      ensure_ascii=False).encode("utf-8") + b"\n"
    if len(full) <= 200_000:
        with open(path, "wb") as f:
            f.write(full)
        return full, {"split": False, "bytes": len(full)}

    stem = name[:-5] if name.endswith(".json") else name
    part_dir = os.path.join(out_dir, stem)
    os.makedirs(part_dir, exist_ok=True)
    parts = {}

    def write_part(part_name: str, payload: dict, count: int) -> None:
        data = (json.dumps(payload, indent=1, sort_keys=True,
                           ensure_ascii=False).encode("utf-8") + b"\n")
        rel = os.path.join(os.path.basename(part_dir), part_name)
        with open(os.path.join(part_dir, part_name), "wb") as f:
            f.write(data)
        parts[part_name] = {
            "path": rel,
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "count": count,
        }

    by_slot = defaultdict(list)
    for r in manifest["registrations"]:
        by_slot[r["slot"]].append(r)
    for slot in sorted(by_slot):
        rows = sorted(by_slot[slot], key=lambda r: (
            r["row_file"], r["row_line"] or 0, r["callback"], r["slot"]))
        # A slot part may itself exceed the context budget; chunk
        # deterministically at ~150 KB while preserving order.
        chunks = []
        current = []
        for row in rows:
            current.append(row)
            probe = {
                "schema": manifest["schema"] + "/part",
                "part": "registrations",
                "slot": slot,
                "registrations": current,
            }
            if len(json.dumps(probe, indent=1, sort_keys=True,
                              ensure_ascii=False).encode("utf-8")) > 150_000:
                current.pop()
                if current:
                    chunks.append(current)
                current = [row]
        if current:
            chunks.append(current)
        for index, chunk in enumerate(chunks or [[]]):
            suffix = "" if len(chunks) <= 1 else f".part{index + 1}"
            write_part(f"registrations.{slot}{suffix}.json", {
                "schema": manifest["schema"] + "/part",
                "part": "registrations",
                "slot": slot,
                "chunk": index,
                "chunks": len(chunks),
                "registrations": chunk,
            }, len(chunk))
    write_part("callbacks.json", {
        "schema": manifest["schema"] + "/part",
        "part": "callbacks",
        "callbacks": manifest["callbacks"],
    }, len(manifest["callbacks"]))
    # Remove stale parts from an earlier run so the index is the only truth.
    for existing in sorted(os.listdir(part_dir)):
        if existing.endswith(".json") and existing not in parts:
            os.remove(os.path.join(part_dir, existing))

    index = {k: v for k, v in manifest.items()
             if k not in ("registrations", "callbacks")}
    index["split"] = True
    index["parts"] = parts
    index["registration_count"] = len(manifest["registrations"])
    index["callback_count"] = len(manifest["callbacks"])
    data = (json.dumps(index, indent=1, sort_keys=True,
                       ensure_ascii=False).encode("utf-8") + b"\n")
    with open(path, "wb") as f:
        f.write(data)
    return data, {"split": True, "bytes": len(data), "parts": parts}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=".", help="repository or fixture root")
    ap.add_argument("--closure", default="evidence/closure-ssh-b52-applied.json")
    ap.add_argument("--inventory", default=None,
                    help="closure-shaped JSON used for the inventory "
                         "(control fixture); defaults to --closure")
    ap.add_argument("--out-dir",
                    default="forensics/memory-safety/campaign/safe-c33/atlas-refresh")
    ap.add_argument("--manifest-name", default="callback-registration-manifest.json")
    ap.add_argument("--report-name", default="callback-gate-report.json")
    ap.add_argument("--enrolment-name", default="callback-enrolment-blockers.json")
    ap.add_argument("--overrides", default=None,
                    help="test-only classification overrides (control harness)")
    ap.add_argument("--allow-source-drift", action="store_true",
                    help="do not fail on src/ drift vs the inventory source head")
    args = ap.parse_args(argv)

    root = os.path.abspath(args.root)
    closure_path = args.closure
    if not os.path.isabs(closure_path):
        closure_path = os.path.join(os.getcwd(), closure_path)
    with open(closure_path, "r", encoding="utf-8") as f:
        closure = json.load(f)

    inv_path = args.inventory or closure_path
    with open(inv_path, "r", encoding="utf-8") as f:
        inventory_doc = json.load(f)

    overrides = {}
    overrides_sha = None
    if args.overrides:
        with open(args.overrides, "r", encoding="utf-8") as f:
            overrides = json.load(f)
        overrides_sha = sha256_file(args.overrides)

    files = read_sources(root)
    parsed = parse_source(files)
    reach = load_reachable(closure)
    standard_exts = parse_standard_exts(parsed["files"])
    gate = build_gate(root, inventory_doc, parsed, overrides, reach,
                      standard_exts)

    source_head = git_head(args.root)
    inv_head = (closure.get("source_identity", {})
                .get("inventory_source_head"))
    drift = src_tree_unchanged(args.root, inv_head)
    if drift is False and not args.allow_source_drift:
        gate["pass"] = False
        gate["exit_code"] = 1

    gated_regs = [r for r in gate["registration_results"]
                  if r["gated"] and r["source_defined"]
                  and r["unsafe_fn"] and not r["test_only"]]
    slot_regs = [r for r in gated_regs
                 if r["registration_kind"] == "slot-registration"]
    def_only = [r for r in gated_regs
                if r["registration_kind"] == "definition-only"]
    aux_regs = [r for r in gate["registration_results"]
                if r["source_defined"] and r["unsafe_fn"] and not r["test_only"]
                and not r["gated"] and r["slot"] in AUX_SLOT_FIELDS]
    safe_extern = [r for r in gate["registration_results"]
                   if r["gated"] and r["source_defined"] and not r["unsafe_fn"]
                   and not r["test_only"]]
    imported = [r for r in gate["registration_results"]
                if r["gated"] and not r["source_defined"] and not r["test_only"]]
    test_only = [r for r in gate["registration_results"] if r["test_only"]]

    slot_by_slot = Counter(r["slot"] for r in slot_regs)
    def_only_by_slot = Counter(r["slot"] for r in def_only)
    aux_by_slot = Counter(r["slot"] for r in aux_regs)
    distinct_slot = sorted({(r["callback_file"], r["callback_line"], r["callback"])
                            for r in slot_regs})
    distinct_def_only = sorted({(r["callback_file"], r["callback_line"],
                                 r["callback"]) for r in def_only})
    distinct_aux = sorted({(r["callback_file"], r["callback_line"],
                            r["callback"]) for r in aux_regs})
    distinct_gated = sorted(set(distinct_slot) | set(distinct_def_only))
    distinct_imported = sorted({(r["row_file"], r["callback"]) for r in imported})
    distinct_safe = sorted({(r["row_file"], r["callback"]) for r in safe_extern})

    inventory_matched = [c for c in gate["callbacks"] if c["in_inventory"]]
    false_missing = [
        c for c in gate["missing"]
        if (c["file"], c["line"], c["callback"]) in {
            (x["file"], x["line"], x["callback"]) for x in inventory_matched}
    ]

    inv = build_inventory(inventory_doc.get("obligations", []))
    prefix_keys = {(d["file"], d["callback"])
                   for d in parsed.get("slot_prefix_definitions", [])}
    prefix_names = {cb for _f, cb in prefix_keys}
    missing_keys = {(c["file"], c["callback"]) for c in gate["missing"]}
    registered_keys = {(r["callback_file"], r["callback"]) for r in slot_regs}
    prefix_missing = sorted(prefix_keys & missing_keys)
    prefix_matched = sorted(k for k in prefix_keys if k in inv["identity"])
    prefix_unregistered = sorted(prefix_keys - registered_keys)
    registered_without_prefix = sorted(
        cb for _f, _line, cb in distinct_slot
        if not re.match(r"^(?:s2i|i2s|i2r|i2v|r2i|v2i)_", cb))
    ext_free_missing = sorted(
        (c["file"], c["callback"]) for c in gate["missing"]
        if any(x.get("slot") == "ext_free" for x in c["registrations"])
        and not re.match(r"^(?:s2i|i2s|i2r|i2v|r2i|v2i)_", c["callback"]))

    reconciliation = {
        "prefix_definitions_total": len(parsed.get("slot_prefix_definitions", [])),
        "prefix_definitions_distinct": len(prefix_names),
        "prefix_definitions_in_queue_inventory": len(prefix_matched),
        "prefix_definitions_absent_from_queue": len(prefix_missing),
        "prefix_definitions_registered_in_a_slot": len(prefix_keys & registered_keys),
        "prefix_definitions_not_registered_in_any_slot": len(prefix_unregistered),
        "prefix_definitions_absent_and_registered": len(
            prefix_keys & registered_keys & missing_keys),
        "prefix_definitions_absent_and_definition_only": len(
            prefix_keys & missing_keys - registered_keys),
        "registered_callbacks_with_non_prefix_names": len(registered_without_prefix),
        "ext_free_callbacks_absent_from_queue": len(ext_free_missing),
        "gate_missing_distinct_definitions": len({
            (c["file"], c["line"], c["callback"]) for c in gate["missing"]}),
        "gate_missing_distinct_names": len({
            c["callback"] for c in gate["missing"]}),
        "gate_missing_entries": len(gate["missing"]),
        "note": ("name-prefix matching is not the enumeration; these counts "
                 "reconcile the six-prefix definition census with the "
                 "slot-driven manifest and explain why the gate's missing set "
                 "differs from a raw prefix grep"),
    }

    source_identity = {
        "repository_head": source_head,
        "inventory_source_head": inv_head,
        "src_tree_unchanged_vs_inventory_head": drift,
        "source_mode": ("worktree" if os.path.abspath(root) == os.path.abspath(
            os.getcwd()) else "fixture-root"),
        "instrument": {
            "path": os.path.relpath(os.path.abspath(__file__), os.getcwd()),
            "sha256": sha256_file(os.path.abspath(__file__)),
        },
    }

    manifest = {
        "schema": "openssl-rs/campaign/safe-c33/callback-registration-manifest/v1",
        "source_identity": source_identity,
        "closure": {
            "path": os.path.relpath(closure_path, os.getcwd()),
            "sha256": sha256_file(closure_path),
            "family": closure.get("family"),
        },
        "inventory": {
            "path": os.path.relpath(inv_path, os.getcwd()),
            "sha256": sha256_file(inv_path),
            "obligation_count": len(inventory_doc.get("obligations", [])),
            "unsafe_fn_identity_count": len(
                build_inventory(inventory_doc.get("obligations", []))["identity"]),
        },
        "parser": {
            "slot_fields": list(SLOT_FIELDS),
            "aux_slot_fields": list(AUX_SLOT_FIELDS),
            "gated_slots": sorted(GATED_SLOTS),
            "method": ("syntactic slot-field scan of X509V3ExtMethod literals; "
                       "test-only registrations excluded; callbacks are matched "
                       "by assigned identifier, never by name prefix"),
            "name_prefix_matching": False,
        },
        "registrations": sorted(
            gate["registration_results"],
            key=lambda r: (r["row_file"], r["row_line"], r["slot"], r["callback"])),
        "rows": [
            {
                "row": row["row"],
                "file": row["file"],
                "line": row["line"],
                "container_kind": row.get("container_kind"),
                "constructor": row.get("constructor"),
                "instances": row.get("instances", []),
                "slots": row["slots"],
                "test_only": row["test_only"],
            }
            for row in parsed["rows"]
        ],
        "callbacks": gate["callbacks"],
        "labels": {
            "reachable": REACHABLE,
            "reachable_is_proof": False,
            "reachable_bases": list(BASIS_ORDER),
            "non_reachable_bases": ["closed-world-ce-1", "unresolved"],
        },
        "basis_counts": gate["basis_counts"],
        "callback_basis_counts": gate["callback_basis_counts"],
        "missing_counts": {
            "entries": gate["missing_entry_count"],
            "distinct_names": gate["missing_distinct_name_count"],
            "unit": gate["missing_count_unit"],
        },
        "inventory_accounting": gate["inventory_accounting"],
        "reconciliation": reconciliation,
        "summary": {
            "rows_parsed": len(parsed["rows"]),
            "registrations_total": len(gate["registration_results"]),
            "slot_registrations_gated": len(slot_regs),
            "definition_only_callbacks_gated": len(def_only),
            "slot_registrations_by_slot": dict(sorted(slot_by_slot.items())),
            "definition_only_by_slot": dict(sorted(def_only_by_slot.items())),
            "aux_registrations_recorded_not_gated": len(aux_regs),
            "aux_registrations_by_slot": dict(sorted(aux_by_slot.items())),
            "distinct_slot_registered_callbacks": len(distinct_slot),
            "distinct_definition_only_callbacks": len(distinct_def_only),
            "distinct_gated_callbacks": len(distinct_gated),
            "distinct_aux_callbacks": len(distinct_aux),
            "safe_extern_callbacks_not_gated": len(distinct_safe),
            "imported_or_macro_callbacks_not_gated": len(distinct_imported),
            "test_only_registrations_excluded": len(test_only),
            "standard_exts_entries": len(standard_exts),
            "slot_prefix_definitions": len(parsed.get("slot_prefix_definitions", [])),
            "gate_scope_note": ("gated = six extension slots + ext_free, "
                                "source-defined `unsafe fn`, production only; "
                                "safe extern item functions and imported/macro "
                                "targets are recorded but are not census-eligible"),
        },
        "non_claims": NON_CLAIMS,
    }

    manifest_data, manifest_split = write_manifest(
        args.out_dir, args.manifest_name, manifest)

    report = {
        "schema": "openssl-rs/campaign/safe-c33/callback-gate-report/v1",
        "gate": "callback-enumeration-completeness",
        "source_identity": source_identity,
        "closure": manifest["closure"],
        "inventory": manifest["inventory"],
        "manifest": {
            "path": os.path.relpath(
                os.path.join(args.out_dir, args.manifest_name), os.getcwd()),
            "sha256": hashlib.sha256(manifest_data).hexdigest(),
            **manifest_split,
        },
        "overrides": {
            "present": bool(overrides),
            "sha256": overrides_sha,
            "test_only": bool(overrides),
        },
        "summary": manifest["summary"],
        "reconciliation": reconciliation,
        "classification": gate["counts"],
        "classification_labels": {
            "reachable": REACHABLE,
            "reachable_is_proof": False,
            "reachable_bases": list(BASIS_ORDER),
        },
        "registration_classification": gate["registration_counts"],
        "basis_counts": gate["basis_counts"],
        "callback_basis_counts": gate["callback_basis_counts"],
        "inventory_matched_callbacks": len(inventory_matched),
        "inventory_accounting": gate["inventory_accounting"],
        "missing_entry_count": gate["missing_entry_count"],
        "missing_distinct_name_count": gate["missing_distinct_name_count"],
        "missing_count_unit": gate["missing_count_unit"],
        "missing_count": gate["missing_entry_count"],
        "missing": gate["missing"],
        "unresolved_count": len(gate["unresolved"]),
        "unresolved": gate["unresolved"],
        "excluded_without_assumption_count": len(
            gate["excluded_without_assumption"]),
        "excluded_without_assumption": gate["excluded_without_assumption"],
        "false_positive_check": {
            "inventory_matched_reported_missing": len(false_missing),
            "names": [f'{c["file"]}::{c["callback"]}' for c in false_missing],
        },
        "enrolment": {
            "count": len(gate["enrolment"]),
            "path": os.path.relpath(
                os.path.join(args.out_dir, args.enrolment_name), os.getcwd()),
        },
        "pass": gate["pass"],
        "exit_code": gate["exit_code"],
        "non_claims": NON_CLAIMS,
    }
    write_json(os.path.join(args.out_dir, args.report_name), report)

    enrolment_doc = {
        "schema": "openssl-rs/campaign/safe-c33/callback-enrolment/v1",
        "source_identity": source_identity,
        "closure": manifest["closure"],
        "plug_in": {
            "target": "contracts.blockers in the V1 census consumed by "
                      "forensics/tools/consumer_closure.py:obligation_candidates",
            "shape": "{file,line,kind,item,partition,reason}",
            "requested_status": "BLOCKED",
            "note": ("enrol these records before the next census/closure run; "
                     "do not hand-edit the applied ledger"),
        },
        "count": len(gate["enrolment"]),
        "distinct_name_count": len({b["item"] for b in gate["enrolment"]}),
        "count_unit": ("entries are per file-qualified callback definition; "
                       "distinct_name_count counts callback names"),
        "blockers": gate["enrolment"],
    }
    write_json(os.path.join(args.out_dir, args.enrolment_name), enrolment_doc)

    print(json.dumps({
        "pass": gate["pass"],
        "exit_code": gate["exit_code"],
        "registrations": manifest["summary"],
        "classification": gate["counts"],
        "missing_entry_count": gate["missing_entry_count"],
        "missing_distinct_name_count": gate["missing_distinct_name_count"],
        "unresolved_count": len(gate["unresolved"]),
        "enrolment_count": len(gate["enrolment"]),
        "manifest_sha256": hashlib.sha256(manifest_data).hexdigest(),
        "report_sha256": hashlib.sha256(
            json.dumps(report, indent=1, sort_keys=True,
                       ensure_ascii=False).encode() + b"\n").hexdigest(),
    }, indent=1, sort_keys=True))
    return gate["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
