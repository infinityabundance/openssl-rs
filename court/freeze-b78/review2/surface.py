#!/usr/bin/env python3
"""Measure the safe-interface surface of the frozen candidate (review only).

Source-level, lexical. Reuses the campaign's comment/literal stripper so byte
offsets and line numbers are preserved. Not a Rust parser: the limitations are
printed in the JSON (`method.limitations`).

Run from the repository root:
  python3 court/freeze-b78/review2/surface.py > court/freeze-b78/review2/surface.json
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(".").resolve()
sys.path.insert(0, str(ROOT / "forensics/memory-safety/campaign/safe-c33"))
import atlas_refresh as atlas  # noqa: E402

RE_FN = re.compile(r"\bfn\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)")
RE_MOD_BLOCK = re.compile(r"\bmod\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\s*\{")
RE_TYPE = re.compile(r"\b(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum|union|type)\s+([A-Za-z_][A-Za-z0-9_]*)")
RE_IMPL = re.compile(r"\bimpl\b")
RE_EXTERN_BLOCK = re.compile(r'\bextern\s*(?:"[^"]*"\s*)?\{')
RE_ATTR_START = re.compile(r"#[!]?\[")
RE_CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:::\s*<[^;{}()]*>\s*)?\(")
RE_METHOD = re.compile(r"\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(")
RE_MACRO = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*!\s*[\(\[\{]")

QUAL_WORDS = {"pub", "unsafe", "const", "async", "extern", "default", "auto"}


def blanked_neighbour(text: str, pos: int) -> bool:
    """True when pos sits in a run of spaces produced by stripping a literal."""
    i = pos
    while i > 0 and text[i - 1] == " ":
        i -= 1
    # blanked literal regions are preceded by an `r`/`b`/`c` or `"` in the original;
    # here we only need "there is a space run", which `_qualifier_start` handles.
    return i != pos


def qualifier_start(text: str, fn_pos: int) -> int:
    """Walk backwards over item qualifiers (`pub`, `unsafe`, `const`, `extern`, ...)."""
    i = fn_pos
    while True:
        j = i
        while j > 0 and text[j - 1] in " \t\r\n":
            j -= 1
        if j == 0:
            return 0
        # balanced paren group: pub(crate) / pub(in path)
        if text[j - 1] == ")":
            depth = 1
            k = j - 1
            while k > 0 and depth:
                k -= 1
                if text[k] == ")":
                    depth += 1
                elif text[k] == "(":
                    depth -= 1
            m = k
            while m > 0 and (text[m - 1].isalnum() or text[m - 1] == "_"):
                m -= 1
            word = text[m:k]
            if word in QUAL_WORDS:
                i = m
                continue
            return j
        m = j
        while m > 0 and (text[m - 1].isalnum() or text[m - 1] == "_" or text[m - 1] == "#"):
            m -= 1
        word = text[m:j]
        if word in QUAL_WORDS:
            i = m
            continue
        return j


def parse_vis(header: str) -> str:
    m = re.search(r"\bpub\s*\(([^)]*)\)", header)
    if m:
        inner = m.group(1).strip()
        if inner.startswith("crate"):
            return "pub(crate)"
        if inner.startswith("super"):
            return "pub(super)"
        if inner.startswith("self"):
            return "pub(self)"
        return "pub(in)"
    if re.search(r"\bpub\b", header):
        return "pub"
    return "private"


def brace_end(text: str, open_pos: int) -> int:
    depth = 0
    i = open_pos
    n = len(text)
    while i < n:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n - 1


def attribute_spans(text: str):
    spans = []
    for m in RE_ATTR_START.finditer(text):
        i = m.end() - 1  # at '['
        depth = 0
        j = i
        n = len(text)
        while j < n:
            if text[j] == "[":
                depth += 1
            elif text[j] == "]":
                depth -= 1
                if depth == 0:
                    spans.append((m.start(), j + 1))
                    break
            j += 1
    return spans


def attrs_before(text: str, spans, item_start: int) -> str:
    parts = []
    p = item_start
    while True:
        q = p
        while q > 0 and text[q - 1] in " \t\r\n":
            q -= 1
        hit = None
        for start, end in spans:
            if end == q:
                hit = (start, end)
                break
        if hit is None:
            break
        parts.append(text[hit[0] : hit[1]])
        p = hit[0]
    return " ".join(reversed(parts))


def src_files():
    return sorted(p for p in (ROOT / "src").rglob("*.rs"))


def build_records():
    records = []
    files = src_files()
    for path in files:
        rel = str(path.relative_to(ROOT))
        raw = path.read_text(encoding="utf-8", errors="replace")
        text = atlas.strip_comments_and_literals(raw)
        spans = attribute_spans(text)
        # mod blocks: (start_of_body, end_of_body, vis, name)
        mods = []
        for m in RE_MOD_BLOCK.finditer(text):
            b = text.find("{", m.end() - 1)
            mods.append((b + 1, brace_end(text, b), parse_vis(text[: m.start()].rsplit("\n", 1)[-1]), m.group(1)))
        # extern blocks (foreign imports): (body_start, body_end)
        extern_blocks = []
        for m in RE_EXTERN_BLOCK.finditer(text):
            b = text.find("{", m.end() - 1)
            if b >= 0:
                extern_blocks.append((b + 1, brace_end(text, b)))
        # impl blocks: (body_start, body_end, type_name)
        impls = []
        for m in RE_IMPL.finditer(text):
            b = text.find("{", m.end())
            if b < 0:
                continue
            header = text[m.start() : b]
            ty = None
            mt = re.search(r"\bfor\s+([A-Za-z_][A-Za-z0-9_]*)", header)
            if mt:
                ty = mt.group(1)
            else:
                mt = re.search(r"impl(?:\s*<[^>]*>)?\s+([A-Za-z_][A-Za-z0-9_]*)", header)
                if mt:
                    ty = mt.group(1)
            impls.append((b + 1, brace_end(text, b), ty, " for " in header, "unsafe" in header.split("impl")[0]))
        for m in RE_FN.finditer(text):
            name = m.group(1)
            start = qualifier_start(text, m.start())
            header = text[start : m.end()]
            vis = parse_vis(header)
            has_unsafe = bool(re.search(r"\bunsafe\b", header))
            has_extern = bool(re.search(r"\bextern\b", header))
            # body / declaration
            p = m.end()
            while p < len(text) and text[p] in " \t\r\n":
                p += 1
            # signature may continue through parens: find the end of the parameter list
            depth = 0
            body = None
            sig_end = m.end()
            while sig_end < len(text):
                c = text[sig_end]
                if c in ";{}":
                    break
                sig_end += 1
            signature = text[m.end() : sig_end]
            open_paren = signature.find("(")
            if open_paren >= 0:
                depth = 0
                params_end = open_paren
                for k in range(open_paren, len(signature)):
                    if signature[k] == "(":
                        depth += 1
                    elif signature[k] == ")":
                        depth -= 1
                        if depth == 0:
                            params_end = k
                            break
                params = signature[open_paren : params_end + 1]
            else:
                params = ""
            raw_param = bool(re.search(r"\*\s*(?:mut|const)\b", params))
            while p < len(text):
                c = text[p]
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                elif c == "{" and depth == 0:
                    body = (p, brace_end(text, p))
                    break
                elif c == ";" and depth == 0:
                    break
                p += 1
            attrs = attrs_before(text, spans, start)
            # enclosing module chain and impl
            chain = []
            for s, e, mvis, mname in mods:
                if s <= m.start() < e:
                    chain.append((s, e, mvis, mname))
            chain.sort(key=lambda x: x[0])
            impl = None
            for s, e, ty, is_for, is_unsafe_impl in impls:
                if s <= m.start() < e:
                    impl = (s, e, ty, is_for, is_unsafe_impl)
                    break
            body_text = text[body[0] + 1 : body[1]] if body else ""
            foreign = any(s <= m.start() < e for s, e in extern_blocks)
            records.append(
                {
                    "file": rel,
                    "name": name,
                    "line": raw.count("\n", 0, m.start()) + 1,
                    "vis": vis,
                    "unsafe": has_unsafe,
                    "extern": has_extern,
                    "has_body": body is not None,
                    "attrs": attrs,
                    "mod_chain": [c[3] + ":" + c[2] for c in chain],
                    "impl_type": impl[2] if impl else None,
                    "impl_header_unsafe": impl[4] if impl else False,
                    "body_start": body[0] if body else None,
                    "body_end": body[1] if body else None,
                    "body_has_unsafe": bool(re.search(r"\bunsafe\b", body_text)),
                    "foreign_import": foreign,
                    "raw_pointer_param": raw_param,
                    "body_calls": sorted(set(RE_CALL.findall(body_text))),
                    "body_methods": sorted(set(RE_METHOD.findall(body_text))),
                    "body_macros": sorted(set(RE_MACRO.findall(body_text))),
                }
            )

    # name -> records (for the conservative name-based call graph)
    by_name = {}
    for r in records:
        by_name.setdefault(r["name"], []).append(r)
    # method name -> records, preferring same-file
    for r in records:
        r["callees"] = []
        cand = set(r["body_calls"]) | set(r["body_methods"]) | set(r["body_macros"])
        for name in cand:
            for tgt in by_name.get(name, ()):
                if tgt is r:
                    continue
                r["callees"].append(tgt["file"] + "::" + tgt["name"] + "@" + str(tgt["line"]))

    # direct unsafe touching
    for r in records:
        r["direct_unsafe"] = r["unsafe"] or r["body_has_unsafe"]
    index = {}
    for r in records:
        index.setdefault(r["file"] + "::" + r["name"] + "@" + str(r["line"]), r)
    # fixed point over the name graph
    changed = True
    while changed:
        changed = False
        for r in records:
            if r["direct_unsafe"]:
                continue
            for c in r["callees"]:
                t = index.get(c)
                if t is not None and t["direct_unsafe"]:
                    r["direct_unsafe"] = True
                    changed = True
                    break

    # external reachability (conservative for methods, see limitations)
    for r in records:
        r["definition"] = r["has_body"] and not r["foreign_import"]
        r["doc_hidden"] = "doc(hidden)" in r["attrs"].replace(" ", "")
        r["cfg_test"] = bool(re.search(r"cfg\(\s*test\s*\)", r["attrs"]))
        r["in_test_mod"] = any(re.search(r"(^|:)tests:", c) or c.endswith(":tests") for c in r["mod_chain"])
        mods_pub = all(not c.split(":")[0].endswith(")") and ":pub" in ":" + c for c in r["mod_chain"]) if r["mod_chain"] else True
        # simpler: every enclosing inline mod must be pub/pub(...)
        mods_pub = all(c.split(":")[-1].startswith("pub") for c in r["mod_chain"])
        if r["impl_type"]:
            tdefs = by_name.get(r["impl_type"], [])
            type_pub = any(t["vis"] == "pub" for t in tdefs)
            external = r["vis"] == "pub" and (mods_pub or type_pub)
        else:
            external = r["vis"] == "pub" and mods_pub
        r["external"] = bool(external and not r["doc_hidden"] and not r["cfg_test"] and not r["in_test_mod"])
        r["safe"] = not r["unsafe"]

    return records, files, by_name


def analyze(records, files, by_name):
    pub_safe = [r for r in records if r["safe"] and r["vis"] == "pub" and r["definition"]]
    pub_safe_ext = [r for r in pub_safe if r["external"]]
    pub_safe_ext_unsafe = [r for r in pub_safe_ext if r["direct_unsafe"]]
    any_safe_unsafe = [r for r in records if r["safe"] and r["definition"] and r["direct_unsafe"]]
    any_safe_unsafe_rawparam = [
        r for r in any_safe_unsafe if r["raw_pointer_param"]
    ]
    any_safe_unsafe_rawparam_extern = [r for r in any_safe_unsafe_rawparam if r["extern"]]
    any_safe_unsafe_rawparam_plain = [r for r in any_safe_unsafe_rawparam if not r["extern"]]

    def ksig(r):
        return r["file"] + "::" + (r["impl_type"] + "::" if r["impl_type"] else "") + r["name"] + ":" + str(r["line"])

    out = {
        "schema": "openssl-rs/review/safe-surface/v1",
        "method": {
            "scanner": "lexical walk over atlas_refresh.strip_comments_and_literals, offset-preserving",
            "fn_detection": "regex \\bfn NAME over stripped source; qualifier/visibility walk backwards; body brace-match",
            "call_graph": "name-based: identifiers followed by '(' plus .method( plus macro!(; resolves a name to every definition with that name (over-approximation); Self::/Type:: resolve via the last segment",
            "reachability": "transitive fixed point: safe fn reaches unsafe iff its own body has an `unsafe` token or an unsafe fn, or a callee does",
            "external": "vis == pub, every enclosing inline mod pub, and for methods either the type name has a pub definition or the impl is reachable through the type; excludes #[doc(hidden)], #[cfg(test)], and `tests` mods",
            "limitations": [
                "not a rustc-level resolution: trait-object dispatch, generics, closures and macro-expanded call edges are not resolved; the graph over-approximates call edges by name and under-approximates dynamic dispatch",
                "re-exports (`pub use private_mod::x`) are not followed; a pub fn in a private module re-exported is counted as external only if its own module chain is pub, so the external count is a lower bound for that shape",
                "fn-level attributes on the same line as the signature are captured; attributes are matched by balanced brackets on stripped text",
            ],
        },
        "candidate": {
            "head": open(".git/HEAD").read().strip() if Path(".git/HEAD").exists() else None,
        },
        "files": len(files),
        "counts": {
            "fn_records_total": len(records),
            "foreign_import_declarations": sum(1 for r in records if r["foreign_import"]),
            "no_body_declarations_non_foreign": sum(
                1 for r in records if not r["has_body"] and not r["foreign_import"]
            ),
            "safe_fn_definitions_total": sum(1 for r in records if r["safe"] and r["definition"]),
            "unsafe_fn_definitions_total": sum(1 for r in records if not r["safe"]),
            "safe_pub_fn_total": len(pub_safe),
            "safe_pub_plain_rust_abi": sum(1 for r in pub_safe if not r["extern"]),
            "safe_pub_extern_c": sum(1 for r in pub_safe if r["extern"]),
            "safe_pub_fn_external": len(pub_safe_ext),
            "safe_pub_fn_reaching_unsafe": sum(1 for r in pub_safe if r["direct_unsafe"]),
            "safe_pub_plain_rust_abi_reaching_unsafe": sum(
                1 for r in pub_safe if r["direct_unsafe"] and not r["extern"]
            ),
            "safe_pub_extern_c_reaching_unsafe": sum(
                1 for r in pub_safe if r["direct_unsafe"] and r["extern"]
            ),
            "safe_pub_fn_external_reaching_unsafe": len(pub_safe_ext_unsafe),
            "safe_fn_reaching_unsafe_all_visibilities": len(any_safe_unsafe),
            "safe_fn_raw_pointer_param_reaching_unsafe": len(any_safe_unsafe_rawparam),
            "safe_pub_extern_c_raw_pointer_param_reaching_unsafe": sum(
                1 for r in any_safe_unsafe_rawparam_extern if r["vis"] == "pub" and r["external"]
            ),
            "safe_plain_fn_raw_pointer_param_reaching_unsafe": len(any_safe_unsafe_rawparam_plain),
            "extern_c_fn_definitions_total": sum(1 for r in records if r["extern"] and r["definition"]),
            "pub_extern_c_unsafe": sum(
                1 for r in records if r["extern"] and not r["safe"] and r["vis"] == "pub"
            ),
        },
        "safe_pub_external_reaching_unsafe": sorted(ksig(r) for r in pub_safe_ext_unsafe),
        "safe_pub_external_all": sorted(ksig(r) for r in pub_safe_ext),
        "safe_pub_reaching_unsafe_by_visibility": sorted(ksig(r) + " [" + r["vis"] + "]" for r in pub_safe if r["direct_unsafe"]),
        "safe_plain_fn_raw_pointer_param_reaching_unsafe": sorted(
            ksig(r) + " [" + r["vis"] + "]" for r in any_safe_unsafe_rawparam_plain
        ),
        "safe_pub_extern_c_raw_pointer_param_reaching_unsafe": sorted(
            ksig(r) for r in any_safe_unsafe_rawparam_extern if r["vis"] == "pub" and r["external"]
        ),
    }
    print(json.dumps(out, indent=1, sort_keys=False))
    return out


def main():
    records, files, by_name = build_records()
    analyze(records, files, by_name)


if __name__ == "__main__":
    main()
