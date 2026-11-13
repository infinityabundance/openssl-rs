#!/usr/bin/env python3
"""Check the v1l boundary receipt against the frozen candidate S.

Two separate questions:
  1. Coordinate identity: does the receipt's recorded line/ranges still point at
     the reviewed item in the current source?
  2. Witness identity: do the receipt's `established_by` citations still point at
     the code that establishes the precondition?  (The closure tool re-binds the
     operation span only; it does not re-check the callers the discharge cites.)

Writes court/freeze-b76/review/v1l-witness-check.json.
"""
import json
import os
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
RECEIPT = "forensics/memory-safety/campaign/safe-c33/atlas-refresh/openssh-v1l-sites.json"
CLOSURE = "evidence/closure-ssh-b76c.json"
OUT = "court/freeze-b76/review/v1l-witness-check.json"
S = "0238c6e4adbc7ed85a42be68b6fb965e139bd93e"

_cache = {}


def lines(path):
    if path not in _cache:
        with open(os.path.join(ROOT, path), "r", encoding="utf-8") as f:
            _cache[path] = f.read().splitlines()
    return _cache[path]


def first_line(path, needle):
    for i, line in enumerate(lines(path), 1):
        if needle in line:
            return i
    return None


def all_lines(path, needle):
    return [i for i, line in enumerate(lines(path), 1) if needle in line]


def def_line(path, item):
    pat = re.compile(r"(?:^|\s)(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?"
                     r"(?:extern\s+\"C\"\s+)?(?:fn|static|const)\s+" + re.escape(item) + r"\b")
    for i, line in enumerate(lines(path), 1):
        if pat.search(line):
            return i
    return None


def citation_covers(cited, got_lines):
    """True if any anchor line is one of the cited points or lies in a cited range.

    Handles 'path:NNN', 'path:NNN-MMM' and 'path:N1,N2,N3' spellings.
    """
    tail = cited.split(":", 1)[1] if ":" in cited else cited
    points = set()
    ranges = []
    for part in tail.replace(",", " ").split():
        if "-" in part and part.replace("-", "").isdigit():
            a, b = part.split("-", 1)
            ranges.append((int(a), int(b)))
        elif part.isdigit():
            points.add(int(part))
    return any(
        g in points or any(a <= g <= b for a, b in ranges) for g in got_lines
    )


def main():
    with open(os.path.join(ROOT, RECEIPT), "r", encoding="utf-8") as f:
        rec = json.load(f)
    with open(os.path.join(ROOT, CLOSURE), "r", encoding="utf-8") as f:
        clo = json.load(f)

    attempts = {}
    for o in clo["obligations"]:
        if o.get("discharge_receipt") != "openssh-v1l":
            continue
        bid = o["discharge_boundary_id"]
        for a in o.get("scoped_discharge_attempts") or []:
            if a.get("boundary") == bid:
                attempts[bid] = {
                    "declared_ranges": a.get("declared_ranges"),
                    "covers_site": a.get("covers_site"),
                    "span_hash_matches": a.get("span_hash") == a.get("span_current_hash"),
                }

    want = {"OSSH-V1L-006", "OSSH-V1L-007", "OSSH-V1L-009", "OSSH-V1L-010",
            "OSSH-V1L-011", "OSSH-V1L-012", "OSSH-V1L-013", "OSSH-V1L-014",
            "OSSH-V1L-015"}
    rows = []
    for b in rec["boundaries"]:
        if b["id"] not in want:
            continue
        actual = def_line(b["file"], b["operation"])
        declared = attempts.get(b["id"], {}).get("declared_ranges")
        declared_line = None
        if declared and b["file"] in declared:
            declared_line = declared[b["file"]][0][0]
        rows.append({
            "boundary": b["id"],
            "file": b["file"],
            "operation": b["operation"],
            "receipt_line": b["line"],
            "closure_declared_line": declared_line,
            "actual_definition_line": actual,
            "receipt_line_ok": b["line"] == actual,
            "closure_coordinate_covers_site": attempts.get(b["id"], {}).get("covers_site"),
            "span_hash_matches": attempts.get(b["id"], {}).get("span_hash_matches"),
        })

    witness_anchors = [
        # (boundary, receipt citation, source path, anchor text, what it is)
        ("OSSH-V1L-010", "src/decoder_lib.rs:1402", "src/decoder_lib.rs",
         "OPENSSL_sk_pop_free(skdecoders, Some(decoder_free_thunk))", "sole registration"),
        ("OSSH-V1L-006", "src/runtime/confmod/mod.rs:1369", "src/runtime/confmod/mod.rs",
         "OPENSSL_sk_pop_free(to_delete, Some(module_free_thunk))", "sole registration"),
        ("OSSH-V1L-009", "src/engine/eng_fat.rs:235", "src/engine/eng_fat.rs",
         "push_cstr_or_null(&mut msg, def_list)", "sole call site"),
        ("OSSH-V1L-011/012", "src/x509/v3_akid.rs:203-218", "src/x509/v3_akid.rs",
         "pub static ossl_v3_akey_id", "method row"),
        ("OSSH-V1L-013/014/015", "src/x509/v3_san.rs:1193-1217", "src/x509/v3_san.rs",
         "const fn alt_row", "row constructor"),
        ("OSSH-V1L-013/014/015", "src/x509/v3_san.rs:1211-1214", "src/x509/v3_san.rs",
         "pub static ossl_v3_alt", "row table"),
        ("OSSH-V1L-011..015", "src/x509/v3_prn.rs:226-246, :279", "src/x509/v3_prn.rs",
         "nval = unsafe { f(method, ext_str, ptr::null_mut()) };", "i2v dispatch"),
        ("OSSH-V1L-011..015", "src/x509/v3_prn.rs:226-246", "src/x509/v3_prn.rs",
         "ASN1_item_d2i(ptr::null_mut(), &raw mut p, extlen as c_long, item)", "decode with row it"),
        ("OSSH-V1L-012/014/015", "src/x509/v3_conf.rs:1029-1059", "src/x509/v3_conf.rs",
         "ext_struc = unsafe { cb(method, ctx.cast::<c_void>(), nval) };", "v2i dispatch"),
        ("OSSH-V1L-007", "src/ui/ui_util.rs:277,447,500,525", "src/ui/ui_util.rs",
         "UI_METHOD_DATA_INDEX.load(Ordering::Acquire)", "index load sites"),
    ]
    witnesses = []
    for boundary, cited, path, anchor, what in witness_anchors:
        got = all_lines(path, anchor)
        witnesses.append({
            "boundary": boundary,
            "receipt_citation": cited,
            "anchor": what,
            "anchor_lines_now": got,
            "citation_holds": citation_covers(cited, got),
        })

    push_calls = len(re.findall(r"push_cstr_or_null\s*\(", "\n".join(lines("src/engine/eng_fat.rs")))) - 1
    out = {
        "schema": "safe-c33/b76/review-witness-check/v1",
        "frozen_source": S,
        "receipt_candidate": rec["candidate"],
        "receipt_bound_to_frozen_source": rec["candidate"]["source_head"] == S,
        "coordinates": rows,
        "coordinates_stale": [r["boundary"] for r in rows if not r["receipt_line_ok"]],
        "closure_covers_site_false": [r["boundary"] for r in rows
                                      if r["closure_coordinate_covers_site"] is False],
        "witnesses": witnesses,
        "witness_citations_stale": [w["receipt_citation"] for w in witnesses
                                    if not w["citation_holds"]],
        "push_cstr_call_sites_now": push_calls,
        "push_cstr_receipt_claims_two_paths": "the `word` literal path" in json.dumps(rec),
    }
    with open(os.path.join(ROOT, OUT), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
        f.write("\n")

    print("receipt bound to frozen source:", out["receipt_bound_to_frozen_source"],
          f"(receipt={rec['candidate']['source_head'][:12]}, frozen={S[:12]})")
    print("coordinate mismatch (receipt line vs current definition):", out["coordinates_stale"])
    print("closure attempts with covers_site=false:", out["closure_covers_site_false"])
    print("stale establishing witnesses:")
    for w in witnesses:
        if not w["citation_holds"]:
            print(f"   {w['receipt_citation']:36s} {w['anchor']:22s} -> now {w['anchor_lines_now']}")
    print("push_cstr_or_null call sites now:", push_calls,
          "| receipt claims a `word` literal path:", out["push_cstr_receipt_claims_two_paths"])
    print("wrote", OUT)


if __name__ == "__main__":
    main()
