#!/usr/bin/env python3
"""Per-path, five-way attribution for ctgrind memcheck logs (PFP-29).

This is the campaign's `ctgrind/repro-2026-11-26/attribute.py` parser unchanged,
with the classification widened so a *per-path* table can name the five buckets
PFP-29 reports:

  engine   src/ec/p256.rs, p256_ladder_run            (the P-256 field engine)
  bn       src/bn/                                    (generic bignum)
  ec       src/ec/ except p256                        (generic EC)
  driver   src/rsa/, src/dh/, src/ml_kem/, src/provider/, src/evp/
  runtime  everything else (core/std/alloc/libc/valgrind, memcpy/memset)

The original A/B/C/D/E classes are still computed and written to the per-log
TSV, so nothing the earlier classifier could say is lost.  "engine-on-path"
means a p256 frame appears anywhere in the stack, exactly as before.
"""
import json
import os
import re
import sys
from collections import Counter

KINDS = re.compile(
    r"^==\d+== (Conditional jump or move|Use of uninitialised value|Syscall param|"
    r"Invalid read|Invalid write|Invalid free|Mismatched free|"
    r"Jump to the invalid address|Source and destination overlap|Invalid alignment)"
)
FRAME = re.compile(r"^==\d+==\s+(at|by) 0x[0-9A-F]+: (.*)$")


def parse(path):
    recs = []
    cur = None
    for raw in open(path, errors="replace"):
        line = raw.rstrip("\n")
        m = FRAME.match(line)
        if m:
            rest = m.group(2)
            lm = re.search(r"\(([^()]*)\)\s*$", rest)
            loc = lm.group(1) if lm else ""
            fn = re.sub(r"\s*\([^()]*\)\s*$", "", rest).strip()
            if fn.startswith("in "):
                fn = fn[3:]
            if cur is None:
                cur = {"kind": "unknown", "frames": []}
                recs.append(cur)
            cur["frames"].append((m.group(1), fn, loc))
            continue
        km = KINDS.match(line)
        if km:
            cur = {"kind": km.group(1), "frames": []}
            recs.append(cur)
    return [r for r in recs if r["frames"]]


# `#[no_mangle] extern "C"` entry points carry no module path in their symbol
# name, so `BN_nnmod` does not contain "::bn::".  The prefixes below attach the
# exported wrappers to the module whose code they run, without which the bn and
# ec columns would report only the private helpers.
EXPORT_PREFIX = (
    ("BN_", "bn"), ("bn_", "bn"),
    ("ossl_ec_", "ec"), ("EC_", "ec"), ("ECDH_", "ec"), ("ECDSA_", "ec"),
    ("ossl_rsa_", "driver"), ("RSA_", "driver"),
    ("ossl_dh_", "driver"), ("DH_", "driver"),
    ("ossl_ml_kem_", "driver"), ("ossl_ml_dsa_", "driver"),
    ("EVP_", "driver"), ("OSSL_", "driver"),
)


def five_way(fn):
    if "::ec::p256::" in fn or "p256_ladder_run" in fn:
        return "engine"
    if "::bn::" in fn:
        return "bn"
    if any(x in fn for x in (
        "::rsa::", "::dh::", "::ml_kem::", "::ml_dsa::", "::provider::",
        "::evp::", "::cms::", "::modes::",
    )):
        return "driver"
    if "::ec::" in fn:
        return "ec"
    for prefix, bucket in EXPORT_PREFIX:
        if fn.startswith(prefix):
            return bucket
    return "runtime"


def legacy_class(fn):
    if "::ec::p256::" in fn or "p256_ladder_run" in fn:
        return "B"
    if "::bn::" in fn:
        return "C"
    if any(x in fn for x in (
        "::ec::mult::", "::ec::ecdsa_ossl::", "::ec::smpl::", "::ec::field::",
        "::ec::curve::", "::ec::lib::", "::ec::ecdh_ossl::",
    )):
        return "D"
    if "::tests::" in fn or "test::" in fn or "libtest" in fn:
        return "A"
    return "E"


def summarise(path, outdir):
    recs = parse(path)
    rows = []
    for i, r in enumerate(recs, 1):
        top = r["frames"][0]
        text = " ".join(f + " " + l for _, f, l in r["frames"])
        rows.append({
            "i": i,
            "kind": r["kind"],
            "bucket": five_way(top[1]),
            "legacy": legacy_class(top[1]),
            "origin_fn": top[1],
            "origin_loc": top[2],
            "engine_on_path": int("::ec::p256::" in text or "p256_ladder_run" in text),
            "bn_on_path": int("::bn::" in text),
            "stack": " <- ".join(fn for _, fn, _ in r["frames"]),
        })
    base = os.path.basename(path).replace(".out", "")
    with open(os.path.join(outdir, base + ".tsv"), "w") as f:
        f.write("idx\tkind\tbucket\tlegacy\torigin_loc\torigin_fn\t"
                "engine_on_path\tbn_on_path\tstack\n")
        for x in rows:
            f.write("%d\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\n" % (
                x["i"], x["kind"], x["bucket"], x["legacy"], x["origin_loc"],
                x["origin_fn"], x["engine_on_path"], x["bn_on_path"], x["stack"]))
    per_bucket = Counter(x["bucket"] for x in rows)
    # bucket counts by *any frame in the stack*, which is what "on path" means
    on_path = Counter()
    for r in recs:
        names = [fn for _, fn, _ in r["frames"]]
        buckets = set(five_way(n) for n in names)
        for b in ("engine", "bn", "ec", "driver", "runtime"):
            if b in buckets:
                on_path[b] += 1
    sites = Counter((x["origin_loc"], x["origin_fn"]) for x in rows)
    summary = {
        "log": path,
        "contexts": len(rows),
        "origin_by_bucket": dict(per_bucket),
        "contexts_with_bucket_on_path": dict(on_path),
        "engine_on_path": sum(x["engine_on_path"] for x in rows),
        "origin_in_engine": per_bucket.get("engine", 0),
        "top_origins": [
            {"contexts": n, "loc": l, "fn": f}
            for (l, f), n in sites.most_common(20)
        ],
    }
    with open(os.path.join(outdir, base + ".summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    return summary


def main(argv):
    if len(argv) < 3:
        print("usage: attrib_pfp29.py OUTDIR LOG...", file=sys.stderr)
        return 2
    outdir, logs = argv[1], argv[2:]
    os.makedirs(outdir, exist_ok=True)
    for path in logs:
        s = summarise(path, outdir)
        print(json.dumps({k: s[k] for k in (
            "log", "contexts", "origin_by_bucket",
            "contexts_with_bucket_on_path", "engine_on_path",
            "origin_in_engine")}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
