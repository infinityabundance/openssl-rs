#!/usr/bin/env python3
"""Aggregate the PFP-29 raw outputs into per-path rows (never one merged number).

Reads raw/valgrind.tsv, attrib/*.summary.json, raw/timing.tsv and the
differential observables, and writes raw/checkpoint-data.json plus a compact
text table on stdout.
"""
import argparse
import json
import os
import statistics


def read_tsv(path):
    rows = []
    if not os.path.exists(path):
        return rows
    for line in open(path):
        parts = line.rstrip("\n").split("\t")
        if len(parts) == 4:
            mode, rep, errs, ctxs = parts
        elif len(parts) == 3:
            mode, rep, ms = parts
            rows.append((mode, rep, None, None, ms))
            continue
        else:
            continue
        rows.append((mode, rep, int(errs), int(ctxs), None))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    args = ap.parse_args()
    ev = args.dir
    raw = os.path.join(ev, "raw")
    attrib = os.path.join(ev, "attrib")

    val = read_tsv(os.path.join(raw, "valgrind.tsv"))
    timing = read_tsv(os.path.join(raw, "timing.tsv"))

    modes = ["ecdsa-sign", "ecdsa-sign-default", "ecdsa-verify", "ecdh",
             "rsa-crt", "rsa-nocrt", "rsa-crt-pkcs1", "dh", "mlkem-decaps"]
    table = {}
    for mode in modes:
        reps = [r for r in val if r[0] == mode]
        errs = [r[2] for r in reps if r[2] is not None]
        ctxs = [r[3] for r in reps if r[3] is not None]
        sums = []
        for rep in range(1, len(reps) + 1):
            p = os.path.join(attrib, "a-%s-r%d.summary.json" % (mode, rep))
            if os.path.exists(p):
                sums.append(json.load(open(p)))
        buckets = {}
        for b in ("engine", "bn", "ec", "driver", "runtime"):
            vals = [s["contexts_with_bucket_on_path"].get(b, 0) for s in sums]
            buckets[b] = {
                "per_rep": vals,
                "min": min(vals) if vals else None,
                "max": max(vals) if vals else None,
            }
        eops = [s["engine_on_path"] for s in sums]
        origins = {}
        for s in sums:
            for o in s["top_origins"]:
                origins[o["fn"]] = max(origins.get(o["fn"], 0), o["contexts"])
        table[mode] = {
            "runs": len(reps),
            "errors": {"values": errs,
                       "median": int(statistics.median(errs)) if errs else None,
                       "max": max(errs) if errs else None},
            "contexts": {"values": ctxs,
                         "median": int(statistics.median(ctxs)) if ctxs else None,
                         "max": max(ctxs) if ctxs else None},
            "origin_by_bucket": {k: b["max"] for k, b in buckets.items()},
            "bucket_on_path": buckets,
            "engine_on_path": {"values": eops, "max": max(eops) if eops else None},
            "top_origins": sorted(
                ({"fn": f, "contexts": n} for f, n in origins.items()),
                key=lambda x: -x["contexts"])[:8],
        }

    # positives: the pre-PFP-20 sensitivity control
    pre = os.path.join(attrib, "pre-ecdh-r1.summary.json")
    sensitivity = json.load(open(pre)) if os.path.exists(pre) else None

    # differential
    diff = {}
    cand = os.path.join(raw, "differential-cand.txt")
    auth = os.path.join(raw, "differential-auth.txt")
    if os.path.exists(cand) and os.path.exists(auth):
        keys = ("ECDSA_R", "ECDSA_S", "ECDH_SS", "RSA_PT", "DH_SS",
                "MLKEM_CT", "MLKEM_ENCAP_SS", "MLKEM_DECAP_SS")
        def parse(p):
            out = {}
            for line in open(p):
                parts = line.split()
                if len(parts) == 2 and parts[0] in keys:
                    out[parts[0]] = parts[1]
            return out
        c, a = parse(cand), parse(auth)
        for k in c:
            diff[k] = {
                "bytes": len(c[k]) // 2,
                "equal": c.get(k) == a.get(k),
            }
    sweep = {}
    candobs = os.path.join(raw, "sweep-cand.obs")
    authobs = os.path.join(raw, "sweep-auth.obs")
    if os.path.exists(candobs) and os.path.exists(authobs):
        c = open(candobs).read().splitlines()
        a = open(authobs).read().splitlines()
        sweep = {
            "cases": 64,
            "observable_rows": len(c),
            "identical": c == a,
            "paths": {
                "ECDSA": sum(1 for x in c if x.startswith("ECDSA ")),
                "ECDH": sum(1 for x in c if x.startswith("ECDH ")),
                "RSA": sum(1 for x in c if x.startswith("RSA ")),
                "DH": sum(1 for x in c if x.startswith("DH ")),
                "KEM_CT": sum(1 for x in c if x.startswith("KEM_CT ")),
                "KEM_SS": sum(1 for x in c if x.startswith("KEM_SS ")),
            },
        }
    for name in ("sweep-verify-cand-of-auth", "sweep-verify-auth-of-cand"):
        p2 = os.path.join(raw, name + ".txt")
        if os.path.exists(p2):
            for line in open(p2):
                if line.startswith("VERIFY_SWEEP"):
                    sweep[name] = line.strip()

    cross = {}
    for name in ("verify-cand-of-auth", "verify-auth-of-cand"):
        p = os.path.join(raw, name + ".txt")
        cross[name] = os.path.exists(p) and "ok=1" in open(p).read()

    tm = {}
    for mode in modes:
        vals = [float(r[4]) for r in timing if r[0] == mode and r[4]]
        if vals:
            tm[mode] = {
                "median_ns": round(statistics.median(vals), 1),
                "min_ns": round(min(vals), 1),
                "max_ns": round(max(vals), 1),
                "reps": len(vals),
            }

    data = {
        "per_path": table,
        "sensitivity_control": {
            "artefact": "83f67826",
            "engine_on_path": sensitivity["engine_on_path"] if sensitivity else None,
            "contexts": sensitivity["contexts"] if sensitivity else None,
        },
        "differential": diff,
        "cross_verify": cross,
        "sweep": sweep,
        "timing": tm,
    }
    with open(os.path.join(raw, "checkpoint-data.json"), "w") as f:
        json.dump(data, f, indent=2)

    print("path            runs  errors(med/max)  contexts(med/max)  "
          "engine bn ec driver runtime  engine-on-path")
    for mode in modes:
        t = table[mode]
        b = t["origin_by_bucket"]
        eo = t["engine_on_path"]["max"]
        print("%-15s %4d  %7s/%-5s  %8s/%-5s  %4s %4s %4s %6s %7s  %s" % (
            mode, t["runs"],
            t["errors"]["median"], t["errors"]["max"],
            t["contexts"]["median"], t["contexts"]["max"],
            b["engine"], b["bn"], b["ec"], b["driver"], b["runtime"], eo))
    print()
    print("sensitivity control (ecdh on 83f67826): engine_on_path=%s contexts=%s" % (
        data["sensitivity_control"]["engine_on_path"],
        data["sensitivity_control"]["contexts"]))
    print("differential: %s" % ", ".join(
        "%s(%dB)=%s" % (k, v["bytes"], "equal" if v["equal"] else "MISMATCH")
        for k, v in diff.items()))
    print("cross-verify: %s" % cross)
    if sweep:
        print("64-case sweep: identical=%s rows=%s paths=%s" % (
            sweep.get("identical"), sweep.get("observable_rows"),
            sweep.get("paths")))
        print("sweep cross-verify: %s / %s" % (
            sweep.get("sweep-verify-cand-of-auth"),
            sweep.get("sweep-verify-auth-of-cand")))
    print("timing (median ns/op): %s" % ", ".join(
        "%s=%.1f" % (k, v["median_ns"]) for k, v in tm.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
