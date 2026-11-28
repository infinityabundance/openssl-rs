#!/usr/bin/env python3
"""PFP-11 per-curve differential driver.

For each library under test:
  * ECDSA P-384/P-521: 8 deterministic private scalars (1,2,3; four
    pseudorandom full-width; q-1 and q-2) x 6 digests (zero, 2^256-1,
    two pseudorandom 32-byte, 2^512-1, 2^528-1) -> 48 cases. The public key
    and digest must agree between libraries; each signature is then verified
    by the *other* library (both directions).
  * Ed25519: 8 seeds (zero, all-ones, six pseudorandom) x 4 messages
    (0, 1, 64, 64-all-ones) -> 32 cases; public key and signature must be
    byte-identical between libraries.
  * X25519: 6 x 6 private/peer pairs including all-zero and all-ones private
    keys; the derived shared secret (or the derive failure) must agree.

A single mismatch is a STOP. Output is a compact JSON record plus a summary.
"""
import argparse
import json
import os
import subprocess
import sys


def run(bench, lib, args):
    p = subprocess.run([bench, "--lib", lib] + args, capture_output=True,
                       text=True)
    if p.returncode != 0:
        raise SystemExit("FAIL: %s %s rc=%d\n%s" % (lib, args, p.returncode,
                                                    p.stderr))
    return p.stdout


def parse_cases(out):
    cases = {}
    for line in out.splitlines():
        if not line.startswith("CASE "):
            continue
        fields = {}
        for tok in line.split()[2:]:
            if "=" in tok:
                k, v = tok.split("=", 1)
                fields[k] = v
        cases[int(fields["k"])] = fields
    return cases


def ecdsa(bench, cand, auth, curve, report):
    n = 48
    status = {"curve": curve, "cases": n}
    parsed = {}
    for tag, lib in (("cand", cand), ("auth", auth)):
        out = run(bench, lib, ["--op", "ecdsa-diff", "--curve", curve])
        with open(os.path.join(report["raw_dir"], "ecdsa-%s-%s.txt" % (curve, tag)),
                  "w", encoding="utf-8") as fh:
            fh.write(out)
        parsed[tag] = parse_cases(out)
        if len(parsed[tag]) != n:
            raise SystemExit("FAIL: %s %s produced %d/%d cases" %
                             (tag, curve, len(parsed[tag]), n))
    mism = 0
    cross = 0
    for k in range(n):
        c, a = parsed["cand"].get(k), parsed["auth"].get(k)
        if c is None or a is None:
            mism += 1
            continue
        if c["pub"] != a["pub"] or c["dgst"] != a["dgst"] or c["verify"] != "1":
            mism += 1
        # Cross-verify each side's signature in the other library.
        for tag, lib, sig in (("cand-sig-in-auth", auth, c["sig"]),
                              ("auth-sig-in-cand", cand, a["sig"])):
            out = run(bench, lib, ["--op", "ecdsa-verify-external",
                                   "--curve", curve, "--pub", c["pub"],
                                   "--dgst", c["dgst"], "--sig", sig])
            if "EXTERNAL verify=1" not in out:
                mism += 1
            else:
                cross += 1
    status["pub_dgst_mismatches"] = mism
    status["cross_verifications"] = cross
    status["status"] = "PASS" if mism == 0 and cross == 2 * n else "FAIL"
    return status


def deterministic(bench, cand, auth, op, name, expected, report):
    outs = {}
    for tag, lib in (("cand", cand), ("auth", auth)):
        out = run(bench, lib, ["--op", op])
        with open(os.path.join(report["raw_dir"], "%s-%s.txt" % (name, tag)),
                  "w", encoding="utf-8") as fh:
            fh.write(out)
        outs[tag] = [ln for ln in out.splitlines() if ln.startswith("CASE ")]
    mism = sum(1 for a, b in zip(outs["cand"], outs["auth"]) if a != b)
    mism += abs(len(outs["cand"]) - len(outs["auth"]))
    return {"cases_expected": expected, "cases_cand": len(outs["cand"]),
            "cases_auth": len(outs["auth"]), "mismatches": mism,
            "status": "PASS" if mism == 0 and len(outs["cand"]) == expected else "FAIL"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bench", required=True)
    ap.add_argument("--cand", required=True)
    ap.add_argument("--auth", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--raw-dir", required=True)
    args = ap.parse_args()
    os.makedirs(args.raw_dir, exist_ok=True)

    report = {"raw_dir": args.raw_dir}
    results = {}
    for curve in ("p384", "p521"):
        results[curve] = ecdsa(args.bench, args.cand, args.auth, curve, report)
    results["ed25519"] = deterministic(args.bench, args.cand, args.auth,
                                       "ed25519-diff", "ed25519", 32, report)
    results["x25519"] = deterministic(args.bench, args.cand, args.auth,
                                      "x25519-diff", "x25519", 36, report)

    out = {
        "cand_dso_sha256": _sha(args.cand),
        "auth_dso_sha256": _sha(args.auth),
        "bench_sha256": _sha(args.bench),
        "ecdsa_p384": results["p384"],
        "ecdsa_p521": results["p521"],
        "ed25519": results["ed25519"],
        "x25519": results["x25519"],
    }
    out["status"] = ("PASS" if all(v["status"] == "PASS"
                                   for v in (out["ecdsa_p384"], out["ecdsa_p521"],
                                             out["ed25519"], out["x25519"]))
                     else "FAIL")
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(json.dumps(out, indent=2, sort_keys=True))
    if out["status"] != "PASS":
        sys.exit(1)


def _sha(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


if __name__ == "__main__":
    main()
