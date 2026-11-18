#!/usr/bin/env python3
"""Canary harness for v1i_contract_audit.py.

Each canary mutates a *private copy* (never the tree) and asserts that exactly the
targeted audit check flips:
  - a "repair" canary fixes the defect in the copy and requires FAIL -> PASS,
    which proves the detector is sensitive to the repaired property;
  - a "break" canary removes establishing evidence and requires PASS -> FAIL,
    which proves the detector is anchored to real code, not to a fixed string.

Run:  python3 run_canaries_v1i.py     (inside the court; no compilation)
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", "..", ".."))
AUDIT = os.path.join(HERE, "v1i_contract_audit.py")
INV = os.path.join(ROOT, "court/freeze-b76/review/review-65-inventory.json")
RECEIPT = os.path.join(
    ROOT, "forensics/memory-safety/campaign/safe-c33/atlas-refresh/openssh-v1i-sites.json")

SRC_FILES = ["src/evp/digest.rs", "src/provider/digest.rs",
             "src/cmp/cmp_ctx.rs", "src/cmp/cmp_asn.rs"]
COPYCTX = [658, 970, 1165, 1348, 1898]


def run_audit(root, receipt):
    out = subprocess.run([sys.executable, AUDIT, "--root", root,
                          "--inventory", INV, "--receipt", receipt, "--json"],
                         capture_output=True, text=True)
    return {c["id"]: c for c in json.loads(out.stdout)["checks"]}


def make_tree():
    d = tempfile.mkdtemp(prefix="_tmp_v1i_")
    for rel in SRC_FILES:
        dst = os.path.join(d, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(os.path.join(ROOT, rel), dst)
    return d


def edit(path, fn):
    with open(path, "r") as f:
        lines = f.read().split("\n")
    lines = fn(lines)
    with open(path, "w") as f:
        f.write("\n".join(lines))


def canaries():
    base = run_audit(ROOT, RECEIPT)
    expected = {"SPAN19": True, "COORD19": False, "CLOC19": False, "SAFETYFN": False,
                "FAMILY": False, "MACROCTX": False, "NULLCTX": False,
                "NULREACH": True, "REACQ": True, "CALLERS": True}
    results = [{"id": "K1-pristine", "expect": expected,
                "observed": {k: v["pass"] for k, v in base.items()},
                "ok": all(base[k]["pass"] == v for k, v in expected.items())}]

    # K2 repair: give each hand-written copyctx a `# Safety` line, keeping line count.
    d = make_tree()
    edit(os.path.join(d, "src/provider/digest.rs"),
         lambda L: [("    /// # Safety" if (i + 1) in [n - 1 for n in COPYCTX] else x)
                    for i, x in enumerate(L)])
    r = run_audit(d, RECEIPT)
    results.append({"id": "K2-copyctx-safety-doc", "expect": {"MACROCTX": True},
                    "observed": {"MACROCTX": r["MACROCTX"]["pass"]},
                    "ok": r["MACROCTX"]["pass"]})
    shutil.rmtree(d)

    # K3 repair: guard both copyctx call sites against a NULL algctx.
    d = make_tree()
    def add_guards(L):
        idx = [i for i, x in enumerate(L)
               if "copyctx((*out).algctx, (*in_).algctx)" in x]
        for i in sorted(idx, reverse=True):
            ind = L[i][:len(L[i]) - len(L[i].lstrip())]
            L.insert(i, ind + "if (*out).algctx.is_null() || (*in_).algctx.is_null() {")
            L.insert(i + 1, ind + "    return;")
            L.insert(i + 2, ind + "}")
        return L
    edit(os.path.join(d, "src/evp/digest.rs"), add_guards)
    r = run_audit(d, RECEIPT)
    results.append({"id": "K3-null-algctx-guard", "expect": {"NULLCTX": True},
                    "observed": {"NULLCTX": r["NULLCTX"]["pass"]},
                    "ok": r["NULLCTX"]["pass"]})
    shutil.rmtree(d)

    # K4 break: remove the `(*ctx).digest = type_` that makes the NULL state reachable.
    d = make_tree()
    edit(os.path.join(d, "src/evp/digest.rs"),
         lambda L: [x for x in L if x.strip() != "unsafe { (*ctx).digest = type_ };"])
    r = run_audit(d, RECEIPT)
    results.append({"id": "K4-break-reachability", "expect": {"NULREACH": False},
                    "observed": {"NULREACH": r["NULREACH"]["pass"]},
                    "ok": r["NULREACH"]["pass"] is False})
    shutil.rmtree(d)

    # K5 break: remove the re-acquiring arm's own NULL tolerance.
    d = make_tree()
    edit(os.path.join(d, "src/evp/digest.rs"),
         lambda L: [x.replace("if !in_algctx.is_null() {", "if true {") for x in L])
    r = run_audit(d, RECEIPT)
    results.append({"id": "K5-break-reacq-guard", "expect": {"REACQ": False},
                    "observed": {"REACQ": r["REACQ"]["pass"]},
                    "ok": r["REACQ"]["pass"] is False})
    shutil.rmtree(d)

    # K11 break: a direct call of a free thunk on a borrowed pointer (ownership not
    # transferred) must be reported by the per-call-site control.
    d = make_tree()
    edit(os.path.join(d, "src/cmp/cmp_ctx.rs"),
         lambda L: [x.replace("            OPENSSL_sk_pop_free((*ctx).policies, Some(policy_free_void));",
                              "            policy_free_void((*ctx).policies.cast());")
                    for x in L])
    r = run_audit(d, RECEIPT)
    results.append({"id": "K11-break-direct-thunk-call", "expect": {"CALLERS": False},
                    "observed": {"CALLERS": r["CALLERS"]["pass"]},
                    "ok": r["CALLERS"]["pass"] is False})
    shutil.rmtree(d)

    # K12 break: an item free called on an argument with no constructor in its function.
    d = make_tree()
    edit(os.path.join(d, "src/cmp/cmp_asn.rs"),
         lambda L: [x.replace("unsafe { itav_free(itav) };", "unsafe { itav_free(stray) };")
                    for x in L])
    r = run_audit(d, RECEIPT)
    results.append({"id": "K12-break-stray-item-free", "expect": {"CALLERS": False},
                    "observed": {"CALLERS": r["CALLERS"]["pass"]},
                    "ok": r["CALLERS"]["pass"] is False})
    shutil.rmtree(d)

    # K6 repair: rebind every stale receipt coordinate to the current definition line.
    rc = json.load(open(RECEIPT))
    cur = {o["item"]: o["line"] for o in
           json.load(open(INV))["obligations"]
           if o["discharge_receipt"] == "openssh-v1i"}
    for b in rc["boundaries"]:
        if b["operation"] in cur:
            b["line"] = cur[b["operation"]]
    tmp_rc = os.path.join(tempfile.mkdtemp(prefix="_tmp_v1i_rc_"), "r.json")
    json.dump(rc, open(tmp_rc, "w"))
    r = run_audit(ROOT, tmp_rc)
    results.append({"id": "K6-rebind-coordinates", "expect": {"COORD19": True},
                    "observed": {"COORD19": r["COORD19"]["pass"],
                                 "stale_left": len(r["COORD19"]["detail"]["stale"])},
                    "ok": r["COORD19"]["pass"]})
    os.remove(tmp_rc)

    # K7 repair: replace the false ctx_set1_dup! witness with the real pop_free caller.
    rc = json.load(open(RECEIPT))
    for b in rc["boundaries"]:
        if b["operation"] in ("general_name_free_void", "x509_extension_free_void",
                              "utf8_string_free_void", "policy_free_void"):
            b["established_by"] = [
                "caller: OPENSSL_sk_pop_free(<ctx field>, Some(%s)) in src/cmp/cmp_ctx.rs"
                % b["operation"]]
    tmp_rc = os.path.join(tempfile.mkdtemp(prefix="_tmp_v1i_rc_"), "r.json")
    json.dump(rc, open(tmp_rc, "w"))
    r = run_audit(ROOT, tmp_rc)
    results.append({"id": "K7-real-call-site-witness", "expect": {"FAMILY": True},
                    "observed": {"FAMILY": r["FAMILY"]["pass"]},
                    "ok": r["FAMILY"]["pass"]})
    os.remove(tmp_rc)

    # K8 repair: point every bogus contract location at a real `# Safety` line.
    import re as _re
    rc = json.load(open(RECEIPT))
    for b in rc["boundaries"]:
        b["disposition"] = _re.sub(
            r"SAFETY_DISCHARGED:\s*\S+:\d+",
            "SAFETY_DISCHARGED: src/cmp/cmp_ctx.rs:399", b["disposition"])
    tmp_rc = os.path.join(tempfile.mkdtemp(prefix="_tmp_v1i_rc_"), "r.json")
    json.dump(rc, open(tmp_rc, "w"))
    r = run_audit(ROOT, tmp_rc)
    results.append({"id": "K8-contract-location", "expect": {"CLOC19": True},
                    "observed": {"CLOC19": r["CLOC19"]["pass"]},
                    "ok": r["CLOC19"]["pass"]})
    os.remove(tmp_rc)

    # K9 break: corrupt one byte inside a recorded span.
    d = make_tree()
    edit(os.path.join(d, "src/cmp/cmp_asn.rs"),
         lambda L: [x.replace("ASN1_item_free(itav.cast(), cmp_itav_it())",
                              "ASN1_item_free(itav.cast(), cmp_itav_iT())")
                    if "ASN1_item_free(itav.cast()" in x else x for x in L])
    r = run_audit(d, RECEIPT)
    results.append({"id": "K9-break-span-hash", "expect": {"SPAN19": False},
                    "observed": {"SPAN19": r["SPAN19"]["pass"]},
                    "ok": r["SPAN19"]["pass"] is False})
    shutil.rmtree(d)

    # K10 repair: put `# Safety` above all 19 recorded definitions.
    d = make_tree()
    lines_by_file = {}
    recs = [o for o in json.load(open(INV))["obligations"]
            if o["discharge_receipt"] == "openssh-v1i"]
    recs.sort(key=lambda o: o["stable_id"])
    for o in recs[:19]:
        lines_by_file.setdefault(o["file"], []).append(o["line"])
    for rel, lns in lines_by_file.items():
        lns = sorted(set(lns))
        p = os.path.join(d, rel)
        L = open(p).read().split("\n")
        for n in lns:
            L[n - 2] = "    /// # Safety (canary contract)"
        open(p, "w").write("\n".join(L))
    r = run_audit(d, RECEIPT)
    results.append({"id": "K10-all-safety-docs", "expect": {"SAFETYFN": True},
                    "observed": {"SAFETYFN": r["SAFETYFN"]["pass"]},
                    "ok": r["SAFETYFN"]["pass"]})
    shutil.rmtree(d)

    return results


def main():
    res = canaries()
    for r in res:
        print(("FIRED " if r["ok"] else "MISSED ") + r["id"] + " " + json.dumps(r["observed"]))
    fired = sum(1 for r in res if r["ok"])
    print(f"{fired}/{len(res)} canaries behaved as required")
    return 0 if fired == len(res) else 1


if __name__ == "__main__":
    sys.exit(main())
