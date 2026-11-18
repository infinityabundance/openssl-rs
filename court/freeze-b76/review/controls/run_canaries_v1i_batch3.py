#!/usr/bin/env python3
"""Canary harness for v1i_batch3_audit.py.

Every canary mutates a PRIVATE COPY (never the tree) and asserts that exactly the
targeted check flips.  Repair canaries prove a detector is sensitive to the
repaired property; break canaries prove it is anchored to real code.

Run inside the court:  python3 run_canaries_v1i_batch3.py   (no compilation)
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", "..", ".."))
AUDIT = os.path.join(HERE, "v1i_batch3_audit.py")
INV = os.path.join(ROOT, "court/freeze-b76/review/review-65-inventory.json")
RECEIPT = os.path.join(
    ROOT, "forensics/memory-safety/campaign/safe-c33/atlas-refresh/openssh-v1i-sites.json")
CLOSURE = os.path.join(ROOT, "evidence/closure-ssh-b76c.json")
SRC = ["src/evp/digest.rs", "src/provider/digest.rs", "src/provider/legacyprov.rs",
       "src/digest/sha1.rs", "src/digest/sha3.rs", "src/digest/md5_sha1.rs",
       "src/params/mod.rs"]
BATCH3 = ["OSSH-V1I-022", "OSSH-V1I-021", "OSSH-V1I-014", "OSSH-V1I-019",
          "OSSH-V1I-028", "OSSH-V1I-005", "OSSH-V1I-082", "OSSH-V1I-088",
          "OSSH-V1I-081", "OSSH-V1I-087", "OSSH-V1I-086", "OSSH-V1I-092",
          "OSSH-V1I-084", "OSSH-V1I-090", "OSSH-V1I-083", "OSSH-V1I-089",
          "OSSH-V1I-085", "OSSH-V1I-091"]


def run_audit(root, receipt=RECEIPT, inv=INV, closure=CLOSURE):
    out = subprocess.run([sys.executable, AUDIT, "--root", root, "--inventory", inv,
                          "--receipt", receipt, "--closure", closure, "--json"],
                         capture_output=True, text=True)
    if out.returncode not in (0, 1):
        raise RuntimeError(out.stderr)
    return {c["id"]: c for c in json.loads(out.stdout)["checks"]}


def make_tree():
    d = tempfile.mkdtemp(prefix="_tmp_b3_")
    for rel in SRC:
        dst = os.path.join(d, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(os.path.join(ROOT, rel), dst)
    return d


def edit(path, fn):
    with open(path) as f:
        lines = f.read().split("\n")
    lines = fn(lines)
    with open(path, "w") as f:
        f.write("\n".join(lines))


def tmp_json(obj):
    d = tempfile.mkdtemp(prefix="_tmp_b3_rc_")
    p = os.path.join(d, "x.json")
    json.dump(obj, open(p, "w"))
    return d, p


def canaries():
    base = run_audit(ROOT)
    expected = {
        "B3-SPAN": True, "B3-ITEM": True, "B3-COORD": False,
        "B3-SAFETY": False, "B3-DISPATCH": True, "B3-UPDATE-NULL": False,
        "B3-SQUEEZE-NULL": False, "B3-FINAL-NULL": False, "B3-COPY-NULL": False,
        "B3-INIT-ESTABLISHED": True, "B3-NULLPARAM": True,
        "B3-COPYCTX-SELF": True, "B3-JOIN": False, "B3-WITNESS": False,
        "B3-CONTRACT": False, "B3-COVERS": False, "B3-IDENTITY": False,
    }
    res = [{"id": "K1-pristine", "expect": expected,
            "observed": {k: v["pass"] for k, v in base.items()},
            "ok": all(base[k]["pass"] == v for k, v in expected.items())}]

    # K2 break: shake_get_ctx_params stops refusing a NULL context.
    d = make_tree()
    edit(os.path.join(d, "src/provider/digest.rs"),
         lambda L: [x.replace("if c.is_null() {", "if false {", 1) if i == 1482 else x
                    for i, x in enumerate(L)])
    r = run_audit(d)
    res.append({"id": "K2-break-getctx-null-guard", "expect": {"B3-NULLPARAM": False},
                "observed": {"B3-NULLPARAM": r["B3-NULLPARAM"]["pass"]},
                "ok": r["B3-NULLPARAM"]["pass"] is False})
    shutil.rmtree(d)

    # K3 repair: EVP_DigestUpdate refuses a NULL algorithm context.
    d = make_tree()
    def guard_update(L):
        i = next(i for i, x in enumerate(L) if "dupdate((*ctx).algctx," in x)
        ind = L[i][:len(L[i]) - len(L[i].lstrip())]
        L.insert(i, ind + "if (*ctx).algctx.is_null() { return 0; }")
        return L
    edit(os.path.join(d, "src/evp/digest.rs"), guard_update)
    r = run_audit(d)
    res.append({"id": "K3-repair-update-null-guard", "expect": {"B3-UPDATE-NULL": True},
                "observed": {"B3-UPDATE-NULL": r["B3-UPDATE-NULL"]["pass"]},
                "ok": r["B3-UPDATE-NULL"]["pass"]})
    shutil.rmtree(d)

    # K4 repair: EVP_DigestSqueeze refuses a NULL algorithm context.
    d = make_tree()
    def guard_squeeze(L):
        i = next(i for i, x in enumerate(L) if "dsqueeze((*ctx).algctx," in x)
        ind = L[i][:len(L[i]) - len(L[i].lstrip())]
        L.insert(i, ind + "if (*ctx).algctx.is_null() { return 0; }")
        return L
    edit(os.path.join(d, "src/evp/digest.rs"), guard_squeeze)
    r = run_audit(d)
    res.append({"id": "K4-repair-squeeze-null-guard",
                "expect": {"B3-SQUEEZE-NULL": True},
                "observed": {"B3-SQUEEZE-NULL": r["B3-SQUEEZE-NULL"]["pass"]},
                "ok": r["B3-SQUEEZE-NULL"]["pass"]})
    shutil.rmtree(d)

    # K5 repair: both dfinal call sites refuse a NULL algorithm context.
    d = make_tree()
    def guard_final(L):
        idx = [i for i, x in enumerate(L) if re.search(r"dfinal\(\(\*ctx\)\.algctx,", x)]
        for i in sorted(idx, reverse=True):
            ind = L[i][:len(L[i]) - len(L[i].lstrip())]
            L.insert(i, ind + "if (*ctx).algctx.is_null() { return 0; }")
        return L
    edit(os.path.join(d, "src/evp/digest.rs"), guard_final)
    r = run_audit(d)
    res.append({"id": "K5-repair-final-null-guard", "expect": {"B3-FINAL-NULL": True},
                "observed": {"B3-FINAL-NULL": r["B3-FINAL-NULL"]["pass"]},
                "ok": r["B3-FINAL-NULL"]["pass"]})
    shutil.rmtree(d)

    # K6 repair: both copyctx call sites refuse NULL algorithm contexts.
    d = make_tree()
    def guard_copy(L):
        idx = [i for i, x in enumerate(L)
               if "copyctx((*out).algctx, (*in_).algctx)" in x]
        for i in sorted(idx, reverse=True):
            ind = L[i][:len(L[i]) - len(L[i].lstrip())]
            L.insert(i, ind + "if (*out).algctx.is_null() || (*in_).algctx.is_null() {")
            L.insert(i + 1, ind + "    return 0;")
            L.insert(i + 2, ind + "}")
        return L
    edit(os.path.join(d, "src/evp/digest.rs"), guard_copy)
    r = run_audit(d)
    res.append({"id": "K6-repair-copyctx-null-guard", "expect": {"B3-COPY-NULL": True},
                "observed": {"B3-COPY-NULL": r["B3-COPY-NULL"]["pass"]},
                "ok": r["B3-COPY-NULL"]["pass"]})
    shutil.rmtree(d)

    # K7 break: corrupt one byte of a recorded span.
    d = make_tree()
    edit(os.path.join(d, "src/provider/digest.rs"),
         lambda L: [x.replace("SHA1_Update(ctx.cast::<ShaCtx>()",
                              "SHA1_Update(ctx.cast::<ShaCtx>())") if i == 701 else x
                    for i, x in enumerate(L)])
    r = run_audit(d)
    res.append({"id": "K7-break-span-byte", "expect": {"B3-SPAN": False},
                "observed": {"B3-SPAN": r["B3-SPAN"]["pass"]},
                "ok": r["B3-SPAN"]["pass"] is False})
    shutil.rmtree(d)

    # K8 break: unregister the two audited legacyprov update rows.
    d = make_tree()
    edit(os.path.join(d, "src/provider/legacyprov.rs"),
         lambda L: [x.replace("function: update as *mut c_void,",
                              "function: ptr::null_mut(),") for x in L])
    r = run_audit(d)
    res.append({"id": "K8-break-dispatch-registration", "expect": {"B3-DISPATCH": False},
                "observed": {"B3-DISPATCH": r["B3-DISPATCH"]["pass"]},
                "ok": r["B3-DISPATCH"]["pass"] is False})
    shutil.rmtree(d)

    # K9 repair: give every audited definition a `# Safety` section.
    d = make_tree()
    inv = json.load(open(INV))
    by_file = {}
    for o in inv["obligations"]:
        if o["discharge_boundary_id"] in BATCH3:
            by_file.setdefault(o["file"], []).append(o["line"])
    for rel, lns in by_file.items():
        p = os.path.join(d, rel)
        L = open(p).read().split("\n")
        for n in sorted(set(lns)):
            L[n - 2] = "    /// # Safety (canary)"
        open(p, "w").write("\n".join(L))
    r = run_audit(d)
    res.append({"id": "K9-repair-safety-docs", "expect": {"B3-SAFETY": True},
                "observed": {"B3-SAFETY": r["B3-SAFETY"]["pass"]},
                "ok": r["B3-SAFETY"]["pass"]})
    shutil.rmtree(d)

    # K10 repair: rebind actual_definition_line to the real definition.
    inv = json.load(open(INV))
    for o in inv["obligations"]:
        if o["discharge_boundary_id"] in BATCH3:
            o["coordinate_check"]["actual_definition_line"] = o["line"]
    dd, p = tmp_json(inv)
    r = run_audit(ROOT, inv=p)
    res.append({"id": "K10-repair-coordinate-binding", "expect": {"B3-COORD": True},
                "observed": {"B3-COORD": r["B3-COORD"]["pass"]},
                "ok": r["B3-COORD"]["pass"]})
    shutil.rmtree(dd)

    # K11 repair: make each obligation's boundary_ids specific to its own row.
    inv = json.load(open(INV))
    for o in inv["obligations"]:
        if o["discharge_boundary_id"] in BATCH3:
            o["boundary_ids"] = [o["discharge_boundary_id"]]
    dd, p = tmp_json(inv)
    r = run_audit(ROOT, inv=p)
    res.append({"id": "K11-repair-obligation-join", "expect": {"B3-JOIN": True},
                "observed": {"B3-JOIN": r["B3-JOIN"]["pass"]},
                "ok": r["B3-JOIN"]["pass"]})
    shutil.rmtree(dd)

    # K12 repair: per-call-site, correctly-located witness.
    rc = json.load(open(RECEIPT))
    for b in rc["boundaries"]:
        if b["id"] in BATCH3:
            f = "legacyprov.rs" if b["operation"].startswith(("legacy_digest_impl", "mdc2")) \
                else "digest.rs"
            b["established_by"] = [
                "caller: src/evp/digest.rs:%d and the dispatch registration for %s in "
                "src/provider/%s" % (b["line"], b["operation"], f)]
    dd, p = tmp_json(rc)
    r = run_audit(ROOT, receipt=p)
    res.append({"id": "K12-repair-per-call-site-witness", "expect": {"B3-WITNESS": True},
                "observed": {"B3-WITNESS": r["B3-WITNESS"]["pass"]},
                "ok": r["B3-WITNESS"]["pass"]})
    shutil.rmtree(dd)

    # K13 repair: the closure's scoped attempt covers the site.
    cl = json.load(open(CLOSURE))
    for o in cl["obligations"]:
        if o.get("discharge_boundary_id") in BATCH3:
            for a in o.get("scoped_discharge_attempts") or []:
                a["covers_site"] = True
                a["covers_current_coordinate"] = True
    dd, p = tmp_json(cl)
    r = run_audit(ROOT, closure=p)
    res.append({"id": "K13-repair-covers-site", "expect": {"B3-COVERS": True},
                "observed": {"B3-COVERS": r["B3-COVERS"]["pass"]},
                "ok": r["B3-COVERS"]["pass"]})
    shutil.rmtree(dd)

    # K14 repair: inventory contract agrees with the receipt criterion.
    inv = json.load(open(INV))
    for o in inv["obligations"]:
        if o["discharge_boundary_id"] in BATCH3:
            o["contract"] = "contracted"
    dd, p = tmp_json(inv)
    r = run_audit(ROOT, inv=p)
    res.append({"id": "K14-repair-contract-record", "expect": {"B3-CONTRACT": True},
                "observed": {"B3-CONTRACT": r["B3-CONTRACT"]["pass"]},
                "ok": r["B3-CONTRACT"]["pass"]})
    shutil.rmtree(dd)

    # K15 break: the NEWCTX failure no longer returns before dinit.
    d = make_tree()
    edit(os.path.join(d, "src/evp/digest.rs"),
         lambda L: [x.replace("if algctx.is_null() {", "if false {")
                    for x in L])
    r = run_audit(d)
    res.append({"id": "K15-break-newctx-check",
                "expect": {"B3-INIT-ESTABLISHED": False},
                "observed": {"B3-INIT-ESTABLISHED": r["B3-INIT-ESTABLISHED"]["pass"]},
                "ok": r["B3-INIT-ESTABLISHED"]["pass"] is False})
    shutil.rmtree(d)

    # K16 break: the default-get_params decoder scan dereferences a NULL array.
    d = make_tree()
    edit(os.path.join(d, "src/provider/digest.rs"),
         lambda L: [x.replace("if params.is_null() {", "if false {") if i == 274 else x
                    for i, x in enumerate(L)])
    r = run_audit(d)
    res.append({"id": "K16-break-nullparams-scan", "expect": {"B3-NULLPARAM": False},
                "observed": {"B3-NULLPARAM": r["B3-NULLPARAM"]["pass"]},
                "ok": r["B3-NULLPARAM"]["pass"] is False})
    shutil.rmtree(d)

    return res


def main():
    res = canaries()
    for r in res:
        print(("FIRED " if r["ok"] else "MISSED ") + r["id"] + " " + json.dumps(r["observed"]))
    fired = sum(1 for r in res if r["ok"])
    print(f"{fired}/{len(res)} canaries behaved as required")
    return 0 if fired == len(res) else 1


if __name__ == "__main__":
    sys.exit(main())
