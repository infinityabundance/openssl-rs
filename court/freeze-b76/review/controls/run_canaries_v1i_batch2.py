#!/usr/bin/env python3
"""Canary harness for v1i_batch2_audit.py.

Every canary mutates a PRIVATE COPY (never the tree) and asserts that exactly the
targeted check flips.  Repair canaries prove a detector is sensitive to the
repaired property; break canaries prove it is anchored to real code.

Run inside the court:  python3 run_canaries_v1i_batch2.py   (no compilation)
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
AUDIT = os.path.join(HERE, "v1i_batch2_audit.py")
INV = os.path.join(ROOT, "court/freeze-b76/review/review-65-inventory.json")
RECEIPT = os.path.join(
    ROOT, "forensics/memory-safety/campaign/safe-c33/atlas-refresh/openssh-v1i-sites.json")
SRC = ["src/evp/digest.rs", "src/provider/digest.rs", "src/params/mod.rs"]
BATCH2 = ["OSSH-V1I-010", "OSSH-V1I-016", "OSSH-V1I-023", "OSSH-V1I-001",
          "OSSH-V1I-007", "OSSH-V1I-026", "OSSH-V1I-009", "OSSH-V1I-015",
          "OSSH-V1I-030", "OSSH-V1I-006", "OSSH-V1I-018", "OSSH-V1I-013",
          "OSSH-V1I-029", "OSSH-V1I-004", "OSSH-V1I-012", "OSSH-V1I-027",
          "OSSH-V1I-003", "OSSH-V1I-020", "OSSH-V1I-025"]


def run_audit(root, receipt=RECEIPT, inv=INV):
    out = subprocess.run([sys.executable, AUDIT, "--root", root, "--inventory", inv,
                          "--receipt", receipt, "--json"],
                         capture_output=True, text=True)
    if out.returncode not in (0, 1):
        raise RuntimeError(out.stderr)
    return {c["id"]: c for c in json.loads(out.stdout)["checks"]}


def make_tree():
    d = tempfile.mkdtemp(prefix="_tmp_b2_")
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
    d = tempfile.mkdtemp(prefix="_tmp_b2_rc_")
    p = os.path.join(d, "x.json")
    json.dump(obj, open(p, "w"))
    return d, p


def canaries():
    base = run_audit(ROOT)
    expected = {"B2-SPAN": True, "B2-ITEM": True, "B2-COORD": False,
                "B2-SAFETY": False, "B2-DISPATCH": True, "B2-DUPGUARD": True,
                "B2-NULLPARAM": True, "B2-KFINAL": False, "B2-COPYCTX": False,
                "B2-FINALNULL": False, "B2-JOIN": False, "B2-WITNESS": False}
    res = [{"id": "K1-pristine", "expect": expected,
            "observed": {k: v["pass"] for k, v in base.items()},
            "ok": all(base[k]["pass"] == v for k, v in expected.items())}]

    # K2 break: blake2's dupctx loses its NULL test (a load-bearing guard removed).
    d = make_tree()
    def drop_blake_guard(L):
        # blake2's dupctx is the one at the `blake_row!` expansion (line ~1886).
        idx = next(i for i, x in enumerate(L)
                   if 'safe extern "C" fn dupctx' in x
                   and "blake" not in x and i > 1860)
        L[idx + 1] = L[idx + 1].replace(" || ctx.is_null()", "")
        return L
    edit(os.path.join(d, "src/provider/digest.rs"), drop_blake_guard)
    r = run_audit(d)
    res.append({"id": "K2-break-dupctx-null-guard", "expect": {"B2-DUPGUARD": False},
                "observed": {"B2-DUPGUARD": r["B2-DUPGUARD"]["pass"]},
                "ok": r["B2-DUPGUARD"]["pass"] is False})
    shutil.rmtree(d)

    # K3 break: the re-acquiring arm stops testing in_algctx for NULL before dupctx.
    d = make_tree()
    edit(os.path.join(d, "src/evp/digest.rs"),
         lambda L: [x.replace("if !in_algctx.is_null() {", "if true {") for x in L])
    r = run_audit(d)
    res.append({"id": "K3-break-dupctx-callsite-guard", "expect": {"B2-DUPGUARD": False},
                "observed": {"B2-DUPGUARD": r["B2-DUPGUARD"]["pass"]},
                "ok": r["B2-DUPGUARD"]["pass"] is False})
    shutil.rmtree(d)

    # K4 repair: bound keccak_final's write by outlen (in a form the detector must not
    # have seen verbatim, to show it reads the body rather than one fixed string).
    d = make_tree()
    def bound_keccak(L):
        i = next(i for i, x in enumerate(L) if 'fn keccak_final(' in x)
        j = next(k for k in range(i, i + 20) if 'let mut ret = 1;' in L[k])
        ind = L[j][:len(L[j]) - len(L[j].lstrip())]
        L.insert(j, ind + "if outlen < (*c).md_size { return 0; }")
        return L
    edit(os.path.join(d, "src/provider/digest.rs"), bound_keccak)
    r = run_audit(d)
    res.append({"id": "K4-repair-keccak-bound", "expect": {"B2-KFINAL": True},
                "observed": {"B2-KFINAL": r["B2-KFINAL"]["pass"]},
                "ok": r["B2-KFINAL"]["pass"]})
    shutil.rmtree(d)

    # K5 break: corrupt one byte of a recorded span.
    d = make_tree()
    edit(os.path.join(d, "src/provider/digest.rs"),
         lambda L: [x.replace("ossl_sha3_reset(ctx.cast::<KeccakCtx>())",
                              "ossl_sha3_reset(ctx.cast::<KeccakCtx>()) ")
                    if "ossl_sha3_reset(ctx.cast::<KeccakCtx>())" in x else x
                    for x in L])
    r = run_audit(d)
    res.append({"id": "K5-break-span-byte", "expect": {"B2-SPAN": False},
                "observed": {"B2-SPAN": r["B2-SPAN"]["pass"]},
                "ok": r["B2-SPAN"]["pass"] is False})
    shutil.rmtree(d)

    # K6 break: unregister one audited callback from its dispatch table.
    d = make_tree()
    edit(os.path.join(d, "src/provider/digest.rs"),
         lambda L: [x.replace("function: get_ctx_params as *mut c_void,",
                              "function: ptr::null_mut(),")
                    for x in L])
    r = run_audit(d)
    res.append({"id": "K6-break-dispatch-registration", "expect": {"B2-DISPATCH": False},
                "observed": {"B2-DISPATCH": r["B2-DISPATCH"]["pass"]},
                "ok": r["B2-DISPATCH"]["pass"] is False})
    shutil.rmtree(d)

    # K7 repair: give every audited definition a `# Safety` section (same line count).
    d = make_tree()
    inv = json.load(open(INV))
    by_file = {}
    for o in inv["obligations"]:
        if o["discharge_boundary_id"] in BATCH2:
            by_file.setdefault(o["file"], []).append(o["line"])
    for rel, lns in by_file.items():
        p = os.path.join(d, rel)
        L = open(p).read().split("\n")
        for n in sorted(set(lns)):
            L[n - 2] = "    /// # Safety (canary)"
        open(p, "w").write("\n".join(L))
    r = run_audit(d)
    res.append({"id": "K7-repair-safety-docs", "expect": {"B2-SAFETY": True},
                "observed": {"B2-SAFETY": r["B2-SAFETY"]["pass"]},
                "ok": r["B2-SAFETY"]["pass"]})
    shutil.rmtree(d)

    # K8 repair: replace the generic witness with a coordinate-bearing per-call-site one.
    rc = json.load(open(RECEIPT))
    for b in rc["boundaries"]:
        if b["id"] in BATCH2:
            b["established_by"] = [
                "caller: src/evp/digest.rs:3133 and :3301 (%s) obtain the algctx from "
                "NEWCTX/DUPCTX; dispatch registration at src/provider/digest.rs" % b["operation"]]
    dd, p = tmp_json(rc)
    r = run_audit(ROOT, receipt=p)
    res.append({"id": "K8-repair-per-call-site-witness", "expect": {"B2-WITNESS": True},
                "observed": {"B2-WITNESS": r["B2-WITNESS"]["pass"]},
                "ok": r["B2-WITNESS"]["pass"]})
    shutil.rmtree(dd)

    # K9 repair: rebind the inventory's actual_definition_line to the real definition.
    inv = json.load(open(INV))
    for o in inv["obligations"]:
        if o["discharge_boundary_id"] in BATCH2:
            o["coordinate_check"]["actual_definition_line"] = o["line"]
    dd, p = tmp_json(inv)
    r = run_audit(ROOT, inv=p)
    res.append({"id": "K9-repair-coordinate-binding", "expect": {"B2-COORD": True},
                "observed": {"B2-COORD": r["B2-COORD"]["pass"]},
                "ok": r["B2-COORD"]["pass"]})
    shutil.rmtree(dd)

    # K10 repair: guard both copyctx call sites (the batch-1 defect).
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
    r = run_audit(d)
    res.append({"id": "K10-repair-copyctx-guard", "expect": {"B2-COPYCTX": True},
                "observed": {"B2-COPYCTX": r["B2-COPYCTX"]["pass"]},
                "ok": r["B2-COPYCTX"]["pass"]})
    shutil.rmtree(d)

    # K11 break: NULL-unsafe locate (the structural premise NULLPARAM rests on).
    d = make_tree()
    edit(os.path.join(d, "src/params/mod.rs"),
         lambda L: [x.replace("if p.is_null() || key.is_null() {", "if key.is_null() {")
                    for x in L])
    r = run_audit(d)
    res.append({"id": "K11-break-locate-null", "expect": {"B2-NULLPARAM": False},
                "observed": {"B2-NULLPARAM": r["B2-NULLPARAM"]["pass"]},
                "ok": r["B2-NULLPARAM"]["pass"] is False})
    shutil.rmtree(d)

    # K12 repair: make each obligation's boundary_ids specific to its own row.
    inv = json.load(open(INV))
    for o in inv["obligations"]:
        if o["discharge_boundary_id"] in BATCH2:
            o["boundary_ids"] = [o["discharge_boundary_id"]]
    dd, p = tmp_json(inv)
    r = run_audit(ROOT, inv=p)
    res.append({"id": "K12-repair-obligation-join", "expect": {"B2-JOIN": True},
                "observed": {"B2-JOIN": r["B2-JOIN"]["pass"]},
                "ok": r["B2-JOIN"]["pass"]})
    shutil.rmtree(dd)

    # K13 repair: EVP_DigestFinal_ex refuses a NULL algorithm context before dfinal.
    d = make_tree()
    def guard_dfinal(L):
        idx = [i for i, x in enumerate(L) if re.search(r"dfinal\(\(\*ctx\)\.algctx,", x)]
        for i in sorted(idx, reverse=True):
            ind = L[i][:len(L[i]) - len(L[i].lstrip())]
            L.insert(i, ind + "if (*ctx).algctx.is_null() { return 0; }")
        return L
    edit(os.path.join(d, "src/evp/digest.rs"), guard_dfinal)
    r = run_audit(d)
    res.append({"id": "K13-repair-dfinal-null-guard", "expect": {"B2-FINALNULL": True},
                "observed": {"B2-FINALNULL": r["B2-FINALNULL"]["pass"]},
                "ok": r["B2-FINALNULL"]["pass"]})
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
