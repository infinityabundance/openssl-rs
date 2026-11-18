#!/usr/bin/env python3
"""Canary harness for v1l_contract_audit.py.

Builds a private fixture tree (copies of the audited source files), applies one
mutation per violation class, and asserts the audit (a) passes on the pristine
copy and (b) FAILs the specific check on the mutated copy.  A mutation whose
anchor is absent is itself an error, so a canary cannot silently no-op.

Each mutation stands for one violation class:
  release-path      a stack element pushed without the reference the free owns
  registry-provenance  a free callback handed a pointer that is not a registry entry
  owner-identity    ex-data slot given a block the free callback must not own
  c-string          a caller passing a pointer with no NUL-termination contract
  cast-type         an i2v slot casting the value to a type the row's `it` does not produce
  row-pairing       a v2i builder attached to the wrong NID
  write-through-row  a callback writing through the read-only method row
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
FIXTURES = os.path.join(HERE, "fixtures")
AUDIT = os.path.join(HERE, "v1l_contract_audit.py")

FILES = [
    "src/decoder_lib.rs",
    "src/engine/eng_fat.rs",
    "src/engine/eng_cnf.rs",
    "src/runtime/confmod/mod.rs",
    "src/ui/ui_util.rs",
    "src/x509/v3_akid.rs",
    "src/x509/v3_san.rs",
    "src/x509/v3_prn.rs",
    "src/x509/v3_conf.rs",
    "src/x509/v3_lib.rs",
    "src/x509/v3_akeya.rs",
    "src/x509/v3_genn.rs",
]

# name -> (path, old, new, check-that-must-fail)
CANARIES = [
    (
        "release-path",
        "src/decoder_lib.rs",
        "if OSSL_DECODER_up_ref(decoder) != 0\n            && OPENSSL_sk_push(skdecoders, decoder.cast::<c_void>()) <= 0",
        "if OPENSSL_sk_push(skdecoders, decoder.cast::<c_void>()) <= 0",
        "C10 visitor up-refs before push",
    ),
    (
        "registry-provenance",
        "src/runtime/confmod/mod.rs",
        "OPENSSL_sk_push(to_delete, md.cast());",
        "OPENSSL_sk_push(to_delete, (*md).name.cast());",
        "C06 to_delete fed only from the published registry",
    ),
    (
        "double-release",
        "src/runtime/confmod/mod.rs",
        "                OPENSSL_sk_delete(new_modules, i);\n                OPENSSL_sk_push(to_delete, md.cast());",
        "                OPENSSL_sk_push(to_delete, md.cast());",
        "C06 entry removed from the published copy before handoff",
    ),
    (
        "owner-double-free",
        "src/ui/ui_util.rs",
        "    let _ = data.into_raw();",
        "",
        "C07 success path hands the block to the slot exactly once",
    ),
    (
        "owner-identity",
        "src/ui/ui_util.rs",
        "                UI_METHOD_DATA_INDEX.load(Ordering::Acquire),\n                data.as_ptr().cast::<c_void>(),",
        "                UI_METHOD_DATA_INDEX.load(Ordering::Acquire),\n                c\"foreign\".as_ptr().cast::<c_void>(),",
        "C07 every writer allocates through OwnedPwData",
    ),
    (
        "c-string",
        "src/engine/eng_fat.rs",
        "        unsafe { push_cstr_or_null(&mut msg, def_list) };",
        "        unsafe { push_cstr_or_null(&mut msg, def_list) };\n        unsafe { push_cstr_or_null(&mut msg, buf.as_ptr()) };",
        "C09 single call site passes a NUL-termination-contracted argument",
    ),
    (
        "cast-type",
        "src/x509/v3_san.rs",
        "i2v_GENERAL_NAMES(meth.cast_mut(), value.cast::<OpenSslStack>(), out)",
        "i2v_GENERAL_NAMES(meth.cast_mut(), value.cast::<GeneralName>(), out)",
        "C13 san_i2v casts value to OpenSslStack and calls i2v_GENERAL_NAMES",
    ),
    (
        "row-pairing",
        "src/x509/v3_san.rs",
        "    alt_row(NID_subject_alt_name, Some(san_v2i)),\n    alt_row(NID_issuer_alt_name, Some(san_v2i_issuer)),",
        "    alt_row(NID_subject_alt_name, Some(san_v2i_issuer)),\n    alt_row(NID_issuer_alt_name, Some(san_v2i)),",
        "C14/C15 the two alt rows pair each builder with its NID",
    ),
    (
        "write-through-row",
        "src/x509/v3_san.rs",
        "    let origret = ret;\n    let mut ret = ret;\n    // SAFETY: `gens` is live per the contract.",
        "    (*method).usr_data = core::ptr::null_mut();\n    let origret = ret;\n    let mut ret = ret;\n    // SAFETY: `gens` is live per the contract.",
        "C11-C15 no write through the table row (read-only static)",
    ),
]


def build(name, path, old, new):
    dst = os.path.join(FIXTURES, name)
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    for rel in FILES:
        target = os.path.join(dst, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(os.path.join(ROOT, rel), target)
    if old is not None:
        fp = os.path.join(dst, path)
        with open(fp, "r", encoding="utf-8") as f:
            src = f.read()
        n = src.count(old)
        if n != 1:
            raise SystemExit(f"canary {name}: anchor count {n} != 1 in {path}")
        with open(fp, "w", encoding="utf-8") as f:
            f.write(src.replace(old, new))
    return dst


def run(root):
    p = subprocess.run([sys.executable, AUDIT, "--root", root],
                       capture_output=True, text=True)
    return p.returncode, p.stdout


def main():
    os.makedirs(FIXTURES, exist_ok=True)
    pristine = build("pristine", None, None, None)
    rc, out = run(pristine)
    print(f"pristine fixture: exit={rc} (expected 0)")
    if rc != 0:
        print(out)
        return 1
    failures = 0
    for name, path, old, new, must_fail in CANARIES:
        dst = build(name, path, old, new)
        rc, out = run(dst)
        fired = any(line.startswith("FAIL " + must_fail) for line in out.splitlines())
        status = "FIRED" if (rc == 1 and fired) else "DID-NOT-FIRE"
        print(f"canary {name:20s} exit={rc} target='{must_fail}' -> {status}")
        if status != "FIRED":
            failures += 1
            print(out)
    print(f"summary: {len(CANARIES) - failures}/{len(CANARIES)} canaries fire; "
          "pristine copy silent")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
