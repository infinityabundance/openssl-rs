#!/usr/bin/env python3
"""openssl-rs — Phase 10 courts: key formats, PKCS#12 and STORE.

Each court is a C probe in `courts/phase10/` compiled **twice** — once against the admitted
authority, once against the candidate distribution shell — and run. The two transcripts are
compared line by line, and every difference is a residual.

The method is Phases 3-9's, for the same reason: a unit test encodes what its author believes the
contract is, whereas a probe measures what the authority actually does, and the comparison is
between two *executions* of the same program, so the expectation cannot drift.

`RT-KEYFORMAT-REF` is the one court this stratum can register, and what it claims
-------------------------------------------------------------------------------
The stratum's own work has landed nothing: no codec row, no PKCS#12 container, no STORE module,
no hand-off. What it *has* is eighty-seven exports an earlier stratum landed and it now owns —
the 38 `encoder.h` and 41 `decoder.h` exports of Phase 8's 8.8/8.9 chain (D362-D367) and the
eight `pkcs12.h` decryption and PKCS#8 names of D368 — and `court_coverage.py` refuses a
stratum that has begun while any of its implemented exports has no court edge. So this runner
lands `RT-KEYFORMAT-REF`, `courts/phase10/rt_coverage_ref_probe.c`: it takes each of the
eighty-seven's address through a `volatile` table, prints one `coverage_ref.N=nonnull` line per
symbol, and stops. **It does not call any of them and claims no behaviour about them.** The
court coverage atlas records every symbol covered only by it at basis `referenced`, never
`called`, because the probe's name is in that atlas's `reference_probes` table; the atlas's
`claim` is the weaker, true statement. See docs/DECISIONS.md D199 and
docs/PHASE-10-SUBPHASES.md section 4.3, which is where this stratum's activation requires it.

A court the plan names and this stratum cannot run yet is NOT registered here. It is named in
`PENDING_COURTS` with the subphase and the corpus or precondition that brings it, and every name
is printed on each run, so "not run yet" cannot be read as "passed" — the contract Phase 8's
`PENDING_CORRECTNESS_COURTS` and Phase 9's activation both established.

What the pending courts will establish, and what they will not
--------------------------------------------------------------
`RT-CODEC` and `RT-KEYFORMAT` compare the authority's *bytes* for the codecs and the hand-off
helpers: `OSSL_ENCODER_to_data`/`to_bio`/`to_fp`'s exact output, the error queue and coordinate
for a malformed input, the alias and selection behaviour under `set_output_type`/`set_selection`,
and the same shape for the `d2i_*`/`i2d_*`/`PEM_*` pairs. `RT-PKCS12` (10.2) compares the
`PKCS12_SAFEBAG`/`PKCS12_BAGS`/`PKCS12_MAC_DATA` item groups' DER rather than a parsed structure,
and `CT-PKCS12` checks the PKCS#12 KDF and PBE outputs against the vectors the pinned tree
already carries. None of them can claim that a codec which
round-trips is a codec: a transcription whose encoder writes and whose decoder reads back is a
different library, and docs/PHASE-10-SUBPHASES.md section 3.1 records the three joins that make
the difference observable. Nothing here is a parity claim about a key's meaning (section 3.5).

SPDX-License-Identifier: Apache-2.0"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import correctness_vectors as cv  # noqa: E402

from atlas_common import (  # noqa: E402
    PRODUCTION_AUTHORITY,
    REPO_ROOT,
    InputRef,
    envelope,
    rel,
    resolve_authority,
    run,
    write_json,
)

OUT = REPO_ROOT / "artifacts" / "phase10" / "COURTS.json"
GENERATOR = "forensics/tools/phase10_courts.py"
PROBE_DIR = REPO_ROOT / "courts" / "phase10"
PHASE2 = REPO_ROOT / "artifacts" / "phase2"
STAGED = REPO_ROOT / "artifacts" / "phase10" / "probes"
RUN_TIMEOUT_S = "60"

# The differential courts, in the order they land. `(name, probe filename)`, and the probe is
# declared in the same commit as the entry, so a runner that names a probe which does not exist
# cannot be committed -- the check below fails instead.
#
# **One entry, and it is the reference basis rather than a behavioural court.** It is registered
# because the eighty-seven exports this stratum inherited are implemented and
# `court_coverage.py` requires an edge for each; it is the only probe this stratum can link,
# since none of its own rows is implemented. See the module doc.
COURTS: list[tuple[str, str]] = [
    ("RT-KEYFORMAT-REF", "rt_coverage_ref_probe.c"),
    # 10.1's behavioural court: the `OSSL_OP_ENCODER` text and blob rows the first provider codec
    # units land (`encode_key2text.c`, `encode_key2blob.c`), driven through `OSSL_ENCODER_fetch`
    # and `OSSL_ENCODER_CTX_new_for_pkey`, and the one `OSSL_OP_DECODER` row `decode_epki2pki.c`
    # lands, driven through `OSSL_DECODER_fetch` and `OSSL_DECODER_from_data`.
    ("RT-CODEC", "rt_codec_probe.c"),
    # 10.6's behavioural court: the twenty-six `d2i_*`/`i2d_*`/`PEM_*`/`b2i_*`/`i2b_*` hand-off names
    # the five authority units publish, driven with fixed legacy keys and compared byte for byte.
    ("RT-KEYFORMAT", "rt_keyformat_probe.c"),
    # 10.2's and 10.3's behavioural court: the `PKCS12_SAFEBAG`/`PKCS12_BAGS`/`PKCS12_MAC_DATA`
    # item groups `p12_asn.c` lands, the `SafeBag` accessors and constructors `p12_sbag.c`
    # lands, the attribute helpers of `p12_attr.c` and the Unicode conversions of `p12_utl.c`,
    # plus 10.3's `PKCS12_item_pack_safebag`, the two `PKCS12_decrypt_skey` spellings and
    # `PKCS12_add_secret`, driven through the public `pkcs12.h` surface and compared as DER bytes
    # rather than a parsed structure (docs/PHASE-10-SUBPHASES.md section 3.2).
    ("RT-PKCS12", "rt_pkcs12_probe.c"),
]

# The construction court, beside the differential four. It is candidate-only and driven by
# `correctness_vectors.py`, which owns the record shape (D201): a `CT-*` court answers "does it
# satisfy the underlying construction?", which the differential plane cannot, and the differential
# four answer "does it behave like the admitted authority?", which a vector set cannot. Neither
# implies the other. `CT-PKCS12` is 10.4's: the PKCS#12 KDF's `Key` values are a fixed vector, and
# the pinned corpus's `evppbe_pkcs12.txt` carries six of them.
CORRECTNESS_COURTS: list[str] = ["CT-PKCS12"]

# A court the plan names and this stratum cannot run yet. Not a registered court: nothing here
# can pass, and each is printed with the subphase that brings it so that "not run yet" cannot be
# read as "passed".
PENDING_COURTS: dict[str, str] = {
    "RT-STORE": "10.5 -- `OSSL_STORE_open(_ex)` and the `file` loader, the `OSSL_STORE_INFO` "
                "type and its constructor/accessor family, the `OSSL_STORE_LOADER` object and "
                "its registry, and the `OSSL_STORE_SEARCH` family: the `OSSL_STORE_INFO` type "
                "and refcount surface, the `eof`/`error`/`expect` state machine, and the "
                "refusal arms (an unknown scheme, a NULL URI, a loader that answers a NULL "
                "`load`) with the error queue. The loader's sub-fetches resolve in the "
                "publishing provider's library context (D240) and the decoder arm lands after "
                "10.4's pair, so it cannot be written before then "
                "(docs/PHASE-10-SUBPHASES.md section 3.3).",
}


def extra_defs(name: str, libdir: Path) -> list[str]:
    """Per-side build definitions.

    **None.** The one probe this stratum registers takes addresses and prints whether each is
    non-NULL; it is compiled identically on both sides, so a difference in its transcript could
    only be a difference in what the library defines. `extra_defs` is kept because the runner's
    shape is Phase 8's and Phase 9's and a later court here may need one.
    """
    del name, libdir
    return []


def compile_probe(
    src: Path, out: Path, include: Path, libdir: Path, defs: list[str] | None = None
) -> tuple[bool, str]:
    res = run([
        # `-Werror=implicit-function-declaration` is not decoration: without a prototype, C
        # assumes a function returns `int`, so a probe that forgot an include reads a pointer
        # return as its low 32 bits and dereferences it. Phases 6 and 7 both paid a run to learn
        # that, so it is a compile failure here.
        "clang", "-std=c11", "-Wall", "-Werror=implicit-function-declaration", "-O1",
        "-D_GNU_SOURCE",
        *(defs or []),
        "-I", str(include),
        "-o", str(out), str(src),
        "-L", str(libdir), "-lcrypto",
        f"-Wl,-rpath,{libdir}",
    ])
    return res.ok, res.stderr.strip()


def run_probe(binary: Path) -> tuple[str, str, int | None]:
    res = run(["timeout", RUN_TIMEOUT_S, str(binary)])
    code = res.returncode
    if code == 124:
        return res.stdout, res.stderr, None
    return res.stdout, res.stderr, code


def diff(authority: str, candidate: str) -> list[dict]:
    """Line-wise comparison keyed on `key=value`, so a missing or extra line
    produces exactly one residual instead of shifting every following line."""
    def parse(text: str) -> tuple[list[str], dict[str, str]]:
        order: list[str] = []
        values: dict[str, str] = {}
        for line in text.splitlines():
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            if key not in values:
                order.append(key)
                values[key] = value
            else:
                values[key] = f"{values[key]}|{value}"
        return order, values

    a_order, a = parse(authority)
    c_order, c = parse(candidate)
    residuals: list[dict] = []
    for key in a_order:
        if key not in c:
            residuals.append({"observation": key, "authority": a[key],
                              "candidate": None, "class": "missing"})
        elif a[key] != c[key]:
            residuals.append({"observation": key, "authority": a[key],
                              "candidate": c[key], "class": "value"})
    for key in c_order:
        if key not in a:
            residuals.append({"observation": key, "authority": None,
                              "candidate": c[key], "class": "extra"})
    return residuals


def court(name: str, src: Path, auth, work: Path) -> dict:
    auth_lib = auth.prefix / "lib"
    auth_inc = auth.prefix / "include"

    auth_bin = work / f"{src.stem}.authority"
    cand_bin = work / f"{src.stem}.candidate"

    ok, err = compile_probe(src, auth_bin, auth_inc, auth_lib,
                            extra_defs(name, auth_lib))
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-authority",
                "detail": err.splitlines()[:12]}
    ok, err = compile_probe(src, cand_bin, PHASE2 / "include", PHASE2,
                            extra_defs(name, PHASE2))
    if not ok:
        return {"court": name, "verdict": "fail", "stage": "compile-candidate",
                "detail": err.splitlines()[:12]}

    a_out, a_err, a_code = run_probe(auth_bin)
    c_out, c_err, c_code = run_probe(cand_bin)

    staged = {}
    STAGED.mkdir(parents=True, exist_ok=True)
    for side, srcbin in (("authority", auth_bin), ("candidate", cand_bin)):
        dst = STAGED / f"{srcbin.stem}.{side}"
        if srcbin.is_file():
            shutil.copyfile(srcbin, dst)
            dst.chmod(0o755)
            staged[side] = rel(dst)

    if not a_out.strip():
        return {"court": name, "verdict": "fail", "stage": "authority-run",
                "detail": {"exit_code": a_code,
                           "stderr": a_err.splitlines()[:12]}}

    residuals = diff(a_out, c_out)
    # A probe that died on a signal compared nothing beyond the prefix it managed
    # to print, so two sides dying the same way is not agreement.
    crashed = a_code is None or a_code < 0 or c_code is None or c_code < 0
    return {
        "court": name,
        "probe": rel(src),
        "authority_exit_code": a_code,
        "candidate_exit_code": c_code,
        "crashed": crashed,
        "authority_observations": len([l for l in a_out.splitlines() if "=" in l]),
        "candidate_observations": len([l for l in c_out.splitlines() if "=" in l]),
        "residual_count": len(residuals),
        "residuals": residuals,
        "verdict": (
            "pass" if not residuals and c_code == a_code and not crashed else "fail"
        ),
        "staged_binaries": staged,
        "candidate_stderr_tail": c_err.splitlines()[-3:],
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--authority", default=PRODUCTION_AUTHORITY)
    args = ap.parse_args(argv)
    del args

    auth = resolve_authority(PRODUCTION_AUTHORITY)
    work = REPO_ROOT / "court" / "phase10"
    work.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    for name, filename in COURTS:
        src = PROBE_DIR / filename
        if not src.is_file():
            records.append({"court": name, "verdict": "fail",
                            "stage": "probe-missing", "detail": rel(src)})
            continue
        records.append(court(name, src, auth, work))

    for name in CORRECTNESS_COURTS:
        if name == "CT-PKCS12":
            records.append(cv.run_pkcs12_court(name, work_dir=work, authority_id=auth.id))
        else:
            raise SystemExit(f"[{GENERATOR}] no driver for correctness court {name}")

    passed = sum(1 for r in records if r["verdict"] == "pass")
    body = {
        "all_pass": passed == len(records),
        "authority": auth.id,
        "courts": records,
        "summary": {"total": len(records), "pass": passed,
                    "fail": len(records) - passed},
        "pending_courts": PENDING_COURTS,
        "claim": (
            "`RT-KEYFORMAT-REF` is a **reference-basis** court: its probe takes the address "
            "of each of this stratum's eighty-seven inherited `implemented` exports and prints "
            "whether each is non-NULL. A symbol covered only by it means the candidate "
            "distribution defines the name -- which the link proves -- and NOT that any arm of "
            "it was driven; the court coverage atlas records those at basis `referenced`, never "
            "`called` (docs/DECISIONS.md D199). "
            "`RT-CODEC` is this stratum's first **behavioural** court (10.1): it drives the "
            "twenty-nine text and blob encoder rows `encode_key2text.c` and `encode_key2blob.c` "
            "publish through the "
            "public `OSSL_ENCODER_*` surface and the one `EncryptedPrivateKeyInfo` decoder "
            "`decode_epki2pki.c` publishes through `OSSL_DECODER_*`, observing each row's identity "
            "(`OSSL_ENCODER_fetch`/`OSSL_DECODER_fetch`'s name and properties), its exact bytes "
            "(`OSSL_ENCODER_to_data`/`OSSL_DECODER_from_data` with a construct callback), and a "
            "refusal arm for each unit with the error queue. Since 10.6 it also drives the four "
            "`msblob`/`pvk` encoder rows `encode_key2ms.c` publishes and the four `msblob`/`pvk` "
            "decoder rows `decode_msblob2key.c`/`decode_pvk2key.c` publish, in both providers: "
            "identity, a fixed RSA and 160-bit-`q` DSA keypair encoded to each output at the "
            "unencrypted level and the bytes fed back through the matching decoder row, and the "
            "selection and short-header refusals. It is a differential compatibility "
            "claim about those rows, NOT that the other 572 rows or the remaining decoders are "
            "implemented. "
            "`pending_courts` names the courts the plan gives this stratum and the "
            "subphase that brings each, and every name is printed on each run so that 'not run "
            "yet' cannot be read as 'passed' (docs/PHASE-10-SUBPHASES.md sections 3 and 4.3). "
            "`RT-KEYFORMAT` is 10.6's behavioural court: it drives the twenty-four landed "
            "`d2i_*`/`i2d_*`/`PEM_*`/`b2i_*`/`i2b_*` hand-off names with fixed RSA, DSA and EC "
            "keys, compares the exact bytes and each malformed-input arm's error queue, and "
            "references the two `i2d_PKCS8PrivateKey_nid_*` writers held pending because "
            "`PKCS8_encrypt` (10.4) is unlanded. "
            "`RT-PKCS12` is 10.2's and 10.3's behavioural court: it builds the `PKCS12_SAFEBAG`/"
            "`PKCS12_BAGS`/`PKCS12_MAC_DATA` item groups from fixed inputs and fixed hand-written "
            "DER fixtures, prints their bytes, and drives the `SafeBag` accessor surface, the "
            "attribute helpers and the `OPENSSL_{asc2uni,uni2asc,utf82uni,uni2utf8}` conversions, "
            "the ownership adoption of the `create0_*` constructors and the refusal arms with "
            "their error coordinates. Since 10.3 it also drives the four exports of that subphase "
            "contains the fixed `PKCS8_PRIV_KEY_INFO` packed as a `certBag`, printed as DER), the "
            "two `PKCS12_decrypt_skey` spellings (a "
            "shrouded key bag with a non-PBE algorithm, whose refusal and error coordinate are "
            "the observation) and `PKCS12_add_secret` (the `add_*` surface and the stack it "
            "builds). Since 10.4 it also drives that subphase's landed exports: the six "
            "`PKCS12_key_gen_*` spellings (the fixed `smeg`/salt vector through `uni`/`asc`/`utf8` "
            "and their `_ex` twins), `PKCS12_PBE_add`, the two `PKCS12_PBE_keyivgen` spellings "
            "driven directly, the **six `builtin_pbe[]` rows' keygen presence** through "
            "`EVP_PBE_find_ex` (with `EVP_PBE_CipherInit_ex` on the two TripleDES rows, which "
            "actually reach the keygen -- D-PBE-PKCS12-KEYGEN-1's measurement), and "
            "`PKCS8_set0_pbe(_ex)` (a fixed `PrivateKeyInfo` encrypted under a fixed TripleDES "
            "`PBEPARAM`, printed as the `EncryptedPrivateKeyInfo` DER). **It does not cover the "
            "`PKCS12` container itself**: "
            "`PKCS12_it`/`_new`/`_free`, `d2i_PKCS12`/`i2d_PKCS12`, `PKCS12_AUTHSAFES_it` and the "
            "four `d2i_PKCS12*`/`i2d_PKCS12*_bio/fp` spellings are held open on Phase 12's "
            "`PKCS7_it`; the four `PKCS12_SAFEBAG_get1_*` readers and the `create_cert`/"
            "`create_crl` pair on Phase 11's `X509_it`; `PKCS12_add_key*` on Phase 11's "
            "`EVP_PKEY2PKCS8`; `PKCS8_encrypt`/`_ex`, the three `create_pkcs8_encrypt*` spellings "
            "and the two `p7encdata` writers on Phase 11's `PKCS5_pbe_set_ex`/"
            "`PKCS5_pbe2_set_iv_ex`; the four MAC setters on Phase 11's `PBMAC1PARAM`/"
            "`PKCS5_pbkdf2_set`; `PKCS12_parse` on Phase 11's `X509`; and the rest of "
            "`p12_crt.c`/`p12_add.c`/"
            "`p12_init.c`/`p12_npas.c` on Phase 11. The probe prints each as `pending.` "
            "with its blocker rather than driving a fabricated arm "
            "(docs/PHASE-10-SUBPHASES.md section 3.5). "
            "`CT-PKCS12` is 10.4's second evidence plane and the other question: candidate-only "
            "construction verification of the PKCS#12 KDF. Its probe (`courts/phase10/ct_pkcs12.c`) "
            "re-reads the pinned `test/recipes/30-test_evp_data/evppbe_pkcs12.txt`'s six `PBE = "
            "pkcs12` stanzas and calls `PKCS12_key_gen_uni` exactly as `test/evp_test.c`'s "
            "`pbe_test_run` does, comparing each `Key` against the expected bytes mirrored in "
            "`forensics/vectors/pkcs12.json`. It is NOT parity and NOT validation (D201); the "
            "differential question is `RT-PKCS12`'s."
        ),
    }

    inputs = [
        InputRef(name="authority-symbols", path=REPO_ROOT / "forensics" / "atlas"
                 / auth.id / "symbols-libcrypto.json"),
    ]
    for _name, filename in COURTS:
        inputs.append(InputRef(name="probe", path=PROBE_DIR / filename))
    inputs.append(InputRef(name="pkcs12-correctness-probe", path=cv.PKCS12_PROBE))
    inputs.append(InputRef(name="pkcs12-correctness-vectors", path=cv.PKCS12_VECTORS))
    inputs.append(InputRef(name="pkcs12-corpus",
                           path=resolve_authority(PRODUCTION_AUTHORITY).source
                           / "test/recipes/30-test_evp_data/evppbe_pkcs12.txt"))
    doc = envelope(kind="phase10-courts", authority=auth.id, inputs=inputs,
                   body=body, generator=GENERATOR)
    write_json(OUT, doc)

    for r in records:
        if r.get("plane") == "correctness":
            if r["verdict"] == "pass":
                print(f"  {r['court']:<18} pass   "
                      f"({r['vectors_passed']}/{r['vectors_checked']} vectors)")
            else:
                print(f"  {r['court']:<18} FAIL   "
                      f"stage={r.get('stage', 'vector-mismatch')} "
                      f"({r.get('vectors_failed', '?')} vector(s) failed)")
                detail = r.get("detail")
                if isinstance(detail, list):
                    for line in detail:
                        print(f"      {line}")
            continue
        if r["verdict"] == "pass":
            print(f"  {r['court']:<18} pass   "
                  f"({r['authority_observations']} observations)")
        else:
            print(f"  {r['court']:<18} FAIL   stage={r.get('stage', 'compare')}")
            detail = r.get("detail")
            if isinstance(detail, dict):
                print(f"      exit_code={detail.get('exit_code')}")
                for line in detail.get("stderr", []):
                    print(f"      {line}")
            elif isinstance(detail, list):
                for line in detail[:8]:
                    print(f"      {line}")
            for res in r.get("residuals", [])[:12]:
                print(f"      {res['observation']}: authority={res['authority']!r} "
                      f"candidate={res['candidate']!r} ({res['class']})")
    for name, needs in PENDING_COURTS.items():
        print(f"  {name:<18} PENDING (not registered as passing) -- {needs}")
    print(f"  -> {rel(OUT)} all_pass={body['all_pass']} over {len(records)} court(s)")
    return 0 if body["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
