"""ETP-T5 differential driver.

Reads the tracked vector populations, recomputes every expected value with the
independent Python references, runs the C harness against the candidate and the
pinned authority, and writes a machine-readable result document.  Every
observed difference is classified into exactly one of:

    authority_deviation, normative_ambiguity, candidate_defect,
    reference_defect, harness_artefact, UNKNOWN

The classifier never resolves a difference by preference.  A three-way
difference (candidate, authority and reference disagree pairwise) is recorded
``UNKNOWN`` together with the evidence that would settle it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, REPO_ROOT)

from forensics.etp5_crypto import ref_arith as fa
from forensics.etp5_crypto import ref_ec
from forensics.etp5_crypto import ref_ecdsa
from forensics.etp5_crypto import ref_rsa
from forensics.etp5_crypto import ref_symmetric

SEED = "0x45545035"
DEFAULT_VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "vectors")

# FIPS 180-4 / RFC 4231 / RFC 6979 published values used by the cross checks.
SHA256_PUBLISHED = {
    "": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq":
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
    "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu":
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
}
SHA256_MILLION_A = (
    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
)
RFC4231 = [
    (bytes([0x0B]) * 20, b"Hi There",
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    (b"Jefe", b"what do ya want for nothing?",
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
]
RFC6979 = {
    "d": 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721,
    "k": 0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60,
    "r": 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
    "s": 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8,
}


def h32(value: int) -> str:
    return f"{value:064x}"


def hbytes(value: bytes, length: int) -> str:
    return value.to_bytes(length, "big").hex()


def load_json(path: str):
    with open(path, "r", encoding="ascii") as handle:
        return json.load(handle)


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_cases(vectors: dict):
    """Return (case_lines, expected_by_id, inputs_by_id, population)."""
    lines = []
    expected = {}
    inputs = {}
    population = {}

    field = vectors["field_order"]
    by_op = {}
    moduli = {"p": 0, "n": 0}
    for case in field:
        cid = case["id"]
        modulus = int(case["modulus"], 16)
        a = int(case["a"], 16)
        op = case["op"]
        by_op[op] = by_op.get(op, 0) + 1
        moduli["p" if modulus == fa.P else "n"] += 1
        if op in ("modadd", "modsub", "modmul"):
            b = int(case["b"], 16)
            lines.append(f"{cid} {op} {case['modulus']} {case['a']} {case['b']}")
            if op == "modadd":
                value = fa.add_mod(a, b, modulus)
            elif op == "modsub":
                value = fa.sub_mod(a, b, modulus)
            else:
                value = fa.mul_mod(a, b, modulus)
            expected[cid] = [h32(value)]
        elif op == "modinv":
            lines.append(f"{cid} {op} {case['modulus']} {case['a']}")
            expected[cid] = [h32(fa.inv_mod(a, modulus))]
        elif op == "modexp":
            exponent = int(case["e"], 16)
            lines.append(
                f"{cid} {op} {case['modulus']} {case['a']} {case['e']}")
            expected[cid] = [h32(fa.mod_exp(a, exponent, modulus))]
        else:
            raise ValueError(f"unknown field op {op}")
        inputs[cid] = case
    population["field_order"] = {
        "cases": len(field), "by_op": by_op, "by_modulus": moduli,
    }

    scalar_cases = vectors["scalarmul"]
    for case in scalar_cases:
        cid = case["id"]
        k = int(case["k"], 16)
        lines.append(f"{cid} scalarmul {case['k']}")
        expected[cid] = [ref_ec.encode_uncompressed(ref_ec.mul_g_affine(k)).hex()]
        inputs[cid] = case
    population["scalarmul"] = {
        "cases": len(scalar_cases),
        "powers_of_two": sum(1 for c in scalar_cases
                             if int(c["k"], 16).bit_count() == 1),
        "boundary_included": ["0", "1", "2", "n-2", "n-1"],
    }

    ecdsa_cases = vectors["ecdsa"]
    for case in ecdsa_cases:
        cid = case["id"]
        digest = bytes.fromhex(case["digest"])
        private_key = int(case["d"], 16)
        nonce = int(case["k"], 16)
        r, s = ref_ecdsa.sign(private_key, digest, nonce)
        if int(case["r"], 16) != r or int(case["s"], 16) != s:
            raise RuntimeError(f"{cid}: stored signature differs from reference")
        public = (int(case["qx"], 16), int(case["qy"], 16))
        if not ref_ecdsa.verify(public, digest, r, s):
            raise RuntimeError(f"{cid}: reference signature does not verify")
        tampered = int(case["s_tampered"], 16)
        if ref_ecdsa.verify(public, digest, r, tampered):
            raise RuntimeError(f"{cid}: tampered signature verifies")

        lines.append(
            f"{cid}-sign ecdsa_sign {case['digest']} {case['d']} "
            f"{case['kinv']} {case['r']} {case['qx']} {case['qy']}")
        expected[f"{cid}-sign"] = [h32(r), h32(s), "1"]
        inputs[f"{cid}-sign"] = case

        lines.append(
            f"{cid}-verify ecdsa_verify {case['digest']} {case['r']} "
            f"{case['s']} {case['qx']} {case['qy']}")
        expected[f"{cid}-verify"] = ["1"]
        inputs[f"{cid}-verify"] = case

        lines.append(
            f"{cid}-verify-bad ecdsa_verify {case['digest']} {case['r']} "
            f"{case['s_tampered']} {case['qx']} {case['qy']}")
        expected[f"{cid}-verify-bad"] = ["0"]
        inputs[f"{cid}-verify-bad"] = case
    population["ecdsa"] = {
        "vectors": len(ecdsa_cases),
        "sign_cases": len(ecdsa_cases),
        "verify_cases": 2 * len(ecdsa_cases),
        "published_vector": "RFC 6979 A.2.5 P-256/SHA-256 \"sample\"",
    }

    key = ref_rsa.key_from_json(vectors["rsa_key"])
    rsa_cases = vectors["rsa"]
    for case in rsa_cases:
        cid = case["id"]
        message = int(case["m"], 16)
        ciphertext = ref_rsa.public_op(message, key)
        if ref_rsa.crt_private(ciphertext, key) != message:
            raise RuntimeError(f"{cid}: reference CRT does not invert")
        if ref_rsa.plain_private(ciphertext, key) != message:
            raise RuntimeError(f"{cid}: reference plain op does not invert")
        lines.append(f"{cid} rsa_private {ciphertext.to_bytes(256, 'big').hex()}")
        expected[cid] = [hbytes(message, 256)]
        inputs[cid] = case
    lines.append("rsa-check rsa_check")
    expected["rsa-check"] = ["1"]
    inputs["rsa-check"] = {"id": "rsa-check"}
    population["rsa"] = {
        "cases": len(rsa_cases),
        "key_bits": key["bits"],
        "exponent": key["e"],
        "check_case": 1,
    }

    sha_cases = vectors["sha256"]
    for case in sha_cases:
        cid = case["id"]
        data = bytes.fromhex(case["data"])
        argument = case["data"] if case["data"] else "-"
        lines.append(f"{cid} sha256 {argument}")
        expected[cid] = [ref_symmetric.sha256(data).hex()]
        inputs[cid] = case
    population["sha256"] = {"cases": len(sha_cases)}

    return lines, expected, inputs, population, key


def write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="ascii") as handle:
        handle.write(text)


def write_key(path: str, key: dict) -> None:
    lines = []
    for name in ("n", "e", "d", "p", "q", "dmp1", "dmq1", "iqmp"):
        lines.append(f"{name}={format(key[name], 'x')}")
    write_text(path, "\n".join(lines) + "\n")


def run_harness(harness: str, library: str, cases: str,
                key_file: "str | None", output: str) -> dict:
    command = [harness, "--lib", library, "--cases", cases]
    if key_file is not None:
        command += ["--rsa-key", key_file]
    completed = subprocess.run(
        command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(
            f"harness failed for {library}: exit {completed.returncode}: "
            f"{completed.stderr.strip()[:400]}")
    write_text(output, completed.stdout)
    results = {}
    loaded = None
    for line in completed.stdout.splitlines():
        if line.startswith("LIB "):
            loaded = line[4:]
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        cid, status = parts[0], parts[1]
        if status != "ok":
            results[cid] = None
            continue
        fields = parts[2:]
        if any(field == "failed" for field in fields):
            results[cid] = None
        else:
            results[cid] = fields
    return {"by_id": results, "loaded": loaded}


def decision(op: str, fields):
    if fields is None:
        return None
    if op == "ecdsa_verify":
        return "accept" if fields and fields[0] == "1" else "reject"
    return tuple(fields)


def case_op(case_id: str, inputs: dict) -> str:
    entry = inputs[case_id]
    if "op" in entry:
        return entry["op"]
    if case_id.endswith("-sign"):
        return "ecdsa_sign"
    if case_id.endswith("-verify") or case_id.endswith("-verify-bad"):
        return "ecdsa_verify"
    if case_id == "rsa-check":
        return "rsa_check"
    if case_id.startswith("scalarmul"):
        return "scalarmul"
    if case_id.startswith("rsa-"):
        return "rsa_private"
    if case_id.startswith("sha256"):
        return "sha256"
    return "unknown"


def classify(op: str, reference, candidate, authority,
             reference_decision, candidate_decision, authority_decision):
    """Return (classification, evidence) or (None, None) on agreement."""
    if candidate is None or authority is None:
        missing = []
        if candidate is None:
            missing.append("candidate")
        if authority is None:
            missing.append("authority")
        return ("harness_artefact",
                "no result from " + ", ".join(missing)
                + " for this case; the harness or the DSO refused the call, so "
                  "nothing is concluded about the cryptographic result")

    if op == "ecdsa_verify":
        if candidate_decision == reference_decision and \
                authority_decision == reference_decision:
            return None, None
        if candidate_decision == authority_decision and \
                candidate_decision != reference_decision:
            return ("reference_defect",
                    "candidate and authority agree on the accept/reject "
                    "decision and the reference differs; the normative text is "
                    "the arbiter")
        if candidate_decision == reference_decision and \
                authority_decision != reference_decision:
            return ("authority_deviation",
                    "the candidate agrees with the reference and the authority "
                    "differs from both")
        if candidate_decision != reference_decision and \
                authority_decision == reference_decision:
            return ("candidate_defect",
                    "the candidate differs from the reference and the authority "
                    "agrees with the reference")
        return ("UNKNOWN",
                "candidate, authority and reference disagree pairwise; a "
                "reading of the cited normative section is required")

    reference_key = tuple(reference) if reference is not None else None
    candidate_key = tuple(candidate)
    authority_key = tuple(authority)
    if candidate_key == reference_key and authority_key == reference_key:
        return None, None
    if candidate_key == authority_key and candidate_key != reference_key:
        return ("reference_defect",
                "candidate and authority agree exactly and the reference "
                "differs; the normative text is the arbiter")
    if candidate_key == reference_key and authority_key != reference_key:
        return ("authority_deviation",
                "the candidate agrees with the reference and the authority "
                "differs from both")
    if candidate_key != reference_key and authority_key == reference_key:
        return ("candidate_defect",
                "the candidate differs from the reference and the authority "
                "agrees with the reference")
    return ("UNKNOWN",
            "candidate, authority and reference disagree pairwise; a reading "
            "of the cited normative section is required")


def reference_cross_checks(vectors: dict, key: dict) -> list[dict]:
    checks = []

    def record(name, ok, detail):
        checks.append({
            "name": name,
            "status": "PASS" if ok else "FAIL",
            "detail": detail,
        })

    # Modular inverse: extended Euclid versus Fermat on two primes.
    sample = [case for case in vectors["field_order"]
              if case["op"] == "modinv"]
    checked = 0
    failed = []
    for case in sample:
        modulus = int(case["modulus"], 16)
        a = int(case["a"], 16) % modulus
        if a == 0:
            continue
        extended = fa.inv_mod(a, modulus)
        fermat = pow(a, modulus - 2, modulus)
        checked += 1
        if extended != fermat:
            failed.append(case["id"])
    record("arith_inverse_extended_euclid_vs_fermat", not failed,
           f"{checked} inverses over p and n; failures={failed[:5]}")

    # Exponentiation: square-and-multiply versus Python pow.
    checked = 0
    failed = []
    for case in vectors["field_order"]:
        if case["op"] != "modexp":
            continue
        modulus = int(case["modulus"], 16)
        a = int(case["a"], 16)
        e = int(case["e"], 16)
        checked += 1
        if fa.mod_exp(a, e, modulus) != pow(a, e, modulus):
            failed.append(case["id"])
    record("arith_square_and_multiply_vs_pow", not failed,
           f"{checked} exponentiations; failures={failed[:5]}")

    # Affine versus Jacobian scalar multiplication, curve membership, group law.
    scalar_cases = vectors["scalarmul"]
    failed = []
    for case in scalar_cases:
        k = int(case["k"], 16)
        affine = ref_ec.mul_g_affine(k)
        jacobian = ref_ec.mul_g_jacobian(k)
        if affine != jacobian:
            failed.append(case["id"] + ":representation")
            continue
        if not ref_ec.is_on_curve(affine):
            failed.append(case["id"] + ":not-on-curve")
    record("ec_affine_vs_jacobian_and_curve_membership", not failed,
           f"{len(scalar_cases)} scalars; failures={failed[:5]}")

    generator = (fa.GX, fa.GY)
    group_ok = (
        ref_ec.is_on_curve(generator)
        and ref_ec.mul_g_affine(fa.N) is None
        and ref_ec.mul_g_jacobian(fa.N) is None
    )
    sample_scalars = [1, 2, 3, 127, 128, 255, 256, fa.N - 1,
                      fa.N - 2, 0x1234567890ABCDEF]
    details = []
    for k in sample_scalars:
        left = ref_ec.mul_g_affine(k)
        right = ref_ec.mul_g_affine((fa.N - k) % fa.N)
        if left is not None and right is not None:
            if ref_ec.affine_add(left, right) is not None:
                group_ok = False
                details.append(k)
    record("ec_group_law_and_order", group_ok,
           "G on curve, nG = infinity, kG + (n-k)G = infinity for sampled k; "
           f"failures={details}")

    # RSA: CRT versus plain, and the public operation.
    failed = []
    for case in vectors["rsa"]:
        message = int(case["m"], 16)
        ciphertext = ref_rsa.public_op(message, key)
        if ref_rsa.crt_private(ciphertext, key) != message:
            failed.append(case["id"] + ":crt")
        if ref_rsa.plain_private(ciphertext, key) != message:
            failed.append(case["id"] + ":plain")
    record("rsa_crt_vs_plain_and_public_inverse", not failed,
           f"{len(vectors['rsa'])} representatives; failures={failed[:5]}")

    # SHA-256 published vectors.
    failed = []
    for message, expected_hex in SHA256_PUBLISHED.items():
        digest = ref_symmetric.sha256(message.encode()).hex()
        if digest != expected_hex:
            failed.append(message[:16])
    million = ref_symmetric.sha256(b"a" * 1000000).hex()
    if million != SHA256_MILLION_A:
        failed.append("million-a")
    record("sha256_fips180_4_published_vectors", not failed,
           f"4 short vectors plus the 1,000,000-byte vector; failures={failed}")

    # HMAC-SHA-256 RFC 4231.
    failed = []
    for key_bytes, message, expected_hex in RFC4231:
        if ref_symmetric.hmac_sha256(key_bytes, message).hex() != expected_hex:
            failed.append(message[:16].decode(errors="replace"))
    record("hmac_sha256_rfc4231", not failed,
           f"{len(RFC4231)} vectors; failures={failed}")

    # RFC 6979 deterministic nonce and signature.
    digest = ref_symmetric.sha256(b"sample")
    nonce = ref_ecdsa.rfc6979_nonce(RFC6979["d"], digest)
    r, s = ref_ecdsa.sign(RFC6979["d"], digest, nonce)
    public = ref_ec.mul_g_affine(RFC6979["d"])
    ok = (nonce == RFC6979["k"] and r == RFC6979["r"] and s == RFC6979["s"]
          and ref_ecdsa.verify(public, digest, r, s))
    record("rfc6979_p256_sha256_sample", ok,
           "derived k, r, s and the verification result against "
           "RFC 6979 A.2.5")

    # The fixed RSA key itself.
    key_ok = (key["p"] * key["q"] == key["n"]
              and (key["e"] * key["d"]) % key["lambda"] == 1
              and ref_rsa.is_probable_prime(key["p"])
              and ref_rsa.is_probable_prime(key["q"]))
    record("rsa_fixed_key_invariants", key_ok,
           "n = p*q, e*d = 1 (mod lambda), both factors probable prime")

    return checks


def transport_control(harness: str, library: str, workdir: str) -> int:
    """Prove the harness plus comparison path detects a wrong expected value."""
    os.makedirs(workdir, exist_ok=True)
    case_path = os.path.join(workdir, "transport-control.cases")
    write_text(case_path, f"control modadd {fa.P:x} 1 2\n")
    result = run_harness(harness, library, case_path, None,
                         os.path.join(workdir, "transport-control.out"))
    fields = result["by_id"].get("control")
    correct = fields == [h32(3)]
    detected = fields != [h32(4)]
    if correct and detected:
        print("TRANSPORT CONTROL OK: correct value observed and an injected "
              "wrong expected value is rejected")
        return 0
    print(f"TRANSPORT CONTROL FAIL: observed={fields}, correct={correct}, "
          f"injected_difference_detected={detected}")
    return 1


def self_test() -> int:
    """Classifier sensitivity controls.

    Each known difference is presented directly to the classifier; a control
    passes only when the expected class is returned.  This proves the
    differential report is sensitive to each class it claims to distinguish,
    without asserting anything about the candidate.
    """
    failures = []

    def expect(label, expected, op, reference, candidate, authority):
        got, _ = classify(op, reference, candidate, authority,
                          decision(op, reference), decision(op, candidate),
                          decision(op, authority))
        if got != expected:
            failures.append(f"{label}: expected {expected}, got {got}")

    expect("agreement", None, "modadd", ["2a"], ["2a"], ["2a"])
    expect("candidate defect", "candidate_defect", "modadd",
           ["2a"], ["2b"], ["2a"])
    expect("reference defect", "reference_defect", "modadd",
           ["2a"], ["2b"], ["2b"])
    expect("authority deviation", "authority_deviation", "modadd",
           ["2a"], ["2a"], ["2b"])
    expect("three-way unknown", "UNKNOWN", "modadd",
           ["2a"], ["2b"], ["2c"])
    expect("harness artefact", "harness_artefact", "modadd",
           ["2a"], None, ["2a"])
    expect("verify candidate defect", "candidate_defect", "ecdsa_verify",
           ["1"], ["0"], ["1"])
    expect("verify reference defect", "reference_defect", "ecdsa_verify",
           ["1"], ["0"], ["0"])
    expect("verify authority deviation", "authority_deviation",
           "ecdsa_verify", ["1"], ["1"], ["0"])
    expect("tampered accepted", "candidate_defect", "ecdsa_verify",
           ["0"], ["1"], ["0"])

    if failures:
        for failure in failures:
            print("SELFTEST FAIL " + failure)
        return 1
    print(f"SELFTEST OK: {10} classifier controls")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--transport-control", action="store_true")
    parser.add_argument("--candidate")
    parser.add_argument("--authority")
    parser.add_argument("--harness")
    parser.add_argument("--vectors", default=DEFAULT_VECTORS)
    parser.add_argument("--workdir")
    parser.add_argument("--out")
    parser.add_argument("--source-head")
    parser.add_argument("--source-dirty", default="")
    parser.add_argument("--court-image", default="unknown")
    parser.add_argument("--rustc", default="unknown")
    parser.add_argument("--cc", default="unknown")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if args.transport_control:
        if not args.candidate or not args.harness or not args.workdir:
            parser.error("--transport-control requires --candidate, --harness "
                         "and --workdir")
        return transport_control(args.harness, args.candidate, args.workdir)
    for name in ("candidate", "authority", "harness", "workdir", "out",
                 "source_head"):
        if getattr(args, name) is None:
            parser.error(f"--{name.replace('_', '-')} is required")

    os.makedirs(args.workdir, exist_ok=True)
    vectors = {
        name[:-5]: load_json(os.path.join(args.vectors, name))
        for name in ("field_order.json", "scalarmul.json", "ecdsa.json",
                     "rsa_key.json", "rsa.json", "sha256.json")
    }

    lines, expected, inputs, population, key = build_cases(vectors)
    case_path = os.path.join(args.workdir, "cases.txt")
    key_path = os.path.join(args.workdir, "rsa_key.txt")
    write_text(case_path, "\n".join(lines) + "\n")
    write_key(key_path, key)

    cross_checks = reference_cross_checks(vectors, key)
    reference_ok = all(check["status"] == "PASS" for check in cross_checks)

    candidate = run_harness(
        args.harness, args.candidate, case_path, key_path,
        os.path.join(args.workdir, "candidate.out"))
    authority = run_harness(
        args.harness, args.authority, case_path, key_path,
        os.path.join(args.workdir, "authority.out"))

    ecdsa_cross = {
        "candidate_verifies_reference": {"cases": 0, "failures": []},
        "authority_verifies_reference": {"cases": 0, "failures": []},
        "reference_verifies_candidate": {"cases": 0, "failures": []},
        "reference_verifies_authority": {"cases": 0, "failures": []},
    }
    for case_id in expected:
        if not case_id.endswith("-verify"):
            continue
        for label, observation in (
                ("candidate_verifies_reference", candidate),
                ("authority_verifies_reference", authority)):
            record = ecdsa_cross[label]
            record["cases"] += 1
            fields = observation["by_id"].get(case_id)
            if not fields or fields[0] != "1":
                record["failures"].append(case_id)
    for case_id in expected:
        if not case_id.endswith("-sign"):
            continue
        case = inputs[case_id]
        digest = bytes.fromhex(case["digest"])
        public = (int(case["qx"], 16), int(case["qy"], 16))
        for label, observation in (
                ("reference_verifies_candidate", candidate),
                ("reference_verifies_authority", authority)):
            record = ecdsa_cross[label]
            fields = observation["by_id"].get(case_id)
            if not fields or len(fields) < 2:
                record["failures"].append(case_id)
                continue
            record["cases"] += 1
            try:
                accepted = ref_ecdsa.verify(
                    public, digest, int(fields[0], 16), int(fields[1], 16))
            except ValueError:
                accepted = False
            if not accepted:
                record["failures"].append(case_id)
    cross_direction_ok = all(
        not record["failures"] for record in ecdsa_cross.values())

    disagreements = []
    notes = []
    for case_id in expected:
        op = case_op(case_id, inputs)
        reference = expected[case_id]
        candidate_result = candidate["by_id"].get(case_id)
        authority_result = authority["by_id"].get(case_id)
        classification, evidence = classify(
            op, reference, candidate_result, authority_result,
            decision(op, reference), decision(op, candidate_result),
            decision(op, authority_result))
        if classification is None:
            if op == "ecdsa_verify" and candidate_result != authority_result:
                notes.append({
                    "case_id": case_id,
                    "note": "same accept/reject decision, different integer "
                            "return value",
                    "candidate": candidate_result,
                    "authority": authority_result,
                })
            continue
        disagreements.append({
            "case_id": case_id,
            "op": op,
            "inputs": inputs[case_id],
            "reference": reference,
            "candidate": candidate_result,
            "authority": authority_result,
            "classification": classification,
            "evidence": evidence,
        })

    by_class = {}
    for item in disagreements:
        by_class[item["classification"]] = \
            by_class.get(item["classification"], 0) + 1

    incomplete = bool(by_class.get("UNKNOWN") or by_class.get("harness_artefact")
                      or not reference_ok or not cross_direction_ok)
    status = "INCOMPLETE" if incomplete else (
        "DISAGREEMENTS_CLASSIFIED" if disagreements else "AGREEMENT")

    document = {
        "schema": "openssl-rs/etp-t5/crypto-differential/1",
        "item": "ETP-T5",
        "seed": SEED,
        "source": {
            "commit": args.source_head,
            "dirty_porcelain": args.source_dirty,
            "dirty_scope": "src, Cargo.toml, Cargo.lock, build.rs, "
                           "rust-toolchain.toml",
            "candidate_link": "distribution-shaped DSO (whole archive, "
                              "shell object, artifacts/phase2/libcrypto.ld)",
            "authority_label": "openssl-3.6.4-production",
            "candidate_dso": args.candidate,
            "candidate_dso_sha256": sha256_file(args.candidate),
            "authority_dso": args.authority,
            "authority_dso_sha256": sha256_file(args.authority),
            "harness": args.harness,
            "harness_sha256": sha256_file(args.harness),
            "court_image": args.court_image,
            "rustc": args.rustc,
            "cc": args.cc,
        },
        "references": {
            "modules": [
                "ref_arith.py", "ref_ec.py", "ref_ecdsa.py",
                "ref_rsa.py", "ref_symmetric.py",
            ],
            "normative_sources": [
                "SEC 2 v2.0 section 2.4.2 (P-256 parameters)",
                "FIPS 186-4 Appendix D.1.2.3 (P-256 parameters)",
                "NIST SP 800-186 section 3.2.1.3 (P-256 parameters)",
                "FIPS 186-5 sections 6.4.1 and 6.4.2 (ECDSA generation and verification)",
                "PKCS #1 v2.2 / RFC 8017 section 3.2 (RSA private key and CRT)",
                "FIPS 180-4 section 6.2 (SHA-256)",
                "RFC 6979 section 3.2 (deterministic ECDSA nonce)",
            ],
        },
        "populations": population,
        "cross_checks": cross_checks,
        "cross_checks_all_pass": reference_ok,
        "ecdsa_cross_direction": ecdsa_cross,
        "ecdsa_cross_direction_all_pass": cross_direction_ok,
        "differences": {
            "counts_by_class": by_class,
            "items": disagreements,
        },
        "notes": notes,
        "status": status,
        "boundary": {
            "covered": [
                "modular add, sub, mul, inverse and exponentiation over the P-256 prime and group order",
                "P-256 scalar multiplication in affine and Jacobian coordinates",
                "ECDSA signing with a supplied nonce (kinv and r through ECDSA_do_sign_ex)",
                "ECDSA verification in both directions and rejection of a tampered signature",
                "RSA CRT recombination and the plain private operation for one fixed 2048-bit key",
                "SHA-256 as a harness control",
            ],
            "not_covered": [
                "any curve other than P-256",
                "ECDSA nonce generation as an implementation under test (the RFC 6979 path is only a reference cross check)",
                "RSA key generation by the candidate, signature padding (PKCS #1 v1.5, PSS) and OAEP",
                "constant-time behaviour",
                "memory safety, ownership and aliasing",
                "binary-level refinement between the Rust source and the DSO",
            ],
            "sampling": "every pseudo-random population is regenerated from the recorded seed; the populations are sampled, not exhaustive",
            "proof_status": "a differential observation is bounded evidence, not a proof; a green differential does not establish constant-time behaviour or memory safety",
            "reference_status": "the reference's own correctness rests on the stated reading of the normative documents",
        },
    }

    write_text(args.out, json.dumps(document, indent=2, sort_keys=True) + "\n")

    print(f"status={status}")
    print(f"candidate={candidate['loaded']}")
    print(f"authority={authority['loaded']}")
    print(f"cases={len(expected)} differences={len(disagreements)} "
          f"by_class={by_class}")
    print("cross_checks=" + ", ".join(
        f"{check['name']}:{check['status']}" for check in cross_checks))
    print("ecdsa_cross_direction=" + ", ".join(
        f"{name}:{len(record['failures'])} failures/{record['cases']} cases"
        for name, record in ecdsa_cross.items()))
    for item in disagreements[:10]:
        print(f"  {item['classification']} {item['case_id']} "
              f"ref={item['reference']} cand={item['candidate']} "
              f"auth={item['authority']}")
    return 0 if not incomplete else 1


if __name__ == "__main__":
    raise SystemExit(main())
