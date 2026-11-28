#!/usr/bin/env python3
"""PFP-12 attribution by two-point differencing.

Two callgrind profiles per (arm, operation) at different iteration counts are
subtracted function-by-function. The one-time provider/namemap/loader startup
is identical in both and cancels, leaving steady-state per-operation
instruction counts. The result is a disjoint self-cost partition: each function
is mapped to exactly one group, in priority order, and the unclassified share
is `other` (reported with its largest members).
"""
import argparse
import json
import os
import re

SELF_RE = re.compile(r"^\s*([\d,]+)\s+\(\s*([\d.]+)%\)\s+(.+?)(?:\s+\[.*\])?\s*$")

GROUPS = [
    ("key_schedule", [
        "aes_expand", "AES_set_encrypt_key", "AES_set_decrypt_key",
        "aesni_set_encrypt_key", "aes_gcm_init_key", "ossl_aes_gcm_init_key",
        "chacha20_initkey", "chacha20_initiv", "poly1305_init",
        "sha256_init", "sha512_init", "SHA256_Init", "SHA512_Init",
        "aes_init_key",
    ]),
    ("ghash", [
        "gf_mul", "ossl_gcm_gmult_4bit", "ossl_gcm_ghash_4bit",
        "gcm_ghash", "gcm_gmult", "aesni_gcm", "gcm_init",
        "ossl_gcm_init_4bit", "gcm_clmul", "gmult", "gcm::crypt",
        "_aesni_ctr32_ghash", "ctr32_ghash", "CRYPTO_gcm128_aad",
        "gcm128_aad",
    ]),
    ("block_cipher", [
        "AES_encrypt", "AES_decrypt", "aes_encrypt", "aes_decrypt",
        "aesni_encrypt", "aesni_ecb_encrypt", "vpaes_encrypt",
        "aes_gcm_encrypt", "aes_gcm_decrypt", "aesni_gcm_encrypt",
    ]),
    ("poly1305", ["poly1305", "Poly1305"]),
    ("chacha", ["chacha20_core", "ChaCha20", "chacha20", "chacha"]),
    ("tag", [
        "CRYPTO_memcmp", "CRYPTO_gcm128_finish", "gcm_finish",
        "CRYPTO_gcm128_tag",
    ]),
    ("sha_compress", [
        "sha256_block", "sha512_block", "sha256_block_data_order",
        "sha512_block_data_order", "shaext", "sha256rnds2", "sha256msg",
        "compress", "sha2_compress", "sha256_compress", "sha512_compress",
        "Md32>::block", "Sha256Ctx", "Sha512Ctx", "sha2::Sha",
    ]),
    ("sha_framing", [
        "SHA256_Update", "SHA512_Update", "SHA256_Final", "SHA512_Final",
        "sha256_update", "sha512_update", "sha256_final", "sha512_final",
        "md32_common", "digest_update", "ossl_sha",
    ]),
    ("evp_framing", [
        "EVP_", "evp_", "aes_gcm_cipher", "aes_gcm_ctrl",
        "chacha20_poly1305_cipher", "chacha20_poly1305_ctrl",
        "ossl_gcm_stream", "ossl_cipher", "provider", "PROV_", "ossl_prov",
        "cipher_generic", "cipher_update", "cipher_final", "cipher_init",
        "ossl_ccm", "aes_gcm_cleanup",
    ]),
]

COLUMNS = ["key_schedule", "block_cipher", "ghash", "poly1305", "chacha", "tag",
           "sha_compress", "sha_framing", "evp_framing", "other"]


def classify(name):
    for group, pats in GROUPS:
        for p in pats:
            if p in name:
                return group
    return "other"


def parse_counts(path):
    counts = {}
    if not os.path.exists(path):
        return counts
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = SELF_RE.match(line)
            if not m:
                continue
            name = m.group(3).strip()
            if "PROGRAM TOTALS" in name:
                continue
            counts[name] = counts.get(name, 0) + int(m.group(1).replace(",", ""))
    return counts


def ops_for(iters):
    warm = iters // 4
    if warm < 1:
        warm = 1
    return warm + iters


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    keys = []
    for name in sorted(os.listdir(args.dir)):
        if name.endswith("-big.self"):
            keys.append(name[: -len("-big.self")])

    report = {"method": "two-point differencing", "groups": {}, "top_other": {},
              "per_op_ir": {}}
    rows_out = []
    for key in keys:
        arm, op = key.split("-", 1)
        small = parse_counts(os.path.join(args.dir, key + "-small.self"))
        big = parse_counts(os.path.join(args.dir, key + "-big.self"))
        if "-64" in op:
            s_iters, b_iters = 250, 1000
        else:
            s_iters, b_iters = 16, 64
        d_ops = ops_for(b_iters) - ops_for(s_iters)
        deltas = {}
        for name in set(small) | set(big):
            d = big.get(name, 0) - small.get(name, 0)
            if d > 0:
                deltas[name] = d / d_ops
        total = sum(deltas.values()) or 1.0
        totals = {}
        for name, ir in deltas.items():
            g = classify(name)
            totals[g] = totals.get(g, 0.0) + 100.0 * ir / total
        report["groups"][key] = {k: round(v, 2) for k, v in sorted(totals.items())}
        report["per_op_ir"][key] = round(total, 1)
        other = sorted(
            ((100.0 * ir / total, name) for name, ir in deltas.items()
             if classify(name) == "other"), reverse=True)
        report["top_other"][key] = [{"pct": round(p, 2), "fn": n[:130]}
                                    for p, n in other[:10]]
        rows_out.append((key, totals))

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
        fh.write("\n")

    print("%-22s %s" % ("arm-op", " ".join("%11s" % c for c in COLUMNS)))
    for key, g in rows_out:
        print("%-22s %s" % (key, " ".join("%11.2f" % g.get(c, 0.0) for c in COLUMNS)))


if __name__ == "__main__":
    main()
