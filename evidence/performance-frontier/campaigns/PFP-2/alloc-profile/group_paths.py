#!/usr/bin/env python3
"""Group a PFP-24 profile's rows by the top-level call path that reaches them."""
import collections
import json
import sys

GROUPS = [
    ("EC_POINT_mul (ladder: pre/step/post, incl. the field inverse)", "ossl_ec_scalar_mul_ladder"),
    ("k^-1 via ossl_ec_group_do_inverse_ord (mod_exp ladder)", "ossl_ec_group_do_inverse_ord"),
    ("signature arithmetic in ossl_ecdsa_simple_sign_sig", "ossl_ecdsa_simple_sign_sig"),
    ("RAND / namemap on the nonce paths", "RAND_"),
    ("nonce draw (ossl_bn_gen_dsa_nonce_fixed_top)", "ossl_bn_gen_dsa_nonce_fixed_top"),
    ("EC_KEY/ECDSA object creation in ecdsa_sign_setup", "ecdsa_sign_setup"),
]


def classify(stack):
    text = " <- ".join(stack)
    if "ossl_ec_scalar_mul_ladder" in text:
        return GROUPS[0][1]
    if "ossl_ec_group_do_inverse_ord" in text:
        return GROUPS[1][1]
    if "ossl_ecdsa_simple_sign_sig" in text:
        return GROUPS[2][1]
    if "RAND_" in text:
        return GROUPS[3][1]
    if "ossl_bn_gen_dsa_nonce_fixed_top" in text:
        return GROUPS[4][1]
    if "ecdsa_sign_setup" in text:
        return GROUPS[5][1]
    return "other"


for path in sys.argv[1:]:
    doc = json.load(open(path))
    tot = collections.Counter()
    for r in doc["rows"]:
        tot[classify(r["stack"])] += r["blocks_per_op"]
    print("==", path, "total %.2f" % sum(tot.values()))
    order = [g[1] for g in GROUPS] + ["other"]
    for key in order:
        if tot.get(key):
            label = next((g[0] for g in GROUPS if g[1] == key), "-")
            print("  %8.2f  %s  [%s]" % (tot[key], label, key))
