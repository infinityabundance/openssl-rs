#!/usr/bin/env python3
"""Frontier analysis: direct/GOT closure + address-taken markers + reverse chains."""
import json, re, collections

g = json.load(open("graph.json"))
G = {k: set(v) for k, v in g["graph"].items()}
S = g["sites"]
R = set(g["reachable"])
roots = set(g["roots"])

# ---- addr -> function name (from lc.syms, all FUNC sizes) ----
sym_re = re.compile(r"^\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+FUNC\s+\S+\s+\S+\s+(\S+)\s+(.+)$")
addr_name = {}
for line in open("lc.syms"):
    m = sym_re.match(line)
    if not m:
        continue
    a, sz, ndx, name = m.groups()
    if ndx == "UND":
        continue
    name = name.strip().split("@@")[0].split("@")[0]
    addr_name.setdefault(int(a, 16), name)

# ---- address-taken: data relocations + lea/mov references ----
taken_rel = collections.defaultdict(list)
rel_re = re.compile(r"^([0-9a-f]{16})\s+[0-9a-f]+\s+(R_X86_64_(?:RELATIVE|64))\s+([0-9a-f]+)?\s*(.*)$")
for line in open("lc.reloc"):
    m = rel_re.match(line)
    if not m:
        continue
    off, typ, val, rest = m.groups()
    rest = rest.strip()
    if rest:
        nm = rest.split("+")[0].split("@@")[0].split("@")[0]
        if nm:
            taken_rel[nm].append(f"{typ}@{off}")
    elif val:
        nm = addr_name.get(int(val, 16))
        if nm:
            taken_rel[nm].append(f"{typ}@{off}->0x{int(val,16):x}")

lea_re = re.compile(r"\b(?:lea|mov)\b.*<([^>+]+)(?:\+0x[0-9a-f]+)?>")
taken_lea = collections.defaultdict(list)
for line in open("lc.dis", errors="replace"):
    if not line.startswith("  ") or "<" not in line:
        continue
    m = lea_re.search(line)
    if m:
        taken_lea[m.group(1)].append(line.strip()[:100])

def is_taken(n):
    return bool(taken_rel.get(n)) or bool(taken_lea.get(n))

# ---- reverse chains over direct+GOT ----
def rev_chains(target, maxdepth=7, maxchains=12):
    out = []
    def rec(n, chain, seen):
        if len(out) >= maxchains:
            return
        if len(chain) > maxdepth:
            out.append(chain + ["DEPTH_LIMIT"]); return
        if n in roots:
            out.append(chain); return
        preds = S.get(n, [])
        if not preds:
            out.append(chain + ["NO_DIRECT/GOT_PREDECESSOR"]); return
        for c, k, a, i in preds[:5]:
            if c in seen:
                out.append(chain + [c + " (cycle)"]); continue
            rec(c, chain + [f"{c} [{k}@{a}]"], seen | {c})
    rec(target, [target], {target})
    return out

print(f"== closure == {len(R)} functions reachable by direct+GOT edges from {len(roots)} imported roots")
for probe in ("BN_div_internal", "BN_mod_exp_mont", "bn_mod_exp_mont_fixed_top",
              "BN_mod_exp_mont_consttime", "BN_mod_inverse", "DH_compute_key"):
    print(f"   {probe}: {'REACHABLE' if probe in R else 'not in closure'}")

print("\n== direct/GOT callees of nominal ssh-reachable entries ==")
for root in ("DH_compute_key", "DH_generate_key", "EC_POINT_mul", "EC_KEY_generate_key",
             "EVP_PKEY_keygen", "EVP_DigestSign", "EVP_DigestSignInit",
             "EC_KEY_METHOD_get_sign", "RSA_new", "BN_div"):
    if root in G:
        cs = sorted(G[root])
        print(f"   {root} -> {cs[:16]}{' ...' if len(cs) > 16 else ''}")

print("\n== reverse chains from BN_mod_exp_mont_consttime (direct+GOT) ==")
for ch in rev_chains("BN_mod_exp_mont_consttime"):
    print("   " + "  <-  ".join(ch))

print("\n== reverse chains from BN_mod_inverse (direct+GOT) ==")
for ch in rev_chains("BN_mod_inverse", 6, 8):
    print("   " + "  <-  ".join(ch))

print("\n== address-taken (indirect-dispatch) evidence ==")
for n in ("rsa_ossl_mod_exp", "ossl_ec_group_do_inverse_ord", "bn_mod_exp_mont_fixed_top",
          "dsa_do_sign", "ossl_dsa_sign_int", "ossl_ecdsa_sign_sig",
          "ossl_ec_GFp_simple_field_inv", "BN_mod_exp_mont_consttime", "BN_mod_inverse"):
    r, l = taken_rel.get(n, []), taken_lea.get(n, [])
    print(f"   {n}: data-reloc={r[:3] or 'none'} lea/mov={l[:2] or 'none'}")
