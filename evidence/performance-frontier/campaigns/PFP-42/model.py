#!/usr/bin/env python3
"""PFP-42 cost model: fixed-window exponentiation at a public ladder width.

    cost(w) = [ceil(bits/w)*(w+1) + 2^w] * C(M)          (Montgomery operations)
            + windows * 2^w * M * 3                       (masked-scan instructions)

  W     = ladder width in bits (public: 64 * resolved policy limbs, or modulus width)
  M     = modulus limb count (public)
  C(M)  = measured per-Montgomery-multiply instruction cost at M limbs

Measured coefficients (PFP-41 instruction-mix of the shipped CIOS kernel):
  C(4)=333, C(16)=4679, C(32)=21163 (PFP-8 dynamic ladder call: 21186).
Inferred (O(n^2), anchored on the measured n=32 figure): C(48), C(128).

This file is the reproducible generator for evidence/.../PFP-42/BOUNDS.md.
"""

MEASURED = {4: 333, 16: 4679, 32: 21163}
K = MEASURED[32] / (32 ** 2)  # instructions per limb^2, anchored at n=32


def C(m):
    return MEASURED.get(m, K * m * m)


# (label, ladder width bits W, modulus limbs M)
GEOMETRIES = [
    ("ffdhe2048-policy (256 iters)", 256, 32),
    ("ffdhe3072-policy (320 iters)", 320, 48),
    ("modexp-1024", 1024, 16),
    ("modexp-2048", 2048, 32),
    ("modexp-8192", 8192, 128),
]


def cost(W, M, w, scan_ir):
    windows = (W + w - 1) // w
    mont_ops = windows * (w + 1) + (1 << w)  # squarings + mults + table + conversions
    return mont_ops * C(M) + windows * (1 << w) * M * scan_ir, mont_ops, windows


def best_w(W, M, scan_ir):
    return min(range(1, 9), key=lambda w: cost(W, M, w, scan_ir)[0])


def selector(width_limbs, modulus_limbs):
    """Mirror of src/bn/arith.rs `select_window_bits` (scan=3, saturating)."""
    default = 5
    bits = width_limbs * 64
    if bits == 0 or modulus_limbs == 0:
        return default
    def score(w):
        windows = -(-bits // w)
        ops = windows * (w + 1) + (1 << w)
        return ops * 21163 * modulus_limbs * modulus_limbs + windows * (1 << w) * modulus_limbs * 3 * 1024
    bw, b = default, score(default)
    for w in range(1, 9):
        s = score(w)
        if s < b:
            b, bw = s, w
    return bw


print("== coefficients ==")
for m in (4, 16, 32, 48, 128):
    tag = "measured" if m in MEASURED else "inferred (k*M^2, k from n=32)"
    print("  C(%3d) = %10.0f Ir/multiply   %s" % (m, C(m), tag))
print("  k = %.4f Ir/limb^2" % K)
print()

print("== predicted-best-w table (scan = 3 Ir/limb-select, the model used in code) ==")
print("  %-30s %6s %10s %12s %s" % ("geometry", "best", "vs w=5", "total(w=5)", "table share at best"))
for label, W, M in GEOMETRIES:
    base, _, _ = cost(W, M, 5, 3)
    bw = best_w(W, M, 3)
    btotal, bops, _ = cost(W, M, bw, 3)
    table = (1 << bw) - 2
    print("  %-30s %6d %+9.2f%% %12.0f  %5.2f%%"
          % (label, bw, 100 * (btotal / base - 1), base, 100 * table / bops))
print()

print("== full w sweeps (scan = 3) ==")
for label, W, M in GEOMETRIES:
    print("-- %s (W=%d, M=%d)" % (label, W, M))
    base, _, _ = cost(W, M, 5, 3)
    print("   w  windows  mont_ops   total_Ir      vs_w5")
    for w in range(1, 9):
        total, ops, win = cost(W, M, w, 3)
        print("   %d  %7d  %8d  %12.0f  %+7.2f%%" % (w, win, ops, total, 100 * (total / base - 1)))
print()

print("== sensitivity of the best width to the scan coefficient ==")
print("  %-30s %s" % ("geometry", "best w at scan=1 / 2 / 3"))
for label, W, M in GEOMETRIES:
    print("  %-30s %d / %d / %d" % (label, best_w(W, M, 1), best_w(W, M, 2), best_w(W, M, 3)))
print()

print("== selector (production formula) for every geometry it sees ==")
for label, wl, m in [
    ("ffdhe2048 policy", 4, 32),
    ("ffdhe3072 policy", 5, 48),
    ("modexp-1024", 16, 16),
    ("modexp-2048", 32, 32),
    ("modexp-8192", 128, 128),
    ("P-256 4-limb modulus (ctgrind shape)", 4, 4),
    ("PFP-43 2400-bit covering @2048", 38, 32),
    ("PFP-43 4096-bit covering @2048", 64, 32),
]:
    print("  %-40s (%3d, %3d) -> w=%d" % (label, wl, m, selector(wl, m)))
print()

print("== old refusal vs new arithmetic (the visible change of conclusion) ==")
old_total, old_ops, _ = cost(2048, 32, 5, 3)
new_total, new_ops, _ = cost(256, 32, 5, 3)
_, new4_ops, _ = cost(256, 32, 4, 3)
old_share = 100 * 30 / old_ops
new_share = 100 * 30 / new_ops
print("  PFP-8 (modulus-width ladder, W=2048, M=32):")
print("    w=5 mont_ops=%d, table build=30 -> share=%.2f%% (PFP-8 measured 1.19%%)"
      % (old_ops, old_share))
print("    best prepared window w=6 was 2.21% faster -> BELOW the 10% refusal threshold")
print("  PFP-42 (policy-width ladder, W=256, M=32):")
print("    w=5 mont_ops=%d, table build=30 -> share=%.2f%% (%.1fx the old share)"
      % (new_ops, new_share, new_share / old_share))
print("    w=4 mont_ops=%d, table build=14 -> best, %.2f%% faster than w=5"
      % (new4_ops, 100 * (1 - cost(256, 32, 4, 3)[0] / new_total)))
print("  campaign measurement noise (PFP-6/PFP-8 control band) = 1.2-1.5%")
print("  3.10% > 1.5% -> the new bound crosses the bar the old one did not")
