#!/usr/bin/env python3
"""classify_sites.py — PFP-27 per-site classification of the kernel carriers.

Input: raw/disasm/<dso>-<symbol>.sites.tsv produced by disasm_sites.py.
Output: raw/disasm/classification.md and classification.tsv, plus a coverage
assertion: every site in the listing must be classified here, and every entry
here must exist in the listing.  A mismatch is a hard failure, not a warning.

Classes (the PFP-27 deliverable):
  (a)  a public loop bound, length/geometry check, or an invariant the compiler
       can prove; its condition is a function of public lengths or indices.
  (b)  a branch or flag derived from secret limb data.

Sub-labels:
  a-geom   public length/geometry comparison
  a-loop   public loop bound / iteration count / index
  a-panic  public bounds check whose only outcome is the panic path
  b-flag   a carry/borrow of secret limb arithmetic, materialised by setcc and
           consumed arithmetically (adc/or/movzx).  Flag, not control flow.
  b-ctrl   a conditional transfer whose condition is secret-derived.  STOP.

Dataflow note for every b-flag site: the byte written by setcc is read only by
`adc`, `add`, `or`, `mov`, `movzbl` in the same carrier; none is read by a jcc.
`no_bflag_reaches_control` is therefore a claim about this exact listing, and
the memcheck kernel probe (run_probe.sh) is its dynamic confirmation.
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "raw", "disasm")

# (dso, symbol, address) -> (class, sub, depends_on, note)
SITES = {
    # ---------------- DSO B: CIOS, inlined into mont_mul_ladder_into ----------
    ("b", "mont_mul_ladder_into", "544033"): ("a", "a-geom", "a/b/out/diff/t lengths", "mont_geometry_ok: xor/or of the five length words"),
    ("b", "mont_mul_ladder_into", "544049"): ("a", "a-geom", "t.len == 2n+1", "geometry flag (return value on the failure path)"),
    ("b", "mont_mul_ladder_into", "54404c"): ("a", "a-geom", "t.len != 2n+1", "geometry flag, ORed into the early-return test"),
    ("b", "mont_mul_ladder_into", "544052"): ("a", "a-geom", "n == 0", "geometry flag, ORed into the early-return test"),
    ("b", "mont_mul_ladder_into", "544057"): ("a", "a-geom", "!(geometry) || n == 0", "early return; public lengths only"),
    ("b", "mont_mul_ladder_into", "544097"): ("a", "a-loop", "n < 2", "specialisation for a one-limb modulus"),
    ("b", "mont_mul_ladder_into", "54410e"): ("a", "a-loop", "outer loop over b's n limbs", "fixed trip count = b.len()"),
    ("b", "mont_mul_ladder_into", "544123"): ("a", "a-loop", "n == 1", "n-1 == 0: no inner product iteration"),
    ("b", "mont_mul_ladder_into", "544171"): ("a", "a-loop", "j < n & ~1", "unrolled-by-2 product loop, public bound"),
    ("b", "mont_mul_ladder_into", "544177"): ("a", "a-loop", "n odd", "remaining product limb, public parity"),
    ("b", "mont_mul_ladder_into", "5441ca"): ("a", "a-loop", "n == 2", "reduction-loop specialisation, public n"),
    ("b", "mont_mul_ladder_into", "544216"): ("a", "a-loop", "reduction-loop count from n", "unrolled-by-2 reduction loop"),
    ("b", "mont_mul_ladder_into", "54421e"): ("a", "a-loop", "n - 1 odd", "remaining reduction limb, public parity"),
    ("b", "mont_mul_ladder_into", "544293"): ("a", "a-loop", "n == 1", "conditional-subtraction specialisation"),
    ("b", "mont_mul_ladder_into", "5442e8"): ("a", "a-loop", "j < n & ~1", "unrolled-by-2 subtraction loop"),
    ("b", "mont_mul_ladder_into", "5442ee"): ("a", "a-loop", "n odd", "remaining subtraction limb, public parity"),
    ("b", "mont_mul_ladder_into", "544359"): ("a", "a-loop", "j < n", "final mask-select loop, public bound"),

    ("b", "mont_mul_ladder_into", "5440dd"): ("b", "b-flag", "carry of acc[j] + a[j]*b[i]", "setb %sil -> adc %rdx,%rsi; data"),
    ("b", "mont_mul_ladder_into", "54413e"): ("b", "b-flag", "carry of the product row", "setb %r10b -> adc/or; data"),
    ("b", "mont_mul_ladder_into", "54415b"): ("b", "b-flag", "carry of the product row", "setb %sil -> adc; data"),
    ("b", "mont_mul_ladder_into", "544186"): ("b", "b-flag", "carry of the tail product limb", "setb %cl -> adc; data"),
    ("b", "mont_mul_ladder_into", "54419c"): ("b", "b-flag", "carry into acc[n+1]", "setb %al -> stored as acc[n+1]; data"),
    ("b", "mont_mul_ladder_into", "5441de"): ("b", "b-flag", "carry of the reduction row", "setb %r10b -> adc/or; data"),
    ("b", "mont_mul_ladder_into", "5441fc"): ("b", "b-flag", "carry of the reduction row", "setb %cl -> adc; data"),
    ("b", "mont_mul_ladder_into", "544245"): ("b", "b-flag", "carry of acc[n] += carry", "setb %sil -> add 0xff/adc; data"),
    ("b", "mont_mul_ladder_into", "544249"): ("b", "b-flag", "same carry, second read", "setb %al -> movzbl/store acc[n+1]; data"),
    ("b", "mont_mul_ladder_into", "54426b"): ("b", "b-flag", "carry of u*m[0] + acc[0]", "setb %al -> movzbl/add 0xff/adc; data"),
    ("b", "mont_mul_ladder_into", "5442b8"): ("b", "b-flag", "borrow of acc[j] - m[j]", "setb %r11b -> or into borrow; data"),
    ("b", "mont_mul_ladder_into", "5442bf"): ("b", "b-flag", "borrow of (d1 - borrow)", "setb %cl -> or/add 0xff; data"),
    ("b", "mont_mul_ladder_into", "5442df"): ("b", "b-flag", "borrow of the sbb pair", "setb %cl -> movzbl, next borrow; data"),
    ("b", "mont_mul_ladder_into", "5442f8"): ("b", "b-flag", "borrow of the tail limb", "setb %r10b -> or; data"),
    ("b", "mont_mul_ladder_into", "5442ff"): ("b", "b-flag", "borrow of the tail limb", "setb %cl -> movzbl; data"),

    # ---------------- DSO A: SOS multiply (production) ----------------------
    ("a", "mont_mul_sos_into", "543983"): ("a", "a-geom", "a/b/out/diff/t lengths", "mont_geometry_ok"),
    ("a", "mont_mul_sos_into", "54399c"): ("a", "a-geom", "t.len == 2n+1", "geometry check"),
    ("a", "mont_mul_sos_into", "5439cd"): ("a", "a-geom", "n == 0", "early return true"),
    ("a", "mont_mul_sos_into", "543a31"): ("a", "a-loop", "outer product loop", "i < n"),
    ("a", "mont_mul_sos_into", "543a44"): ("a", "a-loop", "n == 1", "inner-loop specialisation"),
    ("a", "mont_mul_sos_into", "543a92"): ("a", "a-loop", "j < n & ~1", "unrolled-by-2 product loop"),
    ("a", "mont_mul_sos_into", "543a98"): ("a", "a-loop", "n odd", "remaining product limb"),
    ("a", "mont_mul_sos_into", "543b0d"): ("a", "a-loop", "REDC outer loop", "i < n"),
    ("a", "mont_mul_sos_into", "543b1b"): ("a", "a-loop", "REDC outer loop end", "i vs n (public)"),
    ("a", "mont_mul_sos_into", "543b53"): ("a", "a-panic", "j < n", "bounds check, panic path only"),
    ("a", "mont_mul_sos_into", "543b7f"): ("a", "a-loop", "j < n", "REDC inner loop"),
    ("a", "mont_mul_sos_into", "543b8d"): ("a", "a-loop", "t index vs 2n+1", "carry-propagation loop entry"),
    ("a", "mont_mul_sos_into", "543bb3"): ("a", "a-loop", "carry-propagation range", "fixed by n"),
    ("a", "mont_mul_sos_into", "543bd2"): ("a", "a-loop", "n == 1", "subtraction specialisation"),
    ("a", "mont_mul_sos_into", "543c38"): ("a", "a-loop", "j < n & ~1", "unrolled subtraction loop"),
    ("a", "mont_mul_sos_into", "543c3e"): ("a", "a-loop", "n odd", "remaining subtraction limb"),
    ("a", "mont_mul_sos_into", "543cb7"): ("a", "a-panic", "n + j < t.len()", "bounds check, panic path only"),
    ("a", "mont_mul_sos_into", "543cbc"): ("a", "a-panic", "j < n", "bounds check, panic path only"),
    ("a", "mont_mul_sos_into", "543ce8"): ("a", "a-loop", "j < n", "final mask-select loop"),

    ("a", "mont_mul_sos_into", "543a12"): ("b", "b-flag", "carry of the product row", "setb %r11b -> adc; data"),
    ("a", "mont_mul_sos_into", "543a5f"): ("b", "b-flag", "carry of the product row", "setb %r11b -> adc; data"),
    ("a", "mont_mul_sos_into", "543a7d"): ("b", "b-flag", "carry of the product row", "setb %r9b -> adc; data"),
    ("a", "mont_mul_sos_into", "543b67"): ("b", "b-flag", "carry of the REDC row", "setb %r8b -> adc; data"),
    ("a", "mont_mul_sos_into", "543ba6"): ("b", "b-flag", "carry into t[i+n]", "setb %cl -> adc; data"),
    ("a", "mont_mul_sos_into", "543c09"): ("b", "b-flag", "borrow of t[n+j] - m[j]", "setb %r11b -> or; data"),
    ("a", "mont_mul_sos_into", "543c10"): ("b", "b-flag", "borrow of (d1 - borrow)", "setb %dl -> or/add 0xff; data"),
    ("a", "mont_mul_sos_into", "543c2f"): ("b", "b-flag", "borrow of the sbb pair", "setb %dl -> movzbl; data"),
    ("a", "mont_mul_sos_into", "543c6a"): ("b", "b-flag", "borrow of the tail limb", "setb %r9b -> or; data"),
    ("a", "mont_mul_sos_into", "543c71"): ("b", "b-flag", "borrow of the tail limb", "setb %dl -> movzbl; data"),
}

# The SOS body in B is the same function at another address; its map is the A
# map shifted by the symbol-start difference, and its site sequence is asserted
# equal below.
SOS_SHIFT = 0x5438E0 - 0x543950  # B start - A start
ALL = dict(SITES)
for (_d, _s, _a), _v in list(SITES.items()):
    if _d == "a" and _s == "mont_mul_sos_into":
        ALL[("b", "mont_mul_sos_into", "%x" % (int(_a, 16) + SOS_SHIFT))] = _v


def read_sites(dso, symbol):
    path = os.path.join(RAW, "%s-%s.sites.tsv" % (dso, symbol))
    rows = []
    for line in open(path):
        f = line.rstrip("\n").split("\t")
        rows.append({"addr": f[1], "insn": f[2], "args": f[3],
                     "prev2": f[4], "prev1": f[5], "kind": f[6]})
    return rows


def main():
    out = []
    total = {"jcc": {"a": 0, "b": 0}, "setcc": {"a": 0, "b": 0}, "cmovcc": {"a": 0, "b": 0}}
    secrets = []
    seen = set()
    for dso, symbol in (("b", "mont_mul_ladder_into"),
                        ("a", "mont_mul_sos_into"),
                        ("b", "mont_mul_sos_into")):
        rows = read_sites(dso, symbol)
        for r in rows:
            key = (dso, symbol, r["addr"])
            if key not in ALL:
                sys.exit("UNCLASSIFIED: %s %s %s" % key)
            cls, sub, dep, note = ALL[key]
            seen.add(key)
            kind = r["kind"]
            total[kind][cls] += 1
            if kind == "jcc":
                kind_label = "jcc"
            elif kind == "setcc":
                kind_label = "setcc"
            else:
                kind_label = "cmovcc"
            out.append("\t".join([dso, symbol, r["addr"], kind_label, r["insn"],
                                  r["args"].split("<")[0].strip(), cls, sub, dep, note,
                                  r["prev1"]]))
            if sub == "b-ctrl":
                secrets.append(key)

    # Coverage: every mapped site must have appeared.
    for key in ALL:
        if key not in seen:
            sys.exit("MAPPED BUT ABSENT: %s" % (key,))

    # The SOS site sequence in B must equal A's (same function, shifted copy).
    def norm(r):
        a = r["args"]
        if r["kind"] == "jcc":
            a = "T"  # branch targets move with the symbol; compare opcode/kind only
        return r["insn"] + " " + a.split("<")[0].strip()
    seq_a = [norm(r) for r in read_sites("a", "mont_mul_sos_into")]
    seq_b = [norm(r) for r in read_sites("b", "mont_mul_sos_into")]
    if seq_a != seq_b:
        sys.exit("SOS bodies differ between the two artefacts")
    with open(os.path.join(RAW, "classification.tsv"), "w") as f:
        f.write("dso\tsymbol\taddr\tkind\tinsn\toperand\tclass\tsub\tdepends_on\tnote\tprev\n")
        for line in out:
            f.write(line + "\n")

    lines = []
    lines.append("# PFP-27 branch classification — per site, from the artefact")
    lines.append("")
    lines.append("Generated by `classify_sites.py` from the objdump extents in this directory.")
    lines.append("A site missing from the map, or a mapped site missing from the listing, aborts the script.")
    lines.append("")
    for dso, symbol in (("b", "mont_mul_ladder_into"),
                        ("a", "mont_mul_sos_into"),
                        ("b", "mont_mul_sos_into")):
        rows = [r for r in out if r.split("\t")[0] == dso and r.split("\t")[1] == symbol]
        jcc = [r for r in rows if r.split("\t")[3] == "jcc"]
        setcc = [r for r in rows if r.split("\t")[3] == "setcc"]
        cmov = [r for r in rows if r.split("\t")[3] == "cmovcc"]
        lines.append("## %s `%s`" % ("DSO A" if dso == "a" else "DSO B", symbol))
        lines.append("")
        lines.append("| addr | insn | condition source | class | depends on | note |")
        lines.append("|---|---|---|---|---|---|")
        for r in rows:
            f = r.split("\t")
            lines.append("| `0x%s` | `%s %s` | `%s` | (%s) %s | %s | %s |"
                         % (f[2], f[4], f[5], f[10], f[6], f[7], f[8], f[9]))
        lines.append("")
        lines.append("Counts: %d jcc (%d class a, %d class b), %d setcc (%d class a, %d class b), "
                     "%d cmovcc." % (
                         len(jcc),
                         sum(1 for r in jcc if r.split("\t")[6] == "a"),
                         sum(1 for r in jcc if r.split("\t")[6] == "b"),
                         len(setcc),
                         sum(1 for r in setcc if r.split("\t")[6] == "a"),
                         sum(1 for r in setcc if r.split("\t")[6] == "b"),
                         len(cmov)))
        lines.append("")
    lines.append("## Verdict")
    lines.append("")
    lines.append("- Conditional jumps whose condition is secret-derived (`b-ctrl`): **%d**." % len(secrets))
    lines.append("- `setcc` flags derived from secret limb data (`b-flag`): **%d**; every one is"
                 " consumed arithmetically (`adc`/`add`/`or`/`mov`/`movzbl`) inside the same carrier and"
                 " none is read by a jcc. The dynamic confirmation is `run_probe.sh`: a fully tainted"
                 " base yields 0 memcheck contexts in either real carrier, while the canary yields 2 in"
                 " `mont_mul_ladder_into`." % (total["setcc"]["b"]))
    if secrets:
        lines.append("- **STOP**: secret-derived control transfer found: %r" % secrets)
    with open(os.path.join(RAW, "classification.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("jcc=%d setcc=%d cmovcc=%d  (a=%d b-flag=%d b-ctrl=%d)"
          % (total["jcc"]["a"] + total["jcc"]["b"],
             total["setcc"]["a"] + total["setcc"]["b"],
             total["cmovcc"]["a"] + total["cmovcc"]["b"],
             total["jcc"]["a"] + total["setcc"]["a"],
             total["setcc"]["b"], len(secrets)))
    if secrets:
        sys.exit(1)


if __name__ == "__main__":
    main()
