#!/usr/bin/env python3
"""classify_cios.py — PFP-6 admission: per-site classification of the CIOS
carrier (`mont_mul_ladder_into`) from THIS digest's disassembly.

Input:
  raw/disasm/cand-mont_mul_ladder_into.dis        (objdump, symbol extent)
  raw/disasm/cand-mont_mul_ladder_into.sites.tsv  (disasm_sites.py)
  raw/disasm/carrier-identity.txt                 (digest bind)

The script fails (exit 1) if:
  * the carrier digest is not the recorded candidate digest;
  * a site in the listing is unclassified, or a mapped site is absent;
  * a site's opcode/kind differs from the map, or the nearest preceding
    flag-setting instruction is not the recorded flag source;
  * a class-(b) `setcc` has no verified arithmetic consumer at the recorded
    address (the dataflow assertion);
  * the counted totals differ from the emitted enumeration.

Classes:
  (a) public-bound: loop bound, length/geometry check, or a compiler-provable
      invariant; its condition is a function of public lengths or indices.
  (b) secret-derived: a carry/borrow of secret limb arithmetic materialised by
      `setcc`, consumed arithmetically.  `b-ctrl` (a conditional transfer whose
      condition is secret-derived) is a STOP and is never expected here.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "raw", "disasm")
SYMBOL = "mont_mul_ladder_into"
EXPECT_DIGEST = "6d002db20c815e252d1672a72b654f40844c2a1b24400cfbdfce5d1eaf828f39"

# (symbol, addr) -> (class, sub, depends_on, note, flag_source, consumer_addr,
#                     consumer_insn_prefix).  `flag_source` is the exact nearest
# preceding flag-setting instruction in THIS listing.  `consumer_*` is None
# for class (a); for class (b) it is verified in the full listing.
SITES = {
    # ---- jcc: all public-bound ------------------------------------------
    ("mont_mul_ladder_into", "58ce93"): (
        "a", "a-geom", "mont_geometry_ok: xor/or of the five length words",
        "early return false; public lengths only", "or %r9,%rax", None, None),
    ("mont_mul_ladder_into", "58ceb7"): (
        "a", "a-geom", "!(t.len == 2n+1) || n == 0",
        "early return true; public lengths only", "or %cl,%dl", None, None),
    ("mont_mul_ladder_into", "58cef7"): (
        "a", "a-loop", "n < 2", "one-limb modulus specialisation",
        "cmp $0x2,%r13", None, None),
    ("mont_mul_ladder_into", "58cf6e"): (
        "a", "a-loop", "outer loop over b's n limbs (pointer vs b_end)",
        "fixed trip count = b.len()", "cmp 0x20(%rsp),%r14", None, None),
    ("mont_mul_ladder_into", "58cf83"): (
        "a", "a-loop", "n - 1 == 0", "no inner product iteration for n == 1",
        "test %rax,%rax", None, None),
    ("mont_mul_ladder_into", "58cfd1"): (
        "a", "a-loop", "j < n & ~1", "unrolled-by-2 product loop",
        "cmp %r9,%r13", None, None),
    ("mont_mul_ladder_into", "58cfd7"): (
        "a", "a-loop", "n odd", "remaining product limb, public parity",
        "test $0x1,%dil", None, None),
    ("mont_mul_ladder_into", "58d02a"): (
        "a", "a-loop", "n == 2", "reduction specialisation, public n",
        "cmp $0x2,%rdi", None, None),
    ("mont_mul_ladder_into", "58d076"): (
        "a", "a-loop", "reduction-loop count from n", "unrolled-by-2 reduction loop",
        "cmp $0x1,%rax", None, None),
    ("mont_mul_ladder_into", "58d07e"): (
        "a", "a-loop", "n - 1 odd", "remaining reduction limb, public parity",
        "test $0x1,%al", None, None),
    ("mont_mul_ladder_into", "58d0f3"): (
        "a", "a-loop", "n == 1", "conditional-subtraction specialisation",
        "cmp $0x1,%rdi", None, None),
    ("mont_mul_ladder_into", "58d148"): (
        "a", "a-loop", "j < n & ~1", "unrolled-by-2 subtraction loop",
        "cmp %rsi,%r9", None, None),
    ("mont_mul_ladder_into", "58d14e"): (
        "a", "a-loop", "n odd", "remaining subtraction limb, public parity",
        "test $0x1,%dil", None, None),
    ("mont_mul_ladder_into", "58d1b9"): (
        "a", "a-loop", "j < n", "final mask-select loop, public bound",
        "cmp %r9,%rdi", None, None),

    # ---- setcc: geometry flags (public) ---------------------------------
    ("mont_mul_ladder_into", "58cea9"): (
        "a", "a-geom", "t.len == 2n+1", "geometry flag (public lengths)",
        "cmp %rax,0x80(%rsp)", None, None),
    ("mont_mul_ladder_into", "58ceac"): (
        "a", "a-geom", "t.len != 2n+1", "geometry flag ORed into the early-return test",
        "cmp %rax,0x80(%rsp)", "58ceb7", "jne"),
    ("mont_mul_ladder_into", "58ceb2"): (
        "a", "a-geom", "n == 0", "geometry flag ORed into the early-return test",
        "test %rsi,%rsi", "58ceb5", "or"),

    # ---- setcc: carry/borrow flags (secret data, consumed arithmetically)
    ("mont_mul_ladder_into", "58cf3d"): (
        "b", "b-flag", "carry of acc[j] + a[j]*b[i]",
        "setb %sil -> adc %rdx,%rsi; data", "add (%rbx,%r9,8),%rcx",
        "58cf44", "adc"),
    ("mont_mul_ladder_into", "58cf9e"): (
        "b", "b-flag", "carry of the product row",
        "setb %r10b -> adc %rdx,%r10; data", "add (%rbx,%r9,8),%rsi",
        "58cfa5", "adc"),
    ("mont_mul_ladder_into", "58cfbb"): (
        "b", "b-flag", "carry of the second product-row limb",
        "setb %sil -> adc %rdx,%rsi; data", "add 0x8(%rbx,%r9,8),%r10",
        "58cfcb", "adc"),
    ("mont_mul_ladder_into", "58cfe6"): (
        "b", "b-flag", "carry of the tail product limb",
        "setb %cl -> adc %rdx,%rcx; data", "add (%rbx,%r9,8),%rsi",
        "58cfec", "adc"),
    ("mont_mul_ladder_into", "58cffc"): (
        "b", "b-flag", "carry into acc[n+1]",
        "setb %al -> store as acc[n+1]; data",
        "add %rsi,(%rbx,%rdi,8)", "58cfff", "mov"),
    ("mont_mul_ladder_into", "58d03e"): (
        "b", "b-flag", "carry of the reduction row",
        "setb %r10b -> adc %rdx,%r10; data", "add (%rbx,%r9,8),%rcx",
        "58d045", "adc"),
    ("mont_mul_ladder_into", "58d05c"): (
        "b", "b-flag", "carry of the second reduction-row limb",
        "setb %cl -> adc %rdx,%rcx; data", "add 0x8(%rbx,%r9,8),%r10",
        "58d06f", "adc"),
    ("mont_mul_ladder_into", "58d0a5"): (
        "b", "b-flag", "carry of acc[n] += carry (n == 1 path)",
        "setb %sil -> add $0xff,%sil; data", "adc (%rbx,%rdi,8),%rcx",
        "58d0d6", "add"),
    ("mont_mul_ladder_into", "58d0a9"): (
        "b", "b-flag", "same carry, second read (n == 1 path)",
        "setb %al -> movzbl/store acc[n+1]; data", "adc (%rbx,%rdi,8),%rcx",
        "58d0b0", "movzbl"),
    ("mont_mul_ladder_into", "58d0cb"): (
        "b", "b-flag", "carry of u*m[0] + acc[0] (n == 1 path)",
        "setb %al -> movzbl/add 0xff/adc; data", "adc %rcx,%rdx",
        "58d0d3", "movzbl"),
    ("mont_mul_ladder_into", "58d118"): (
        "b", "b-flag", "borrow of acc[j] - m[j]",
        "setb %r11b -> or %r11b,%cl; data", "sub (%r12,%rsi,8),%r10",
        "58d126", "or"),
    ("mont_mul_ladder_into", "58d11f"): (
        "b", "b-flag", "borrow of (d1 - borrow)",
        "setb %cl -> add $0xff,%cl; data", "sub %rcx,%r10",
        "58d12e", "add"),
    ("mont_mul_ladder_into", "58d13f"): (
        "b", "b-flag", "borrow of the sbb pair",
        "setb %cl -> movzbl; data", "sbb 0x8(%r12,%rsi,8),%r10",
        "58d142", "movzbl"),
    ("mont_mul_ladder_into", "58d158"): (
        "b", "b-flag", "borrow of the tail limb",
        "setb %r10b -> or %r10b,%cl; data", "sub (%r12,%rsi,8),%r9",
        "58d166", "or"),
    ("mont_mul_ladder_into", "58d15f"): (
        "b", "b-flag", "borrow of the tail limb, second read",
        "setb %cl -> movzbl; data", "sub %rcx,%r9",
        "58d169", "movzbl"),
}

JCC = re.compile(r"^j(?!mp$)[a-z]+$")
SETCC = re.compile(r"^set[a-z]+$")
CMOV = re.compile(r"^cmov[a-z]+$")
LINE = re.compile(r"^\s*([0-9a-f]+):\t(.*)$")
FLAG_SET = {"add", "adc", "sub", "sbb", "neg", "inc", "dec", "cmp", "test",
            "and", "or", "xor", "mul", "imul"}
CONTROL = re.compile(r"^(j[a-z]+|call|ret|retq)$")


def die(msg):
    sys.exit("CLASSIFY STOP: " + msg)


def read_sites():
    rows = {}
    path = os.path.join(RAW, "cand-%s.sites.tsv" % SYMBOL)
    for line in open(path):
        f = line.rstrip("\n").split("\t")
        rows[f[1]] = {"insn": f[2], "args": f[3], "prev2": f[4],
                      "prev1": f[5], "kind": f[6]}
    return rows


def read_insns():
    seq = []
    path = os.path.join(RAW, "cand-%s.dis" % SYMBOL)
    for line in open(path):
        m = LINE.match(line)
        if m:
            text = m.group(2).split("#")[0].strip()
            parts = text.split(None, 1)
            seq.append((m.group(1), parts[0] if parts else "", text))
    return seq


def norm(text):
    return " ".join(text.split())


def nearest_flag_source(seq, addr):
    idx = next(i for i, (a, _m, _t) in enumerate(seq) if a == addr)
    for i in range(idx - 1, max(idx - 9, -1), -1):
        a, mnemonic, text = seq[i]
        if mnemonic in FLAG_SET:
            return norm(text)
        if CONTROL.match(mnemonic):
            break
    return None


def main():
    ident = os.path.join(RAW, "carrier-identity.txt")
    if EXPECT_DIGEST not in open(ident).read():
        die("candidate digest not in carrier-identity.txt")
    rows = read_sites()
    seq = read_insns()
    insns = {a: t for a, _m, t in seq}

    for addr in rows:
        if (SYMBOL, addr) not in SITES:
            die("UNCLASSIFIED site %s %s" % (SYMBOL, addr))
    for key in SITES:
        if key[1] not in rows:
            die("MAPPED BUT ABSENT site %s %s" % key)

    out = []
    counts = {"jcc": {"a": 0, "b": 0}, "setcc": {"a": 0, "b": 0},
              "cmovcc": {"a": 0, "b": 0}}
    for addr in sorted(rows, key=lambda a: int(a, 16)):
        r = rows[addr]
        cls, sub, dep, note, src, cons_addr, cons_insn = SITES[(SYMBOL, addr)]
        if r["kind"] == "jcc":
            ok = JCC.match(r["insn"]) is not None
        elif r["kind"] == "setcc":
            ok = SETCC.match(r["insn"]) is not None
        elif r["kind"] == "cmovcc":
            ok = CMOV.match(r["insn"]) is not None
        else:
            ok = False
        if not ok:
            die("kind/opcode mismatch at %s: %s %s" % (addr, r["kind"], r["insn"]))
        actual_src = nearest_flag_source(seq, addr)
        if actual_src != norm(src):
            die("flag source before %s is %r, map says %r"
                % (addr, actual_src, norm(src)))
        counts[r["kind"]][cls] += 1
        consumed = "-"
        if cls == "b":
            if cons_addr is None:
                die("class-b site %s has no consumer" % addr)
            if cons_addr not in insns:
                die("consumer %s for %s not in listing" % (cons_addr, addr))
            if not norm(insns[cons_addr]).startswith(cons_insn):
                die("consumer %s for %s is %r, expected %r"
                    % (cons_addr, addr, norm(insns[cons_addr]), cons_insn))
            consumed = "%s:%s" % (cons_addr, insns[cons_addr])
            if r["kind"] == "jcc":
                die("secret-derived control transfer at %s" % addr)
        out.append("\t".join([SYMBOL, addr, r["kind"], r["insn"],
                              r["args"].split("<")[0].strip(), cls, sub, dep,
                              note, src, consumed]))

    with open(os.path.join(RAW, "classification.tsv"), "w") as f:
        f.write("symbol\taddr\tkind\tinsn\toperand\tclass\tsub\tdepends_on\tnote\tflag_source\tconsumed\n")
        for line in out:
            f.write(line + "\n")

    if len(rows) != len(SITES):
        die("enumerated %d sites, map has %d" % (len(rows), len(SITES)))

    lines = ["# PFP-6 admission — CIOS carrier classification (per site)", "",
             "Generated by `classify_cios.py` from `cand-mont_mul_ladder_into.dis`",
             "at candidate digest `%s`." % EXPECT_DIGEST, "",
             "A site missing from the map, a mapped site missing from the listing, a",
             "flag-source mismatch, or a class-(b) flag without a verified arithmetic",
             "consumer aborts the script.", "",
             "| addr | kind | insn | class | depends on | flag source | consumed by |",
             "|---|---|---|---|---|---|---|"]
    for line in out:
        f = line.split("\t")
        lines.append("| `0x%s` | %s | `%s` | (%s) %s | %s | `%s` | `%s` |"
                     % (f[1], f[2], f[3], f[5], f[6], f[7], f[9], f[10]))
    lines += ["",
              "Counts: %d jcc (%d class a, %d class b), %d setcc (%d class a, "
              "%d class b), %d cmovcc."
              % (counts["jcc"]["a"] + counts["jcc"]["b"], counts["jcc"]["a"],
                 counts["jcc"]["b"], counts["setcc"]["a"] + counts["setcc"]["b"],
                 counts["setcc"]["a"], counts["setcc"]["b"],
                 counts["cmovcc"]["a"] + counts["cmovcc"]["b"]), "",
              "Secret-derived control transfers (`b-ctrl`): **0**.",
              "Class-(b) `setcc` flags consumed arithmetically, none by a `jcc`: **%d**."
              % counts["setcc"]["b"]]
    with open(os.path.join(RAW, "classification.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("classification: jcc=%d setcc=%d cmovcc=%d  (a=%d b-flag=%d b-ctrl=0)"
          % (counts["jcc"]["a"] + counts["jcc"]["b"],
             counts["setcc"]["a"] + counts["setcc"]["b"],
             counts["cmovcc"]["a"] + counts["cmovcc"]["b"],
             counts["jcc"]["a"] + counts["setcc"]["a"], counts["setcc"]["b"]))
    if counts["jcc"]["b"] != 0:
        die("secret-derived control transfer in the carrier")


if __name__ == "__main__":
    main()
