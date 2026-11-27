#!/usr/bin/env python3
"""classify_widths.py — M-A1: per-site classification of the CIOS carrier
(`mont_mul_ladder_into`) from THIS digest's disassembly.

The candidate inlines all eight compile-time-width CIOS kernels (4/6/9/16/32/48/
64/128 limbs) plus the generic fallback into one symbol, so there is one carrier
to enumerate.

Input (raw/disasm/, produced by run_branch_audit.sh):
  cand-mont_mul_ladder_into.dis        objdump, symbol extent
  cand-mont_mul_ladder_into.sites.tsv  disasm_sites.py
  carrier-identity.txt                  digest bind

Structural rules (each is checked, not assumed):

  * A `jcc` is class (a) public-bound iff its nearest preceding flag-setting
    instruction in the same basic block is a comparison (`cmp`/`test`), or, at
    the recorded dispatch/geometry early returns, a public length `or`/`xor`.
    A `jcc` whose flags are set by arithmetic (`add`/`adc`/`sub`/`sbb`/`mul`/
    `imul`/`neg`/`inc`/`dec`) is a secret-derived transfer and is a STOP.
  * A `setcc` whose flag source is `cmp`/`test` is a class-(a) public geometry
    flag. A `setcc` whose flag source is `add`/`adc`/`sub`/`sbb` is a class-(b)
    secret carry/borrow; its first data consumer must be arithmetic
    (`adc`/`add`/`or`/`and`/`xor`/`neg`/`dec`/`mov`/`movzbl`/`movzbq`/`store`),
    never a comparison or a branch. A class-(b) setcc read by a `jcc` is a STOP.
  * No `cmovcc` is expected; any present one is classified and a secret-derived
    source is a STOP.

The script also requires the digest in carrier-identity.txt, that every listed
site is classified, and that the emitted totals equal the enumeration.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "raw", "disasm")
SYMBOL = "mont_mul_ladder_into"
EXPECT_DIGEST = "88c0c7e04d52a1bf84d665fdd691bddf2bbe700e35505d95bf145bfdc3774d87"

# The dispatch/geometry early-return jumps whose flags come from a public length
# `or`/`xor` rather than a `cmp`/`test`.
GEOMETRY_JCC = {"2fa80b"}

JCC = re.compile(r"^j(?!mp$)[a-z]+$")
SETCC = re.compile(r"^set[a-z]+$")
CMOV = re.compile(r"^cmov[a-z]+$")
LINE = re.compile(r"^\s*([0-9a-f]+):\t(.*)$")
FLAG_SET = {"add", "adc", "sub", "sbb", "neg", "inc", "dec", "cmp", "test",
            "and", "or", "xor", "mul", "imul"}
ARITH_FLAGS = {"add", "adc", "sub", "sbb", "mul", "imul", "neg", "inc", "dec"}
PUBLIC_FLAGS = {"cmp", "test"}
CONTROL = re.compile(r"^(j[a-z]+|call|ret|retq)$")
CONSUMER_PREFIXES = ("adc", "add", "or", "and", "xor", "neg", "dec", "inc",
                     "mov", "lea", "shl", "shr")


def is_arithmetic_consumer(m):
    return m.startswith(CONSUMER_PREFIXES)


def die(msg):
    sys.exit("M-A1 CLASSIFY STOP: " + msg)


def read_seq(path):
    seq = []
    for line in open(path):
        m = LINE.match(line)
        if m:
            text = m.group(2).split("#")[0].strip()
            parts = text.split(None, 1)
            seq.append((m.group(1), parts[0] if parts else "", text))
    return seq


def mnemonic(text):
    t = text.split("#")[0].strip()
    return t.split(None, 1)[0] if t else ""


def operands(text):
    t = text.split("#")[0].strip()
    p = t.split(None, 1)
    return p[1].strip() if len(p) > 1 else ""


def nearest_flag_source(seq, addr):
    idx = next(i for i, (a, _m, _t) in enumerate(seq) if a == addr)
    for i in range(idx - 1, max(idx - 25, -1), -1):
        a, m, t = seq[i]
        if m in FLAG_SET:
            return " ".join(t.split())
        if CONTROL.match(m):
            break
    return None


LEGACY_ALIASES = {
    "%al": ["%al", "%ax", "%eax", "%rax"],
    "%bl": ["%bl", "%bx", "%ebx", "%rbx"],
    "%cl": ["%cl", "%cx", "%ecx", "%rcx"],
    "%dl": ["%dl", "%dx", "%edx", "%rdx"],
    "%sil": ["%sil", "%si", "%esi", "%rsi"],
    "%dil": ["%dil", "%di", "%edi", "%rdi"],
    "%bpl": ["%bpl", "%bp", "%ebp", "%rbp"],
    "%spl": ["%spl", "%sp", "%esp", "%rsp"],
}


def dest_tokens(dest):
    if not dest.startswith("%"):
        return [dest]
    if dest in LEGACY_ALIASES:
        return LEGACY_ALIASES[dest]
    m = re.fullmatch(r"%(r\d+)b", dest)
    if m:
        r = "%" + m.group(1)
        return [dest, r + "w", r + "d", r]
    return [dest]


def first_consumer(seq, idx, dest):
    # Search forward for the first instruction that mentions the destination
    # operand (any width alias of the same register). A carry slot can be
    # written in one loop iteration and read in a later one, so the window is
    # the whole carrier tail; the first mention is still the first use (a store
    # before any read makes the value dead).
    toks = dest_tokens(dest)
    for j in range(idx + 1, min(idx + 400, len(seq))):
        m, t = seq[j][1], " ".join(seq[j][2].split())
        if any(tok in t for tok in toks):
            return seq[j][0], m, t
    return None, None, None


def main():
    ident = os.path.join(RAW, "carrier-identity.txt")
    if not os.path.exists(ident) or EXPECT_DIGEST not in open(ident).read():
        die("candidate digest not in carrier-identity.txt")
    sites = []
    for line in open(os.path.join(RAW, "cand-%s.sites.tsv" % SYMBOL)):
        f = line.rstrip("\n").split("\t")
        sites.append({"addr": f[1], "insn": f[2], "args": f[3], "kind": f[6]})
    seq = read_seq(os.path.join(RAW, "cand-%s.dis" % SYMBOL))
    order = {a: i for i, (a, _m, _t) in enumerate(seq)}

    counts = {"jcc": {"a": 0, "b": 0}, "setcc": {"a": 0, "b": 0},
              "cmovcc": {"a": 0, "b": 0}}
    rows = []
    for s in sorted(sites, key=lambda r: int(r["addr"], 16)):
        addr, kind = s["addr"], s["kind"]
        src = nearest_flag_source(seq, addr)
        if src is None:
            die("no flag source before %s" % addr)
        sm = mnemonic(src)
        if kind == "jcc":
            if not JCC.match(s["insn"]):
                die("kind/opcode mismatch at %s: %s" % (addr, s["insn"]))
            if sm in PUBLIC_FLAGS:
                cls, sub = "a", "a-loop"
            elif sm in {"or", "xor", "and"} and addr in GEOMETRY_JCC:
                cls, sub = "a", "a-geom"
            else:
                die("jcc %s at %s has arithmetic flag source %r (secret-derived "
                    "control transfer)" % (s["insn"], addr, src))
            cons = "-"
        elif kind == "setcc":
            if not SETCC.match(s["insn"]):
                die("kind/opcode mismatch at %s: %s" % (addr, s["insn"]))
            if sm in PUBLIC_FLAGS:
                cls, sub = "a", "a-geom"
                cons = "-"
            elif sm in ARITH_FLAGS:
                cls, sub = "b", "b-flag"
                ca, cm, ct = first_consumer(
                    seq, order[addr], s["args"].split(",")[0].strip())
                if cm is None:
                    die("class-b setcc %s at %s has no findable consumer" % (s["insn"], addr))
                if not is_arithmetic_consumer(cm):
                    die("class-b setcc %s at %s consumed by %r (not arithmetic)"
                        % (s["insn"], addr, ct))
                cons = "%s:%s" % (ca, ct)
            else:
                die("setcc %s at %s has unexpected flag source %r" % (s["insn"], addr, src))
        else:
            if not CMOV.match(s["insn"]):
                die("kind/opcode mismatch at %s: %s" % (addr, s["insn"]))
            cls = "b" if sm in ARITH_FLAGS else "a"
            sub = "b-flag" if cls == "b" else "a-loop"
            cons = "-"
            if cls == "b":
                die("cmovcc at %s reads an arithmetic flag (secret-derived data select)"
                    % addr)
        counts[kind][cls] += 1
        rows.append([SYMBOL, addr, kind, s["insn"], s["args"].split("<")[0].strip(),
                     cls, sub, src, cons])

    with open(os.path.join(RAW, "classification.tsv"), "w") as f:
        f.write("symbol\taddr\tkind\tinsn\toperand\tclass\tsub\tflag_source\tconsumed\n")
        for r in rows:
            f.write("\t".join(r) + "\n")

    lines = ["# M-A1 — specialised CIOS carrier classification (per site)", "",
             "Generated by `classify_widths.py` from `cand-mont_mul_ladder_into.dis`",
             "at candidate digest `%s`." % EXPECT_DIGEST, "",
             "A `jcc` whose flags come from arithmetic, a class-(b) `setcc` whose first",
             "consumer is not arithmetic, or an unclassified site aborts the script.", "",
             "| addr | kind | insn | class | flag source | consumed by |",
             "|---|---|---|---|---|---|"]
    for r in rows:
        lines.append("| `0x%s` | %s | `%s` | (%s) %s | `%s` | `%s` |"
                     % (r[1], r[2], r[3], r[5], r[6], r[7], r[8]))
    total = sum(counts[k]["a"] + counts[k]["b"] for k in counts)
    lines += ["",
              "Counts: %d jcc (%d class a, %d class b), %d setcc (%d class a, %d class b), "
              "%d cmovcc; %d sites total."
              % (counts["jcc"]["a"] + counts["jcc"]["b"], counts["jcc"]["a"],
                 counts["jcc"]["b"], counts["setcc"]["a"] + counts["setcc"]["b"],
                 counts["setcc"]["a"], counts["setcc"]["b"],
                 counts["cmovcc"]["a"] + counts["cmovcc"]["b"], total), "",
              "Secret-derived control transfers: **0**.",
              "Class-(b) carry/borrow flags consumed arithmetically, none by a `jcc`: **%d**."
              % counts["setcc"]["b"]]
    with open(os.path.join(RAW, "classification.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    if counts["jcc"]["b"] != 0 or counts["cmovcc"]["b"] != 0:
        die("secret-derived control transfer in the carrier")
    print("classification: jcc=%d setcc=%d cmovcc=%d  (a=%d b-flag=%d b-ctrl=0)"
          % (counts["jcc"]["a"] + counts["jcc"]["b"],
             counts["setcc"]["a"] + counts["setcc"]["b"],
             counts["cmovcc"]["a"] + counts["cmovcc"]["b"],
             counts["jcc"]["a"] + counts["setcc"]["a"] + counts["cmovcc"]["a"],
             counts["setcc"]["b"]))


if __name__ == "__main__":
    main()
