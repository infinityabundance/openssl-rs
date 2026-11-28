#!/usr/bin/env python3
"""phase2_audit.py — PFP-11 phase 2 branch audit of the Mersenne REDC carrier.

Input: an `objdump -d --start-address --stop-address` listing of one symbol.
Output: every jcc/setcc/cmov site with its nearest preceding flag-setting
instruction, a class, and (for arithmetic-flag setcc) the first consumer.

Classes
  a-public    flag source is a comparison/test over public geometry (loop index,
              slice length, symbol pointer). Not secret-derived.
  b-flag      flag source is an arithmetic carry/borrow; the value may be
              secret-derived but must be consumed arithmetically.
  STOP        a jcc/cmov whose flags are arithmetic (secret-derived control or
              data select), or a b-flag setcc read by a control transfer.

The script exits non-zero on any STOP or on any unclassified site.
"""
import re
import sys

LINE = re.compile(r"^\s*([0-9a-f]+):\t(.*)$")
JCC = re.compile(r"^j(?!mp$)[a-z]+$")
SETCC = re.compile(r"^set[a-z]+$")
CMOV = re.compile(r"^cmov[a-z]+$")
FLAG_SET = {
    "cmp", "test", "add", "adc", "sub", "sbb", "neg", "inc", "dec",
    "and", "or", "xor", "mul", "imul", "shl", "shr", "sar", "sal",
    "div", "idiv",
}
ARITH = {"add", "adc", "sub", "sbb", "neg", "inc", "dec",
         "and", "or", "xor", "mul", "imul", "shl", "shr", "sar", "sal"}
PUBLIC = {"cmp", "test"}
CONTROL = re.compile(r"^(j[a-z]+|call|ret|retq|leave)$")
ARITH_CONSUMER = ("adc", "add", "sub", "sbb", "or", "and", "xor", "neg",
                  "dec", "inc", "mov", "lea", "shl", "shr", "sar", "imul", "mul")

# objdump prints size suffixes on the flag-setting forms (`cmpb`, `testb`, ...).
# Strip one only when the unsuffixed spelling is a known mnemonic.
KNOWN_BASE = FLAG_SET | {"mov", "lea", "call", "jmp"}


def base(mnem):
    if len(mnem) > 1 and mnem[-1] in "bwlq" and mnem[:-1] in KNOWN_BASE:
        return mnem[:-1]
    return mnem


# A `jcc` whose flags come from `or`/`xor`/`and` is public geometry only at the
# slice-length check, where the operands are the two public lengths (`xor $0x9`
# on each). Recorded by address from this exact digest; anything else is a STOP.
PUBLIC_GEOMETRY_JCC = {"1d49b9"}
ALIASES = {
    "%al": ["%al", "%ax", "%eax", "%rax"],
    "%bl": ["%bl", "%bx", "%ebx", "%rbx"],
    "%cl": ["%cl", "%cx", "%ecx", "%rcx"],
    "%dl": ["%dl", "%dx", "%edx", "%rdx"],
    "%sil": ["%sil", "%si", "%esi", "%rsi"],
    "%dil": ["%dil", "%di", "%edi", "%rdi"],
    "%bpl": ["%bpl", "%bp", "%ebp", "%rbp"],
    "%spl": ["%spl", "%sp", "%esp", "%rsp"],
}


def parse(path):
    seq = []
    for line in open(path, errors="replace"):
        m = LINE.match(line)
        if not m:
            continue
        text = m.group(2).split("#")[0].strip()
        parts = text.split(None, 1)
        seq.append((int(m.group(1), 16), parts[0] if parts else "", text))
    return seq


def dest_aliases(operand):
    operand = operand.strip()
    if operand in ALIASES:
        return ALIASES[operand]
    m = re.fullmatch(r"%(r\d+)b", operand)
    if m:
        r = "%" + m.group(1)
        return [operand, r + "w", r + "d", r]
    return [operand]


def flag_source(seq, idx):
    for j in range(idx - 1, max(idx - 40, -1), -1):
        _, mnem, text = seq[j]
        if base(mnem) in FLAG_SET:
            return " ".join(text.split())
        if CONTROL.match(mnem):
            break
    return None


def first_consumer(seq, idx, operand):
    toks = dest_aliases(operand)
    for j in range(idx + 1, min(idx + 200, len(seq))):
        _, mnem, text = seq[j]
        if any(tok in text for tok in toks):
            return mnem, " ".join(text.split())
    return None, None


def main(path, symbol):
    seq = parse(path)
    rows = []
    stops = []
    for i, (addr, mnem, text) in enumerate(seq):
        if JCC.match(mnem):
            kind = "jcc"
        elif SETCC.match(mnem):
            kind = "setcc"
        elif CMOV.match(mnem):
            kind = "cmovcc"
        else:
            continue
        src = flag_source(seq, i)
        if src is None:
            rows.append([symbol, "%x" % addr, kind, mnem, "-", "UNCLASSIFIED", "-"])
            stops.append("no flag source at %x" % addr)
            continue
        sm = base(src.split(None, 1)[0])
        operand = text.split(None, 1)[1] if " " in text else ""
        if kind == "jcc":
            if sm in PUBLIC:
                cls, cons = "a-public", "-"
            elif sm in {"or", "xor", "and"} and ("%x" % addr) in PUBLIC_GEOMETRY_JCC:
                cls, cons = "a-public-geom", "-"
            else:
                cls, cons = "STOP", "-"
                stops.append("jcc %s at %x has flag source %r" % (mnem, addr, src))
        elif kind == "setcc":
            if sm in PUBLIC:
                cls, cons = "a-public", "-"
            elif sm in ARITH:
                cmnem, ctext = first_consumer(seq, i, operand)
                if cmnem is None or not base(cmnem).startswith(ARITH_CONSUMER):
                    cls, cons = "STOP", str(ctext)
                    stops.append("setcc %s at %x consumed by %r" % (mnem, addr, ctext))
                else:
                    cls, cons = "b-flag", ctext
            else:
                cls, cons = "UNCLASSIFIED", "-"
                stops.append("setcc %s at %x source %r" % (mnem, addr, src))
        else:
            cls, cons = ("STOP" if sm in ARITH else "a-public"), "-"
            if cls == "STOP":
                stops.append("cmov %s at %x has arithmetic source %r" % (mnem, addr, src))
        rows.append([symbol, "%x" % addr, kind, mnem, src, cls, cons or "-"])

    print("symbol\taddr\tkind\tinsn\tflag_source\tclass\tconsumed")
    for r in rows:
        print("\t".join(r))
    counts = {}
    for r in rows:
        counts[r[5]] = counts.get(r[5], 0) + 1
    print()
    print("counts: " + ", ".join("%s=%d" % (k, v) for k, v in sorted(counts.items())))
    if stops:
        print("STOP: " + "; ".join(stops))
        return 1
    if any(r[5] == "UNCLASSIFIED" for r in rows):
        print("STOP: unclassified site present")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
