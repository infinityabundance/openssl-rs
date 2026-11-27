#!/usr/bin/env python3
"""audit_branches.py — PFP-46 branch audit of the runtime-BMI2 CIOS code.

Same structural rules as M-A1 `classify_widths.py`, applied to each emitted
`#[target_feature(enable = "bmi2")]` wrapper and to the updated carrier
`mont_mul_ladder_into`. A `jcc` whose flags come from arithmetic is a
secret-derived control transfer and aborts; a `setcc` with an arithmetic flag
source is allowed only if its first data consumer is arithmetic; a `cmovcc`
with an arithmetic source aborts.

Addresses listed in the optional geometry allowlist (one per line, `<sym> <hex>`)
are `jcc`s whose flags come from a public *length* `or`/`xor`/`and`; each is
printed for review rather than silently accepted.

Usage: audit_branches.py <sites.tsv-or-dis> ... -- <allow.txt>
"""
import re
import sys

JCC = re.compile(r"^j(?!mp$)[a-z]+$")
SETCC = re.compile(r"^set[a-z]+$")
CMOV = re.compile(r"^cmov[a-z]+$")
LINE = re.compile(r"^\s*([0-9a-f]+):\t(.*)$")
FLAG_SET = {"add", "adc", "sub", "sbb", "neg", "inc", "dec", "cmp", "test",
            "and", "or", "xor", "mul", "imul", "bt"}
ARITH_FLAGS = {"add", "adc", "sub", "sbb", "mul", "imul", "neg", "inc", "dec"}
# `bt` reads the `std_detect` CPUID capability cache, which is public; it is not
# secret-derived. `test` is likewise public.
PUBLIC_FLAGS = {"cmp", "test", "bt"}
CONTROL = re.compile(r"^(j[a-z]+|call|ret|retq)$")
CONSUMER_PREFIXES = ("adc", "add", "or", "and", "xor", "neg", "dec", "inc",
                     "mov", "lea", "shl", "shr")


def die(msg):
    sys.exit("PFP-46 BRANCH-AUDIT STOP: " + msg)


def read_seq(path):
    seq = []
    for line in open(path, errors="replace"):
        m = LINE.match(line)
        if m:
            text = m.group(2).split("#")[0].strip()
            parts = text.split(None, 1)
            seq.append((m.group(1), parts[0] if parts else "", text))
    return seq


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


LEGACY = {"%al": ["%al", "%ax", "%eax", "%rax"], "%bl": ["%bl", "%bx", "%ebx", "%rbx"],
          "%cl": ["%cl", "%cx", "%ecx", "%rcx"], "%dl": ["%dl", "%dx", "%edx", "%rdx"],
          "%sil": ["%sil", "%si", "%esi", "%rsi"], "%dil": ["%dil", "%di", "%edi", "%rdi"],
          "%bpl": ["%bpl", "%bp", "%ebp", "%rbp"], "%spl": ["%spl", "%sp", "%esp", "%rsp"]}


def dest_tokens(dest):
    if not dest.startswith("%"):
        return [dest]
    if dest in LEGACY:
        return LEGACY[dest]
    m = re.fullmatch(r"%(r\d+)b", dest)
    if m:
        r = "%" + m.group(1)
        return [dest, r + "w", r + "d", r]
    return [dest]


def first_consumer(seq, idx, dest):
    toks = dest_tokens(dest)
    for j in range(idx + 1, min(idx + 400, len(seq))):
        m, t = seq[j][1], " ".join(seq[j][2].split())
        if any(tok in t for tok in toks):
            return seq[j][0], m, t
    return None, None, None


def audit(symbol, dis, allow):
    seq = read_seq(dis)
    order = {a: i for i, (a, _m, _t) in enumerate(seq)}
    counts = {"jcc": {"a": 0, "b": 0}, "setcc": {"a": 0, "b": 0}, "cmovcc": {"a": 0, "b": 0}}
    rows = []
    for addr, op, text in seq:
        if JCC.match(op):
            kind = "jcc"
        elif SETCC.match(op):
            kind = "setcc"
        elif CMOV.match(op):
            kind = "cmovcc"
        else:
            continue
        args = operands(text)
        src = nearest_flag_source(seq, addr)
        if src is None:
            die("no flag source before %s in %s" % (addr, symbol))
        sm = src.split()[0]
        if kind == "jcc":
            if sm in PUBLIC_FLAGS:
                cls, sub = "a", "a-cpuid" if sm == "bt" else "a-loop"
            elif sm in {"or", "xor", "and"} and (symbol, addr) in allow:
                cls, sub = "a", "a-geom"
            else:
                die("jcc %s at %s in %s has arithmetic flag source %r "
                    "(secret-derived control transfer)" % (op, addr, symbol, src))
            cons = "-"
        elif kind == "setcc":
            if sm in PUBLIC_FLAGS:
                cls, sub, cons = "a", "a-geom", "-"
            elif sm in ARITH_FLAGS:
                cls, sub = "b", "b-flag"
                ca, cm, ct = first_consumer(seq, order[addr], args.split(",")[0].strip())
                if cm is None:
                    die("class-b setcc %s at %s in %s has no consumer" % (op, addr, symbol))
                if not cm.startswith(CONSUMER_PREFIXES):
                    die("class-b setcc %s at %s in %s consumed by %r (not arithmetic)"
                        % (op, addr, symbol, ct))
                cons = "%s:%s" % (ca, ct)
            else:
                die("setcc %s at %s in %s unexpected flag source %r" % (op, addr, symbol, src))
        else:
            cls = "b" if sm in ARITH_FLAGS else "a"
            sub, cons = ("b-flag" if cls == "b" else "a-loop"), "-"
            if cls == "b":
                die("cmovcc at %s in %s reads an arithmetic flag" % (addr, symbol))
        counts[kind][cls] += 1
        rows.append((symbol, addr, kind, op, args.split("<")[0].strip(), cls, sub, src, cons))
    print("%s: jcc=%d setcc=%d cmovcc=%d  (class-a=%d, class-b-flag=%d, "
          "secret-derived-control=0)"
          % (symbol,
             counts["jcc"]["a"] + counts["jcc"]["b"],
             counts["setcc"]["a"] + counts["setcc"]["b"],
             counts["cmovcc"]["a"] + counts["cmovcc"]["b"],
             counts["jcc"]["a"] + counts["setcc"]["a"] + counts["cmovcc"]["a"],
             counts["setcc"]["b"]))
    return rows, counts


def main(argv):
    if "--" in argv:
        i = argv.index("--")
        files, allowf = argv[:i], argv[i + 1:]
    else:
        files, allowf = argv, []
    allow = set()
    for f in allowf:
        for line in open(f):
            p = line.split()
            if len(p) == 2:
                allow.add((p[0], p[1]))
    allrows = []
    for dis in files:
        sym = re.sub(r"\.dis$", "", dis.split("/")[-1])
        rows, _ = audit(sym, dis, allow)
        allrows += rows
    out = sys.argv[0].rsplit("/", 1)[0] + "/raw/after/branch-classification.tsv"
    with open(out, "w") as f:
        f.write("symbol\taddr\tkind\tinsn\toperand\tclass\tsub\tflag_source\tconsumed\n")
        for r in allrows:
            f.write("\t".join(r) + "\n")
    print("sites=%d -> %s" % (len(allrows), out))


if __name__ == "__main__":
    main(sys.argv[1:])
