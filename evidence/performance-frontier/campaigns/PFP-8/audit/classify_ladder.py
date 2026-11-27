#!/usr/bin/env python3
"""classify_ladder.py — PFP-8: per-site classification of `run_mont_ladder`.

This is the window-loop carrier reached by DH key generation and agreement.  It
contains the digit construction and the inlined full masked scan
(`select_window_digit`); the multiplications themselves are calls to
`mont_mul_ladder_into`, which has its own classification.

Input: `raw/disasm/cand-run_mont_ladder.dis` and `.sites.tsv` at the frozen
digest.  The structural rules are the M-A1 ones, extended for this carrier:

  * `jcc` after `cmp`/`test` is public geometry (loop counters, slice lengths).
  * `jcc` after a shift, `or`/`and`/`xor`, `add`/`sub`, or `mul` is public only
    at a reviewed address in `PUBLIC_ARITH`.  Every such site is in the
    allocation/length path (`finish_grow`, slice-length masks, allocation-size
    overflow checks); the operand is a length or a pointer tag, never a limb.
  * `setcc` after `cmp`/`test` is public.  `setcc` after `bt` is class (b): the
    hidden bit is a secret exponent bit, and its first consumer must be a data
    operation (`mov`/`and`/`or`/...), never a comparison or branch.
  * `cmovcc` must take its flag from `cmp`/`test`; an arithmetic source is a
    secret-dependent data select and is a STOP.
  * Any unclassified site aborts.

A `jcc` whose flags come from a secret limb (including a `bt` on the exponent),
a class-(b) `setcc` consumed by a control transfer, or an arithmetic-source
`cmovcc` is a STOP: a secret-derived transfer.
"""

from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "raw", "disasm")
SYMBOL = "run_mont_ladder"
EXPECT_DIGEST = "88c0c7e04d52a1bf84d665fdd691bddf2bbe700e35505d95bf145bfdc3774d87"

# Reviewed public-geometry transfers whose flags come from length/allocation
# arithmetic rather than cmp/test.  Each address is listed with its source in
# the generated table so the reviewer can inspect it.
PUBLIC_ARITH = {
    "2f895b": "slice-length high-bit check (shr 58)",
    "2f8a2d": "allocation-length overflow mask (or of two setcc)",
    "2f8c43": "allocation-length overflow mask (or of two setcc)",
    "2f8d27": "allocation-length overflow mask (or of two setcc)",
    "2f8de5": "allocation-length overflow mask (or of two setcc)",
    "2f90f6": "allocation-length overflow mask (or of two setcc)",
    "2f9239": "pointer/tag high-bit check (shr 59)",
    "2f931a": "allocation-size difference (sub)",
    "2f9397": "allocation counter underflow (subq)",
    "2f93bb": "allocation-size overflow (mul, jo)",
    "2f9465": "allocation-length overflow mask (or of two setcc)",
    "2f94f0": "allocation-length overflow mask (or of two setcc)",
    "2f9a1f": "allocation-size overflow (mul, jo)",
    "2f9a2b": "allocation-size overflow (add)",
    "2f9a50": "length-difference sign mask (shr 63)",
}

JCC = re.compile(r"^j(?!mp$)[a-z]+$")
SETCC = re.compile(r"^set[a-z]+$")
CMOV = re.compile(r"^cmov[a-z]+$")
LINE = re.compile(r"^\s*([0-9a-f]+):\t(.*)$")
CTRL = re.compile(r"^(j[a-z]+|call|ret|retq)$")
PUBLIC_FLAGS = {"cmp", "test"}
ARITH_FLAGS = {"add", "adc", "sub", "sbb", "mul", "imul", "neg", "inc", "dec",
               "shr", "sar", "shl", "sal", "and", "or", "xor"}
BIT_FLAGS = {"bt", "bts", "btc", "btr"}
CONSUMER_PREFIXES = ("adc", "add", "or", "and", "xor", "neg", "dec", "inc",
                     "mov", "lea", "shl", "shr", "sar", "not")


def die(msg):
    sys.exit("PFP8 LADDER CLASSIFY STOP: " + msg)


def read_seq(path):
    seq = []
    for line in open(path):
        m = LINE.match(line)
        if m:
            text = m.group(2).split("#")[0].strip()
            parts = text.split(None, 1)
            seq.append((m.group(1), parts[0] if parts else "", text))
    return seq


def norm(mnemonic):
    if mnemonic in PUBLIC_FLAGS or mnemonic in ARITH_FLAGS or mnemonic in BIT_FLAGS:
        return mnemonic
    for base in list(PUBLIC_FLAGS | ARITH_FLAGS | BIT_FLAGS):
        if mnemonic.startswith(base) and mnemonic[len(base):] in ("b", "w", "l", "q"):
            return base
    return mnemonic


def nearest_flag_source(seq, addr):
    idx = next(i for i, (a, _m, _t) in enumerate(seq) if a == addr)
    for i in range(idx - 1, max(idx - 25, -1), -1):
        m, t = norm(seq[i][1]), " ".join(seq[i][2].split())
        if m in PUBLIC_FLAGS or m in ARITH_FLAGS or m in BIT_FLAGS:
            return m, t
        if CTRL.match(seq[i][1]):
            break
    return None, None


def first_consumer(seq, idx, dest):
    if not dest.startswith("%"):
        return None, None
    base = dest[1:]
    aliases = {dest, "%" + base}
    m = re.fullmatch(r"r(\d+)b", base)
    if m:
        aliases |= {"%r%sb" % m.group(1), "%r%sw" % m.group(1),
                    "%r%sd" % m.group(1), "%r%s" % m.group(1)}
    legacy = {"al": "ax eax rax", "bl": "bx ebx rbx", "cl": "cx ecx rcx",
              "dl": "dx edx rdx", "sil": "si esi rsi", "dil": "di edi rdi",
              "bpl": "bp ebp rbp", "spl": "sp esp rsp"}
    if base in legacy:
        aliases |= {"%" + a for a in legacy[base].split()}
    for j in range(idx + 1, min(idx + 400, len(seq))):
        text = " ".join(seq[j][2].split())
        if any(a in text for a in aliases):
            return seq[j][1], text
    return None, None


def is_arithmetic_consumer(m):
    return any(m.startswith(p) for p in CONSUMER_PREFIXES)


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
        sm, src = nearest_flag_source(seq, addr)
        if sm is None:
            die("no flag source before %s" % addr)
        if kind == "jcc":
            if not JCC.match(s["insn"]):
                die("kind/opcode mismatch at %s: %s" % (addr, s["insn"]))
            if sm in PUBLIC_FLAGS:
                cls, sub, cons = "a", "a-loop", "-"
            elif addr in PUBLIC_ARITH:
                cls, sub = "a", "a-geom:" + PUBLIC_ARITH[addr]
                cons = "-"
            else:
                die("jcc %s at %s takes flags from %r (secret-derived control "
                    "transfer)" % (s["insn"], addr, src))
        elif kind == "setcc":
            if not SETCC.match(s["insn"]):
                die("kind/opcode mismatch at %s: %s" % (addr, s["insn"]))
            if sm in PUBLIC_FLAGS:
                cls, sub, cons = "a", "a-geom", "-"
            elif sm in BIT_FLAGS:
                cls, sub = "b", "b-secret-bit"
                ca, ct = first_consumer(seq, order[addr],
                                        s["args"].split(",")[0].strip())
                if ct is None:
                    die("class-b setcc %s at %s has no findable consumer"
                        % (s["insn"], addr))
                if not is_arithmetic_consumer(norm(ct.split(None, 1)[0])):
                    die("class-b setcc %s at %s consumed by %r (not arithmetic "
                        "or data)" % (s["insn"], addr, ct))
                cons = "%s:%s" % (ca, ct)
            elif sm in ARITH_FLAGS:
                # Not present at this digest; if it appears, the reviewer must
                # justify it explicitly rather than have it absorbed.
                die("setcc %s at %s takes flags from arithmetic %r"
                    % (s["insn"], addr, src))
            else:
                die("setcc %s at %s has unexpected flag source %r"
                    % (s["insn"], addr, src))
        else:
            if not CMOV.match(s["insn"]):
                die("kind/opcode mismatch at %s: %s" % (addr, s["insn"]))
            if sm in PUBLIC_FLAGS:
                cls, sub, cons = "a", "a-loop", "-"
            else:
                die("cmovcc at %s takes flags from %r (secret-dependent select)"
                    % (addr, src))
        counts[kind][cls] += 1
        rows.append([SYMBOL, addr, kind, s["insn"], s["args"].split("<")[0].strip(),
                     cls, sub, src, cons])

    with open(os.path.join(RAW, "ladder-classification.tsv"), "w") as f:
        f.write("symbol\taddr\tkind\tinsn\toperand\tclass\tsub\tflag_source\tconsumed\n")
        for r in rows:
            f.write("\t".join(r) + "\n")

    lines = ["# PFP-8 — window-loop carrier classification (per site)", "",
             "Generated by `classify_ladder.py` from `cand-run_mont_ladder.dis`",
             "at candidate digest `%s`." % EXPECT_DIGEST, "",
             "A `jcc` taking flags from a secret limb, a class-(b) `setcc` consumed",
             "by a control transfer, or an arithmetic-source `cmovcc` aborts the",
             "script.  The only secret flag source in this carrier is `bt` on the",
             "exponent limb in the digit-selection loop; its `setb` is a data value",
             "stored for the masked scan, never a branch.", "",
             "| addr | kind | insn | class | flag source | consumed by |",
             "|---|---|---|---|---|---|"]
    for r in rows:
        lines.append("| `0x%s` | %s | `%s` | (%s) %s | `%s` | `%s` |"
                     % (r[1], r[2], r[3], r[5], r[6], r[7], r[8]))
    total = sum(counts[k]["a"] + counts[k]["b"] for k in counts)
    lines += ["",
              "Counts: %d jcc (%d class a, %d class b), %d setcc (%d class a, "
              "%d class b), %d cmovcc; %d sites total."
              % (counts["jcc"]["a"] + counts["jcc"]["b"], counts["jcc"]["a"],
                 counts["jcc"]["b"], counts["setcc"]["a"] + counts["setcc"]["b"],
                 counts["setcc"]["a"], counts["setcc"]["b"],
                 counts["cmovcc"]["a"] + counts["cmovcc"]["b"], total), "",
              "Secret-derived control transfers: **0**.",
              "Class-(b) secret-bit `setcc` consumed by data operations: **%d**."
              % counts["setcc"]["b"]]
    with open(os.path.join(RAW, "ladder-classification.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    if counts["jcc"]["b"] != 0 or counts["cmovcc"]["b"] != 0:
        die("secret-derived control transfer in the carrier")
    print("ladder classification: jcc=%d setcc=%d cmovcc=%d  (a=%d b-data=%d b-ctrl=0)"
          % (counts["jcc"]["a"] + counts["jcc"]["b"],
             counts["setcc"]["a"] + counts["setcc"]["b"],
             counts["cmovcc"]["a"] + counts["cmovcc"]["b"],
             counts["jcc"]["a"] + counts["setcc"]["a"] + counts["cmovcc"]["a"],
             counts["setcc"]["b"]))


if __name__ == "__main__":
    main()
