#!/usr/bin/env python3
"""classify_wp.py — PFP8-WIDTH-POLICY branch audit for one carrier.

    python3 classify_wp.py LABEL public-arith.json

Inputs (written by `run_branch_audit_wp.sh`):

  audit/raw/disasm/LABEL.dis        objdump of the symbol extent at the new digest
  audit/raw/disasm/LABEL.sites.tsv  every jcc/setcc/cmovcc (disasm_sites.py)

The structural rules are the M-A1/PFP-8 ones, applied at this digest:

  * `jcc` after `cmp`/`test` is public (loop counters, lengths, error checks).
  * `jcc` after `bt` is a transfer on a secret bit — STOP.
  * `jcc`/`setcc` after arithmetic (`shr`, `or`, `add`, `mul`, ...) is public
    **only** at an address the reviewer listed in `public-arith.json` with its
    reason; anything else aborts.
  * `setcc` after `bt` is a data value from a secret bit (class b); its first
    consumer must be an arithmetic/data operation, never a control transfer.
  * `cmovcc` must take its flags from `cmp`/`test`.

A secret-derived control transfer is a STOP, and the script exits non-zero. A
review aid is not a constant-time proof.
"""

from __future__ import annotations

import json
import os
import re
import sys

RAW = os.environ.get(
    "PFP8WP_AUDIT",
    "/work/evidence/performance-frontier/campaigns/PFP-8/width-policy/audit/raw/disasm",
)

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


def die(msg: str) -> None:
    sys.exit("PFP8WP CLASSIFY STOP: " + msg)


def read_seq(path: str):
    seq = []
    for line in open(path):
        m = LINE.match(line)
        if m:
            text = m.group(2).split("#")[0].strip()
            parts = text.split(None, 1)
            seq.append((m.group(1), parts[0] if parts else "", text))
    return seq


def norm(mnemonic: str) -> str:
    if mnemonic in PUBLIC_FLAGS or mnemonic in ARITH_FLAGS or mnemonic in BIT_FLAGS:
        return mnemonic
    for base in list(PUBLIC_FLAGS | ARITH_FLAGS | BIT_FLAGS):
        if mnemonic.startswith(base) and mnemonic[len(base):] in ("b", "w", "l", "q"):
            return base
    return mnemonic


def nearest_flag_source(seq, addr: str):
    idx = next(i for i, (a, _m, _t) in enumerate(seq) if a == addr)
    for i in range(idx - 1, max(idx - 25, -1), -1):
        m, t = norm(seq[i][1]), " ".join(seq[i][2].split())
        if m in PUBLIC_FLAGS or m in ARITH_FLAGS or m in BIT_FLAGS:
            return m, t
        if CTRL.match(seq[i][1]):
            break
    return None, None


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


def dest_tokens(dest: str):
    if not dest.startswith("%"):
        return [dest]
    if dest in LEGACY_ALIASES:
        return LEGACY_ALIASES[dest]
    m = re.fullmatch(r"%(r\d+)b", dest)
    if m:
        r = "%" + m.group(1)
        return [dest, r + "w", r + "d", r]
    return [dest]


def first_consumer(seq, idx: int, dest: str):
    # The M-A1 rule: the first instruction that mentions the destination (any
    # width alias, or the literal memory operand) is its first use. A carry slot
    # can be written in one loop iteration and read in a later one, so the
    # window is the whole carrier tail.
    toks = dest_tokens(dest)
    for j in range(idx + 1, min(idx + 400, len(seq))):
        m, t = seq[j][1], " ".join(seq[j][2].split())
        if any(tok in t for tok in toks):
            return seq[j][0], t
    return None, None


def is_arithmetic_consumer(m: str) -> bool:
    return any(m.startswith(p) for p in CONSUMER_PREFIXES)


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit("usage: classify_wp.py LABEL public-arith.json")
    label, allow_path = sys.argv[1], sys.argv[2]
    allow = {}
    if os.path.exists(allow_path):
        allow = json.load(open(allow_path)).get(label, {})

    sites = []
    for line in open(os.path.join(RAW, label + ".sites.tsv")):
        f = line.rstrip("\n").split("\t")
        sites.append({"addr": f[1], "insn": f[2], "args": f[3], "kind": f[6]})
    seq = read_seq(os.path.join(RAW, label + ".dis"))
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
            elif sm in ARITH_FLAGS and addr in allow:
                cls, sub, cons = "a", "a-geom:" + allow[addr], "-"
            elif sm in BIT_FLAGS:
                die("jcc %s at %s takes flags from a secret bit (%r)"
                    % (s["insn"], addr, src))
            else:
                die("unreviewed jcc %s at %s takes flags from %r (%s)"
                    % (s["insn"], addr, src, sm))
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
                    die("class-b setcc %s at %s consumed by %r (not arithmetic or data)"
                        % (s["insn"], addr, ct))
                cons = "%s:%s" % (ca, ct)
            elif sm in ARITH_FLAGS:
                # Carry/borrow of limb arithmetic is secret-derived data. The
                # M-A1 rule (unchanged): it is class (b) only when its first
                # consumer is an arithmetic/data operation; a consumer that
                # transfers control aborts below.
                cls, sub = "b", "b-flag"
                ca, ct = first_consumer(seq, order[addr],
                                        s["args"].split(",")[0].strip())
                if ct is None:
                    die("class-b setcc %s at %s has no findable consumer"
                        % (s["insn"], addr))
                if not is_arithmetic_consumer(norm(ct.split(None, 1)[0])):
                    die("class-b setcc %s at %s consumed by %r (not arithmetic or data)"
                        % (s["insn"], addr, ct))
                cons = "%s:%s" % (ca, ct)
            else:
                die("unreviewed setcc %s at %s takes flags from %r"
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
        rows.append([label, addr, kind, s["insn"], s["args"].split("<")[0].strip(),
                     cls, sub, src, cons])

    with open(os.path.join(RAW, label + "-classification.tsv"), "w") as f:
        f.write("symbol\taddr\tkind\tinsn\toperand\tclass\tsub\tflag_source\tconsumed\n")
        for r in rows:
            f.write("\t".join(r) + "\n")

    lines = ["# PFP8-WIDTH-POLICY — `%s` classification (per site)" % label, "",
             "Generated by `classify_wp.py` from `%s.dis` at DSO" % label,
             "`ca80ca202168edec3417eee2a760e834cf1be92b070f92698546ae3d67c9fab3`.", "",
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
    with open(os.path.join(RAW, label + "-classification.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    if counts["jcc"]["b"] != 0 or counts["cmovcc"]["b"] != 0:
        die("secret-derived control transfer in %s" % label)
    print("%s: jcc=%d setcc=%d cmovcc=%d (class-a=%d, b-data=%d, b-ctrl=0)"
          % (label,
             counts["jcc"]["a"] + counts["jcc"]["b"],
             counts["setcc"]["a"] + counts["setcc"]["b"],
             counts["cmovcc"]["a"] + counts["cmovcc"]["b"],
             counts["jcc"]["a"] + counts["setcc"]["a"] + counts["cmovcc"]["a"],
             counts["setcc"]["b"]))


if __name__ == "__main__":
    main()
