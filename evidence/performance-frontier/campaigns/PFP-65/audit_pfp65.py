#!/usr/bin/env python3
"""PFP-65 indexed-memory audit of the Camellia/ARIA/SM4 carriers at the shipped DSO.

This is the PFP-63 classifier (`nm -S` range + `objdump -d -M intel`) applied to
the three remaining ciphers.  It reports every indexed memory operand, every
conditional transfer, and every crypto instruction inside each carrier, so a
table load and its address source can be attributed rather than assumed.

An indexed operand is a data-dependent-address *candidate*; attribution (public
loop counter vs secret-derived byte) is done from the two-instruction context and
recorded in RECEIPT.md.  The firing control is live: the Camellia and ARIA
carriers are unchanged by this batch and must keep producing indexed hits after
the SM4 conversion.
"""
import argparse
import json
import re
import subprocess

SYM_RE = re.compile(r"^([0-9a-f]+)\s+([0-9a-f]+)\s+([tT])\s+(.+)$")
INSN_RE = re.compile(
    r"^\s*([0-9a-f]+):[ \t]+(?:[0-9a-f]{2}[ \t]+)*([a-z][a-z0-9.]*)[ \t]*(.*)$"
)

CRYPTO = {
    "aesenc", "aesenclast", "aesdec", "aesdeclast", "aeskeygenassist",
    "aesimc", "pclmulqdq", "pclmullqlqdq", "pclmulhqlqdq", "pclmullqhqdq",
    "pclmulhqhqdq", "vsm4key4", "vsm4rnds4", "vaesenc", "vaesenclast",
}

# (symbol, human label) -- the three family members, data path and key schedule.
WANT = [
    ("Camellia_encrypt", "camellia data path (public encrypt)"),
    ("Camellia_decrypt", "camellia data path (public decrypt)"),
    ("Camellia_set_key", "camellia key schedule"),
    ("openssl_rs::aria::ossl_aria_encrypt", "aria data path"),
    ("openssl_rs::aria::ossl_aria_set_encrypt_key", "aria key schedule"),
    ("openssl_rs::sm4::ossl_sm4_encrypt", "sm4 data path"),
    ("openssl_rs::sm4::ossl_sm4_decrypt", "sm4 data path (decrypt)"),
    ("openssl_rs::sm4::ossl_sm4_set_key", "sm4 key schedule"),
    ("openssl_rs::sm4::portable::sub_bytes", "sm4 constant-pattern S-box carrier"),
]


def symbols(dso):
    out = subprocess.run(
        ["nm", "-S", "-C", "--defined-only", dso],
        capture_output=True, text=True, errors="replace", check=False,
    ).stdout
    tab = {}
    for line in out.splitlines():
        m = SYM_RE.match(line.strip())
        if m:
            tab.setdefault(m.group(4), (int(m.group(1), 16), int(m.group(2), 16)))
    addrs = sorted(a for a, _ in tab.values())
    for name, (addr, size) in list(tab.items()):
        if size == 0:
            nxt = [a for a in addrs if a > addr]
            if nxt:
                tab[name] = (addr, nxt[0] - addr)
    return tab


def disasm(dso, start, size):
    end = start + max(size, 1)
    return subprocess.run(
        ["objdump", "-d", "-M", "intel",
         "--start-address=0x%x" % start, "--stop-address=0x%x" % end, dso],
        capture_output=True, text=True, errors="replace", check=False,
    ).stdout


def classify(text):
    insns = []
    for ln in text.splitlines():
        m = INSN_RE.match(ln)
        if m:
            insns.append((int(m.group(1), 16), m.group(2), m.group(3).strip()))
    jcc, setcc, cmov, indexed, indexed_lea, crypto, calls = [], [], [], [], [], [], []
    for i, (addr, mn, ops) in enumerate(insns):
        ctx = insns[max(0, i - 3):i]
        ctx_txt = " ; ".join("%s %s" % (m, o) for _, m, o in ctx)
        if mn.startswith("j") and mn != "jmp":
            jcc.append({"at": "0x%x" % addr, "mnemonic": mn, "operands": ops,
                        "context": ctx_txt})
        elif mn.startswith("set"):
            setcc.append({"at": "0x%x" % addr, "mnemonic": mn, "operands": ops,
                          "context": ctx_txt})
        elif mn.startswith("cmov"):
            cmov.append({"at": "0x%x" % addr, "mnemonic": mn, "operands": ops,
                         "context": ctx_txt})
        if mn == "call":
            calls.append("0x%x %s" % (addr, ops))
        # An address expression with a scale/index form; AT&T would be `(,%r,4)`,
        # intel is `[reg + reg*4 + disp]`.  Any `[` with a `*` is index-scaled.
        if "[" in ops and "*" in ops:
            row = {"at": "0x%x" % addr, "mnemonic": mn, "operands": ops,
                   "context": ctx_txt}
            if mn in ("lea", "nop") or mn.startswith("data16"):
                indexed_lea.append(row)
            else:
                indexed.append(row)
        if mn in CRYPTO:
            crypto.append({"at": "0x%x" % addr, "mnemonic": mn})
    return {
        "n_insns": len(insns),
        "jcc": jcc, "setcc": setcc, "cmov": cmov, "calls": calls,
        "indexed_memory_operands": indexed,
        "indexed_lea_arithmetic": indexed_lea,
        "crypto_instructions": crypto,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dso", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    tab = symbols(args.dso)
    report = {"dso": args.dso, "label": args.label, "functions": {}}
    dumps = []
    for name, label in WANT:
        if name not in tab:
            report["functions"][name] = {"status": "ABSENT", "label": label}
            continue
        start, size = tab[name]
        text = disasm(args.dso, start, size)
        dumps.append("### %s [%s]  0x%x..0x%x\n%s" % (
            name, label, start, start + size, text))
        row = classify(text)
        row["status"] = "PRESENT"
        row["label"] = label
        row["range"] = ["0x%x" % start, "0x%x" % (start + size)]
        report["functions"][name] = row

    with open(args.out + ".json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
        fh.write("\n")
    with open(args.out + ".disasm.txt", "w", encoding="utf-8") as fh:
        fh.write("\n".join(dumps) + "\n")

    print("label=%s dso=%s" % (args.label, args.dso))
    for name, row in report["functions"].items():
        if row.get("status") != "PRESENT":
            print("%-52s ABSENT" % name)
            continue
        print("%-52s insns=%4d jcc=%2d setcc=%d cmov=%2d indexed=%2d lea=%d crypto=%s" % (
            name, row["n_insns"], len(row["jcc"]), len(row["setcc"]),
            len(row["cmov"]), len(row["indexed_memory_operands"]),
            len(row["indexed_lea_arithmetic"]),
            ",".join(sorted({c["mnemonic"] for c in row["crypto_instructions"]})) or "-",
        ))


if __name__ == "__main__":
    main()
