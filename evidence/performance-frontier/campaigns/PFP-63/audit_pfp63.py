#!/usr/bin/env python3
"""PFP-63 instruction audit of the AES/GHASH carriers at the shipped digest.

Disassembles the named functions of a DSO by address range (parsed from `nm -S`)
and classifies every conditional (`jcc`, `setcc`, `cmov`), every indexed memory
operand (a data-dependent address candidate), and the AES/PCLMUL instructions.

The scope is stated in BOUNDS.md: this is an instruction-level classification of
the carrier, not a cache-timing proof. A jcc is classified by the quantity whose
flags it reads, which is reported with two instructions of context; an indexed
operand is reported so it can be attributed to a public loop index or rejected.
"""
import argparse
import json
import re
import subprocess
import sys

SYM_RE = re.compile(r"^([0-9a-f]+)\s+([0-9a-f]+)\s+([tT])\s+(.+)$")
INSN_RE = re.compile(
    r"^\s*([0-9a-f]+):[ \t]+(?:[0-9a-f]{2}[ \t]+)*([a-z][a-z0-9.]*)[ \t]*(.*)$"
)

CRYPTO = {
    "aesenc", "aesenclast", "aesdec", "aesdeclast", "aeskeygenassist",
    "aesimc", "pclmulqdq", "pclmullqlqdq", "pclmulhqlqdq", "pclmullqhqdq",
    "pclmulhqhqdq",
}

WANT = [
    "AES_encrypt", "AES_decrypt",
    "openssl_rs::aes::aes_encrypt_ni", "openssl_rs::aes::aes_decrypt_ni",
    "openssl_rs::aes::aes_expand_ni",
    "openssl_rs::modes::gcm::gf_mul", "openssl_rs::modes::gcm::gf_mul_clmul",
    "CRYPTO_gcm128_aad", "CRYPTO_gcm128_encrypt", "CRYPTO_gcm128_decrypt",
    "CRYPTO_gcm128_finish", "CRYPTO_gcm128_setiv",
    "openssl_rs::modes::gcm::crypt",
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
    # Fill zero sizes from the next symbol address in the file.
    addrs = sorted(a for a, _ in tab.values())
    for name, (addr, size) in list(tab.items()):
        if size == 0:
            nxt = [a for a in addrs if a > addr]
            if nxt:
                tab[name] = (addr, nxt[0] - addr)
    return tab


def disasm(dso, start, size):
    end = start + max(size, 1)
    p = subprocess.run(
        ["objdump", "-d", "-M", "intel",
         "--start-address=0x%x" % start, "--stop-address=0x%x" % end, dso],
        capture_output=True, text=True, errors="replace", check=False,
    )
    return p.stdout


def classify(text):
    insns = []
    for ln in text.splitlines():
        m = INSN_RE.match(ln)
        if m:
            insns.append((int(m.group(1), 16), m.group(2), m.group(3).strip()))
    rows = []
    jcc = []
    setcc = []
    cmov = []
    indexed = []
    indexed_lea = []
    crypto = []
    calls = []
    for i, (addr, mn, ops) in enumerate(insns):
        ctx = insns[max(0, i - 2):i]
        ctx_txt = " ; ".join("%s %s" % (m, o) for _, m, o in ctx)
        if mn.startswith("j") and mn != "jmp" and not mn.startswith("jmp"):
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
        if "*" in ops and "[" in ops:
            row = {"at": "0x%x" % addr, "mnemonic": mn, "operands": ops}
            # `lea`/`nop` do not access memory; separate arithmetic from loads/stores.
            if mn in ("lea", "nop") or mn.startswith("data16"):
                indexed_lea.append(row)
            else:
                indexed.append(row)
        if mn in CRYPTO:
            crypto.append({"at": "0x%x" % addr, "mnemonic": mn})
    rows.append({
        "n_insns": len(insns),
        "jcc": jcc,
        "setcc": setcc,
        "cmov": cmov,
        "calls": calls,
        "indexed_memory_operands": indexed,
        "indexed_lea_arithmetic": indexed_lea,
        "crypto_instructions": crypto,
    })
    return rows[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dso", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    tab = symbols(args.dso)
    report = {"dso": args.dso, "label": args.label, "functions": {}}
    dumps = []
    for name in WANT:
        if name not in tab:
            report["functions"][name] = {"status": "ABSENT"}
            continue
        start, size = tab[name]
        text = disasm(args.dso, start, size)
        dumps.append("### %s  0x%x..0x%x\n%s" % (name, start, start + size, text))
        row = classify(text)
        row["status"] = "PRESENT"
        row["range"] = ["0x%x" % start, "0x%x" % (start + size)]
        report["functions"][name] = row

    with open(args.out + ".json", "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
        fh.write("\n")
    with open(args.out + ".disasm.txt", "w", encoding="utf-8") as fh:
        fh.write("\n".join(dumps))
        fh.write("\n")

    print("label=%s" % args.label)
    for name, row in report["functions"].items():
        if row.get("status") != "PRESENT":
            print("%-44s ABSENT" % name)
            continue
        print("%-44s insns=%4d jcc=%2d setcc=%d cmov=%2d indexed=%d crypto=%s" % (
            name, row["n_insns"], len(row["jcc"]), len(row["setcc"]),
            len(row["cmov"]), len(row["indexed_memory_operands"]),
            ",".join(sorted({c["mnemonic"] for c in row["crypto_instructions"]})) or "-",
        ))


if __name__ == "__main__":
    main()
