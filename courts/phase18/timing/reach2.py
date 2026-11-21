#!/usr/bin/env python3
"""Direct/GOT call reachability over libcrypto.so.3 from ssh/sshd imported roots."""
import re, bisect, json, collections

SYMS = "lc.syms"
DIS = "lc.dis"
REL = "lc.reloc"

# ---------- symbols: split .dynsym / .symtab ----------
sym_re = re.compile(r"^\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$")
funcs = []                 # (addr,size,name) from .symtab
dyn = {}                   # name -> addr from .dynsym defined FUNC
table = None
for line in open(SYMS):
    if line.startswith("Symbol table"):
        table = "dyn" if ".dynsym" in line else "sym"
        continue
    m = sym_re.match(line)
    if not m:
        continue
    addr, size, typ, bind, vis, ndx, name = m.groups()
    name = name.strip().split("@@")[0].split("@")[0]
    if typ != "FUNC" or ndx == "UND":
        continue
    a, sz = int(addr, 16), int(size)
    if table == "dyn":
        dyn.setdefault(name, a)
    if sz:
        funcs.append((a, sz, name))
funcs.sort()
starts = [f[0] for f in funcs]

def containing(addr):
    i = bisect.bisect_right(starts, addr) - 1
    if i < 0:
        return None
    a, sz, name = funcs[i]
    return (name, a, sz) if a <= addr < a + sz else None

name_at = collections.defaultdict(list)
for a, sz, n in funcs:
    name_at[a].append(n)

def canonical(addr):
    names = name_at.get(addr)
    if not names:
        c = containing(addr)
        return c[0] if c else None
    # prefer the short non-mangled public name
    for n in names:
        if not n.startswith("_R") and n in dyn:
            return n
    for n in names:
        if not n.startswith("_R"):
            return n
    return names[0]

# ---------- GOT mapping from relocations ----------
got = {}
rel_re = re.compile(r"^([0-9a-f]{16})\s+[0-9a-f]+\s+(R_X86_64_\S+)\s+([0-9a-f]+)\s+(\S+)")
for line in open(REL):
    m = rel_re.match(line)
    if not m:
        continue
    off, typ, val, name = m.groups()
    name = name.split("@@")[0].split("@")[0]
    if typ in ("R_X86_64_GLOB_DAT", "R_X86_64_JUMP_SLOT"):
        got[int(off, 16)] = name
    else:
        got.setdefault(int(off, 16), name)

# ---------- disassembly ----------
hdr_re = re.compile(r"^([0-9a-f]{16}) <(.+)>:$")
ins_re = re.compile(r"^  ([0-9a-f]+):\t(.*)$")
plt_name = {}
edges = []   # (caller, kind, target_name_or_None, callsite, text)
for line in open(DIS, errors="replace"):
    line = line.rstrip("\n")
    m = hdr_re.match(line)
    if m:
        a, n = int(m.group(1), 16), m.group(2)
        if n.endswith("@plt"):
            plt_name[a] = n[:-4]
        continue
    m = ins_re.match(line)
    if not m:
        continue
    parts = line.split("\t")
    if len(parts) < 3:
        continue
    addr = int(parts[0].strip().rstrip(":"), 16)
    insn = "\t".join(parts[2:]).strip()
    mn = insn.split()[0] if insn else ""
    if mn not in ("call", "callq", "jmp", "jmpq"):
        continue
    c = containing(addr)
    caller = c[0] if c else "?"
    rest = insn.split(None, 1)[1].strip() if " " in insn else ""
    if rest.startswith("*"):
        # objdump resolves the GOT slot in a trailing comment: # <hex>
        m3 = re.search(r"#\s*([0-9a-f]+)", insn)
        if m3:
            slot = int(m3.group(1), 16)
            if slot in got:
                nm = got[slot]
                da = dyn.get(nm)
                tgt = canonical(da) if da is not None else nm
                edges.append((caller, "got", tgt, addr, insn))
                continue
        edges.append((caller, "indirect-unresolved", None, addr, insn))
        continue
    m2 = re.match(r"^([0-9a-f]+)\s*(?:<(.+)>)?$", rest)
    if not m2:
        continue
    tgt, ann = int(m2.group(1), 16), (m2.group(2) or "")
    base = ann.split("+")[0]
    if tgt in plt_name:
        nm = plt_name[tgt]
        if nm in dyn:
            tgt = dyn[nm]
        else:
            edges.append((caller, "external", "EXTERNAL:" + nm, addr, insn))
            continue
    nm = canonical(tgt)
    if nm is None:
        continue
    if nm == caller:
        continue
    edges.append((caller, "direct", nm, addr, insn))

# ---------- roots ----------
roots = set()
for path in ("ssh.und", "sshd.und"):
    for line in open(path):
        n = line.strip().split("@")[0]
        if n in dyn:
            roots.add(canonical(dyn[n]))
roots = sorted(roots)

def build(kinds):
    g = collections.defaultdict(set)
    site = collections.defaultdict(list)
    for caller, kind, tgt, addr, insn in edges:
        if kind not in kinds or tgt is None:
            continue
        g[caller].add(tgt)
        site[tgt].append((caller, kind, addr, insn))
    return g, site

def rev_path(g, target, limit=20):
    rev = collections.defaultdict(set)
    for u, vs in g.items():
        for v in vs:
            rev[v].add(u)
    q = collections.deque([target]); prev = {target: None}; found = None
    while q:
        n = q.popleft()
        if n in roots:
            found = n; break
        if n.startswith("EXTERNAL"):
            continue
        for p in rev.get(n, ()):
            if p not in prev:
                prev[p] = n; q.append(p)
    if found is None:
        return None
    chain = []; n = found
    while n is not None:
        chain.append(n); n = prev[n]
    return chain

report = {"libcrypto": "/work/artifacts/phase2/install/lib/libcrypto.so.3",
          "roots": len(roots), "edges": len(edges),
          "edge_kinds": dict(collections.Counter(k for _, k, _, _, _ in edges)),
          "targets": {}}
for tname in ("BN_mod_exp_mont_consttime", "BN_mod_inverse", "BN_mod_exp_mont_consttime_x2"):
    addr = dyn.get(tname)
    if addr is None:
        cand = [f for f in funcs if f[2] == tname]
        addr = cand[0][0] if cand else None
    info = {"address": hex(addr) if addr is not None else None,
            "exported": tname in dyn}
    for label, kinds in (("direct_only", {"direct"}),
                         ("direct_plus_got", {"direct", "got"})):
        g, site = build(kinds)
        p = rev_path(g, canonical(addr)) if addr is not None else None
        info[label] = {
            "reachable": p is not None,
            "path": p,
            "incoming_sites": [
                {"caller": c, "kind": k, "callsite": hex(a), "insn": i}
                for (c, k, a, i) in site.get(canonical(addr), [])],
        }
    report["targets"][tname] = info

print(json.dumps(report, indent=2))

# ---- dump the direct+GOT graph and forward closure for follow-up queries ----
g_all, site_all = build({"direct", "got"})
seen = set(roots)
q = collections.deque(roots)
while q:
    n = q.popleft()
    for m in g_all.get(n, ()):
        if m not in seen:
            seen.add(m)
            q.append(m)
report["forward_closure_size"] = len(seen)
with open("graph.json", "w") as f:
    json.dump({"roots": roots,
               "reachable": sorted(seen),
               "graph": {k: sorted(v) for k, v in g_all.items()},
               "sites": {k: [[c, kind, hex(a), i] for c, kind, a, i in v]
                         for k, v in site_all.items()}}, f)
