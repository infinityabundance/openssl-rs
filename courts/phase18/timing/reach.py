#!/usr/bin/env python3
"""Direct-call reachability over libcrypto.so.3 from ssh/sshd imported roots.

Inputs are produced by the court container:
  lc.dis            objdump -d -j .text -j .plt -j .plt.got
  lc.syms           readelf -sW libcrypto.so.3
  ssh.und, sshd.und readelf --dyn-syms (undefined names), one per line
"""
import sys, re, bisect, json, collections

LC = "/work/artifacts/phase2/install/lib/libcrypto.so.3"
DIS = "lc.dis"
SYMS = "lc.syms"

# ---------- symbols ----------
# readelf -sW columns: Num: Value Size Type Bind Vis Ndx Name
sym_re = re.compile(r"^\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$")
all_funcs = []            # (addr, size, name, is_dyn)
name_by_addr = collections.defaultdict(list)
for line in open(SYMS):
    m = sym_re.match(line)
    if not m:
        continue
    addr, size, typ, bind, vis, ndx, name = m.groups()
    name = name.strip()
    if typ != "FUNC" or ndx == "UND":
        continue
    a, sz = int(addr, 16), int(size)
    if sz == 0:
        continue
    all_funcs.append((a, sz, name, ndx != "UND"))
    name_by_addr[a].append(name)

all_funcs.sort()
starts = [f[0] for f in all_funcs]

def containing(addr):
    i = bisect.bisect_right(starts, addr) - 1
    if i < 0:
        return None
    a, sz, name, _ = all_funcs[i]
    if a <= addr < a + sz:
        return (name, a, sz)
    return None

# dynsym-defined names -> address (first)
dyn_addr = {}
for a, sz, name, isdyn in all_funcs:
    if isdyn and name not in dyn_addr:
        dyn_addr[name] = a

# ---------- disassembly ----------
hdr_re = re.compile(r"^([0-9a-f]{16}) <(.+)>:$")
ins_re = re.compile(r"^  ([0-9a-f]+):\t(.*)$")
plt_name = {}
cur_hdr = None
calls = []   # (callsite, caller_name, edge_kind, text)
pending = None
for line in open(DIS, errors="replace"):
    line = line.rstrip("\n")
    m = hdr_re.match(line)
    if m:
        a = int(m.group(1), 16)
        n = m.group(2)
        cur_hdr = n
        if n.endswith("@plt"):
            plt_name[a] = n[:-4]
        continue
    m = ins_re.match(line)
    if not m:
        continue
    parts = line.split("\t")
    if len(parts) < 3:
        # continuation of a multi-line instruction; not an instruction start
        continue
    addr = int(parts[0].strip().rstrip(":"), 16)
    insn = "\t".join(parts[2:]).strip()
    mn = insn.split()[0] if insn else ""
    if mn in ("call", "callq", "jmp", "jmpq"):
        calls.append((addr, insn))

# ---------- edge resolution ----------
def resolve(insn):
    """return (kind, target_addr_or_name) for a call/jmp instruction"""
    rest = insn.split(None, 1)[1] if len(insn.split(None, 1)) > 1 else ""
    rest = rest.strip()
    if rest.startswith("*"):
        return ("indirect", rest)
    m = re.match(r"^([0-9a-f]+)\s*(?:<(.+)>)?$", rest)
    if not m:
        return ("other", rest)
    tgt = int(m.group(1), 16)
    sym = m.group(2) or ""
    base = sym.split("+")[0]
    return ("direct", tgt, base)

graph = collections.defaultdict(set)
nedges = 0
indirect_in = collections.defaultdict(int)
direct_sites = collections.defaultdict(list)   # target start -> [(caller, callsite, text)]
direct_to_name = collections.defaultdict(set)
for addr, insn in calls:
    c = containing(addr)
    caller = c[0] if c else (cur_hdr or "?")
    r = resolve(insn)
    if r[0] != "direct":
        continue
    tgt, base = r[1], r[2]
    # PLT stub -> resolve to in-DSO definition if possible
    if tgt in plt_name:
        nm = plt_name[tgt]
        if nm in dyn_addr:
            tgt = dyn_addr[nm]
            base = nm
        else:
            graph[caller].add("EXTERNAL:" + nm)
            continue
    if tgt in name_by_addr:
        target_names = name_by_addr[tgt]
        this_tgt_name = base if base in target_names else target_names[0]
    else:
        cc = containing(tgt)
        if cc is None:
            continue
        this_tgt_name = cc[0]
        # a direct transfer into the middle of another function is still an edge
    if this_tgt_name == caller:
        continue
    graph[caller].add(this_tgt_name)
    direct_sites[this_tgt_name].append((caller, addr, insn))
    direct_to_name[caller].add(this_tgt_name)
    nedges += 1

# ---------- roots ----------
roots = []
root_src = collections.defaultdict(list)
for path in ("ssh.und", "sshd.und"):
    for line in open(path):
        n = line.strip()
        if not n:
            continue
        a = dyn_addr.get(n)
        if a is not None:
            roots.append(name_by_addr[a][0])
            root_src[name_by_addr[a][0]].append(path)

roots = sorted(set(roots))

# ---------- reverse BFS from target ----------
rev = collections.defaultdict(set)
for u, vs in graph.items():
    for v in vs:
        rev[v].add(u)

def rev_path(target, maxlen=14):
    # BFS backwards to any root
    q = collections.deque([target])
    prev = {target: None}
    found = None
    while q:
        n = q.popleft()
        if n in roots:
            found = n
            break
        if n.startswith("EXTERNAL"):
            continue
        for p in rev.get(n, ()):
            if p not in prev:
                prev[p] = n
                q.append(p)
    if found is None:
        return None
    chain = []
    n = found
    while n is not None:
        chain.append(n)
        n = prev[n]
    return chain

def all_callers(name, depth=0, seen=None, maxd=6):
    if seen is None:
        seen = set()
    out = []
    for (caller, site, insn) in direct_sites.get(name, []):
        out.append((depth, caller, site, insn))
        if depth < maxd and caller not in seen:
            seen.add(caller)
            out.extend(all_callers(caller, depth + 1, seen, maxd))
    return out

report = {
    "candidate": {
        "libcrypto": LC,
        "direct_edges": nedges,
        "functions_with_size": len(all_funcs),
        "roots": len(roots),
    },
    "targets": {},
}
for tname in ("BN_mod_exp_mont_consttime", "BN_mod_inverse"):
    a = dyn_addr.get(tname)
    if a is None:
        # internal: find symtab definition
        defs = [f for f in all_funcs if f[2] == tname]
        a = defs[0][0] if defs else None
    info = {"address": hex(a) if a is not None else None,
            "exported": tname in dyn_addr}
    if a is not None:
        canonical = name_by_addr[a][0]
        info["canonical"] = canonical
        info["direct_call_sites"] = [
            {"caller": c, "callsite": hex(s), "insn": i}
            for (c, s, i) in direct_sites.get(canonical, [])]
        p = rev_path(canonical)
        info["root_to_target_path"] = p
        info["reachable"] = p is not None
    report["targets"][tname] = info

# write callers lists for the two targets (bounded depth, full caller names)
for tname in ("BN_mod_exp_mont_consttime", "BN_mod_inverse"):
    info = report["targets"][tname]
    if info.get("canonical"):
        info["upstream_tree"] = [
            {"depth": d, "caller": c, "callsite": hex(s), "insn": i}
            for (d, c, s, i) in all_callers(info["canonical"])[:200]]

print(json.dumps(report, indent=2))
