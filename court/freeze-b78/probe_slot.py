#!/usr/bin/env python3
"""Diagnose the frame-slot reaching-store query for the decoder loop."""
import sys
from pathlib import Path

ROOT = Path("/work")
sys.path.insert(0, "/work/forensics/tools")
import consumer_closure as cc  # noqa: E402


class P:
    def __init__(self, i):
        self.insns_by_func = i

    def switch_targets(self, b, a):
        return set()


class G:
    def __init__(self, b, i):
        self.funcs = b.funcs
        self.start_set = b.start_set
        self.names_at = b.names_at
        self.sym_sizes = b.sym_sizes
        self.sections = b.sections
        self.dynamic_defs = b.dynamic_defs
        self.slot_syms = b.slot_syms
        self.precision = P(i)
        self._b = b

    def __getattr__(self, n):
        return getattr(self._b, n)


def main():
    b = cc.DsoGraph(Path("/work/artifacts/phase2/install/lib/libcrypto.so.3"),
                    ROOT / "court/tmp/v4-consumer-closure")
    g = G(b, dict(b.functions))
    g.source_root = "/work"
    g.install_prefix = "/work/artifacts/phase2/install"
    f = cc._external_function_address(g, "file_load")
    ins = g.precision.insns_by_func[f]
    cfg = cc._function_cfg(g, f)
    blocks = cfg["blocks"]
    preds = {}
    for bb, ss in cfg["succ"].items():
        for s in ss:
            preds.setdefault(s, []).append(bb)
    openb = sorted(cfg["open_reach"])
    print("open blocks:", [(hex(ins[blocks[x][0]][0]), hex(ins[blocks[x][1] - 1][0]))
                           for x in openb])
    ridx = [i for i, (a, t) in enumerate(ins) if a == 0x2ccae4][0]
    bi = cfg["block_of"][ridx]
    lo, hi = blocks[bi]
    print("reload idx", ridx, "block", bi, "range",
          hex(ins[lo][0]), hex(ins[hi - 1][0]), "open?", bi in cfg["open_reach"])
    print("preds", [(p, hex(ins[blocks[p][0]][0]), hex(ins[blocks[p][1] - 1][0]))
                    for p in preds.get(bi, [])])
    w = cc._stack_slot_writes(g, f, -264)
    print("stores", [(x["kind"], hex(ins[x["index"]][0])) for x in w])
    print("slot_reaching", cc._slot_reaching_stores(g, f, -264, ridx))

    # trace the backward walk manually
    stores = {x["index"]: x for x in w if x["kind"] == "store"}
    seen = set()
    frontier = [bi]
    steps = 0
    while frontier and steps < 40:
        steps += 1
        bb = frontier.pop()
        if bb in seen:
            continue
        seen.add(bb)
        blo, bhi = blocks[bb]
        loc = [i for i in stores if blo <= i < bhi]
        print(f"  walk block {bb} {hex(ins[blo][0])}-{hex(ins[bhi-1][0])} "
              f"local={[hex(ins[i][0]) for i in loc]} "
              f"open={bb in cfg['open_reach']} preds={preds.get(bb, [])}")
        if loc:
            break
        pr = preds.get(bb, ())
        if not pr:
            print("   -> entry reached, refuse")
            break
        frontier.extend(p for p in pr if p not in seen)


if __name__ == "__main__":
    main()
