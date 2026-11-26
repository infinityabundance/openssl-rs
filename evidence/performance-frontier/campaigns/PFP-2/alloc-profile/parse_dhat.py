#!/usr/bin/env python3
"""Attribute a P-256 signing operation's allocations to sites, from two DHAT runs.

`ecdsa_alloc_harness --sign-ops N` performs exactly N measured steps
(ECDSA_do_sign + ECDSA_SIG_free) after the identical key setup. Differencing the
program-point trees of two N by stack signature therefore yields the
per-operation allocation count and bytes for each site, with no attribution
guesswork, provided both runs used the same harness binary.

    parse_dhat.py --before dhat-30.json --after dhat-50.json --ops 20 \
                  [--subject cand|auth] [--json out.json] [--top 25]

DHAT prints `<address>: <symbol> (in <object>)` for a resolved frame; the
address is ASLR-dependent and is stripped so stacks from two processes match.
Frames belonging to allocator plumbing (`vgpreload`, `RawVec::finish_grow`,
`CRYPTO_malloc`, ...) are dropped from the *reported* site so the innermost
frame that is the caller's own code names the site.
"""
import argparse
import json
import sys

PLUMBING = (
    "vgpreload",
    "CRYPTO_malloc",
    "CRYPTO_zalloc",
    "CRYPTO_realloc",
    "CRYPTO_clear_realloc",
    "CRYPTO_secure_malloc",
    "CRYPTO_secure_zalloc",
    "CRYPTO_clear_malloc",
    "alloc::raw_vec",
    "RawVec",
    "alloc_impl",
    "alloc::alloc",
    "__rust_alloc",
    "finish_grow",
    "grow_one",
    "malloc (",
    "calloc (",
    "realloc (",
    "operator new",
    "[root]",
)


def is_plumbing(frame):
    return any(p in frame for p in PLUMBING)


def norm_frame(frame):
    if frame.startswith("0x") and ": " in frame:
        return frame.split(": ", 1)[1]
    return frame


def short(frame):
    return frame.split(" (in ", 1)[0] if " (in " in frame else frame


def load(path):
    doc = json.load(open(path))
    table = doc["ftbl"]
    out = {}
    for pp in doc["pps"]:
        key = tuple(norm_frame(table[i]) for i in pp["fs"])
        rec = out.setdefault(key, [0, 0])
        rec[0] += pp["tbk"]
        rec[1] += pp["tb"]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--before", required=True)
    ap.add_argument("--after", required=True)
    ap.add_argument("--ops", type=int, required=True)
    ap.add_argument("--subject", default="candidate")
    ap.add_argument("--json", default=None)
    ap.add_argument("--top", type=int, default=25)
    args = ap.parse_args()

    before = load(args.before)
    after = load(args.after)

    rows = []
    for key, (bk, by) in after.items():
        pbk, pby = before.get(key, (0, 0))
        dbk, dby = bk - pbk, by - pby
        if dbk <= 0 and dby <= 0:
            continue
        own = [short(f) for f in key if not is_plumbing(f)]
        rows.append(
            {
                "site": own[0] if own else "[plumbing]",
                "caller": own[1] if len(own) > 1 else "",
                "caller2": own[2] if len(own) > 2 else "",
                "stack": [short(f) for f in key],
                "blocks_per_op": dbk / args.ops,
                "blocks_total": dbk,
                "bytes_per_op": dby / args.ops,
                "bytes_total": dby,
            }
        )

    total_blocks = sum(r["blocks_total"] for r in rows)
    total_bytes = sum(r["bytes_total"] for r in rows)

    # Group by (site, caller) for the ranked table.
    groups = {}
    for r in rows:
        g = groups.setdefault((r["site"], r["caller"]), [0.0, 0.0, 0])
        g[0] += r["blocks_per_op"]
        g[1] += r["bytes_per_op"]
        g[2] += 1
    ranked = sorted(groups.items(), key=lambda kv: -kv[1][0])

    print(f"# PFP-24 allocation profile — subject={args.subject} ops={args.ops}")
    print(
        f"# per-sign totals: {total_blocks / args.ops:.3f} blocks, "
        f"{total_bytes / args.ops:.1f} bytes over {len(rows)} program points"
    )
    print()
    print(f"{'blocks/op':>10}  {'bytes/op':>9}  {'pps':>3}  site <- caller")
    for (site, caller), (b, byt, n) in ranked[: args.top]:
        print(f"{b:>10.3f}  {byt:>9.1f}  {n:>3}  {site}"
              + (f" <- {caller}" if caller else ""))
    if len(ranked) > args.top:
        rest = ranked[args.top:]
        print(f"{sum(r[1][0] for r in rest):>10.3f}  "
              f"{sum(r[1][1] for r in rest):>9.1f}  "
              f"{sum(r[1][2] for r in rest):>3}  (other groups)")

    if args.json:
        json.dump(
            {
                "schema": "openssl-rs/performance/pfp24-alloc-profile/v1",
                "subject": args.subject,
                "ops": args.ops,
                "totals": {
                    "blocks_per_op": total_blocks / args.ops,
                    "bytes_per_op": total_bytes / args.ops,
                },
                "groups": [
                    {"site": s, "caller": c, "blocks_per_op": v[0],
                     "bytes_per_op": v[1], "program_points": v[2]}
                    for (s, c), v in ranked
                ],
                "rows": rows,
            },
            open(args.json, "w"),
            indent=2,
            sort_keys=True,
        )
        print(f"\n# wrote {args.json}", file=sys.stderr)


if __name__ == "__main__":
    main()
