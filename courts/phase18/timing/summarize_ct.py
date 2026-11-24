#!/usr/bin/env python3
"""Summarise valgrind memcheck ctgrind logs into file:line sites.

Outcome contract (E5a)
----------------------
The script reports one outcome and its exit status is part of the result:

* ``0``  a parsed, non-empty, well-formed taint report: at least one memcheck
  context block was found and every block carries at least one frame.  The
  counts printed are the counts this run always printed; their meaning has not
  changed.
* ``2``  ``CT_SUMMARY_USAGE``: the argument vector or the address base is not
  usable.
* ``3``  ``CT_SUMMARY_EMPTY_LOG``: the log has no non-whitespace bytes.
* ``4``  ``CT_SUMMARY_UNRELATED_LOG``: the log has content but no recognised
  memcheck uninitialised-value context.  A run that produced no taint output
  (including a genuinely clean run) lands here: the summariser cannot tell
  "nothing ran" from "ran clean", and it no longer reports success for either.
* ``5``  ``CT_SUMMARY_MALFORMED_LOG``: a context header was recognised but the
  block it opens has no ``at``/``by`` frame, so the report is truncated or
  interleaved.
* ``6``  ``CT_SUMMARY_UNREADABLE_LOG``: the log could not be read.

Only exit ``0`` certifies a summarised result.  On any refusal no counts are
printed on stdout; the stable code and its reason go to stderr.

Usage: ``summarize_ct.py BASE LOG`` where ``BASE`` is the load address in hex.
"""
import re
import subprocess
import sys
import collections

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_EMPTY = 3
EXIT_UNRELATED = 4
EXIT_MALFORMED = 5
EXIT_UNREADABLE = 6

USAGE = "CT_SUMMARY_USAGE"
EMPTY_LOG = "CT_SUMMARY_EMPTY_LOG"
UNRELATED_LOG = "CT_SUMMARY_UNRELATED_LOG"
MALFORMED_LOG = "CT_SUMMARY_MALFORMED_LOG"
UNREADABLE_LOG = "CT_SUMMARY_UNREADABLE_LOG"

LIB = "/work/artifacts/phase2/install/lib/libcrypto.so.3"

kind_re = re.compile(r"^==\d+== (Conditional jump or move depends on uninitialised value\(s\)|Use of uninitialised value of size \d+|Syscall param .* uninitialised)")
at_re = re.compile(r"^==\d+==\s+(?:at|by) 0x([0-9a-fA-F]+): (.+?)(?: \((.*)\))?$")


def _refuse(code, detail, status):
    print(f"{code}: {detail}", file=sys.stderr)
    return status


def _line_for(addr, base):
    off = addr - base
    if off < 0:
        return None, None
    try:
        out = subprocess.run(["addr2line", "-e", LIB, "-f", "-C", "-i", "0x%x" % off],
                             capture_output=True, text=True).stdout.splitlines()
    except OSError:
        # Address resolution is an annotation, not the count.  An absent
        # resolver degrades the annotation to the recorded symbol and leaves
        # the context count unchanged.
        return off, []
    # pairs of (func, file:line)
    pairs = []
    for i in range(0, len(out) - 1, 2):
        pairs.append((out[i], out[i + 1]))
    return off, pairs


def summarize(base, log_path):
    """Return ``(exit status, output lines)`` for one log."""
    try:
        with open(log_path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        _refuse(UNREADABLE_LOG, f"{log_path}: {exc}", EXIT_UNREADABLE)
        return EXIT_UNREADABLE, []

    text = raw.decode("utf-8", errors="replace")
    if not text.strip():
        _refuse(
            EMPTY_LOG,
            f"{log_path} has no content: an empty log is not a clean run",
            EXIT_EMPTY,
        )
        return EXIT_EMPTY, []

    blocks = []
    cur = None
    for line in text.splitlines():
        m = kind_re.match(line)
        if m:
            cur = {"kind": m.group(1), "frames": []}
            blocks.append(cur)
            continue
        m = at_re.match(line)
        if m and cur is not None:
            addr, func, where = m.groups()
            cur["frames"].append((int(addr, 16), func.strip(), (where or "").strip()))

    if not blocks:
        _refuse(
            UNRELATED_LOG,
            f"{log_path} contains no memcheck uninitialised-value context; it is "
            "not a ctgrind finding report, and a zero-context run is not "
            "distinguishable from one that did not execute",
            EXIT_UNRELATED,
        )
        return EXIT_UNRELATED, []

    frameless = [index for index, block in enumerate(blocks) if not block["frames"]]
    if frameless:
        _refuse(
            MALFORMED_LOG,
            f"{log_path}: context block(s) {frameless} carry no at/by frame; "
            "the report is truncated or interleaved",
            EXIT_MALFORMED,
        )
        return EXIT_MALFORMED, []

    agg = collections.Counter()
    rows = []
    for b in blocks:
        addr, func, where = b["frames"][0]
        off, pairs = _line_for(addr, base)
        if pairs:
            fn, fl = pairs[0]
            if fl in ("??:0", "??:?"):
                fn, fl = func, "?"
        else:
            fn, fl = func, "?"
        stack = " <- ".join(f[1] for f in b["frames"][:4])
        key = (b["kind"], fl, fn)
        agg[key] += 1
        rows.append((b["kind"], fl, fn, stack))

    lines = ["total contexts: %d" % len(blocks)]
    for (kind, fl, fn), n in agg.most_common():
        lines.append(f"{n:4d}  {kind[:34]:34s} {fl}  {fn}")
    lines.append("")
    lines.append("-- first 12 distinct stacks --")
    seen = set()
    for kind, fl, fn, stack in rows:
        k = (kind, fl, stack)
        if k in seen:
            continue
        seen.add(k)
        lines.append(f"[{kind[:30]}] {fl}")
        lines.append(f"    {stack}")
        if len(seen) >= 12:
            break
    return EXIT_OK, lines


def main(argv):
    if len(argv) != 2:
        return _refuse(
            USAGE,
            "usage: summarize_ct.py BASE LOG (BASE is the load address in hex)",
            EXIT_USAGE,
        )
    try:
        base = int(argv[0], 16)
    except ValueError:
        return _refuse(USAGE, f"the address base {argv[0]!r} is not hexadecimal", EXIT_USAGE)
    status, lines = summarize(base, argv[1])
    if status == EXIT_OK:
        print("\n".join(lines))
    return status


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
