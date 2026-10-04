#!/usr/bin/env python3
#
# openssl-rs — Phase 17 downstream: bounded runner for CPython's `test_ssl`.
#
# A plain `./python -m test -v -u all,-network test_ssl` HANGS: the candidate's
# `SSL_read_ex` stalls when a record is larger than the caller's buffer (details in
# EVIDENCE.md), so any test that does a small `recv()` blocks forever. This runner runs
# each *test method group* as its own regrtest invocation under a wall-clock timeout, in
# parallel, so a hang is recorded as a timeout instead of stalling the whole suite.
#
# It discovers the method names in-process, then for each name runs
#   timeout <PER_TEST_TIMEOUT> <python> -m test -v -u all,-network -m <name> test_ssl
# capturing the unittest summary (`Ran N`, `OK`/`FAILED (...)`), and aggregates counts.
#
# Env: PY, PER_TEST_TIMEOUT (default 20), WORKERS (default 4), BOUNDED_LOGDIR.
# Run via run_test_ssl.sh.
#
import os
import re
import shlex
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

PY = os.environ.get("PY", sys.executable)
SRC = os.path.dirname(PY)
PER = os.environ.get("PER_TEST_TIMEOUT", "20")
WORKERS = int(os.environ.get("WORKERS", "4"))
LOGDIR = os.environ.get("BOUNDED_LOGDIR", "/court/python/bounded_logs")

DISCOVER = r"""
import unittest
loader = unittest.TestLoader()
suite = loader.loadTestsFromName('test.test_ssl')
counts = {}
def walk(s):
    for t in s:
        if isinstance(t, unittest.TestSuite):
            walk(t)
        else:
            name = t.id().rsplit('.', 1)[1]
            counts[name] = counts.get(name, 0) + 1
walk(suite)
for name in sorted(counts):
    print('%s\t%d' % (name, counts[name]))
"""


def discover():
    out = subprocess.run([PY, "-c", DISCOVER], cwd=SRC, capture_output=True, text=True)
    names = {}
    for line in out.stdout.splitlines():
        m = re.match(r"^(\S+)\t(\d+)$", line)
        if m:
            names[m.group(1)] = int(m.group(2))
    if not names:
        sys.stderr.write("discovery failed:\n%s\n%s\n" % (out.stdout, out.stderr))
        sys.exit(2)
    return names


def run_one(name):
    os.makedirs(LOGDIR, exist_ok=True)
    logpath = os.path.join(LOGDIR, name + ".log")
    with open(logpath, "w") as fh:
        p = subprocess.run(
            ["timeout", PER, PY, "-m", "test", "-v", "-u", "all,-network", "-m", name, "test_ssl"],
            cwd=SRC, stdout=fh, stderr=subprocess.STDOUT,
        )
    text = open(logpath, errors="replace").read()
    if p.returncode == 124:
        return (name, "timeout", 0, 0, 0, 0, "")
    ran = fail = err = skip = 0
    m = re.search(r"^Ran (\d+) tests? in", text, re.M)
    if m:
        ran = int(m.group(1))
    m = re.search(r"^(OK|FAILED)\b(.*)$", text, re.M)
    detail = ""
    if m:
        status = m.group(1)
        rest = m.group(2)
        for key, pat in (("failures", r"failures=(\d+)"),
                         ("errors", r"errors=(\d+)"),
                         ("skipped", r"skipped=(\d+)")):
            mm = re.search(pat, rest)
            if mm:
                if key == "failures":
                    fail = int(mm.group(1))
                elif key == "errors":
                    err = int(mm.group(1))
                else:
                    skip = int(mm.group(1))
        if status == "OK":
            status = "ok"
        else:
            status = "fail"
    else:
        status = "unknown"
    # first failure/error header line for the report
    fm = re.search(r"^(?:FAIL|ERROR): .*$", text, re.M)
    if fm:
        detail = fm.group(0)
    return (name, status, ran, fail, err, skip, detail)


def main():
    names = discover()
    total_cases = sum(names.values())
    print("bounded_test_ssl: %d unique method names covering %d test cases"
          % (len(names), total_cases))
    print("bounded_test_ssl: parallel=%d per-test-timeout=%ss logdir=%s" % (WORKERS, PER, LOGDIR))

    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for r in ex.map(run_one, sorted(names)):
            results.append(r)
            n, status, ran, fail, err, skip, _ = r
            if status != "ok":
                print("  %-8s %s (ran=%d fail=%d err=%d skip=%d)" % (status, n, ran, fail, err, skip))

    passed = failed = errors = skipped = timeouts = unknown = 0
    for name, status, ran, fail, err, skip, _ in results:
        cases = names[name]
        skipped += skip
        if status == "ok":
            passed += cases - skip
        elif status == "fail":
            failed += fail
            errors += err
            passed += max(0, ran - fail - err - skip)
        elif status == "timeout":
            timeouts += cases
        else:
            unknown += cases

    print("\n== bounded test_ssl summary ==")
    print("cases total : %d" % total_cases)
    print("passed      : %d" % passed)
    print("failed      : %d" % failed)
    print("errors      : %d" % errors)
    print("skipped     : %d" % skipped)
    print("timed out   : %d" % timeouts)
    print("unknown     : %d" % unknown)

    print("\n== first failure/error per non-ok method ==")
    for name, status, ran, fail, err, skip, detail in results:
        if status in ("fail", "unknown"):
            print("  %-8s %-40s %s" % (status, name, detail or "(see %s/%s.log)" % (LOGDIR, name)))

    return 0


if __name__ == "__main__":
    sys.exit(main())
