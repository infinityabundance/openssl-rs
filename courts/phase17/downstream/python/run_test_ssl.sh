#!/bin/sh
#
# openssl-rs — Phase 17 downstream: run CPython's OWN `test_ssl` suite against the
# candidate-linked interpreter.
#
# A plain `./python -m test -v -u all,-network test_ssl` HANGS on the candidate (a test does
# a small `recv()`, and the candidate's `SSL_read_ex` only delivers a record when the buffer
# is at least as large as the record). `bounded_test_ssl.py` therefore runs each test-method
# group as its own regrtest invocation under a wall-clock timeout, in parallel, so a hang is
# recorded as a timeout instead of stalling the suite. Network-using tests are disabled with
# `-u all,-network`.
#
# Run (court container up, build.sh already run):
#
#   bash docker/openssl-rs-court.sh exec \
#     sh /work/courts/phase17/downstream/python/run_test_ssl.sh
#
# Environment overrides: WORK, PY, PER_TEST_TIMEOUT, WORKERS.
#
set -u

WORK=${WORK:-/court/python}
PY=${PY:-$WORK/Python-3.12.15/python}
export PY
export PER_TEST_TIMEOUT=${PER_TEST_TIMEOUT:-20}
export WORKERS=${WORKERS:-4}
export BOUNDED_LOGDIR=${BOUNDED_LOGDIR:-$WORK/bounded_logs}

if [ ! -x "$PY" ]; then
    echo "run_test_ssl.sh: '$PY' not found; run build.sh first" >&2
    exit 2
fi

echo "run_test_ssl.sh: interpreter $($PY -VV)"
"$PY" /work/courts/phase17/downstream/python/bounded_test_ssl.py
RC=$?
echo "run_test_ssl.sh: bounded_test_ssl exit=$RC"
exit "$RC"
