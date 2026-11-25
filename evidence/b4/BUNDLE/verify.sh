#!/bin/sh
# The shell form of verify.py. It calls no external command: the script's own
# directory is derived by parameter expansion, and the interpreter is taken from
# PATH, which the caller controls.
set -eu
here=${0%/*}
[ "$here" = "$0" ] && here=.
exec python3 -I -S -B "$here/verify.py" "$@"
