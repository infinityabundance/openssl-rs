#!/bin/sh
# The shell convenience form of verify.py. It uses no external command: the
# directory of this script is derived by parameter expansion, and the interpreter
# is taken from PATH, which the caller must set to the interpreter's directory.
set -eu
here=${0%/*}
[ "$here" = "$0" ] && here=.
exec python3 -B "$here/verify.py" "$@"
