#!/bin/sh
# Run a Compliance hook with the first working Python 3 (3.8+).
# Probing matters on Windows, where `python3` can be the Microsoft Store stub that
# exits silently, and Git Bash hands over /c/... paths a Windows Python can't open.
# No Python at all: stay silent rather than break every edit.
for py in python3 python "py -3"; do
  if $py -c "import sys; sys.exit(sys.version_info < (3, 8))" </dev/null >/dev/null 2>&1; then
    if command -v cygpath >/dev/null 2>&1; then
      script=$(cygpath -w "$1"); shift
      exec $py "$script" "$@"
    fi
    exec $py "$@"
  fi
done
exit 0
