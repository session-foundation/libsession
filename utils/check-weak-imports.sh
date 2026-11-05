#!/bin/bash
#
# Fails if an Apple static archive weakly imports any symbol not on the allowlist below.
#
# A function the SDK declares as newer than the deployment target is weakly imported, and is null
# when called on an older OS.  Dependencies built with autoconf are where this comes from: a
# configure link test cannot see availability, so it finds the function and the library then calls
# it unconditionally -- pipe2 (iOS/macOS 27) in libevent crashed every older device at the first
# event loop.  Nothing at compile or link time objects, and only a device on the older OS crashes.
#
# A call guarded by __builtin_available is weakly imported just the same, so an allowed symbol is
# trusted only in the object files its entry names: the same function called unguarded from
# elsewhere still fails.  Entries are MEMBER:SYMBOL extended regular expressions, matched in full
# against the object file name and the Mach-O symbol name (leading underscore included).
#
# Usage: utils/check-weak-imports.sh ARCHIVE...

allowed=(
    # The SDK's own FD_SET checks this for null before calling it.
    '.*:___darwin_check_fd_set_overflow'
)

set -e -o pipefail

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 ARCHIVE..." >&2
    exit 1
fi

allowed_re="^($(IFS='|'; echo "${allowed[*]}"))\$"

status=0
for archive in "$@"; do
    # -A prefixes every line with the archive and member, -arch all covers every slice of a fat
    # archive, and nm prints the same "(undefined) weak external" for machine code and LTO bitcode.
    # Members with no symbols of their own (gnulib stubs) each get a line on stderr, which is noise.
    imports=$(nm -m -A -arch all "$archive" 2> >(grep -v ': no symbols$' >&2) \
        | sed -nE 's/^.*:([^:]+): +\(undefined\) weak external ([^ ]+).*$/\1:\2/p' \
        | sort -u)
    unexpected=$(grep -Ev "$allowed_re" <<<"$imports" || true)

    if [ -n "$unexpected" ]; then
        echo "$archive: unexpected weak imports (object:symbol):" >&2
        sed 's/^/    /' <<<"$unexpected" >&2
        status=1
    fi
done

if [ "$status" -ne 0 ]; then
    cat >&2 <<'EOF'
Each is a function the SDK declares as newer than the deployment target, and is null when called on
an older OS.  Fix the dependency that calls it (usually in session-deps, by telling its configure
the function is missing on Apple), or, only if every call is behind __builtin_available, add it to
the allowlist in utils/check-weak-imports.sh.
EOF
fi
exit $status
