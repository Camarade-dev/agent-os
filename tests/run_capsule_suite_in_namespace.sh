#!/bin/sh
# Run the capsule suite inside a disposable user + mount namespace.
#
# The external owner-authority tests need a genuine privileged installer
# identity (uid 0) to install a signing key, provision authorizations and bind
# a broker socket.  A user namespace supplies exactly that, without touching
# the real host: the process is uid 0 only inside the namespace, every mount is
# private to it, and the whole world disappears when the namespace exits.
#
# This is a *synthetic* privilege witness.  It is not, and does not claim to
# be, the real root-owned production installation under /etc, /var/lib and
# /run --- that installation remains an explicit privileged owner action.
#
# Scope: the owner-authority files only.  Inside the namespace this process is
# uid 0, which legitimately breaks unrelated tests that assert a *non-root*
# capsule identity, so the rest of the suite must be run normally:
#
#     python3 -m pytest tests/test_admissible_capsule_*.py
#
# Usage:  tests/run_capsule_suite_in_namespace.sh [pytest arguments...]
#         (with no arguments it runs the owner-authority files)
set -eu

if [ "$(id -u)" = "0" ]; then
    echo "refusing: run this as an ordinary user; it creates its own namespace" >&2
    exit 2
fi

repository="$(cd "$(dirname "$0")/.." && pwd)"
: "${PYTHON:=python3}"

# Append the owner-authority files unless the caller named targets of its own.
selected=0
for argument in "$@"; do
    # A target is an existing path; everything else is a pytest option or its
    # value (for example `-p no:cacheprovider`).
    if [ -e "$argument" ]; then
        selected=1
    fi
done
if [ "$selected" -eq 0 ]; then
    set -- "$@" \
        "$repository/tests/test_admissible_capsule_external_owner_authority.py" \
        "$repository/tests/test_admissible_capsule_owner_rooted_witness_trust.py" \
        "$repository/tests/test_admissible_capsule_owner_bound_rehearsal.py" \
        "$repository/tests/test_admissible_capsule_owner_authority_privilege_witness.py"
fi

exec unshare --user --map-root-user --mount -- \
    "$PYTHON" -m pytest "$@"
