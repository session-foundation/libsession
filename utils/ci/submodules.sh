#!/bin/sh
# Fetches the submodule tree, minus the ones no CI build configures, each as a single shallow fetch of
# its pinned commit.  Every submodule starts fetching as soon as its parent is checked out.
# `git submodule update --recursive` clones each branch tip before fetching the pinned commit, and does
# one repo at a time.  A submodule added upstream is fetched until it's listed in `skipped`.
set -e
start=$(date +%s)

sr=external/session-router
quic=$sr/external/oxen-libquic

# No CI build configures these.  Skipping a submodule skips everything under it.
skipped="
cmake/session-deps/external/ios-cmake
external/protobuf/third_party/benchmark
external/protobuf/third_party/googletest
external/session-sqlite/SQLiteCpp/googletest
external/session-sqlite/tests/Catch2
$sr/gui
$sr/test/Catch2
$sr/external/oxen-mq/cppzmq
$sr/external/oxen-mq/oxen-encoding
$sr/external/oxen-mq/oxen-logging
$sr/external/oxen-mq/tests/Catch2
$quic/cmake/session-deps/external/ios-cmake
$quic/external/oxen-encoding/tests/Catch2
$quic/tests/CLI11
$quic/tests/Catch2
"

skip() {
    printf '%s\n' "$skipped" | grep -qxF "$1"
}

# get DIR: checks out DIR's submodules at the commits DIR pins, then theirs, in parallel.
get() {
    dir=$1
    [ -f "$dir/.gitmodules" ] || return 0
    pids=
    for name in $(git config -f "$dir/.gitmodules" --name-only --get-regexp '^submodule\..*\.path$' |
            sed 's/^submodule\.//; s/\.path$//'); do
        path=$(git config -f "$dir/.gitmodules" "submodule.$name.path")
        full=${dir#.}/$path
        full=${full#/}
        skip "$full" && continue
        # A .gitmodules entry with no gitlink behind it is stale; git submodule update skips it too.
        sha=$(git -C "$dir" ls-tree HEAD -- "$path" | awk '$1 == "160000" { print $3 }')
        [ -n "$sha" ] || continue
        url=$(git config -f "$dir/.gitmodules" "submodule.$name.url")
        (
            cd "$full"
            git init -q
            git fetch -q --depth=1 "$url" "$sha"
            git -c advice.detachedHead=false checkout -q FETCH_HEAD
            cd - >/dev/null
            get "$full"
        ) &
        pids="$pids $!"
    done
    for pid in $pids; do
        wait "$pid"
    done
}

get .
echo "Submodules fetched in $(($(date +%s) - start)) s"
