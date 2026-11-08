#!/bin/sh
# Fetches the submodules CI builds use, each as a single shallow fetch of its pinned commit, all in
# parallel.  `git submodule update --recursive` fetches every nested repo (~18 more, none of them
# built here), clones each branch tip before fetching the pinned commit, and does one repo at a time.
# A submodule missing from this list fails cmake's check_submodule, so the list cannot go stale
# silently.
set -e

# get DIR PATH...: checks out each PATH, a submodule of the repo at DIR, at the commit DIR pins.
get() {
    dir=$1
    shift
    pids=
    for path in "$@"; do
        name=$(git config -f "$dir/.gitmodules" --get-regexp '^submodule\..*\.path$' |
            awk -v p="$path" '$2 == p { sub(/^submodule\./, "", $1); sub(/\.path$/, "", $1); print $1 }')
        url=$(git config -f "$dir/.gitmodules" "submodule.$name.url")
        sha=$(git -C "$dir" rev-parse "HEAD:$path")
        (
            cd "$dir/$path"
            git init -q
            git fetch -q --depth=1 "$url" "$sha"
            git -c advice.detachedHead=false checkout -q FETCH_HEAD
        ) &
        pids="$pids $!"
    done
    for pid in $pids; do
        wait "$pid"
    done
}

sr=external/session-router
quic=$sr/external/oxen-libquic

get . tests/Catch2 external/ios-cmake external/protobuf external/session-router \
    external/session-sqlite external/date cmake/session-deps
get external/session-sqlite SQLiteCpp cmake/session-deps &
sqlite=$!
get $sr cmake/session-deps external/CLI11 external/mlkem-native external/nlohmann \
    external/oxen-libquic external/oxen-mq external/pybind11 external/sqlite_orm
get $quic cmake/session-deps external/oxen-encoding external/oxen-logging
get $quic/external/oxen-logging fmt spdlog
wait $sqlite
