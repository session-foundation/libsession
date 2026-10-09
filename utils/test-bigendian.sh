#!/usr/bin/env bash
#
# Occasional big-endian sanity audit for libsession-util. NOT wired into CI — run it by hand now and
# then (especially after touching hashing or any wire/config serialization).
#
# Most of libsession runs only on little-endian hosts, so endian-sensitive byte serialization — the
# Pro signed-digest encoding, config data, protobuf packing — normally never exercises its big-endian
# path. This script builds and runs the test suite inside an emulated big-endian target (s390x) so
# those paths run for real.
#
# session-router (the onion-routing layer) is endian-irrelevant to what we test and drags in the
# heaviest deps, so we build with -DENABLE_NETWORKING_SROUTER=OFF. oxen::quic itself can't be turned
# off (a couple of ungated backend-session test sources include its headers), so it still builds — we
# satisfy it with libngtcp2 + gnutls from apt (nghttp3 is not needed; libquic uses raw QUIC).
#
# Cost: everything runs under qemu-user emulation, so expect a slow build (oxen-libquic is the bulk of
# it). Fine for an occasional manual audit; it is deliberately not in CI.
#
# Requires: Docker, plus a one-time host install of qemu-user-static + binfmt-support (see below).
# Run from the repo root with submodules checked out.
set -euo pipefail

# One-time host prerequisite (Debian/Ubuntu):
#     sudo apt install qemu-user-static binfmt-support
# That registers the binfmt_misc handlers with the "F" (fix-binary) flag, which is what lets Docker
# transparently run foreign-arch images under emulation from inside a container — no privileged helper
# container needed.
if [ ! -e /proc/sys/fs/binfmt_misc/qemu-s390x ]; then
    echo "s390x binfmt handler not registered; run: sudo apt install qemu-user-static binfmt-support" >&2
    exit 1
fi

# Build + test inside an emulated s390x Debian. BUILD_STATIC_DEPS=OFF pulls the heavy deps (libsodium,
# protobuf, sqlite, zstd, and the oxen::quic deps libngtcp2/gnutls/libevent) as prebuilt s390x apt
# packages rather than compiling them from source under emulation.
docker run --platform=linux/s390x --rm -v "$PWD:/src" -w /src debian:sid bash -euxc '
    apt-get update
    apt-get install -y --no-install-recommends \
        g++ cmake ninja-build pkg-config git ca-certificates \
        libsodium-dev libprotobuf-dev protobuf-compiler libcurl4-openssl-dev \
        libsqlite3-dev libzstd-dev \
        libngtcp2-dev libngtcp2-crypto-gnutls-dev libgnutls28-dev libevent-dev
    rm -rf build-bigendian   # fresh configure each run; the dir lives in the mounted tree and would otherwise reuse a stale CMake cache
    cmake -B build-bigendian -G Ninja -DBUILD_STATIC_DEPS=OFF -DENABLE_NETWORKING_SROUTER=OFF -DCMAKE_BUILD_TYPE=Release
    cmake --build build-bigendian --target testAll
    # Run the endian-sensitive tags on this big-endian host. Catch2 exits 0 even when a filter clause
    # matches no tests, so capture the output and fail loudly if any tag went unmatched — that guards
    # against a tag rename silently shrinking the audit. ([endian] is a pfs-only test, not present here.)
    out=$(./build-bigendian/tests/testAll "[hash],[session-protocol],[pro_backend],[config]")
    echo "$out"
    if echo "$out" | grep -q "No test cases matched"; then
        echo "ERROR: a filter tag matched no tests — the audit under-ran (tag renamed?)" >&2
        exit 1
    fi
'
echo "big-endian audit passed"
