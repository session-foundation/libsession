# Build image for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
#
# The scanner builds this with network access, then audits the finished image with none. Everything
# the build or the test suite needs has to be fetched here: submodules, packages and any dependency
# CMake would otherwise download at configure time.

FROM debian:trixie@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308

ENV DEBIAN_FRONTEND=noninteractive

# System libraries wherever session-deps accepts them, so the build compiles little beyond
# libsession itself. deb.session.foundation supplies the ones Debian lacks or ships too old
# (liboxen-quic, liboxenc); its signing key is the one in utils/, so it is copied in on its own
# ahead of the full checkout to keep this layer cacheable.
# deb.session.foundation redirects to https, which the bare image cannot verify until
# ca-certificates is installed from Debian's own mirror.
COPY utils/deb.session.foundation.gpg /etc/apt/trusted.gpg.d/
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && echo "deb https://deb.session.foundation trixie main" >/etc/apt/sources.list.d/session.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        git cmake make ninja-build pkg-config g++ \
        nlohmann-json3-dev libgnutls28-dev libprotobuf-dev libngtcp2-dev libngtcp2-crypto-gnutls-dev \
        libevent-dev libfmt-dev liboxen-quic-dev liboxenc-dev libsodium-dev libspdlog-dev \
        libsqlite3-dev libutf8proc-dev libzstd-dev nettle-dev libvips-dev libheif-dev \
    && rm -rf /var/lib/apt/lists/*

# The servers libsession talks to, as reference for what their responses can contain. They are
# not built and are not part of the scan.
RUN for repo in session-storage-server session-file-server session-pysogs session-pro-backend; do \
        git clone --quiet --depth 1 "https://github.com/session-foundation/$repo.git" "/opt/context/$repo" \
        || exit 1; \
    done

COPY . /src
WORKDIR /src

# The scanner clones without submodules. All of them are fetched, not only the ones this
# configuration compiles: external/CMakeLists.txt checks most of them, ios-cmake and protobuf
# included, and refuses to configure if one is missing or stale.
RUN git submodule update --init --recursive --depth 1 --jobs 8

# Debug, because libsession's threading and state checks are asserts that a release build drops.
# Live tests are left out: they talk to the real Session network, which the audit cannot reach.
# Warnings are not errors, so a newer compiler in the base image cannot fail the build outright.
#
# Even with system libraries, session-deps downloads a few tarballs (libsodium, zstd, simdutf,
# sqlite3mc) into the build tree at build time. They are kept in /opt/session-deps-sources so a
# fresh build directory, e.g. a sanitizer build, can be configured offline: copy them into
# <builddir>/static-deps-sources/src/ first and the hash-checked download is skipped.
RUN cmake -S /src -B /src/build -G Ninja \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_FLAGS="-fno-omit-frame-pointer" \
        -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer" \
        -DBUILD_SHARED_LIBS=ON \
        -DBUILD_STATIC_DEPS=OFF \
        -DUSE_LTO=OFF \
        -DWARNINGS_AS_ERRORS=OFF \
        -DBUILD_LIVE_TESTS=OFF \
    && cmake --build /src/build -j"$(nproc)" \
    && mkdir -p /opt/session-deps-sources \
    && cp /src/build/static-deps-sources/src/*.tar.* /opt/session-deps-sources/

# The same build with ASan and UBSan. Scans run on 2 CPUs and 8 GB, where sanitizing the tree takes a
# large share of a scan; the build machine does it in minutes. Sanitized C++ compiles need well over
# 1 GB each, so parallelism is bounded by memory as well as cores.
#
# Static libraries, because a shared build can link the same static dependency (mlkem-native) into
# a library and into the test binary, and ASan aborts at startup on the duplicate globals.
ENV UBSAN_OPTIONS=print_stacktrace=1
RUN mkdir -p /src/build-asan/static-deps-sources/src \
    && cp /opt/session-deps-sources/* /src/build-asan/static-deps-sources/src/ \
    && cmake -S /src -B /src/build-asan -G Ninja \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
        -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_STATIC_DEPS=OFF \
        -DUSE_LTO=OFF \
        -DWARNINGS_AS_ERRORS=OFF \
        -DBUILD_LIVE_TESTS=OFF \
    && jobs=$(awk -v cpus="$(nproc)" '/^MemTotal:/ { j = int($2 / 1500000); print (j < 1 ? 1 : j < cpus ? j : cpus) }' /proc/meminfo) \
    && cmake --build /src/build-asan -j"$jobs"

# A smoke test, not a gate: a failing test should reach the maintainers as a report, not as a
# build failure that stops the scan.
RUN cd /src/build \
    && { timeout 900 ./tests/testLogging || echo "WARNING: testLogging reported failures"; } \
    && { timeout 900 ./tests/testAll || echo "WARNING: testAll reported failures"; }
