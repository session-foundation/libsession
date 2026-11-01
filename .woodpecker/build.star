# Linux builds run in our Debian/Ubuntu images on the docker agents, macOS builds directly on the
# Mac agents.

registry = "registry.session.codes/"

events = ["push", "pull_request", "tag", "manual"]

apt_get = "apt-get -o=Dpkg::Use-Pty=0 -q"

ngtcp2_deps = ["libgnutls28-dev", "libprotobuf-dev", "libngtcp2-dev", "libngtcp2-crypto-gnutls-dev"]

# Without the compiler, so that the clang builds can bring their own.
lib_deps = ["nlohmann-json3-dev"] + ngtcp2_deps

gcc_deps = ["g++"] + lib_deps

# Everything we can link against rather than compiling our own copy of, for builds that are not
# deliberately static (BUILD_STATIC_DEPS).  Two reasons: such a build is much faster, and it is the
# only thing that tests us against the library versions distros actually ship -- Debian 12's fmt 9,
# for instance, which our own code has to stay compatible with.
#
# liboxen-quic-dev pulls in liboxen-logging-dev, which is older than we accept
# (OXEN_LOGGING_MIN_VERSION in external/CMakeLists.txt); the submodule is used for that one and
# builds against the system fmt/spdlog, which is what puts fmt 9 in front of our code.
#
# A too-old system library is not an error: cmake falls back to building that one dependency.
# libsodium is that case on Debian 12 and Ubuntu 22.04, which ship less than the 1.0.21 we need.
system_deps = [
    "libevent-dev",
    "libfmt-dev",
    "liboxen-quic-dev",
    "liboxenc-dev",
    "libsodium-dev",
    "libspdlog-dev",
    "libsqlite3-dev",
    "libutf8proc-dev",
    "libzstd-dev",
    "nettle-dev",
]

# The ones known not to link into a full llvm-with-libc++ build, mostly through incompatibilities in
# C++ linking.
libcxx_system_deps = [d for d in system_deps if d not in ["libfmt-dev", "liboxen-quic-dev", "libspdlog-dev"]]

test_deps = ngtcp2_deps + system_deps

# s390x, our big-endian target, cross-compiled against multiarch :s390x libraries and tested under
# qemu.  deb.session.foundation publishes nothing for s390x, so its packages are left to submodules.
s390x_libs = [
    p + ":s390x"
    for p in sorted([d for d in test_deps if d not in ["liboxen-quic-dev", "liboxenc-dev"]]) +
             ["libsimdutf-dev", "pkgconf"]
]
s390x_test_deps = s390x_libs + ["qemu-user"]
s390x_deps = ["crossbuild-essential-s390x", "libcli11-dev", "nlohmann-json3-dev"] + s390x_test_deps

# BUILD_STATIC_DEPS is given either way because it defaults to the opposite of BUILD_SHARED_LIBS.
default_cmake = {
    "CMAKE_BUILD_TYPE": "Release",
    "CMAKE_CXX_FLAGS": "-fdiagnostics-color=always",
    "WARNINGS_AS_ERRORS": True,
    "BUILD_SHARED_LIBS": True,
    "BUILD_STATIC_DEPS": False,
    "USE_LTO": False,
    "LOCAL_MIRROR": "https://builds.session.codes/deps",
}

def cmake_args(opts):
    args = []
    for k, v in opts.items():
        if type(v) == "bool":
            v = "ON" if v else "OFF"
        else:
            v = str(v)
            if " " in v:
                v = '"%s"' % v
        args.append("-D%s=%s" % (k, v))
    return " ".join(args)

# The commands, run from the top of the checkout, that configure and build in build/.
def build_commands(cmake, jobs):
    opts = dict(default_cmake)
    opts.update(cmake)
    return [
        "mkdir build",
        "cd build",
        "cmake .. " + cmake_args(opts),
        "make VERBOSE=1 -j%d" % jobs,
    ]

def test_commands(runner = ""):
    return ["cd build"] + [
        runner + "./tests/%s --colour-mode ansi -d yes" % t
        for t in ["testLogging", "testAll"]
    ]

def tests(runner = ""):
    return {"name": "tests", "commands": test_commands(runner)}

# Checks that a database made by every earlier schema in the history upgrades to the current one.
# Those schemas exist only in git, so this needs the whole history and the tags, which the default
# shallow clone has neither of.
schema_history = {
    "name": "schema history",
    "pkgs": test_deps + ["git"],
    "commands": ["tests/schema_history_check.sh build/tests/schema-upgrade-check"],
}
full_clone = [{
    "name": "clone",
    "image": "woodpeckerci/plugin-git:2",
    "settings": {"depth": 0, "partial": False, "tags": True},
}]

def workflow(name, platform, steps, when = None, clone = None):
    wf = {
        "name": name,
        "labels": {"platform": platform, "backend": "local" if platform.startswith("darwin/") else "docker"},
        # The debian/* and ubuntu/* branches build packages, with CI configs of their own.
        "when": when or [{"event": events, "branch": {"exclude": ["debian/*", "ubuntu/*"]}}],
        "steps": steps,
    }
    if clone:
        wf["clone"] = clone
    return wf

# Installs `pkgs` in a fresh container of `image`, from deb.session.foundation as well if wanted.
def apt_install(image, pkgs, session_repo = True, foreign_arch = None):
    cmds = ['echo "man-db man-db/auto-update boolean false" | debconf-set-selections']
    if foreign_arch:
        # Has to come before the `apt-get update`.
        cmds.append("dpkg --add-architecture " + foreign_arch)
    cmds += [apt_get + " update", apt_get + " install -y eatmydata"]
    if session_repo:
        codename = "sid" if image.startswith(registry + "debian-sid") else "$$(lsb_release -sc)"
        cmds += [
            "eatmydata " + apt_get + " install --no-install-recommends -y lsb-release",
            "cp utils/deb.session.foundation.gpg /etc/apt/trusted.gpg.d",
            "echo deb http://deb.session.foundation %s main >/etc/apt/sources.list.d/session.list" % codename,
            "eatmydata " + apt_get + " update",
        ]
    return cmds + [
        "eatmydata " + apt_get + " dist-upgrade -y",
        "eatmydata " + apt_get + " install --no-install-recommends -y " + " ".join(pkgs),
    ]

def build_step(image, commands):
    step = {"name": "build", "image": image, "commands": ['echo "Building on $${CI_MACHINE}"'] + commands}
    if image != "sh":
        step["pull"] = True
    return step

# Uploads only from pushes to our own repositories, which are what the upload key is given to.
def upload_step(image, command):
    step = {
        "name": "upload",
        "image": image,
        "environment": {"SSH_KEY": {"from_secret": "SSH_KEY"}},
        "commands": [command],
        "when": [{"event": ["push", "tag", "manual"], "repo": "session-foundation/*"}],
    }
    if image != "sh":
        step["pull"] = True
    return step

# A build of the library, followed by `checks` against it: by default the test suite.  Each check
# runs in a fresh container holding what running it needs, its `pkgs`, by default `test_deps`.
def linux(
        name,
        image,
        arch = "amd64",
        deps = gcc_deps,
        system = system_deps,
        test_deps = test_deps,
        session_repo = True,
        foreign_arch = None,
        cmake = {},
        jobs = 6,
        test_runner = "",
        checks = None,
        clone = None):
    if cmake.get("BUILD_STATIC_DEPS"):
        system = []
    if checks == None:
        checks = [tests(test_runner)]
    image = registry + image
    steps = [build_step(
        image,
        apt_install(image, ["cmake", "make", "git", "ccache", "ca-certificates"] + deps + system, session_repo, foreign_arch) +
        build_commands(cmake, jobs),
    )]
    for check in checks:
        steps.append({
            "name": check["name"],
            "image": image,
            "pull": True,
            "commands": apt_install(image, check.get("pkgs", test_deps), session_repo, foreign_arch) + check["commands"],
        })
    return workflow(name, "linux/" + arch, steps, clone = clone)

def clang(version):
    return linux(
        "Debian sid: clang-%d" % version,
        "debian-sid-clang",
        deps = ["clang-%d" % version] + lib_deps,
        cmake = {"CMAKE_C_COMPILER": "clang-%d" % version, "CMAKE_CXX_COMPILER": "clang++-%d" % version},
    )

def full_llvm(version, cxx = None):
    cmake = {
        "CMAKE_C_COMPILER": "clang-%d" % version,
        "CMAKE_CXX_COMPILER": "clang++-%d" % version,
        "CMAKE_CXX_FLAGS": "-stdlib=libc++ -fcolor-diagnostics",
        "BUILD_SHARED_LIBS": False,
        "OXEN_LOGGING_FORCE_SUBMODULES": True,
        "DEPS_FORCE_protobuf-lite_SUBMODULE": True,
        "DEPS_FORCE_liboxenquic_SUBMODULE": True,
    }
    for kind in ["EXE", "MODULE", "SHARED"]:
        cmake["CMAKE_%s_LINKER_FLAGS" % kind] = "-fuse-ld=lld-%d" % version
    if cxx:
        cmake["CMAKE_CXX_STANDARD"] = cxx
    return linux(
        "Debian sid: llvm-%d" % version + ("" if cxx == None else ": C++%d" % cxx),
        "debian-sid-clang",
        deps = [
            "clang-%d" % version,
            "lld-%d" % version,
            "libc++-%d-dev" % version,
            "libc++abi-%d-dev" % version,
        ] + lib_deps,
        system = libcxx_system_deps,
        cmake = cmake,
    )

# Release archives: built by `commands` and uploaded from `directory`, where they leave the archive.
def package(name, image, commands, directory, arch = "amd64", deps = gcc_deps, session_repo = False):
    image = registry + image
    return workflow(name, "linux/" + arch, [
        build_step(
            image,
            apt_install(image, ["cmake", "make", "git", "ccache", "ca-certificates"] + deps, session_repo) +
            ["export JOBS=6"] + commands,
        ),
        upload_step(image, "cd %s && ../utils/ci/static-upload.sh" % directory),
    ])

def static_linux(name, image, archive, arch = "amd64", deps = gcc_deps, cmake = {}):
    opts = {"STATIC_LIBSTD": True}
    opts.update(cmake)
    opts["LOCAL_MIRROR"] = default_cmake["LOCAL_MIRROR"]
    return package(
        name,
        image,
        ["./utils/static-bundle.sh build %s %s" % (archive, cmake_args(opts))],
        "build",
        arch = arch,
        deps = deps,
    )

mac_setup = [
    # If you don't do this then the C compiler doesn't have an include path containing basic system
    # headers.  WTF apple:
    'export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"',
]

def macos(name, arch, cmake = {}):
    opts = {"CMAKE_CXX_FLAGS": "-fcolor-diagnostics"}
    opts.update(cmake)
    return workflow(name, "darwin/" + arch, [
        build_step("sh", mac_setup + build_commands(opts, 6)),
        {"name": "tests", "image": "sh", "commands": test_commands()},
    ])

def macos_package(name, script, directory):
    return workflow(name, "darwin/arm64", [
        build_step("sh", mac_setup + ["export JOBS=6", script]),
        upload_step("sh", "cd %s && ../utils/ci/static-upload.sh" % directory),
    ])

def live_test(mode):
    return {
        "name": "live tests (%s)" % mode,
        "commands": ["cd build", './tests/testLive --%s --log-level warning --colour-mode ansi -d yes "[file]"' % mode],
    }

# Live Pro-backend integration test: build testAll with the dev-server hook, stand up an ephemeral
# backend (throwaway postgres + flask, provider_dry_run) via tests/pro_backend/run-dev-backend.sh,
# and run the [pro_live] suite against it.  The backend is a separate Python service, checked out at
# a pinned ref (repos stay decoupled -- CI keeps its own clone).
pro_backend_git = "https://github.com/session-foundation/session-pro-backend.git"

# Track upstream mainline (session-foundation dev): the [pro_live] drift check is meant to follow it.
pro_backend_ref = "dev"

# What the live Pro-backend check needs beyond the test deps: postgres, the backend's python3-*
# runtime, and clone/venv tooling.
pro_backend_pkgs = [
    "postgresql",
    "python3-session-util",
    "python3-nacl",
    "python3-psycopg",
    "python3-psycopg-c",
    "python3-psycopg-pool",
    "python3-flask",
    "python3-venv",
    "python3-pip",
    "python3-pendulum",
    "git",
    "curl",
    "ca-certificates",
]

pro_backend_check = {
    "name": "pro-backend live tests",
    "pkgs": pro_backend_pkgs + test_deps,
    "commands": [
        # Check out and provision the backend: the venv reuses the apt-installed python3-* through
        # the system site packages, so only the pip-only provider libraries are installed.
        "git clone --depth=1 --branch %s %s /opt/pro-backend" % (pro_backend_ref, pro_backend_git),
        "python3 -m venv --system-site-packages /opt/pro-backend/.venv",
        "/opt/pro-backend/.venv/bin/pip install --no-input app-store-server-library google-cloud-pubsub google-api-python-client",
        # initdb/pg_ctl refuse to run as root, so the whole launcher runs as a non-root user; its temp
        # dirs (postgres cluster, key) are created by that user, so initdb is satisfied.
        "useradd -m pro && chown -R pro /opt/pro-backend",
        'ws="$(pwd)"',
        "su pro -c \"cd $ws && SESSION_PRO_BACKEND_DIR=/opt/pro-backend PRO_BACKEND_PORT=5544 " +
        "tests/pro_backend/run-dev-backend.sh ./build/tests/testAll --colour-mode ansi -d yes '[pro_live]'\"",
    ],
}

def main(ctx):
    return [
        workflow("lint check", "linux/amd64", [{
            "name": "formatting",
            "image": registry + "lint",
            "pull": True,
            "commands": [
                'echo "Building on $${CI_MACHINE}"',
                apt_get + " update",
                apt_get + " install -y eatmydata",
                "eatmydata " + apt_get + " install --no-install-recommends -y git clang-format-19",
                "./utils/format.sh",
                "git --no-pager diff --exit-code --color || " +
                "(printf '\\n\\n\\033[31;1mLint check failed; please run ./utils/format.sh\\033[0m\\n\\n'; exit 1)",
            ],
        }]),

        workflow("API Documentation", "linux/amd64", [
            build_step(registry + "debian-stable", [
                apt_get + " update",
                apt_get + " install -y rsync python3-venv",
                "cd docs/api/",
                "python3 -m venv .venv",
                ". .venv/bin/activate",
                "pip install -r requirements.txt",
                "make build-all",
            ]),
            upload_step(registry + "debian-stable", "cd docs/api && ../../utils/ci/docs-upload.sh"),
        ], when = [{"event": "push", "branch": "dev"}]),

        linux("Debian sid", "debian-sid"),

        # With session-router, and the live file transfer tests.
        linux(
            "Debian sid (live tests)",
            "debian-sid",
            cmake = {"ENABLE_NETWORKING": True, "ENABLE_NETWORKING_SROUTER": True, "BUILD_LIVE_TESTS": True},
            checks = [tests()] + [live_test(m) for m in ["onionreq", "srouter", "direct"]],
        ),

        # Live Pro-backend integration tests, which stand in for the ordinary test run.
        linux(
            "Debian sid (Pro backend live)",
            "debian-sid",
            cmake = {"TEST_PRO_BACKEND_WITH_DEV_SERVER": True},
            checks = [pro_backend_check],
        ),

        linux("Debian sid: Debug", "debian-sid", cmake = {"CMAKE_BUILD_TYPE": "Debug"}),
        linux("Debian testing", "debian-testing"),

        # C++23, which is what `session::Expected` is written against: under it `expected.hpp`
        # resolves to `std::expected` rather than the local stand-in, so these compile every use in
        # the project against the real thing.  That is what keeps the stand-in a strict subset -- a
        # use that has drifted outside it fails here rather than waiting for whoever eventually
        # raises the standard.
        #
        # Both libstdc++ and libc++, because the two disagree about plenty and a subset that only
        # holds against one of them is not a subset.
        linux("Debian sid: C++23", "debian-sid", cmake = {"CMAKE_CXX_STANDARD": 23}),
        full_llvm(23, cxx = 23),

        clang(19),
        full_llvm(19),
        linux("Debian stable (i386)", "debian-stable/i386"),
        linux("Debian 13", "debian-trixie", checks = [tests(), schema_history], clone = full_clone),
        linux("Debian 12", "debian-bookworm"),
        linux("Ubuntu latest", "ubuntu-rolling"),
        linux("Ubuntu LTS", "ubuntu-lts"),

        # The one build that compiles every dependency itself rather than taking the distro's, on
        # the oldest distro we support: what the release artifacts do, and the only thing that
        # notices when a dependency we vendor stops building.
        linux("Ubuntu 22.04 (static deps)", "ubuntu-jammy", cmake = {"BUILD_STATIC_DEPS": True}),

        # ARM builds; armhf builds in a 32-bit image on the arm64 agents.
        linux("Debian sid (ARM64)", "debian-sid", arch = "arm64", jobs = 4),
        linux("Debian stable (armhf)", "debian-stable/arm32v7", arch = "arm64", jobs = 4),

        # Big-endian:
        linux(
            "Debian forky (s390x cross)",
            "debian-forky-s390x-cross",
            deps = s390x_deps,
            system = [],
            test_deps = s390x_test_deps,
            session_repo = False,
            foreign_arch = "s390x",
            test_runner = "qemu-s390x ",
            cmake = {"CMAKE_TOOLCHAIN_FILE": "../cmake/debian-cross-s390x-toolchain.cmake"},
        ),

        macos_package("Static iOS", "./utils/ios.sh libsession-util-ios-TAG", "build-ios"),

        macos("macOS Arm64 (Release)", "arm64"),
        macos("macOS Arm64 (Debug)", "arm64", cmake = {"CMAKE_BUILD_TYPE": "Debug"}),

        static_linux("Static Linux: amd64", "debian-stable", "libsession-util-linux-amd64-TAG.tar.xz"),
        static_linux("Static Linux: i386", "debian-stable/i386", "libsession-util-linux-i386-TAG.tar.xz"),
        static_linux("Static Linux: arm64", "debian-stable", "libsession-util-linux-arm64-TAG.tar.xz", arch = "arm64"),
        static_linux(
            "Static Linux: armhf",
            "debian-stable/arm32v7",
            "libsession-util-linux-armhf-TAG.tar.xz",
            arch = "arm64",
        ),
        static_linux(
            "Static Windows x64",
            "debian-win32-cross",
            "libsession-util-windows-x64-TAG.zip",
            deps = ["g++-mingw-w64-x86-64-posix"],
            cmake = {
                "CMAKE_CXX_FLAGS": "-fdiagnostics-color=always",
                "CMAKE_TOOLCHAIN_FILE": "../cmake/mingw-x86-64-toolchain.cmake",
                "ENABLE_NETWORKING_SROUTER": False,
            },
        ),
        package(
            "Static Android",
            "android",
            ["export NDK=/usr/lib/android-ndk", "./utils/android.sh libsession-util-android-TAG.tar.xz"],
            "build-android",
            session_repo = True,
        ),

        macos_package("Static macOS", "./utils/macos.sh", "build-macos"),
    ]
