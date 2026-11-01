# Cross-compiles for s390x -- our big-endian test target -- on a Debian host with
# crossbuild-essential-s390x and the :s390x multiarch -dev packages installed, as in the
# debian-forky-s390x-cross CI image.  What it builds runs under qemu-user.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR s390x)

set(CROSS_TARGET s390x-linux-gnu)
# session-deps passes this as the autoconf --host of any dependency that falls back to a static build
set(ARCH_TRIPLET ${CROSS_TARGET})
set(CMAKE_C_COMPILER ${CROSS_TARGET}-gcc)
set(CMAKE_CXX_COMPILER ${CROSS_TARGET}-g++)
set(CMAKE_CROSSCOMPILING_EMULATOR qemu-s390x)

# Multiarch puts the target's libraries in the host's own /usr rather than a sysroot, so there is no
# root path to confine searches to: the library architecture is what keeps find_library in
# /usr/lib/s390x-linux-gnu, and pkgconf's triplet wrapper does the same for .pc files.
set(CMAKE_LIBRARY_ARCHITECTURE ${CROSS_TARGET})
set(PKG_CONFIG_EXECUTABLE ${CROSS_TARGET}-pkg-config)
