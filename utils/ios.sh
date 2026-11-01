#!/bin/bash

set -e

if ! [ -f LICENSE ] || ! [ -d include/session ]; then
    echo "You need to run this as ./utils/ios.sh from the top-level libsession-util project directory" >&2
    exit 1
fi

if ! command -v xcodebuild; then
    echo "xcodebuild not found; are you on macOS with Xcode and Xcode command-line tools installed?" >&2
    exit 1
fi

# Import settings from XCode (defaulting values if not present)

VALID_SIM_ARCHS=(arm64 x86_64)
VALID_DEVICE_ARCHS=(arm64)
VALID_SIM_ARCH_PLATFORMS=(SIMULATORARM64 SIMULATOR64)
VALID_DEVICE_ARCH_PLATFORMS=(OS64)

OUTPUT_DIR="${TARGET_BUILD_DIR:-build-ios}"
IPHONEOS_DEPLOYMENT_TARGET=${IPHONEOS_DEPLOYMENT_TARGET:-13}
ENABLE_BITCODE=${ENABLE_BITCODE:-OFF}
CONFIGURATION=${CONFIGURATION:-App_Store_Release}
BUILD_STATIC_LIBS=${2:-true}             # Parameter 2 is a flag indicating whether we want to build the static libraries
MERGE_STATIC_LIBS=${3:-true}             # Parameter 3 is a flag indicating whether we want to merge any static libraries
CREATE_FRAMEWORK=${4:-true}              # Parameter 4 is a flag indicating whether we want to generate the framework
SHOULD_ACHIVE=${5:-true}                 # Parameter 5 is a flag indicating whether we want to archive the result

# We want to customise the env variable so can't just default the value
if [ -z "${TARGET_TEMP_DIR}" ]; then
    BUILD_DIR="./build-ios"
elif [ "${#ARCHS[@]}" = 1 ]; then
    BUILD_DIR="${TARGET_TEMP_DIR}/../libSession-util"
fi

# Can't default an array in the same way as above
if [ -z "${ARCHS}" ]; then
    ARCHS=(arm64 x86_64)
elif [ "${#ARCHS[@]}" = 1 ]; then
    # The env value is probably a string, convert it to an array just in case
    read -ra ARCHS <<< "$ARCHS"
fi

projdir="$PWD"
UNIQUE_NAME=""

if [ $SHOULD_ACHIVE = true ]; then
    UNIQUE_NAME="${1:-libsession-util-ios-TAG}"

    if [[ "$UNIQUE_NAME" =~ TAG ]]; then
        . "$(dirname "$0")/archive-name.sh"
        UNIQUE_NAME="$(archive_name "$UNIQUE_NAME")"
    fi

    OUTPUT_DIR="${OUTPUT_DIR}/${UNIQUE_NAME}"
fi


set -x


# Generate the target architectures we want to build for
TARGET_ARCHS=()
TARGET_PLATFORMS=()
TARGET_SIM_ARCHS=()
TARGET_DEVICE_ARCHS=()

if [ -z $PLATFORM_NAME ] || [ $PLATFORM_NAME = "iphonesimulator" ]; then
    for i in "${!VALID_SIM_ARCHS[@]}"; do
        ARCH="${VALID_SIM_ARCHS[$i]}"
        ARCH_PLATFORM="${VALID_SIM_ARCH_PLATFORMS[$i]}"

        if [[ " ${ARCHS[*]} " =~ " ${ARCH} " ]]; then
            TARGET_ARCHS+=("sim-${ARCH}")
            TARGET_PLATFORMS+=("${ARCH_PLATFORM}")
            TARGET_SIM_ARCHS+=("sim-${ARCH}")
        fi
    done
fi

if [ -z $PLATFORM_NAME ] || [ $PLATFORM_NAME = "iphoneos" ]; then
    for i in "${!VALID_DEVICE_ARCHS[@]}"; do
        ARCH="${VALID_DEVICE_ARCHS[$i]}"
        ARCH_PLATFORM="${VALID_DEVICE_ARCH_PLATFORMS[$i]}"

        if [[ " ${ARCHS[*]} " =~ " ${ARCH} " ]]; then
            TARGET_ARCHS+=("ios-${ARCH}")
            TARGET_PLATFORMS+=("${ARCH_PLATFORM}")
            TARGET_DEVICE_ARCHS+=("ios-${ARCH}")
        fi
    done
fi

# Build the individual architectures
submodule_check=ON
build_type="Release"

# Make the logs look nicer
SHOULD_BUILD_STATIC_LIBS=""
SHOULD_MERGE_STATIC_LIBS=""
SHOULD_CREATE_FRAMEWORK=""
FINAL_SHOULD_ACHIVE=""

if [ $BUILD_STATIC_LIBS = true ]; then
    SHOULD_BUILD_STATIC_LIBS="SHOULD_BUILD_STATIC_LIBS"
fi
if [ $MERGE_STATIC_LIBS = true ]; then
    SHOULD_MERGE_STATIC_LIBS="SHOULD_MERGE_STATIC_LIBS"
fi
if [ $CREATE_FRAMEWORK = true ]; then
    SHOULD_CREATE_FRAMEWORK="SHOULD_CREATE_FRAMEWORK"
fi
if [ $SHOULD_ACHIVE = true ]; then
    FINAL_SHOULD_ACHIVE="SHOULD_ACHIVE"
fi

if [ "$CONFIGURATION" == "Debug" ] || [ "$CONFIGURATION" == "Debug_Compile_LibSession" ]; then
    submodule_check=OFF
    build_type="Debug"
fi

if [ "${SHOULD_BUILD_STATIC_LIBS}" == "SHOULD_BUILD_STATIC_LIBS" ]; then
    for i in "${!TARGET_ARCHS[@]}"; do
        build="${BUILD_DIR}/${TARGET_ARCHS[$i]}"
        platform="${TARGET_PLATFORMS[$i]}"
        echo "Building ${TARGET_ARCHS[$i]} for $platform in $build"

        env -i PATH="$PATH" SDKROOT="$(xcrun --sdk macosx --show-sdk-path)" \
            ./utils/static-bundle.sh "$build" "" \
            -DCMAKE_TOOLCHAIN_FILE="${projdir}/external/ios-cmake/ios.toolchain.cmake" \
            -DPLATFORM=$platform \
            -DDEPLOYMENT_TARGET=$IPHONEOS_DEPLOYMENT_TARGET \
            -DENABLE_BITCODE=$ENABLE_BITCODE \
            -DBUILD_TESTS=OFF \
            -DBUILD_STATIC_DEPS=ON \
            -DENABLE_VISIBILITY=ON \
            -DSROUTER_FULL=OFF \
            -DSROUTER_DAEMON=OFF \
            -DSUBMODULE_CHECK=$submodule_check \
            -DCMAKE_BUILD_TYPE=$build_type \
            -DLOCAL_MIRROR=https://builds.session.codes/deps
    done
fi

# Strip debug info from bundled dependency object files (consumers don't need it
# and it causes dsymutil warnings when the original build machine's paths are unavailable)
for f in ${BUILD_DIR}/{sim,ios}/libsession-util.a; do
    if [ -f "$f" ]; then
        strip -S "$f"
    fi
done

if [ "${SHOULD_MERGE_STATIC_LIBS}" == "SHOULD_MERGE_STATIC_LIBS" ]; then
    # If needed combine simulator builds into a multi-arch lib
    sim_files=( "${BUILD_DIR}/sim-"* )
    if [ "${#TARGET_SIM_ARCHS[@]}" -eq "1" ] && [ -e "${sim_files[0]}" ]; then
        # Single device build
        mkdir -p "${BUILD_DIR}/sim"
        rm -rf "${BUILD_DIR}/sim/libsession-util.a"
        cp "${BUILD_DIR}/${TARGET_SIM_ARCHS[0]}/libsession-util.a" "${BUILD_DIR}/sim/libsession-util.a"
    elif [ "${#TARGET_SIM_ARCHS[@]}" -gt "1" ] && [ -e "${sim_files[0]}" ]; then
        # Combine multiple device builds into a multi-arch lib
        mkdir -p "${BUILD_DIR}/sim"
        lipo -create "${BUILD_DIR}"/sim-*/libsession-util.a -output "${BUILD_DIR}/sim/libsession-util.a"
    else
        echo "No sim build static libs found"
    fi

    # If needed combine device builds into a multi-arch lib
    ios_files=( "${BUILD_DIR}/ios-"* )
    if [ "${#TARGET_DEVICE_ARCHS[@]}" -eq "1" ] && [ -e "${ios_files[0]}" ]; then
        # Single device build
        mkdir -p "${BUILD_DIR}/ios"
        rm -rf "${BUILD_DIR}/ios/libsession-util.a"
        cp "${BUILD_DIR}/${TARGET_DEVICE_ARCHS[0]}/libsession-util.a" "${BUILD_DIR}/ios/libsession-util.a"
    elif [ "${#TARGET_DEVICE_ARCHS[@]}" -gt "1" ] && [ -e "${ios_files[0]}" ]; then
        # Combine multiple device builds into a multi-arch lib
        mkdir -p "${BUILD_DIR}/ios"
        lipo -create "${BUILD_DIR}"/ios-*/libsession-util.a -output "${BUILD_DIR}/ios/libsession-util.a"
    else
        echo "No ios build static libs found"
    fi
fi

if [ "${SHOULD_CREATE_FRAMEWORK}" == "SHOULD_CREATE_FRAMEWORK" ]; then
    # Create a '.xcframework' so XCode can deal with the different architectures
    rm -rf "${OUTPUT_DIR}/libsession-util.xcframework"
    sim_files=( "${BUILD_DIR}/sim-"* )
    ios_files=( "${BUILD_DIR}/ios-"* )

    if [ "${#TARGET_SIM_ARCHS}" -gt "0" ] && [ -e "${sim_files[0]}" ] && [ "${#TARGET_DEVICE_ARCHS}" -gt "0" ] && [ -e "${ios_files[0]}" ]; then
        xcodebuild -create-xcframework \
            -library "${BUILD_DIR}/ios/libsession-util.a" \
            -headers "include" \
            -library "${BUILD_DIR}/sim/libsession-util.a" \
            -headers "include" \
            -output "${OUTPUT_DIR}/libsession-util.xcframework"
    elif [ "${#TARGET_DEVICE_ARCHS}" -gt "0" ] && [ -e "${ios_files[0]}" ]; then
        xcodebuild -create-xcframework \
            -library "${BUILD_DIR}/ios/libsession-util.a" \
            -headers "include" \
            -output "${OUTPUT_DIR}/libsession-util.xcframework"
    elif [ -e "${sim_files[0]}" ]; then
        xcodebuild -create-xcframework \
            -library "${BUILD_DIR}/sim/libsession-util.a" \
            -headers "include" \
            -output "${OUTPUT_DIR}/libsession-util.xcframework"
    else
        echo "No static libraries to turn into framework"
        exit 1
    fi

    # The 'module.modulemap' is needed for XCode to be able to find the headers
    modmap="${OUTPUT_DIR}/module.modulemap"
    echo "module SessionUtil {" >"$modmap"
    echo "  module capi {" >>"$modmap"
    for x in $(cd include && find session -name '*.h'); do
        echo "    header \"$x\"" >>"$modmap"
    done
    echo -e "    export *\n  }" >>"$modmap"
    echo "}" >>"$modmap"

    # Need to add the module.modulemap into each architecture directory in the xcframework
    for dir in "${OUTPUT_DIR}/libsession-util.xcframework"/*/; do
        cp "${modmap}" "${dir}/Headers/module.modulemap"
    done

    rm -rf "${modmap}"

    if [ $FINAL_SHOULD_ACHIVE = "SHOULD_ACHIVE" ]; then
        (cd "${OUTPUT_DIR}/.." && tar cvJf "${UNIQUE_NAME}.tar.xz" "${UNIQUE_NAME}")
    fi
        
    echo "Packaged everything up at ${OUTPUT_DIR}/libsession-util.xcframework"
else
    # Copy the static libraries to the output
    rm -rf "${OUTPUT_DIR}/libsession-util-sim.a"
    rm -rf "${OUTPUT_DIR}/libsession-util-dev.a"

    if [ -f "${BUILD_DIR}/sim/libsession-util.a" ]; then
        cp "${BUILD_DIR}/sim/libsession-util.a" "${OUTPUT_DIR}/libsession-util-sim.a"
    fi

    if [ -f "${BUILD_DIR}/ios/libsession-util.a" ]; then
        cp "${BUILD_DIR}/ios/libsession-util.a" "${OUTPUT_DIR}/libsession-util-dev.a"
    fi

    echo "Packaged everything up at ${OUTPUT_DIR}/libsession-util-{sim|dev}.a"
fi
