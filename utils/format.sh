#!/usr/bin/env bash

CLANG_FORMAT_DESIRED_VERSION=19

binary=$(command -v clang-format-$CLANG_FORMAT_DESIRED_VERSION 2>/dev/null)
if [ $? -ne 0 ]; then
    binary=$(command -v clang-format-mp-$CLANG_FORMAT_DESIRED_VERSION 2>/dev/null)
fi
if [ $? -ne 0 ]; then
    binary=$(command -v clang-format 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "Please install clang-format version $CLANG_FORMAT_DESIRED_VERSION and re-run this script."
        exit 1
    fi
    version=$(clang-format --version)
    if [[ ! $version == *"clang-format version $CLANG_FORMAT_DESIRED_VERSION"* ]]; then
        echo "Please install clang-format version $CLANG_FORMAT_DESIRED_VERSION and re-run this script."
        exit 1
    fi
fi

cd "$(dirname $0)/../"
readarray -t sources < <(find include proto src tests | grep -E '\.([hc](pp)?)$' | grep -v '\#' | grep -v Catch2 | grep -v -E '\.pb\.(h|cc)$' | grep -v -E 'ip_country/data\.cpp$')
if [ "$1" = "verify" ] ; then
    if [ $($binary --output-replacements-xml "${sources[@]}"  | grep '</replacement>' | wc -l) -ne 0 ] ; then
        exit 2
    fi
else
    $binary -i "${sources[@]}" &> /dev/null
fi
