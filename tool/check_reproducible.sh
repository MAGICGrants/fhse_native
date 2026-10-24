#!/bin/sh
# Checks that the Android library is reproducible: builds it twice for each ABI
# the apps ship, with the flags the Android Gradle Plugin passes for a release
# build, and fails unless both builds are byte-identical, before and after
# stripping, and free of absolute paths.
#
# The second build differs from the first in everything a rebuild elsewhere
# might: the source and build directories (and reached through a symlink), the
# NDK's path (a symlink to it), CMake ($CMAKE_B, if given), the time, time zone,
# locale, umask, SOURCE_DATE_EPOCH and the number of parallel jobs.
#
# Usage: tool/check_reproducible.sh <ndk-dir> [abi...]
#   <ndk-dir>  the NDK the apps pin (their android/app/build.gradle ndkVersion)
#   [abi...]   default: armeabi-v7a arm64-v8a x86_64
# Environment: CMAKE (default: cmake), CMAKE_B (default: $CMAKE). Both need
# Ninja on PATH, as AGP's builds use it.
#
# Prints each ABI's stripped sha256, the library as it goes into the APK, so
# builds on other machines can be compared with it.
set -eu
ndk=$(cd "${1:?usage: tool/check_reproducible.sh <ndk-dir> [abi...]}" && pwd)
shift
[ $# -gt 0 ] || set -- armeabi-v7a arm64-v8a x86_64
cmake_a=${CMAKE:-cmake}
cmake_b=${CMAKE_B:-$cmake_a}
strip=$(ls "$ndk"/toolchains/llvm/prebuilt/*/bin/llvm-strip | head -n 1)
src=$(cd "$(dirname "$0")/../src" && pwd)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/a" "$work/elsewhere/deeper/b"
cp -R "$src" "$work/a/src"
cp -R "$src" "$work/elsewhere/deeper/b/src"
ln -s "$work/elsewhere/deeper/b" "$work/b"
ln -s "$ndk" "$work/ndk"

# build <cmake> <dir> <ndk> <jobs>: configures, builds and strips the library
# as AGP does.
build() {
  "$1" -S "$2/src" -B "$2/build" -G Ninja \
    -DCMAKE_SYSTEM_NAME=Android \
    -DCMAKE_SYSTEM_VERSION=21 \
    -DANDROID_PLATFORM=android-21 \
    -DANDROID_ABI="$abi" \
    -DCMAKE_ANDROID_ARCH_ABI="$abi" \
    -DANDROID_NDK="$3" \
    -DCMAKE_ANDROID_NDK="$3" \
    -DCMAKE_TOOLCHAIN_FILE="$3/build/cmake/android.toolchain.cmake" \
    -DCMAKE_LIBRARY_OUTPUT_DIRECTORY="$2/out" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON > "$2/configure.log" 2>&1 ||
    { cat "$2/configure.log" >&2; return 1; }
  "$1" --build "$2/build" -j "$4" > "$2/build.log" 2>&1 ||
    { cat "$2/build.log" >&2; return 1; }
  "$strip" --strip-unneeded -o "$2/stripped.so" "$2/out/libfhse_native.so"
}

status=0
for abi in "$@"; do
  rm -rf "$work/a/build" "$work/a/out" "$work/b/build" "$work/b/out"
  build "$cmake_a" "$work/a" "$ndk" 1
  (
    umask 077
    export TZ=Pacific/Kiritimati LC_ALL=C LANG=C SOURCE_DATE_EPOCH=1
    build "$cmake_b" "$work/b" "$work/ndk" 8
  )
  for file in out/libfhse_native.so stripped.so; do
    if ! cmp -s "$work/a/$file" "$work/b/$file"; then
      echo "$abi: $file differs between the two builds" >&2
      status=1
    fi
  done
  # Neither build's directories nor the NDK may be named in the library, by
  # either path.
  for dir in "$work" "$(cd "$work" && pwd -P)" "$ndk" "$(cd "$ndk" && pwd -P)" "$src"; do
    if grep -q -F "$dir" "$work/a/out/libfhse_native.so" "$work/b/out/libfhse_native.so"; then
      echo "$abi: the library names $dir" >&2
      status=1
    fi
  done
  hash=$(shasum -a 256 "$work/a/stripped.so" 2>/dev/null || sha256sum "$work/a/stripped.so")
  echo "$abi ${hash%% *}"
done
exit $status
