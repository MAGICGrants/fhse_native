# Builds libfhse_native: FHSE, libcbor and libsodium from the vendored sources,
# behind the small interface in wfhse.h.
#
# Used by the Android plugin (android/build.gradle), the Linux and Windows
# plugins (linux/ and windows/CMakeLists.txt) and for host builds that
# wallet-core's wallet_fhse tests load (its tool/build_host_library.dart). iOS
# and macOS compile the same sources through CocoaPods instead; see ios/ and
# macos/fhse_native.podspec, which repeat the Apple definitions below (iOS minus
# the two its SDK lacks) and must be kept in step with them. The Apple branch
# here serves the host builds.

cmake_minimum_required(VERSION 3.10)
project(fhse_native LANGUAGES C)

set(VENDOR "${CMAKE_CURRENT_SOURCE_DIR}/vendor")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)

if(NOT MSVC)
  # Reproducible builds: debug info records where the sources, the build
  # directory and the NDK's toolchain are, and the build ID the linker hashes
  # from it stays in the stripped library. Recorded by relative names instead,
  # the library is the same wherever it is built. Each directory is mapped by
  # the path CMake has for it and by its real path: when a symlink leads there
  # (a symlinked pub cache, macOS's /tmp), the compiler records its working
  # directory, the build directory, by the latter. The last matching map wins,
  # so a build directory inside src/ still maps to build.
  function(wfhse_map_prefix dir name)
    get_filename_component(real "${dir}" REALPATH)
    add_compile_options("-ffile-prefix-map=${dir}=${name}")
    if(NOT real STREQUAL dir)
      add_compile_options("-ffile-prefix-map=${real}=${name}")
    endif()
  endfunction()
  wfhse_map_prefix("${CMAKE_CURRENT_SOURCE_DIR}" src)
  wfhse_map_prefix("${CMAKE_BINARY_DIR}" build)
  if(ANDROID)
    wfhse_map_prefix("${ANDROID_TOOLCHAIN_ROOT}" ndk)
  endif()
endif()

if(MSVC)
  # Control Flow Guard: an indirect call may only reach a real function entry
  # point. The library links with it too, below.
  add_compile_options(/guard:cf)
else()
  # Stack variables start zeroed, so a missed initialisation cannot expose
  # key material left on the stack. The iOS and macOS builds get the same
  # from the apps' Podfiles (CLANG_ENABLE_STACK_ZERO_INIT). Compilers without
  # the flag (clang before 16 needs another to accept it) go without.
  include(CheckCCompilerFlag)
  check_c_compiler_flag(-ftrivial-auto-var-init=zero WFHSE_HAVE_ZERO_INIT)
  if(WFHSE_HAVE_ZERO_INIT)
    add_compile_options(-ftrivial-auto-var-init=zero)
  endif()
endif()

if(UNIX AND NOT APPLE AND NOT ANDROID)
  # Linux: the hardening the apps' runners get (their linux/CMakeLists.txt),
  # since Flutter builds this library outside it. Stack canaries, stack clash
  # probes, and hardware control-flow protection (CET on x86-64, BTI and PAC on
  # arm64), each only where the compiler accepts it; checked with -Werror, as a
  # flag the compiler takes but ignores for the target only warns. Then glibc's
  # bounds-checked string and memory functions (FORTIFY), which need an
  # optimised build: not Flutter's Profile, which this library builds without
  # optimisation. Android's NDK turns on canaries and FORTIFY by default.
  set(CMAKE_REQUIRED_FLAGS "-Werror")
  foreach(flag
      -fstack-protector-strong
      -fstack-clash-protection
      -fcf-protection=full
      -mbranch-protection=standard)
    string(MAKE_C_IDENTIFIER "WFHSE_HAVE${flag}" have_flag)
    check_c_compiler_flag(${flag} ${have_flag})
    if(${have_flag})
      add_compile_options(${flag})
    endif()
  endforeach()
  unset(CMAKE_REQUIRED_FLAGS)
  set(WFHSE_OPTIMISED
    "$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>")
  add_compile_options(
    "$<${WFHSE_OPTIMISED}:-U_FORTIFY_SOURCE>"
    "$<${WFHSE_OPTIMISED}:-D_FORTIFY_SOURCE=3>")
endif()

# ----- libsodium -----
#
# Every source file, as libsodium's own build.zig compiles it. The optimised
# variants (SSE, AVX, ARM crypto, x86-64 assembly) are guarded by HAVE_*
# macros that are left undefined here, so they compile to nothing and the
# portable reference code is used; FHSE's hashing is far too small for that
# to matter. The defines are build.zig's Linux and macOS sets; with MSVC
# (Windows) only the few that hold there, and libsodium's own Windows code
# takes over (RtlGenRandom, VirtualLock, __declspec(thread)).

file(GLOB_RECURSE SODIUM_SOURCES CONFIGURE_DEPENDS "${VENDOR}/libsodium/src/libsodium/*.c")
add_library(wfhse_sodium STATIC ${SODIUM_SOURCES})
target_include_directories(wfhse_sodium
  PUBLIC "${VENDOR}/libsodium/src/libsodium/include"
  PRIVATE "${VENDOR}/libsodium/src/libsodium/include/sodium")
target_compile_definitions(wfhse_sodium PUBLIC SODIUM_STATIC=1)
if(MSVC)
  target_compile_definitions(wfhse_sodium PRIVATE
    CONFIGURED=1
    HAVE_INTTYPES_H=1
    HAVE_STDINT_H=1
    NATIVE_LITTLE_ENDIAN=1
    _CRT_SECURE_NO_WARNINGS=1)
  target_compile_options(wfhse_sodium PRIVATE /w)
else()
  target_compile_definitions(wfhse_sodium
    PRIVATE
      CONFIGURED=1
      HAVE_ATOMIC_OPS=1
      HAVE_C11_MEMORY_FENCES=1
      HAVE_GCC_MEMORY_FENCES=1
      HAVE_INTTYPES_H=1
      HAVE_STDINT_H=1
      NATIVE_LITTLE_ENDIAN=1
      TLS=_Thread_local
      HAVE_CLOCK_GETTIME=1
      HAVE_GETPID=1
      HAVE_MADVISE=1
      HAVE_MLOCK=1
      HAVE_MMAP=1
      HAVE_MPROTECT=1
      HAVE_NANOSLEEP=1
      HAVE_POSIX_MEMALIGN=1
      HAVE_PTHREAD=1
      HAVE_RAISE=1
      HAVE_SYSCONF=1
      HAVE_SYS_MMAN_H=1
      HAVE_SYS_PARAM_H=1
      HAVE_SYS_RANDOM_H=1
      HAVE_WEAK_SYMBOLS=1)
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    # 128-bit integers; absent on 32-bit ARM (armeabi-v7a).
    target_compile_definitions(wfhse_sodium PRIVATE HAVE_TI_MODE=1)
  endif()
  if(APPLE)
    # Randomness from arc4random_buf, Apple's kernel-seeded CSPRNG, rather
    # than libsodium's default of opening /dev/urandom (whose fstat is an API
    # the App Store wants a stated reason for).
    target_compile_definitions(wfhse_sodium PRIVATE
      HAVE_ARC4RANDOM=1 HAVE_ARC4RANDOM_BUF=1 HAVE_GETENTROPY=1 HAVE_MEMSET_S=1
      HAVE_SAFE_ARC4RANDOM=1 NONEXISTENT_DEV_RANDOM=1)
  else()
    target_compile_definitions(wfhse_sodium PRIVATE _GNU_SOURCE=1 HAVE_SYS_AUXV_H=1)
  endif()
  target_compile_options(wfhse_sodium PRIVATE
    -fno-strict-aliasing -fno-strict-overflow -fwrapv -w)
endif()

# clang runs out of memory compiling this file (6-7 GB, then killed)
# for 32-bit ABIs at -O2 with debug info.
if(ANDROID AND CMAKE_SIZEOF_VOID_P EQUAL 4)
  set_source_files_properties(
    "${VENDOR}/libsodium/src/libsodium/crypto_core/keccak1600/ref/keccak1600_ref.c"
    PROPERTIES COMPILE_OPTIONS "-g0")
endif()

# ----- libcbor 0.13.0 -----

file(GLOB CBOR_SOURCES CONFIGURE_DEPENDS
  "${VENDOR}/libcbor/src/*.c"
  "${VENDOR}/libcbor/src/cbor/*.c"
  "${VENDOR}/libcbor/src/cbor/internal/*.c")
add_library(wfhse_cbor STATIC ${CBOR_SOURCES})
target_include_directories(wfhse_cbor PUBLIC "${VENDOR}/libcbor/src")
set_target_properties(wfhse_cbor PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
if(MSVC)
  target_compile_options(wfhse_cbor PRIVATE /w)
else()
  target_compile_options(wfhse_cbor PRIVATE -w)
endif()

# ----- FHSE -----

file(GLOB FHSE_SOURCES CONFIGURE_DEPENDS
  "${VENDOR}/fhse/src/public/*.c"
  "${VENDOR}/fhse/src/private/*.c")
add_library(wfhse_fhse STATIC ${FHSE_SOURCES})
target_include_directories(wfhse_fhse
  PUBLIC "${VENDOR}/fhse/include"
  PRIVATE "${VENDOR}/fhse/src")
# libsodium backend; no FHSE_LIBFIDO2: the platform's own FIDO2 stack talks to
# the key and hands FHSE the hmac-secret.
target_compile_definitions(wfhse_fhse PUBLIC FHSE_LIBSODIUM=1)
target_link_libraries(wfhse_fhse PUBLIC wfhse_cbor wfhse_sodium)
set_target_properties(wfhse_fhse PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)

# ----- the library Dart opens -----

add_library(fhse_native SHARED wfhse.c)
target_link_libraries(fhse_native PRIVATE wfhse_fhse)
set_target_properties(fhse_native PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON)
if(ANDROID)
  # 16 KB pages, required for apps targeting Android 15 and later.
  target_link_options(fhse_native PRIVATE "-Wl,-z,max-page-size=16384")
elseif(MSVC)
  target_link_options(fhse_native PRIVATE /guard:cf)
elseif(UNIX AND NOT APPLE)
  # Linux: the GOT read-only after load, and no executable stack.
  target_link_options(fhse_native PRIVATE "-Wl,-z,relro" "-Wl,-z,now" "-Wl,-z,noexecstack")
endif()
