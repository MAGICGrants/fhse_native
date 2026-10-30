# fhse_native

The native half of [wallet-core](https://github.com/MAGICGrants/wallet-core)'s
`wallet_fhse`: vtnerd's FHSE (FIDO2 hmac-secret encryption) with libcbor and
libsodium, built as a Flutter FFI plugin for Android, iOS, macOS, Linux and
Windows behind the small C interface in `src/wfhse.h`.

It has no Dart API beyond `openFhseNative()` (`lib/fhse_native.dart`), which
opens the library for the running platform. `wallet_fhse` binds to the
interface and holds everything else: the Dart API, the security-key channels
and the screens. It depends on this package by commit:

```yaml
fhse_native:
  git:
    url: https://github.com/MAGICGrants/fhse_native
    ref: <full commit SHA>
```

## Layout

- `src/vendor/`: third-party sources, copied unmodified except as noted. GitHub
  collapses them in diffs (`.gitattributes`).
  - FHSE, from [MAGICGrants/fhse](https://github.com/MAGICGrants/fhse) (a fork
    of vtnerd/fhse) at `8364cf5`: vtnerd's `35b32c6` plus fixes (32-byte KDF
    input, atomic open, PIN handling and a credProtect check in `device.c` that
    reads the key's own answer from its authenticator data, CBOR counts and the
    key length bounded before anything is allocated), and then a change that
    reports a failed lock as `fhse_mlock_failure` rather than
    `fhse_bad_alloc`, in the AEAD, CBOR and libfido2 paths. `src/`, `include/` and
    `LICENSE` only, without its CMake files. `device.c` is not compiled here (no
    `FHSE_LIBFIDO2`); each of wallet_fhse's platform backends checks credProtect
    itself.
  - libcbor 0.13.0, with its two CMake-generated headers written by hand.
  - libsodium 1.0.22 stable, without its assembly and build files.
- `src/wfhse.{h,c}`: the C interface Dart binds to (wallet_fhse, and
  wallet_backup for libsodium's XChaCha20-Poly1305). Only these 21 functions
  are exported. `wfhse.c` also gives FHSE its memory: blocks locked once and
  kept locked, rather than FHSE's default of locking each secret on its own,
  which needs more pages than Android lets an app lock on 16 KB-page phones.
- `test/locked_memory_test.c`: tests those blocks and FHSE's flows on them.
- `src/CMakeLists.txt`: the Android, Linux and Windows builds, and host
  builds. The defines follow libsodium's own `build.zig`.
- `ios/` and `macos/`: the CocoaPods builds of the same sources, through
  forwarding files that `tool/generate_ios_classes.sh` generates for both.
  Re-run that script after changing anything under `src/`.
- `linux/` and `windows/`: the FFI plugin builds of `src/` (MSVC on
  Windows; `src/CMakeLists.txt` has its settings).
- `android/`: the Android Gradle Plugin builds `src/` with the NDK the app
  pins.

## Building for the host

```sh
cmake -S src -B build/host -DCMAKE_BUILD_TYPE=Release
cmake --build build/host -j8
```

This gives `build/host/libfhse_native.{dylib,so}`. wallet_fhse's tests build and
load the same thing from its pub cache copy of this package
(`tool/build_host_library.dart` there).

The test of the locked blocks builds with the same CMake project:

```sh
cmake -S src -B build/test -DWFHSE_BUILD_TESTS=ON
cmake --build build/test -j8 && build/test/wfhse_test
```

## Changing the vendored sources

Replace the directory under `src/vendor/` with the new upstream release, apply
the exceptions listed above, run `tool/generate_ios_classes.sh`, and update the
version above. Then bump the commit wallet_fhse pins.

## Reproducible builds

F-Droid rebuilds the apps' Android library from these sources and compares it
with the release. Nothing here embeds a build time, and the build reads nothing
from the network. The library builds with the NDK the app pins
(`android/build.gradle`), and its debug info names the source, build and NDK
directories relatively (`src/CMakeLists.txt`), so the build ID the linker
hashes from it is the same wherever those are.

`tool/check_reproducible.sh <ndk-dir>` checks this, and CI runs it: it builds
each ABI the apps ship twice, the second time from other directories, through
symlinks, with another CMake if `CMAKE_B` names one, and in another time zone
and locale, and fails unless the two libraries are identical and name no
absolute path. It prints the hash of each stripped library, the file that goes
into the APK, for comparing builds on different machines. Those must run the
same operating system: the NDK's startup objects for Linux and for macOS name
different builds of its compiler, so the two libraries differ in that note
(`.comment`) and in the build ID hashed from it, though not in code or data.
Release and F-Droid builds both run on Linux.
