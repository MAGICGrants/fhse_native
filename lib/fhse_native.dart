import 'dart:ffi';
import 'dart:io';

/// Opens the library this package builds for the running platform: a shared
/// object on Android and Linux, a DLL on Windows, and on iOS and macOS a
/// framework CocoaPods links into the app (the apps' Podfiles use
/// `use_frameworks!`). The interface is src/wfhse.h; wallet_fhse binds to it.
DynamicLibrary openFhseNative() {
  if (Platform.isAndroid || Platform.isLinux) return DynamicLibrary.open('libfhse_native.so');
  if (Platform.isIOS || Platform.isMacOS) {
    return DynamicLibrary.open('fhse_native.framework/fhse_native');
  }
  if (Platform.isWindows) return DynamicLibrary.open('fhse_native.dll');
  throw UnsupportedError('fhse_native is not built for ${Platform.operatingSystem}');
}
