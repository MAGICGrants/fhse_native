// Hand-written stand-in for the header CMake's GenerateExportHeader writes for
// libcbor. libcbor is linked statically into fhse_ffi and none of its symbols
// are part of that library's interface, so nothing is exported.
#ifndef CBOR_EXPORT_H
#define CBOR_EXPORT_H

#define CBOR_EXPORT
#define CBOR_NO_EXPORT
#if defined(_MSC_VER)
#define CBOR_DEPRECATED __declspec(deprecated)
#else
#define CBOR_DEPRECATED __attribute__((__deprecated__))
#endif
#define CBOR_DEPRECATED_EXPORT CBOR_DEPRECATED
#define CBOR_DEPRECATED_NO_EXPORT CBOR_DEPRECATED

#endif // CBOR_EXPORT_H
