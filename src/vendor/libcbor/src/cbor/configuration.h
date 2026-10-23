// Hand-written stand-in for the header libcbor's CMake generates from
// configuration.h.in, with the defaults of libcbor 0.13.0's CMakeLists.txt.
// The pretty printer is off: FHSE never calls it, and it pulls in stdio.
#ifndef LIBCBOR_CONFIGURATION_H
#define LIBCBOR_CONFIGURATION_H

#define CBOR_MAJOR_VERSION 0
#define CBOR_MINOR_VERSION 13
#define CBOR_PATCH_VERSION 0

#define CBOR_BUFFER_GROWTH 2
#define CBOR_MAX_STACK_SIZE 2048
#define CBOR_PRETTY_PRINTER 0

// MSVC spells C99's restrict its own way (Windows builds).
#if defined(_MSC_VER)
#define CBOR_RESTRICT_SPECIFIER __restrict
#else
#define CBOR_RESTRICT_SPECIFIER restrict
#endif
#define CBOR_INLINE_SPECIFIER

#endif //LIBCBOR_CONFIGURATION_H
