// Copyright (c) 2026, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef FHSE_MEMORY_H
#define FHSE_MEMORY_H

#include <stddef.h>
#ifdef __cplusplus
  extern "C" {
#endif

/*!
  Customize backend memory functions used by fhse. `mlock` and `munlock` must
  both be set: without them every buffer for secret data is refused
  (`fhse_bad_argument`), and if `mlock` fails, the library errors out.

  \note `realloc` and `free` only modify how fhse allocates memory; libfido2
    and libcbor use standard `malloc` and `free` that are difficult to replace.
    fhse uses the streaming interface for libcbor output, and thus only the user
    supplied `realloc` is used, but decoding/opening cbor requires system
    allocators. The primary use for the user supplied allocators is the
    potential to support `epee::byte_slice` in Monero related libs.

    This also unfortunately means `fido_userid`, `fido_salt`, and encrypted
    blobs of each FIDO2 key - which are all semi-sensitive - exist in libcbor
    memory while unpacking. Fixing this requires a custom parser or custom DOM
    objects. */
typedef struct fhse_memory_t
{
  void* context;
  void* (*realloc)(void* ptr, size_t size, void* context);
  void (*free)(void* ptr, void* context);
  int (*mlock)(void* ptr, size_t length, void* context);
  int (*munlock)(void* ptr, size_t length, void* context);
  void (*memzero)(void* ptr, size_t length, void* context);
} fhse_memory_t;

void fhse_memory_defaults(struct fhse_memory_t* memory);

#ifdef __cplusplus
  }
#endif
#endif
