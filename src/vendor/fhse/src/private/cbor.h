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

#ifndef FHSE_CBOR_UTILS_H
#define FHSE_CBOR_UTILS_H

#include <cbor/data.h>
#include <cbor/maps.h>
#include <cbor/strings.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "private/cbor_fwd.h"
#include "private/config.h"
#include "fhse/memory.h"
#include "fhse/sbytes.h"

#define FHSE_CBOR_MAP_START_(rc, parent, min, max)                       \
  do                                                                     \
  {                                                                      \
    if (cbor_typeof(parent) != CBOR_TYPE_MAP)                            \
    {                                                                    \
      rc = fhse_cbor_failure;                                            \
      break;                                                             \
    }                                                                    \
                                                                         \
    struct cbor_pair* current = cbor_map_handle(parent);                 \
    struct cbor_pair const* const end = current + cbor_map_size(parent); \
    if (end - current < min || max < end - current)                      \
    {                                                                    \
      rc = fhse_cbor_failure;                                            \
      break;                                                             \
    }                                                                    \
    bool matched[max] = {0};                                             \
    for ( ; current != end && rc == fhse_success; ++current)             \
    {                                                                    \
      if (cbor_typeof(current->key) != CBOR_TYPE_STRING)                 \
      {                                                                  \
        rc = fhse_cbor_failure;                                          \
        break;                                                           \
      }                                                                  \
                                                                         \
      size_t key_id = -1;                                                \
      size_t key_length = cbor_string_length(current->key);              \
      cbor_mutable_data key_name = cbor_string_handle(current->key);     \
      for (unsigned i = 0; i < 1; ++i)
 
 
#define FHSE_CBOR_MAP_START(min, max) \
  FHSE_CBOR_MAP_START_(rc, parent, min, max)

#define FHSE_CBOR_MAP_END_(rc)                                        \
  }                                                                   \
  if (rc == fhse_success)                                             \
    for (size_t i = 0; i < sizeof(matched) / sizeof(matched[0]); ++i) \
      if (!matched[i])                                                \
        rc = fhse_cbor_failure;                                       \
  } while(0);

#define FHSE_CBOR_MAP_END() \
  FHSE_CBOR_MAP_END_(rc)

#define FHSE_CBOR_UNPACK_(rc, key, val, unpacker, memory) \
  ++key_id;                                               \
  if (rc == fhse_success && key_name && key_length == strlen(#key) && memcmp(key_name, #key, key_length) == 0) \
  {                                                       \
    if (matched[key_id])                                  \
      rc = fhse_cbor_failure;                             \
    else                                                  \
      rc = unpacker(val, current->value, memory) ;        \
    matched[key_id] = true;                               \
  }

#define FHSE_CBOR_UNPACK(key, unpacker) \
  FHSE_CBOR_UNPACK_(rc, key, &self->key, unpacker, memory)


#define FHSE_CBOR_WRITE_(rc, out, memory, ...)           \
  do                                                     \
  {                                                      \
    if (rc != fhse_success)                              \
      break;                                             \
    size_t try = 0;                                      \
    for (; try < 3; ++try)                               \
      if (fhse_cbor_increment(out, __VA_ARGS__, memory)) \
        break;                                           \
    if (try == 3)                                        \
      rc = fhse_bad_alloc;                               \
  } while (0)

#define FHSE_CBOR_WRITE(...) \
  FHSE_CBOR_WRITE_(rc, out, memory, __VA_ARGS__)


struct fhse_cbor_t
{
  fhse_sbytes_t payload;
  uint8_t* write_ptr;
  size_t remaining;
};

int fhse_cbor_increase_capacity(fhse_cbor_t* self, size_t more, fhse_memory_t const* memory);
size_t fhse_cbor_increment(fhse_cbor_t* self, size_t more, fhse_memory_t const* memory);
int fhse_cbor_field(fhse_cbor_t* self, const char* name, fhse_memory_t const* memory);

int fhse_size_unpack(size_t* self, cbor_item_t* src, fhse_memory_t const*);

//! `cbor_load`, after refusing any definite array or map that declares more
//! elements than there are bytes left.
cbor_item_t* fhse_cbor_load(fhse_cview_t source, struct cbor_load_result* result);

//! The credProtect level in WebAuthn authenticator data, as the authenticator
//! reports it: 0 when the data has no credProtect extension.
int fhse_cbor_authdata_cred_protect(fhse_cview_t authdata, uint64_t* level);


#endif // FHSE_CBOR_UTILS_H
