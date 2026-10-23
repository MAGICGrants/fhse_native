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

#include "private/bytes.h"

#include <cbor/bytestrings.h>
#include <cbor/common.h>
#include <cbor/encoding.h>
#include <cbor/strings.h>
#include <string.h>
#include "fhse.h"
#include "private/cbor.h"
#include "private/utils.h"

int fhse_bytes_unpack(fhse_bytes_t* self, cbor_item_t* src, fhse_memory_t const* memory)
{
  cbor_mutable_data ptr = NULL;
  size_t length = 0;
  switch (cbor_typeof(src))
  {
  case CBOR_TYPE_BYTESTRING:
    ptr = cbor_bytestring_handle(src);
    length = cbor_bytestring_length(src);
    break;
  case CBOR_TYPE_STRING:
    ptr = cbor_string_handle(src);
    length = cbor_string_length(src);
    break;
  default:
    return fhse_cbor_failure;
  };

  if (ptr && length)
  {
    FHSE_TRY(fhse_bytes_realloc(self, length, memory));
    memcpy(self->data, ptr, length);
  }
  else
    fhse_bytes_free(self, memory);
  return fhse_success;
}

int fhse_bytes_pack_bytes(fhse_bytes_t* self, fhse_cbor_t* out, fhse_memory_t const* memory)
{
  if (!self || !out)
    return fhse_bad_argument;

  int rc = fhse_success;
  FHSE_CBOR_WRITE(cbor_encode_bytestring_start(self->length, out->write_ptr, out->remaining));
  if (rc != fhse_success)
    return rc;

  if (!self->length)
    return fhse_success;

  if (out->remaining < self->length && fhse_cbor_increase_capacity(out, self->length, memory) != fhse_success)
    return fhse_bad_alloc;

  memmove(out->write_ptr, self->data, self->length);
  if (!fhse_cbor_increment(out, self->length, memory))
    return fhse_bad_alloc;
  return fhse_success;
}

int fhse_bytes_pack_string(fhse_bytes_t* self, fhse_cbor_t* out, fhse_memory_t const* memory)
{
  if (!self || !out)
    return fhse_bad_argument;

  int rc = fhse_success;
  FHSE_CBOR_WRITE(cbor_encode_string_start(self->length, out->write_ptr, out->remaining));
  if (rc != fhse_success)
    return rc;

  if (!self->length)
    return fhse_success;

  if (out->remaining < self->length && fhse_cbor_increase_capacity(out, self->length, memory) != fhse_success)
    return fhse_bad_alloc;

  memmove(out->write_ptr, self->data, self->length);
  if (!fhse_cbor_increment(out, self->length, memory))
    return fhse_bad_alloc;
  return fhse_success;
}

