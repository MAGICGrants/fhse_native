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

#include "fhse/bytes.h"

#include <string.h>

int fhse_bytes_realloc(fhse_bytes_t* self, size_t length, fhse_memory_t const* memory)
{
  if (!self || !memory || !memory->realloc || !memory->free)
    return fhse_bad_argument;
  if (self->length == length)
    return fhse_success;

  self->data = memory->realloc(self->data, length, memory->context);
  if (!self->data)
  {
    self->length = 0;
    return fhse_bad_alloc;
  }

  self->length = length;
  return fhse_success;
}

int fhse_bytes_free(fhse_bytes_t* self, fhse_memory_t const* memory)
{
  if (!self || !memory || !memory->free)
    return fhse_bad_argument;
  if (self->data)
    memory->free(self->data, memory->context);

  memset(self, 0, sizeof(fhse_bytes_t));
  return fhse_success;
}

int fhse_bytes_copy(fhse_bytes_t* out, fhse_bytes_t src, fhse_memory_t const* memory)
{
  if (out && out->data == src.data)
    return fhse_success;

  const int rc = fhse_bytes_realloc(out, src.length, memory);
  if (rc == fhse_success)
    memcpy(out->data, src.data, src.length);
  return rc;
}

int fhse_bytes_move(fhse_bytes_t* out, fhse_bytes_t* src, fhse_memory_t const* memory)
{
  if (!out || !src)
    return fhse_bad_argument;
  if (out == src)
    return fhse_success;
  fhse_bytes_free(out, memory);
  *out = *src;
  memset(src, 0, sizeof(fhse_bytes_t));
  return fhse_success;
}

int fhse_bytes_from_string(fhse_bytes_t* self, const char* in, fhse_memory_t const* memory)
{
  if (!self || !in)
    return fhse_bad_argument;
  size_t length = strlen(in);
  if (fhse_bytes_realloc(self, length, memory) != fhse_success)
    return fhse_bad_alloc;
  memcpy(self->data, in, length);
  return fhse_success;
}

int fhse_bytes_compare_string(fhse_bytes_t left, const char* right)
{
  if (!right)
    return -1;
  size_t length = strlen(right);
  if (length != left.length)
    return -1;
  return memcmp(left.data, right, length);
}

fhse_view_t fhse_bytes_to_view(fhse_bytes_t src)
{
  fhse_view_t out = {
    .data = src.data,
    .length = src.length
  };
  return out;
}

fhse_cview_t fhse_bytes_to_cview(fhse_bytes_t src)
{
  fhse_cview_t out = {
    .data = src.data,
    .length = src.length
  };
  return out;
}

