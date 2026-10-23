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

#include "fhse/sbytes.h"

#include <assert.h>
#include <string.h>
#include "fhse/bytes.h"
#include "private/utils.h"

static int fhse_sbytes_lock(fhse_bytes_t self, fhse_memory_t const* memory)
{
  assert(memory);
  if (memory && memory->mlock && memory->munlock && self.data)
    return memory->mlock(self.data, self.length, memory->context);
  return fhse_success;
}

static int fhse_sbytes_unlock(fhse_sbytes_t self, fhse_memory_t const* memory)
{
  assert(memory);
  if (!memory)
    return fhse_bad_argument;
  if (memory->memzero) // wipe before unlocking data
    memory->memzero(self.data, self.length, memory->context);
  if (memory->munlock)
    return memory->munlock(self.data, self.length, memory->context);
  return fhse_bad_argument;
}

int fhse_sbytes_realloc(fhse_sbytes_t* self, size_t length, fhse_memory_t const* memory)
{
  if (!self || !memory || !memory->realloc || !memory->mlock || !memory->munlock)
    return fhse_bad_argument;
  if (self->length == length)
    return fhse_success;

  fhse_bytes_t temp = {0};
  FHSE_TRY(fhse_bytes_realloc(&temp, length, memory));

  int rc = fhse_sbytes_lock(temp, memory);
  if (rc != fhse_success)
  {
    fhse_bytes_free(&temp, memory);
    return rc;
  }

  memcpy(temp.data, self->data, temp.length < self->length ? temp.length : self->length);
  fhse_sbytes_unlock(*self, memory);
  fhse_sbytes_free(self, memory);
  self->data = temp.data;
  self->length = temp.length;
  return fhse_success;
}

int fhse_sbytes_free(fhse_sbytes_t* self, fhse_memory_t const* memory)
{
  if (!self || !memory || !memory->free)
    return fhse_bad_argument;

  int rc = fhse_success;
  if (self->data)
  {
    rc = fhse_sbytes_unlock(*self, memory);
    if (memory->memzero)
      memory->memzero(self->data, self->length, memory->context);
    memory->free(self->data, memory->context);
  }

  memset(self, 0, sizeof(fhse_sbytes_t));
  return rc;
}

int fhse_sbytes_copy(fhse_sbytes_t* out, fhse_sbytes_t in, fhse_memory_t const* memory)
{
  if (out && out->data == in.data)
    return fhse_success;

  const int rc = fhse_sbytes_realloc(out, in.length, memory);
  if (rc == fhse_success)
    memmove(out->data, in.data, in.length);
  return rc;
}

int fhse_sbytes_move(fhse_sbytes_t* out, fhse_sbytes_t* src, fhse_memory_t const* memory)
{
  if (!out || !src)
    return fhse_bad_argument;
  if (out == src)
    return fhse_success;
  fhse_sbytes_free(out, memory);
  *out = *src;
  memset(src, 0, sizeof(fhse_sbytes_t));
  return fhse_success;
}

fhse_view_t fhse_sbytes_to_view(fhse_sbytes_t src)
{
  fhse_view_t out = {
    .data = src.data,
    .length = src.length
  };
  return out;
}

fhse_cview_t fhse_sbytes_to_cview(fhse_sbytes_t src)
{
  fhse_cview_t out = {
    .data = src.data,
    .length = src.length
  };
  return out;
}
