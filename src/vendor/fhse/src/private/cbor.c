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

#include "private/cbor.h"

#include <cbor.h>
#include <cbor/callbacks.h>
#include <cbor/encoding.h>
#include <cbor/ints.h>
#include <cbor/streaming.h>
#include <stdint.h>
#include <string.h>
#include "fhse/sbytes.h"
#include "private/config.h"
#include "private/utils.h"

int fhse_cbor_increase_capacity(fhse_cbor_t* self, size_t more, fhse_memory_t const* memory)
{
  if (!self)
    return fhse_bad_argument;
  if (SIZE_MAX - more < self->payload.length)
    return fhse_bad_alloc;
  if (self->payload.length < SIZE_MAX / 2 && more < self->payload.length)
    more = self->payload.length;

  size_t offset = self->write_ptr - self->payload.data;
  FHSE_TRY(fhse_sbytes_realloc(&self->payload, self->payload.length + more, memory));
  self->write_ptr = self->payload.data + offset;
  self->remaining += more;
  return fhse_success;
}

size_t fhse_cbor_increment(fhse_cbor_t* self, size_t more, fhse_memory_t const* memory)
{
  if (!self || SIZE_MAX - more < self->remaining)
    return 0;
  if (!more)
  {
    size_t next_length = self->payload.length ?
      self->payload.length : FHSE_CBOR_BUFFER_DEFAULT;
    self->error = fhse_cbor_increase_capacity(self, next_length, memory);
    return 0;
  }
  self->write_ptr += more;
  self->remaining -= more;
  return more;
}

int fhse_cbor_field(fhse_cbor_t* self, const char* name, fhse_memory_t const* memory)
{
  if (!self || !name)
    return fhse_bad_argument;

  int rc = fhse_success;
  size_t length = strlen(name);
  FHSE_CBOR_WRITE_(rc, self, memory, cbor_encode_string_start(length, self->write_ptr, self->remaining));
  if (rc != fhse_success)
    return rc;

  if (length && self->remaining < length)
    FHSE_TRY(fhse_cbor_increase_capacity(self, length, memory));

  memmove(self->write_ptr, name, length);
  fhse_cbor_increment(self, length, memory);
  return fhse_success;
}

struct fhse_cbor_bound
{
  size_t remaining;
  size_t declared; // elements declared so far, by every definite container
  size_t length;
  bool fits;
};

// Every element of every container is its own item and starts on its own
// byte, so the elements all containers declare cannot outnumber the bytes.
static void fhse_cbor_bound_array(void* context, uint64_t count)
{
  struct fhse_cbor_bound* bound = context;
  if (bound->remaining < count || bound->length - bound->declared < count)
    bound->fits = false;
  else
    bound->declared += count;
}

static void fhse_cbor_bound_map(void* context, uint64_t count)
{
  struct fhse_cbor_bound* bound = context;
  if (bound->remaining / 2 < count || (bound->length - bound->declared) / 2 < count)
    bound->fits = false;
  else
    bound->declared += 2 * count;
}

cbor_item_t* fhse_cbor_load(fhse_cview_t source, struct cbor_load_result* result)
{
  if (!result)
    return NULL;
  memset(result, 0, sizeof(*result));
  if (!source.data)
  {
    result->error.code = CBOR_ERR_NODATA;
    return NULL;
  }

  // libcbor allocates a definite array or map for its declared count before
  // it reads any element, so a few bytes can ask for gigabytes. Every element
  // takes at least a byte: walk the item headers first, and refuse a count
  // larger than the bytes left.
  struct cbor_callbacks callbacks = cbor_empty_callbacks;
  callbacks.array_start = fhse_cbor_bound_array;
  callbacks.map_start = fhse_cbor_bound_map;

  struct fhse_cbor_bound bound = {0, 0, source.length, true};
  size_t offset = 0;
  while (offset < source.length && bound.fits)
  {
    bound.remaining = source.length - offset;
    struct cbor_decoder_result decoded =
      cbor_stream_decode(source.data + offset, source.length - offset, &callbacks, &bound);
    if (decoded.status != CBOR_DECODER_FINISHED || !decoded.read)
      bound.fits = false;
    else
      offset += decoded.read;
  }
  if (!bound.fits)
  {
    result->error.code = CBOR_ERR_MALFORMATED;
    result->error.position = offset;
    return NULL;
  }

  return cbor_load(source.data, source.length, result);
}

int fhse_cbor_authdata_cred_protect(fhse_cview_t authdata, uint64_t* level)
{
  if (!authdata.data || !level)
    return fhse_bad_argument;
  *level = 0;

  // rpIdHash (32 bytes), flags (1), signCount (4); then, with flag AT, the
  // attested credential: AAGUID (16), credential id length (2, big endian),
  // credential id, and its public key as one CBOR item; then, with flag ED,
  // the extensions as a CBOR map.
  static const size_t header = 37;
  static const unsigned char attested = 0x40;
  static const unsigned char extensions = 0x80;
  if (authdata.length < header)
    return fhse_cbor_failure;

  const unsigned char flags = authdata.data[32];
  size_t offset = header;
  struct cbor_load_result result;
  if (flags & attested)
  {
    if (authdata.length - offset < 18)
      return fhse_cbor_failure;
    const size_t id_length =
      ((size_t)authdata.data[offset + 16] << 8) | authdata.data[offset + 17];
    offset += 18;
    if (authdata.length - offset < id_length)
      return fhse_cbor_failure;
    offset += id_length;

    const fhse_cview_t rest = {authdata.data + offset, authdata.length - offset};
    cbor_item_t* key = fhse_cbor_load(rest, &result);
    if (!key)
      return fhse_cbor_failure;
    cbor_decref(&key);
    offset += result.read;
  }
  if (!(flags & extensions))
    return fhse_success;

  const fhse_cview_t rest = {authdata.data + offset, authdata.length - offset};
  cbor_item_t* map = fhse_cbor_load(rest, &result);
  if (!map)
    return fhse_cbor_failure;

  int rc = cbor_isa_map(map) ? fhse_success : fhse_cbor_failure;
  static const char name[] = "credProtect";
  struct cbor_pair const* const pairs = rc == fhse_success ? cbor_map_handle(map) : NULL;
  for (size_t i = 0; pairs && i < cbor_map_size(map) && rc == fhse_success; ++i)
  {
    cbor_item_t* const key = pairs[i].key;
    if (!cbor_isa_string(key) || !cbor_string_is_definite(key) ||
        cbor_string_length(key) != sizeof(name) - 1 ||
        memcmp(cbor_string_handle(key), name, sizeof(name) - 1) != 0)
      continue;
    if (cbor_isa_uint(pairs[i].value))
      *level = cbor_get_int(pairs[i].value);
    else
      rc = fhse_cbor_failure;
  }

  cbor_decref(&map);
  return rc;
}

int fhse_size_unpack(size_t* self, cbor_item_t* src, fhse_memory_t const* memory)
{
  if (!self || !src)
    return fhse_bad_argument;
  if (cbor_typeof(src) != CBOR_TYPE_UINT)
    return fhse_cbor_failure;

  uint64_t value = cbor_get_int(src);
  if (SIZE_MAX < value)
    return fhse_cbor_failure;

  *self = value;
  return fhse_success;
}

