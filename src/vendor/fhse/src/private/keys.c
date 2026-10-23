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

#include "private/keys.h"

#include <cbor/arrays.h>
#include <cbor/encoding.h>
#include "private/bytes.h"
#include "private/cbor.h"
#include "private/config.h"
#include "private/crypto.h"
#include "private/sbytes.h"
#include "private/utils.h"

int fhse_key_unpack(fhse_key_t* self, cbor_item_t* parent, fhse_memory_t const* memory)
{
  if (!self || !parent)
    return fhse_bad_argument;

  int rc = fhse_success;
  FHSE_CBOR_MAP_START(3, 3)
  {
    FHSE_CBOR_UNPACK(kdf_name, fhse_bytes_unpack);
    FHSE_CBOR_UNPACK(fido_cred, fhse_sbytes_unpack);
    FHSE_CBOR_UNPACK(aead, fhse_aead_unpack);
  }
  FHSE_CBOR_MAP_END()

  if (rc != fhse_success)
    fhse_key_free(self, memory);
  return rc; 
}

int fhse_key_pack(fhse_key_t* self, fhse_cbor_t* out, fhse_memory_t const* memory)
{
  if (!self || !out)
    return fhse_bad_argument;

  int rc = fhse_success;
  FHSE_CBOR_WRITE(cbor_encode_map_start(3, out->write_ptr, out->remaining));
  if (rc != fhse_success)
    return rc;

  FHSE_TRY(fhse_cbor_field(out, "aead", memory));
  FHSE_TRY(fhse_aead_pack(&self->aead, out, memory));

  FHSE_TRY(fhse_cbor_field(out, "fido_cred", memory));
  FHSE_TRY(fhse_sbytes_pack(&self->fido_cred, out, memory));

  FHSE_TRY(fhse_cbor_field(out, "kdf_name", memory));
  FHSE_TRY(fhse_bytes_pack_string(&self->kdf_name, out, memory));
 
  return rc;
}

int fhse_key_move(fhse_key_t* self, fhse_key_t* src, fhse_memory_t const* memory)
{
  if (!self || !src)
    return fhse_bad_argument;

  fhse_bytes_move(&self->kdf_name, &src->kdf_name, memory);
  fhse_sbytes_move(&self->fido_cred, &src->fido_cred, memory);
  fhse_aead_move(&self->aead, &src->aead, memory);
  return fhse_success;
}

int fhse_key_free(fhse_key_t* self, fhse_memory_t const* memory)
{
  if (!self || !memory)
    return fhse_bad_argument;
  fhse_bytes_free(&self->kdf_name, memory);
  fhse_sbytes_free(&self->fido_cred, memory);
  fhse_aead_free(&self->aead, memory);
  memset(self, 0, sizeof(fhse_key_t));
  return fhse_success;
}

int fhse_key_try_open(fhse_key_t* self, fhse_sbytes_t* out, fhse_cview_t hmac_secret, fhse_crypto_t const* crypto, fhse_memory_t const* memory)
{
  if (!self || !out || !hmac_secret.data || !crypto || !crypto->kdf || !crypto->aead)
    return fhse_bad_argument;

  int rc = fhse_success;
  fhse_bytes_t domain = {0}; 
  FHSE_CHECK(fhse_bytes_from_string(&domain, FHSE_KEY_DOMAIN, memory));

  fhse_sbytes_t kdf_key = {0};
  FHSE_CHECK(fhse_sbytes_realloc(&kdf_key, self->aead.key_length, memory));

  FHSE_CHECK(crypto->kdf(&self->kdf_name, fhse_sbytes_to_view(kdf_key), hmac_secret, fhse_bytes_to_cview(domain), crypto->context));
  FHSE_CHECK(crypto->aead(out, &self->aead, fhse_sbytes_to_cview(kdf_key), crypto->context));

  fhse_bytes_free(&domain, memory);
  fhse_sbytes_free(&kdf_key, memory);
  return rc;
}

static int fhse_keys_resize(fhse_keys_t* self, size_t count, fhse_memory_t const* memory)
{
  if (!self || !memory || !memory->realloc)
    return fhse_bad_argument;
  if (count == self->count)
    return fhse_success;
  if (SIZE_MAX / sizeof(fhse_key_t) < count)
    return fhse_bad_alloc;

  size_t next_size = sizeof(fhse_key_t) * count;
  fhse_key_t* next = count ? memory->realloc(NULL, next_size, memory->context) : NULL;
  if (!next && count)
    return fhse_bad_alloc;
  memset(next, 0, next_size);

  size_t current_size = sizeof(fhse_key_t) * self->count;
  memcpy(next, self->data, current_size < next_size ? current_size : next_size);
  if (count < self->count)
  {
    fhse_key_t const* const end = self->data + self->count;
    for (fhse_key_t* current = self->data + count; current != end; ++current)
      fhse_key_free(current, memory);
  }

  memory->free(self->data, memory->context);
  self->data = next;
  self->count = count;
  return fhse_success;
}

int fhse_keys_pack(fhse_keys_t* self, fhse_cbor_t* out, fhse_memory_t const* memory)
{
  if (!self || !out)
    return fhse_bad_argument;

  int rc = fhse_success;
  FHSE_CBOR_WRITE(cbor_encode_array_start(self->count, out->write_ptr, out->remaining));
  if (rc != fhse_success)
    return rc;

  fhse_key_t* current = self->data;
  fhse_key_t const* const end = self->data + self->count;
  for ( ; current != end; ++current)
    FHSE_TRY(fhse_key_pack(current, out, memory));

  return fhse_success;
}

int fhse_keys_unpack(fhse_keys_t* self, cbor_item_t* parent, fhse_memory_t const* memory)
{
  if(!self || !parent|| !memory || !memory->realloc)
    return fhse_bad_argument;

  int rc = fhse_success;
  if (cbor_typeof(parent) == CBOR_TYPE_ARRAY)
  {
    size_t count = cbor_array_size(parent);
    rc = fhse_keys_resize(self, count, memory);
    if (rc == fhse_success)
    {
      cbor_item_t** current = cbor_array_handle(parent);
      cbor_item_t* const* const end = current + count; 
      for ( ; current != end; ++current)
        FHSE_CHECK(fhse_key_unpack(self->data + (end - current) - 1, *current, memory));
    }
  }
  else
    rc = fhse_cbor_failure;

  if (rc != fhse_success)
    fhse_keys_free(self, memory);
  return rc; 
}

int fhse_keys_free(fhse_keys_t* self, fhse_memory_t const* memory)
{
  if (!self || !memory || !memory->free)
    return fhse_bad_argument;
  if (self->data)
  {
    for (size_t i = 0; i < self->count; ++i)
      fhse_key_free(&self->data[i], memory);
  }
  memory->free(self->data, memory->context);
  memset(self, 0, sizeof(fhse_keys_t));
  return fhse_success;
}

int fhse_keys_try_open(fhse_keys_t* self, fhse_sbytes_t* out, size_t* index, fhse_cview_t hmac_secret, fhse_crypto_t const* crypto, fhse_memory_t const* memory)
{
  if (!self)
    return fhse_bad_argument;

  fhse_key_t const* const end = self->data + self->count;
  for (fhse_key_t* current = self->data; current != end; ++current)
  {
    int rc = fhse_key_try_open(current, out, hmac_secret, crypto, memory);
    switch (rc)
    {
    case fhse_decryption_failure:
      break;

    case fhse_success:
      if (index)
        *index = current - self->data;
    default:
      return rc;
    }
  }

  return fhse_key_unavailable;
}

int fhse_keys_add(fhse_keys_t* self, fhse_cview_t root_secret, fhse_cview_t fido_cred, fhse_cview_t hmac_secret, fhse_crypto_t const* crypto, fhse_memory_t const* memory)
{
  if (!self || self->count == SIZE_MAX || !root_secret.data)
    return fhse_bad_argument;

  fhse_sbytes_t unused = {0};
  int rc = fhse_keys_try_open(self, &unused, NULL, hmac_secret, crypto, memory);
  fhse_sbytes_free(&unused, memory);
  switch (rc)
  {
    default:
      return rc;
    case fhse_success:
      return fhse_duplicate_key;
    case fhse_key_unavailable:
      break;
  }

  fhse_key_t latest = {0};
  rc = fhse_sbytes_realloc(&latest.aead.payload, root_secret.length, memory);
  FHSE_CHECK(fhse_sbytes_realloc(&latest.fido_cred, fido_cred.length, memory));
  if (rc == fhse_success)
  {
    fhse_sbytes_t encrypted = {0};
    latest.aead.key_length = crypto->aead_key_length;
    memcpy(latest.aead.payload.data, root_secret.data, root_secret.length);
    memcpy(latest.fido_cred.data, fido_cred.data, fido_cred.length);
    rc = fhse_key_try_open(&latest, &encrypted, hmac_secret, crypto, memory);

    FHSE_CHECK(fhse_sbytes_move(&latest.aead.payload, &encrypted, memory));
    FHSE_CHECK(fhse_keys_resize(self, self->count + 1, memory));
    FHSE_CHECK(fhse_key_move(self->data + self->count - 1, &latest, memory)); 
  }
  fhse_key_free(&latest, memory);
  return rc;
}

int fhse_keys_remove(fhse_keys_t* self, size_t index, fhse_memory_t const* memory)
{
  if (!self || self->count <= index)
    return fhse_bad_argument;

  fhse_key_t temp = {0};
  fhse_key_move(&temp, self->data + index, memory);
  fhse_key_move(self->data + index, self->data + self->count - 1, memory);
  fhse_key_move(self->data + self->count - 1, &temp, memory);

  return fhse_keys_resize(self, self->count - 1, memory);
}
