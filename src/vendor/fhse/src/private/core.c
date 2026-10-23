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

#include "private/core.h"

#include <cbor.h>
#include "fhse/memory.h"
#include "private/bytes.h"
#include "private/cbor.h"
#include "private/config.h"
#include "private/crypto.h"
#include "private/sbytes.h"
#include "private/utils.h"
#include "private/z85.h"

int fhse_core_create(fhse_core_t* self, fhse_bytes_t* kdf_name, fhse_cview_t seed, fhse_crypto_t const* crypto, fhse_memory_t const* memory)
{
  if (!self || !crypto || !crypto->random || !crypto->kdf)
    return fhse_bad_argument;
  if (self->fido_salt.data || self->fido_userid.data || !seed.data)
    return fhse_bad_argument;

  fhse_bytes_t domain = {0};
  int rc = fhse_sbytes_realloc(&self->fido_userid, FHSE_FIDO2_USERID_SIZE, memory);
  FHSE_CHECK(fhse_sbytes_realloc(&self->fido_salt, FHSE_FIDO2_SALT_SIZE, memory));
  FHSE_CHECK(fhse_bytes_from_string(&domain, FHSE_SECRET_DOMAIN, memory));
  FHSE_CHECK(fhse_sbytes_realloc(&self->secret, FHSE_SECRET_SIZE, memory));
  FHSE_CHECK(fhse_sbytes_realloc(&self->z85_secret, FHSE_SECRET_Z85_SIZE, memory));

  FHSE_CHECK(crypto->random(fhse_sbytes_to_view(self->fido_userid), crypto->context));
  FHSE_CHECK(crypto->random(fhse_sbytes_to_view(self->fido_salt), crypto->context));

  memset(self->secret.data, 0, self->secret.length);
  FHSE_CHECK(crypto->kdf(kdf_name, fhse_sbytes_to_view(self->secret), seed, fhse_bytes_to_cview(domain), crypto->context));

  memset(self->z85_secret.data, 0, self->z85_secret.length);
  FHSE_CHECK(fhse_z85_encode(self->z85_secret, self->secret));

  if (rc != fhse_success)
    fhse_core_free(self, memory);
  
  fhse_bytes_free(&domain, memory);
  return rc; 
}

int fhse_core_open(fhse_core_t* self, fhse_cview_t source, fhse_memory_t const* memory)
{
  if(!self)
    return fhse_bad_argument;

  struct cbor_load_result result;
  cbor_item_t* parent = fhse_cbor_load(source, &result);
  if (result.error.code != CBOR_ERR_NONE || !parent)
    return fhse_cbor_failure;

  int rc = fhse_success;
  FHSE_CBOR_MAP_START(3, 3)
  {
    FHSE_CBOR_UNPACK(fido_userid, fhse_sbytes_unpack); 
    FHSE_CBOR_UNPACK(fido_salt, fhse_sbytes_unpack); 
    FHSE_CBOR_UNPACK(keys, fhse_keys_unpack); 
  }
  FHSE_CBOR_MAP_END()
  // `secret` and `z85_secret` not serialized (encrypted in each `keys` entry)

  cbor_decref(&parent);
  if (rc != fhse_success)
    fhse_core_free(self, memory);
  return rc; 
}

int fhse_core_store(fhse_core_t* self, fhse_sbytes_t* dest, fhse_memory_t const* memory)
{
  if (!self || !dest || !self->secret.data || !self->keys.data)
    return fhse_bad_argument;

  int rc = fhse_success;
  fhse_cbor_t out_ = {0};
  fhse_cbor_t* out = &out_;
  FHSE_CBOR_WRITE(cbor_encode_map_start(3, out->write_ptr, out->remaining));

  // `secret` and `z85_secret` not serialized (encrypted in each `keys` entry)
  FHSE_CHECK(fhse_cbor_field(out, "fido_userid", memory));
  FHSE_CHECK(fhse_sbytes_pack(&self->fido_userid, out, memory));

  FHSE_CHECK(fhse_cbor_field(out, "fido_salt", memory));
  FHSE_CHECK(fhse_sbytes_pack(&self->fido_salt, out, memory));

  FHSE_CHECK(fhse_cbor_field(out, "keys", memory));
  FHSE_CHECK(fhse_keys_pack(&self->keys, out, memory));

  FHSE_CHECK(fhse_sbytes_realloc(&out_.payload, out_.payload.length - out_.remaining, memory));

  if (rc == fhse_success)
    fhse_sbytes_move(dest, &out_.payload, memory);
  else
    fhse_sbytes_free(&out_.payload, memory);
  return rc;
}

int fhse_core_unlock(fhse_core_t* self, fhse_cview_t hmac_secret, fhse_crypto_t const* crypto, fhse_memory_t const* memory)
{
  if (!self || !self->fido_userid.data || self->secret.data)
    return fhse_bad_argument;

  fhse_sbytes_t secret = {0};
  fhse_sbytes_t z85_secret = {0};
  int rc = fhse_keys_try_open(&self->keys, &secret, NULL, hmac_secret, crypto, memory);

  if (secret.data && rc == fhse_success)
  {
    rc = fhse_sbytes_realloc(&z85_secret, secret.length * 5 / 4 + 1, memory);
    FHSE_CHECK(fhse_z85_encode(z85_secret, secret));
    if (rc == fhse_success)
    {
      fhse_sbytes_move(&self->secret, &secret, memory);
      fhse_sbytes_move(&self->z85_secret, &z85_secret, memory);
    }
  }

  fhse_sbytes_free(&secret, memory);
  fhse_sbytes_free(&z85_secret, memory);
  return rc;
}

int fhse_core_free(fhse_core_t* self, fhse_memory_t const* memory)
{
  if (!self || !memory)
    return fhse_bad_argument;

  fhse_sbytes_free(&self->fido_userid, memory);
  fhse_sbytes_free(&self->fido_salt, memory);
  fhse_keys_free(&self->keys, memory);
  fhse_sbytes_free(&self->secret, memory);
  fhse_sbytes_free(&self->z85_secret, memory);
  memset(self, 0, sizeof(fhse_core_t));
  return fhse_success;
}

int fhse_core_add_key(fhse_core_t* self, fhse_cview_t fido_cred, fhse_cview_t hmac_secret, fhse_crypto_t const* crypto, fhse_memory_t const* memory)
{
  if (!self || !self->secret.data)
    return fhse_bad_argument;
  return fhse_keys_add(&self->keys, fhse_sbytes_to_cview(self->secret), fido_cred, hmac_secret, crypto, memory);
}

int fhse_core_remove_key(fhse_core_t* self, fhse_cview_t hmac_secret, fhse_crypto_t const* crypto, fhse_memory_t const* memory)
{
  if (!self || !self->secret.data)
    return fhse_bad_argument;

  size_t index = 0;
  fhse_sbytes_t unused = {0};
  int rc = fhse_keys_try_open(&self->keys, &unused, &index, hmac_secret, crypto, memory);
  FHSE_CHECK(fhse_keys_remove(&self->keys, index, memory));
  fhse_sbytes_free(&unused, memory);
  return rc;  
}

