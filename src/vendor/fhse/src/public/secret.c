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

#include "fhse.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "private/bytes.h"
#include "private/config.h"
#include "private/core.h"
#include "private/file.h"
#include "private/sbytes.h"
#include "private/utils.h"

struct fhse_secret_t
{
  fhse_memory_t memory;
  fhse_crypto_t crypto;
  // The KDF that made the root from the seed, as `create` reports it. Not
  // written to the file: its `seed_kdf_name` is stored empty.
  fhse_bytes_t seed_kdf_name;
  fhse_sbytes_t pass;
  fhse_core_t core;
};

int fhse_secret_construct(fhse_secret_t** self, fhse_memory_t const* memory, fhse_crypto_t const* crypto)
{
  if (!self)
    return fhse_bad_argument;

  fhse_memory_t memory_default;
  if (!memory)
  {
    fhse_memory_defaults(&memory_default);
    memory = &memory_default;
  }
  if (!memory->realloc || !memory->free)
    return fhse_bad_argument;

  *self = (fhse_secret_t*)memory->realloc(NULL, sizeof(fhse_secret_t), memory->context);
  if (!*self)
    return fhse_bad_alloc;
  memset(*self, 0, sizeof(fhse_secret_t));

  fhse_crypto_t crypto_default;
  if (!crypto && fhse_crypto_defaults(&crypto_default, &(*self)->memory) == fhse_success)
    crypto = &crypto_default;

  if (!crypto)
  {
    fhse_secret_free(self);
    return fhse_bad_argument;
  }

  memcpy(&(*self)->memory, memory, sizeof(fhse_memory_t));
  memcpy(&(*self)->crypto, crypto, sizeof(fhse_crypto_t));
  return fhse_success;
}

void fhse_secret_free(fhse_secret_t** self)
{
  if (!self || !*self || !(*self)->memory.free)
    return;

  fhse_bytes_free(&(*self)->seed_kdf_name, &(*self)->memory);
  fhse_sbytes_free(&(*self)->pass, &(*self)->memory);
  fhse_core_free(&(*self)->core, &(*self)->memory);

  void* context = (*self)->memory.context;
  void (*destroy)(void*, void*) = (*self)->memory.free;
  destroy(*self, context);
  *self = NULL;
}

const char* fhse_secret_get_ascii(fhse_secret_t* self)
{
  if (self && self->core.z85_secret.data)
    return (const char*)self->core.z85_secret.data;
  return NULL;
}

fhse_cview_t fhse_secret_get(fhse_secret_t* self)
{
  fhse_cview_t out = {0};
  if (self)
  {
    out.data = self->core.secret.data;
    out.length = self->core.secret.length;
  }
  return out;
}

fhse_cview_t fhse_secret_fido_userid(fhse_secret_t* self)
{
  fhse_cview_t out = {0};
  if (self)
  {
    out.data = self->core.fido_userid.data;
    out.length = self->core.fido_userid.length;
  }
  return out;
}

fhse_cview_t fhse_secret_fido_salt(fhse_secret_t* self)
{
  fhse_cview_t out = {0};
  if (self)
  {
    out.data = self->core.fido_salt.data;
    out.length = self->core.fido_salt.length;
  }
  return out;
}

int fhse_secret_bytes_free(fhse_secret_t* self, fhse_bytes_t* bytes)
{
  if (!self || !bytes)
    return fhse_bad_argument;
  return fhse_bytes_free(bytes, &self->memory);
}

int fhse_secret_create(fhse_secret_t* self, fhse_cview_t pass, fhse_cview_t seed)
{
  if (!self)
    return fhse_bad_argument;

  if (!pass.data && pass.length)
    return fhse_bad_argument;

  int rc = fhse_success;
  fhse_sbytes_t random_seed = {0};
  // NULL and empty both mean "no seed", as the README documents. An empty seed
  // behind a non-NULL pointer used to reach the KDF and give every user the
  // same root.
  if (!seed.data || !seed.length)
  {
    if (!self->crypto.random)
      return fhse_bad_argument;

    FHSE_TRY(fhse_sbytes_realloc(&random_seed, FHSE_SEED_SIZE, &self->memory));
    rc = self->crypto.random(fhse_sbytes_to_view(random_seed), self->crypto.context);
    seed = fhse_sbytes_to_cview(random_seed);
  }

  // Build the password copy before touching `self`, and only adopt either on
  // full success, so a failed create leaves no half-made object behind.
  fhse_sbytes_t next_pass = {0};
  FHSE_CHECK(fhse_sbytes_realloc(&next_pass, pass.length, &self->memory));
  if (rc == fhse_success && pass.length)
    memcpy(next_pass.data, pass.data, pass.length);

  FHSE_CHECK(fhse_core_create(&self->core, &self->seed_kdf_name, seed, &self->crypto, &self->memory));
  if (rc == fhse_success)
    fhse_sbytes_move(&self->pass, &next_pass, &self->memory);

  fhse_sbytes_free(&next_pass, &self->memory);
  fhse_sbytes_free(&random_seed, &self->memory);
  return rc;
}

static int fhse_decrypt_outer(fhse_sbytes_t* decrypted, fhse_file_t* file, fhse_cview_t pass, fhse_crypto_t const* crypto, fhse_memory_t const* memory)
{
  assert(decrypted && file && crypto);
  if (!decrypted || !file || !crypto)
    return fhse_bad_argument;
  if (!crypto->pwhash || !crypto->aead)
    return fhse_bad_argument;
  if (!file->pwhash_name.data || !file->pwhash_salt.data || !file->outer.name.data || !file->outer.nonce.data)
    return fhse_bad_argument;
  
  fhse_sbytes_t hardened_pass = {0};
  int rc = fhse_sbytes_realloc(&hardened_pass, file->outer.key_length, memory);
  FHSE_CHECK(crypto->pwhash(&file->pwhash_name, fhse_sbytes_to_view(hardened_pass), pass, &file->pwhash_salt, crypto->context));
  FHSE_CHECK(crypto->aead(decrypted, &file->outer, fhse_sbytes_to_cview(hardened_pass), crypto->context));

  fhse_sbytes_free(&hardened_pass, memory);
  return rc;
}

int fhse_secret_open(fhse_secret_t* self, fhse_cview_t source, fhse_cview_t pass)
{
  if (!self || !source.data)
    return fhse_bad_argument;
  if (!pass.data && pass.length)
    return fhse_bad_argument;
  // Open only into an empty object, as `create` already requires. Re-opening a
  // populated one kept the previous root, and a failed re-open overwrote the
  // retained password with an over-read of the new one.
  if (self->core.fido_userid.data || self->core.secret.data || self->pass.data)
    return fhse_bad_argument;

  fhse_file_t file = {0};
  fhse_sbytes_t decrypted = {0};
  fhse_sbytes_t next_pass = {0};
  int rc = fhse_file_open(&file, source, &self->memory);
  FHSE_CHECK(fhse_decrypt_outer(&decrypted, &file, pass, &self->crypto, &self->memory));
  FHSE_CHECK(fhse_sbytes_realloc(&next_pass, pass.length, &self->memory));
  if (rc == fhse_success && pass.length)
    memcpy(next_pass.data, pass.data, pass.length);
  FHSE_CHECK(fhse_core_open(&self->core, fhse_sbytes_to_cview(decrypted), &self->memory));
  if (rc == fhse_success)
    fhse_sbytes_move(&self->pass, &next_pass, &self->memory);

  fhse_sbytes_free(&next_pass, &self->memory);
  fhse_file_free(&file, &self->memory);
  fhse_sbytes_free(&decrypted, &self->memory);
  return rc;
}

int fhse_secret_store(fhse_secret_t* self, fhse_bytes_t* out)
{
  if (!self || !out || !self->crypto.aead_key_length || !self->crypto.pwhash || !self->crypto.aead)
    return fhse_bad_argument;

  fhse_file_t file = {0};
  file.outer.key_length = self->crypto.aead_key_length;
  fhse_sbytes_t hardened_pass = {0};
  int rc = fhse_sbytes_realloc(&hardened_pass, self->crypto.aead_key_length, &self->memory);
  FHSE_CHECK(self->crypto.pwhash(&file.pwhash_name, fhse_sbytes_to_view(hardened_pass), fhse_sbytes_to_cview(self->pass), &file.pwhash_salt, self->crypto.context));

  fhse_sbytes_t outer = {0};
  FHSE_CHECK(fhse_core_store(&self->core, &file.outer.payload, &self->memory));
  FHSE_CHECK(self->crypto.aead(&outer, &file.outer, fhse_sbytes_to_cview(hardened_pass), self->crypto.context));
  FHSE_CHECK(fhse_sbytes_move(&file.outer.payload, &outer, &self->memory));
  FHSE_CHECK(fhse_file_store(&file, &outer, &self->memory));

  FHSE_CHECK(fhse_sbytes_downgrade(&outer, out, &self->memory));

  fhse_sbytes_free(&hardened_pass, &self->memory);
  fhse_file_free(&file, &self->memory);
  fhse_sbytes_free(&outer, &self->memory);

  return rc;
}

size_t fhse_secret_cred_count(fhse_secret_t* self)
{
  if (!self)
    return 0;
  return self->core.keys.count;
}

fhse_cview_t fhse_secret_cred(fhse_secret_t* self, size_t i)
{
  fhse_cview_t out = {0};
  if (self && i < self->core.keys.count)
  {
    out.data = (self->core.keys.data + i)->fido_cred.data;
    out.length = (self->core.keys.data + i)->fido_cred.length;
  }
  return out;
}

int fhse_secret_unlock(fhse_secret_t* self, fhse_cview_t hmac_secret)
{
  if (!self)
    return fhse_bad_argument;
  return fhse_core_unlock(&self->core, hmac_secret, &self->crypto, &self->memory);
}

int fhse_secret_add_key(fhse_secret_t* self, fhse_cview_t fido_cred, fhse_cview_t hmac_secret)
{
  if (!self || !fido_cred.data || !hmac_secret.data)
    return fhse_bad_argument;
  return fhse_core_add_key(&self->core, fido_cred, hmac_secret, &self->crypto, &self->memory);
}

int fhse_secret_remove_key(fhse_secret_t* self, fhse_cview_t hmac_secret)
{
  if (!self)
    return fhse_bad_argument;
  return fhse_core_remove_key(&self->core, hmac_secret, &self->crypto, &self->memory);
}

