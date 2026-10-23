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

#include "fhse/crypto.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "fhse.h"
#include "fhse/bytes.h"
#include "fhse/sbytes.h"
#include "private/utils.h"

#ifdef FHSE_LIBSODIUM
  #include <sodium/core.h>
  #include <sodium/crypto_aead_xchacha20poly1305.h>
  #include <sodium/crypto_kdf_blake2b.h>
  #include <sodium/crypto_pwhash_argon2id.h>
  #include <sodium/randombytes.h>
  #include <sodium/utils.h>

  #define FHSE_CRYPTO_KDF_NAME "kdf_blake2b"
  #define FHSE_CRYPTO_KDF_KEY_SIZE crypto_kdf_blake2b_KEYBYTES
  #define FHSE_CRYPTO_KDF_DOMAIN_SIZE crypto_kdf_blake2b_CONTEXTBYTES

  #define FHSE_CRYPTO_PWHASH_NAME "argon2id13"
  #define FHSE_CRYPTO_PWHASH_SALT_SIZE crypto_pwhash_argon2id_SALTBYTES
  #define FHSE_CRYPTO_PWHASH_OPS crypto_pwhash_argon2id_OPSLIMIT_MIN
  #define FHSE_CRYPTO_PWHASH_MEM crypto_pwhash_argon2id_MEMLIMIT_MIN

  #define FHSE_CRYPTO_AEAD_NAME "xchacha20-poly1305-ietf"
  #define FHSE_CRYPTO_AEAD_KEY_SIZE crypto_aead_xchacha20poly1305_ietf_KEYBYTES
  #define FHSE_CRYPTO_AEAD_TAG_SIZE crypto_aead_xchacha20poly1305_ietf_ABYTES
  #define FHSE_CRYPTO_AEAD_NONCE_SIZE crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

  static int fhse_crypto_random(fhse_view_t out, void* context)
  {
    if (sodium_init() == -1)
      return fhse_crypto_failure;
    randombytes_buf(out.data, out.length);
    return fhse_success;
  }

  static int fhse_crypto_kdf(fhse_bytes_t* name, fhse_view_t out, fhse_cview_t in, fhse_cview_t domain, void* context)
  {
    fhse_memory_t const* memory = (fhse_memory_t const*)context;
    if (!name || !memory || !memory->realloc || !memory->free)
      return fhse_bad_argument;
    if (FHSE_CRYPTO_KDF_DOMAIN_SIZE < domain.length)
      return fhse_bad_argument;
    // Exactly one key's worth of input. Shorter input was zero-padded (an empty
    // seed gave every user the same root) and longer input was truncated.
    if (!in.data || in.length != FHSE_CRYPTO_KDF_KEY_SIZE)
      return fhse_bad_argument;
    if (sodium_init() == -1)
      return fhse_crypto_failure;

    if (name->data)
    {
      if (fhse_bytes_compare_string(*name, FHSE_CRYPTO_KDF_NAME) != 0)
        return fhse_bad_argument;
    }
    else if (fhse_bytes_from_string(name, FHSE_CRYPTO_KDF_NAME, memory) != fhse_success)
      return fhse_bad_alloc;

    unsigned char key[FHSE_CRYPTO_KDF_KEY_SIZE] = {0};
    memcpy(key, in.data, sizeof(key));

    char ctx[FHSE_CRYPTO_KDF_DOMAIN_SIZE] = {0};
    memcpy(ctx, domain.data, domain.length < sizeof(ctx) ? domain.length : sizeof(ctx));

    const int rc = crypto_kdf_blake2b_derive_from_key(out.data, out.length, 0, ctx, key);
    sodium_memzero(key, sizeof(key));
    return rc == 0 ? fhse_success : fhse_crypto_failure;
  }
 
  static int fhse_crypto_pwhash(fhse_bytes_t* name, fhse_view_t out, fhse_cview_t in, fhse_bytes_t* salt, void* context)
  {
    fhse_memory_t const* memory = (fhse_memory_t const*)context;
    if (!name || !salt)
      return fhse_bad_argument;
    if (sodium_init() == -1)
      return fhse_crypto_failure;

    bool existing = false;
    if (name->data && salt->data)
    {
      existing = true;
      if (fhse_bytes_compare_string(*name, FHSE_CRYPTO_PWHASH_NAME) != 0)
        return fhse_bad_argument;
      if (salt->length != FHSE_CRYPTO_PWHASH_SALT_SIZE)
        return fhse_bad_argument;
    }
    else // new
    {
      if (name->data || salt->data)
        return fhse_bad_argument;

      if (fhse_bytes_from_string(name, FHSE_CRYPTO_PWHASH_NAME, memory) != fhse_success)
        return fhse_bad_alloc;
      if (fhse_bytes_realloc(salt, FHSE_CRYPTO_PWHASH_SALT_SIZE, memory) != fhse_success)
      {
        fhse_bytes_free(name, memory);
        return fhse_bad_alloc;
      }

      randombytes_buf(salt->data, salt->length);
    }

    // An empty password may arrive as {NULL, 0}; libsodium declares the
    // pointer non-null even for a zero length.
    const char* const passwd = in.length ? (const char*)in.data : "";
    const int rc = crypto_pwhash_argon2id(
      out.data, out.length,
      passwd, in.length,
      salt->data,
      FHSE_CRYPTO_PWHASH_OPS,
      FHSE_CRYPTO_PWHASH_MEM,
      crypto_pwhash_argon2id_ALG_ARGON2ID13
    );

    if (rc == 0)
      return fhse_success;
    
    if (existing)
    {
      fhse_bytes_free(name, memory);
      fhse_bytes_free(salt, memory);
    }

    return fhse_crypto_failure;
  }

  static int fhse_crypto_encrypt(fhse_sbytes_t* out, fhse_aead_t* state, fhse_cview_t key, fhse_memory_t const* memory)
  {
    assert(state);
    if (!out || !state || state->name.data || state->nonce.data)
      return fhse_bad_argument;
    if (SIZE_MAX - state->payload.length < FHSE_CRYPTO_AEAD_TAG_SIZE || ULLONG_MAX < state->payload.length + FHSE_CRYPTO_AEAD_TAG_SIZE)
      return fhse_bad_argument;
    if (key.length < FHSE_CRYPTO_AEAD_KEY_SIZE)
      return fhse_crypto_failure;
    if (sodium_init() == -1)
      return fhse_crypto_failure;

    if (fhse_bytes_from_string(&state->name, FHSE_CRYPTO_AEAD_NAME, memory) != fhse_success)
      return fhse_bad_alloc;

    if (fhse_sbytes_realloc(out, state->payload.length + FHSE_CRYPTO_AEAD_TAG_SIZE, memory) != fhse_success)
    {
      fhse_bytes_free(&state->name, memory);
      return fhse_bad_alloc;
    }

    if (fhse_bytes_realloc(&state->nonce, FHSE_CRYPTO_AEAD_NONCE_SIZE, memory) != fhse_success)
    {
      fhse_bytes_free(&state->name, memory);
      fhse_sbytes_free(out, memory);
      return fhse_bad_alloc;
    }
    
    randombytes_buf(state->nonce.data, state->nonce.length);

    unsigned long long out_length = 0;
    const int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
      out->data, &out_length, state->payload.data, state->payload.length, NULL, 0, NULL, state->nonce.data, key.data
    );

    if (rc || SIZE_MAX < out_length)
    {
      fhse_bytes_free(&state->name, memory);
      fhse_bytes_free(&state->nonce, memory);
      return fhse_bad_argument;
    }

    return fhse_sbytes_realloc(out, out_length, memory);
  }

  static int fhse_crypto_decrypt(fhse_sbytes_t* out, fhse_aead_t const* state, fhse_cview_t key, fhse_memory_t const* memory)
  {
    assert(state);
    if (!out)
      return fhse_bad_argument;
    if (fhse_bytes_compare_string(state->name, FHSE_CRYPTO_AEAD_NAME) != 0)
      return fhse_bad_argument;
    if (key.length != FHSE_CRYPTO_AEAD_KEY_SIZE || state->nonce.length != FHSE_CRYPTO_AEAD_NONCE_SIZE)
      return fhse_bad_argument;
    if (state->payload.length < FHSE_CRYPTO_AEAD_TAG_SIZE || ULLONG_MAX < state->payload.length)
      return fhse_bad_argument;
    if (sodium_init() == -1)
      return fhse_crypto_failure;

    if (fhse_sbytes_realloc(out, state->payload.length - FHSE_CRYPTO_AEAD_TAG_SIZE, memory) != fhse_success)
      return fhse_bad_alloc;

    unsigned long long length = out->length;
    const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
      out->data, &length, NULL, state->payload.data, state->payload.length, NULL, 0, state->nonce.data, key.data
    );

    if (rc || SIZE_MAX < length)
      return fhse_decryption_failure;
    return fhse_sbytes_realloc(out, length, memory);
  }

  static int fhse_crypto_aead(fhse_sbytes_t* out, fhse_aead_t* state, fhse_cview_t key, void* context)
  {
    if (!state)
      return fhse_bad_argument;
    fhse_memory_t const* memory = (fhse_memory_t*)context; 
    if (state->name.data)
      return fhse_crypto_decrypt(out, state, key, memory);
    return fhse_crypto_encrypt(out, state, key, memory);
  }

#endif // FHSE_LIBSODIUM

int fhse_crypto_defaults(fhse_crypto_t* crypto, fhse_memory_t* memory)
{
  if (crypto && memory)
  {
    memset(crypto, 0, sizeof(fhse_crypto_t));
#ifdef FHSE_LIBSODIUM
    crypto->context = memory;
    crypto->random = fhse_crypto_random;
    crypto->kdf = fhse_crypto_kdf;
    crypto->pwhash = fhse_crypto_pwhash;
    crypto->aead = fhse_crypto_aead;
    crypto->aead_key_length = FHSE_CRYPTO_AEAD_KEY_SIZE;
    return fhse_success;
#endif 
  }
  return fhse_bad_argument;
}

int fhse_aead_move(fhse_aead_t* self, fhse_aead_t* src, fhse_memory_t const* memory)
{
  if (!self || !src)
    return fhse_bad_argument;
  if (self != src)
  {
    self->key_length = src->key_length;
    src->key_length = 0;
    fhse_bytes_move(&self->name, &src->name, memory);
    fhse_bytes_move(&self->nonce, &src->nonce, memory);
    fhse_sbytes_move(&self->payload, &src->payload, memory);
  }
  return fhse_success;
}

int fhse_aead_free(fhse_aead_t* self, fhse_memory_t const* memory)
{
  if (!self)
    return fhse_bad_argument;

  fhse_bytes_free(&self->name, memory);
  fhse_bytes_free(&self->nonce, memory); 
  fhse_sbytes_free(&self->payload, memory);
  return fhse_success;
}

