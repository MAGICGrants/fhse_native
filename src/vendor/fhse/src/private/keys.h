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

#ifndef FHSE_KEYS_H
#define FHSE_KEYS_H

#include <cbor/data.h>
#include "fhse/bytes.h"
#include "fhse/crypto.h"
#include "fhse/memory.h"
#include "fhse/sbytes.h"
#include "private/cbor_fwd.h"

//! Wrapper struct - Allow for expansion in cbor encoded data
typedef struct fhse_key_t
{
  fhse_bytes_t kdf_name;
  fhse_sbytes_t fido_cred;
  fhse_aead_t aead;
} fhse_key_t;

int fhse_key_pack(fhse_key_t* self, fhse_cbor_t* out, fhse_memory_t const* memory);
int fhse_key_unpack(fhse_key_t* self, cbor_item_t* parent, fhse_memory_t const* memory);

int fhse_key_move(fhse_key_t* self, fhse_key_t* src, fhse_memory_t const* memory);
int fhse_key_free(fhse_key_t* self, fhse_memory_t const* memory);

int fhse_key_try_open(fhse_key_t* self, fhse_sbytes_t* out, fhse_cview_t hmac_secret, fhse_crypto_t const* crypto, fhse_memory_t const* memory);

typedef struct fhse_keys_t
{ 
  fhse_key_t* data;
  size_t count;
} fhse_keys_t;

int fhse_keys_pack(fhse_keys_t* self, fhse_cbor_t* out, fhse_memory_t const* memory);
int fhse_keys_unpack(fhse_keys_t* self, cbor_item_t* parent, fhse_memory_t const* memory);
int fhse_keys_free(fhse_keys_t* self, fhse_memory_t const* memory);

int fhse_keys_try_open(fhse_keys_t* self, fhse_sbytes_t* out, size_t* index, fhse_cview_t hmac_secret, fhse_crypto_t const* crypto, fhse_memory_t const* memory);

int fhse_keys_add(fhse_keys_t* self, fhse_cview_t root_secret, fhse_cview_t fido_cred, fhse_cview_t hmac_secret, fhse_crypto_t const* crypto, fhse_memory_t const* memory);
int fhse_keys_remove(fhse_keys_t* self, size_t index, fhse_memory_t const* memory);

#endif // FHSE_KEYS_H
