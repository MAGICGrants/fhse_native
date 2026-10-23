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

#ifndef FHSE_CRYPTO_H
#define FHSE_CRYPTO_H

#include <stddef.h>
#include "fhse.h"
#include "fhse/sbytes.h"

#ifdef __cplusplus
  extern "C" {
#endif

typedef struct fhse_aead_t
{
  fhse_bytes_t name;
  fhse_bytes_t nonce;
  fhse_sbytes_t payload;
  size_t key_length;
} fhse_aead_t;

int fhse_aead_move(fhse_aead_t* self, fhse_aead_t* src, fhse_memory_t const* memory);
int fhse_aead_free(fhse_aead_t* self, fhse_memory_t const* memory);

typedef struct fhse_crypto_t
{
  void* context;
  int (*random)(fhse_view_t out, void* context);
  int (*kdf)(fhse_bytes_t* name, fhse_view_t out, fhse_cview_t in, fhse_cview_t domain, void* context); 
  int (*pwhash)(fhse_bytes_t* name, fhse_view_t out, fhse_cview_t in, fhse_bytes_t* salt, void* context);
  int (*aead)(fhse_sbytes_t* out, fhse_aead_t* state, fhse_cview_t key, void* context);
  size_t aead_key_length;
} fhse_crypto_t;

int fhse_crypto_defaults(fhse_crypto_t* crypto, fhse_memory_t* memory);

#ifdef __cplusplus
  }
#endif
#endif

