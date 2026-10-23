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

#ifndef FHSE_CORE_H
#define FHSE_CORE_H

#include "bytes.h"
#include "cbor_fwd.h"
#include "fhse.h"
#include "keys.h"

typedef struct fhse_core_t
{
  fhse_sbytes_t fido_userid;
  fhse_sbytes_t fido_salt;
  fhse_keys_t keys;
  fhse_sbytes_t secret;
  fhse_sbytes_t z85_secret; // null-terminated z85 encoding of `secret`
} fhse_core_t;

//! Initialize all values; `secret` is based on `seed`.
int fhse_core_create(fhse_core_t* self, fhse_bytes_t* kdf_name, fhse_cview_t seed, fhse_crypto_t const* crypto, fhse_memory_t const* memory);

//! `secret` and `z85_secret` still encrypted
int fhse_core_open(fhse_core_t* self, fhse_cview_t source, fhse_memory_t const* memory);

//! Store as cbor, except `secret` and `z85_secret` (which are encrypted in `keys`)
int fhse_core_store(fhse_core_t* self, fhse_sbytes_t* dest, fhse_memory_t const* memory);

//! Open "root" `secret`/`z85_secret`. Must use `fhse_core_open` first.
int fhse_core_unlock(fhse_core_t* self, fhse_cview_t hmac_secret, fhse_crypto_t const* crypto, fhse_memory_t const* memory);
int fhse_core_add_key(fhse_core_t* self, fhse_cview_t fido_cred, fhse_cview_t hmac_secret, fhse_crypto_t const* crypto, fhse_memory_t const* memory);
int fhse_core_remove_key(fhse_core_t* self, fhse_cview_t hmac_secret, fhse_crypto_t const* crypto, fhse_memory_t const* memory);

int fhse_core_free(fhse_core_t* self, fhse_memory_t const* memory);



#endif // FHSE_CORE_H
