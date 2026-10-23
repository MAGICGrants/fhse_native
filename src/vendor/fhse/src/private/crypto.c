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

#include "private/crypto.h"

#include <cbor/encoding.h>
#include "private/bytes.h"
#include "private/cbor.h"
#include "private/utils.h"
#include "private/sbytes.h"

int fhse_aead_pack(fhse_aead_t* self, fhse_cbor_t* out, fhse_memory_t const* memory)
{
  int rc = fhse_success;
  FHSE_CBOR_WRITE(cbor_encode_map_start(4, out->write_ptr, out->remaining));

  FHSE_CHECK(fhse_cbor_field(out, "key_length", memory));
  FHSE_CBOR_WRITE(cbor_encode_uint64(self->key_length, out->write_ptr, out->remaining));
  if (rc != fhse_success)
    return rc;

  FHSE_TRY(fhse_cbor_field(out, "name", memory));
  FHSE_TRY(fhse_bytes_pack_string(&self->name, out, memory));

  FHSE_TRY(fhse_cbor_field(out, "nonce", memory));
  FHSE_TRY(fhse_bytes_pack_bytes(&self->nonce, out, memory));

  FHSE_TRY(fhse_cbor_field(out, "payload", memory));
  FHSE_TRY(fhse_sbytes_pack(&self->payload, out, memory));

  return fhse_success;
}

int fhse_aead_unpack(fhse_aead_t* self, cbor_item_t* parent, fhse_memory_t const* memory)
{
  if (!self || !parent || !memory)
    return fhse_bad_argument;

  int rc = fhse_success;
  FHSE_CBOR_MAP_START(4, 4)
  {
    FHSE_CBOR_UNPACK(key_length, fhse_size_unpack); 
    FHSE_CBOR_UNPACK(name, fhse_bytes_unpack); 
    FHSE_CBOR_UNPACK(nonce, fhse_bytes_unpack); 
    FHSE_CBOR_UNPACK(payload, fhse_sbytes_unpack);
  }
  FHSE_CBOR_MAP_END()

  // The key buffer is allocated at this length before anything is checked.
  if (rc == fhse_success && (!self->key_length || FHSE_AEAD_KEY_LENGTH_MAX < self->key_length))
    rc = fhse_cbor_failure;

  if (rc != fhse_success)
    fhse_aead_free(self, memory);
  return rc;
}
