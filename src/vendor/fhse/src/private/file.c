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

#include "private/file.h"

#include <cbor.h>
#include "private/bytes.h"
#include "private/cbor.h"
#include "private/crypto.h"
#include "private/sbytes.h"
#include "private/utils.h"

int fhse_file_open(fhse_file_t* self, fhse_cview_t source, fhse_memory_t const* memory)
{
  if(!self || !memory)
    return fhse_bad_argument;

  struct cbor_load_result result;
  cbor_item_t* parent = fhse_cbor_load(source, &result);
  if (result.error.code != CBOR_ERR_NONE || !parent)
    return fhse_cbor_failure;

  int rc = fhse_success;
  FHSE_CBOR_MAP_START(4, 4)
  {
    FHSE_CBOR_UNPACK(seed_kdf_name, fhse_bytes_unpack); 
    FHSE_CBOR_UNPACK(pwhash_name, fhse_bytes_unpack); 
    FHSE_CBOR_UNPACK(pwhash_salt, fhse_bytes_unpack); 
    FHSE_CBOR_UNPACK(outer, fhse_aead_unpack);
  }
  FHSE_CBOR_MAP_END()

  cbor_decref(&parent);
  if (rc != fhse_success)
    fhse_file_free(self, memory);
  return rc; 
}

int fhse_file_store(fhse_file_t* self, fhse_sbytes_t* dest, fhse_memory_t const* memory)
{
  if (!self || !dest)
    return fhse_bad_argument;

  int rc = fhse_success;
  fhse_cbor_t out_ = {0};
  fhse_cbor_t* out = &out_;
  FHSE_CBOR_WRITE(cbor_encode_map_start(4, out->write_ptr, out->remaining));

  FHSE_CHECK(fhse_cbor_field(out, "outer", memory));
  FHSE_CHECK(fhse_aead_pack(&self->outer, out, memory));

  FHSE_CHECK(fhse_cbor_field(out, "pwhash_name", memory));
  FHSE_CHECK(fhse_bytes_pack_string(&self->pwhash_name, out, memory));

  FHSE_CHECK(fhse_cbor_field(out, "pwhash_salt", memory));
  FHSE_CHECK(fhse_bytes_pack_bytes(&self->pwhash_salt, out, memory));

  FHSE_CHECK(fhse_cbor_field(out, "seed_kdf_name", memory));
  FHSE_CHECK(fhse_bytes_pack_string(&self->seed_kdf_name, out, memory));

  FHSE_CHECK(fhse_sbytes_realloc(&out_.payload, out_.payload.length - out_.remaining, memory));

  if (rc == fhse_success)
    fhse_sbytes_move(dest, &out_.payload, memory);
  else
    fhse_sbytes_free(&out_.payload, memory);

  return rc;
}

int fhse_file_free(fhse_file_t* self, fhse_memory_t const* memory)
{
  if (!self || !memory || !memory->free)
    return fhse_bad_argument;

  fhse_bytes_free(&self->seed_kdf_name, memory);
  fhse_bytes_free(&self->pwhash_name, memory);
  fhse_bytes_free(&self->pwhash_salt, memory);
  fhse_aead_free(&self->outer, memory);
  memset(self, 0, sizeof(fhse_file_t));
  return fhse_success;
}

