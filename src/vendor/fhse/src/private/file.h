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

#ifndef FHSE_FILE_H
#define FHSE_FILE_H

#include "fhse/bytes.h"
#include "fhse/crypto.h"
#include "fhse/memory.h"

//! Represents the type sent to caller (which is stored however client decides)
typedef struct fhse_file
{
  fhse_bytes_t pwhash_name;
  fhse_bytes_t pwhash_salt;
  //! Always written empty, and not read back: which KDF made the root from
  //! the seed is not recorded.
  fhse_bytes_t seed_kdf_name;
  fhse_aead_t outer;
} fhse_file_t;

int fhse_file_open(fhse_file_t* self, fhse_cview_t source, fhse_memory_t const* memory);
int fhse_file_store(fhse_file_t* self, fhse_sbytes_t* dest, fhse_memory_t const* memory);
int fhse_file_free(fhse_file_t* self, fhse_memory_t const* memory);

#endif // FHSE_FILE_H
