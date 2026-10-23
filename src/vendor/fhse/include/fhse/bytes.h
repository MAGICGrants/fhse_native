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

#ifndef FHSE_BYTES_H
#define FHSE_BYTES_H

#include "fhse.h"
#include "fhse/memory.h"

#include <stddef.h>
#ifdef __cplusplus
  extern "C" {
#endif

int fhse_bytes_realloc(fhse_bytes_t* self, size_t length, fhse_memory_t const* memory);
int fhse_bytes_from_string(fhse_bytes_t* self, const char* in, fhse_memory_t const* memory);
int fhse_bytes_copy(fhse_bytes_t* out, fhse_bytes_t src, fhse_memory_t const* memory);
int fhse_bytes_move(fhse_bytes_t* out, fhse_bytes_t* src, fhse_memory_t const* memory);
int fhse_bytes_free(fhse_bytes_t* self, fhse_memory_t const* memory);

int fhse_bytes_compare_string(fhse_bytes_t left, const char* right);
fhse_view_t fhse_bytes_to_view(fhse_bytes_t src);
fhse_cview_t fhse_bytes_to_cview(fhse_bytes_t src);

#ifdef __cplusplus
  }
#endif
#endif

