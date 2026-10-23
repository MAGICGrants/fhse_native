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

#ifdef FHSE_LIBSODIUM
  #include <sodium/utils.h>
#endif 
#include <stdlib.h>
#include <string.h>
#include "fhse.h"
#include "fhse/memory.h"

static void* fhse_realloc(void* ptr, size_t size, void* context)
{
  return realloc(ptr, size);
}

static void fhse_free_(void* ptr, void* context)
{
  if (ptr)
    free(ptr);
}

#ifdef FHSE_LIBSODIUM
  static void fhse_memzero(void* ptr, size_t size, void* context)
  {
    if (ptr)
      sodium_memzero(ptr, size);
  }

  static int fhse_mlock(void* ptr, size_t size, void* context)
  {
    if (!ptr || sodium_mlock(ptr, size) == -1)
      return fhse_mlock_failure;
    return fhse_success;
  }

  static int fhse_munlock(void* ptr, size_t size, void* context)
  {
    if (!ptr || sodium_munlock(ptr, size) == -1)
      return fhse_mlock_failure;
    return fhse_success;
  }
#endif

void fhse_memory_defaults(fhse_memory_t* memory)
{
  if (!memory)
    return;
  memset(memory, 0, sizeof(fhse_memory_t));
  memory->realloc = fhse_realloc;
  memory->free = fhse_free_;
#ifdef FHSE_LIBSODIUM
  memory->memzero = fhse_memzero;
  memory->mlock = fhse_mlock;
  memory->munlock = fhse_munlock;
#endif
}
