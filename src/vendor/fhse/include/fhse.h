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

#ifndef FHSE_H
#define FHSE_H

#include <stddef.h>
#ifdef __cplusplus
  extern "C" {
#endif

// Only append new values to keep consistent values
enum fhse_error
{
  fhse_success = 0,
  fhse_bad_alloc,
  fhse_bad_argument,
  fhse_cbor_failure,
  fhse_crypto_failure,
  fhse_decryption_failure,
  fhse_duplicate_key,
  fhse_fido_failure,
  fhse_fido_needs_pin,
  fhse_key_unavailable,
  fhse_mlock_failure,
  fhse_fido_pin_invalid,
  fhse_fido_pin_blocked,
  fhse_fido_unsupported
};

typedef struct fhse_device_t fhse_device_t;
typedef struct fhse_secret_t fhse_secret_t;
struct fhse_memory_t;
struct fhse_crypto_t;

//! Non-ownership sequence of mutable bytes
typedef struct fhse_view_t
{
  unsigned char* data;
  size_t length;
} fhse_view_t;

//! Non-ownership sequence of immutable bytes
typedef struct fhse_cview_t
{
  unsigned char const* data;
  size_t length;
} fhse_cview_t;

//! 0+ `fhse_cview_t` objects in an array.
typedef struct fhse_cviews_t
{
  fhse_cview_t const* data;
  size_t count;
} fhse_cviews_t;

// Generic bytes with ownership
typedef struct fhse_bytes_t
{
  unsigned char* data;
  size_t length;
} fhse_bytes_t;

//! Secure (RAM locked and wiped) bytes, which implies ownership
typedef struct fhse_sbytes_t
{
  unsigned char* data;
  size_t length;
} fhse_sbytes_t;

//
// fhse_secret_t functions
//

//! pass `NULL` to `memory` or `crypto` for defaults
int fhse_secret_construct(
  fhse_secret_t** self,
  struct fhse_memory_t const* memory,
  struct fhse_crypto_t const* crypto
);
void fhse_secret_free(fhse_secret_t** self);

//! Free `bytes` allocated/returned by `self`
int fhse_secret_bytes_free(fhse_secret_t* self, fhse_bytes_t* bytes);

//! `NULL` if not-restored or null terminated z85 encoded secret. Non-owning.
const char* fhse_secret_get_ascii(fhse_secret_t* self);
fhse_cview_t fhse_secret_get(fhse_secret_t* self);

fhse_cview_t fhse_secret_fido_userid(fhse_secret_t* self);
fhse_cview_t fhse_secret_fido_salt(fhse_secret_t* self);

//! Generate a new FIDO2 userid+salt and derive `secret` from `seed`.
int fhse_secret_create(fhse_secret_t* self, fhse_cview_t pass, fhse_cview_t optiional_seed);

//! Open an existing FIDO2 userid+salt; `secret` still encrypted with FIDO2
int fhse_secret_open(fhse_secret_t* self, fhse_cview_t source, fhse_cview_t pass);

//! Pack entire state into `out` for storage. Lib allocates, user frees
int fhse_secret_store(fhse_secret_t* self, fhse_bytes_t* out);

size_t fhse_secret_cred_count(fhse_secret_t* self);
fhse_cview_t fhse_secret_cred(fhse_secret_t* self, size_t i);

int fhse_secret_unlock(fhse_secret_t* self, fhse_cview_t hmac_secret);

int fhse_secret_add_key(fhse_secret_t* self, fhse_cview_t fido_cred, fhse_cview_t hmac_secret);
int fhse_secret_remove_key(fhse_secret_t* self, fhse_cview_t hmac_secret);

//
// fhse_device_t functions
//

int fhse_device_construct(fhse_device_t** self, const char* path, struct fhse_memory_t const* memory);
void fhse_device_free(fhse_device_t** self);

void fhse_device_sbytes_free(fhse_device_t* self, fhse_sbytes_t* bytes);

//! Creates a non-discoverable hmac-secret credential that requires user
//! verification (credProtect level 3). `pin` is required. `exclude` lists
//! credentials already enrolled, so the same key is not enrolled twice
//! (`fhse_duplicate_key`).
int fhse_device_generate_cred(fhse_device_t* self, fhse_sbytes_t* out, fhse_cview_t userid, const char* pin);
int fhse_device_generate_cred_excluding(fhse_device_t* self, fhse_sbytes_t* out, fhse_cview_t userid, fhse_cviews_t exclude, const char* pin);
//! `pin` is required; the hmac-secret is always taken with user verification.
int fhse_device_get_hmac_secret(fhse_device_t* self, fhse_sbytes_t* out, fhse_cviews_t keys, fhse_cview_t salt, const char* pin);
int fhse_device_cancel(fhse_device_t* self);

#ifdef __cplusplus
  }
#endif
#endif
