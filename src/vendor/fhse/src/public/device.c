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

#include "fhse.h"

#ifndef FHSE_LIBFIDO2
int fhse_device_construct(fhse_device_t** self, const char* path, struct fhse_memory_t const* memory)
{ return fhse_bad_argument; }
void fhse_device_free(fhse_device_t** self) {}
void fhse_device_sbytes_free(fhse_device_t* self, fhse_sbytes_t* bytes) {}
int fhse_device_generate_cred(fhse_device_t* self, fhse_sbytes_t* out, fhse_cview_t userid, const char* pin)
{ return fhse_bad_argument; }
int fhse_device_generate_cred_excluding(fhse_device_t* self, fhse_sbytes_t* out, fhse_cview_t userid, fhse_cviews_t exclude, const char* pin)
{ return fhse_bad_argument; }
int fhse_device_get_hmac_secret(fhse_device_t* self, fhse_sbytes_t* out, fhse_cviews_t keys, fhse_cview_t salt, const char* pin)
{ return fhse_bad_argument; }
int fhse_device_cancel(fhse_device_t* self)
{ return fhse_bad_argument; }
#else
#include <assert.h>
#include <fido.h>
#include <stddef.h>
#include <string.h>

#include "fhse/memory.h"
#include "fhse/sbytes.h"
#include "private/cbor.h"
#include "private/config.h"
#include "private/utils.h"

struct fhse_device_t
{
  fido_dev_t* device;
  fhse_memory_t memory;
};

#define FHSE_FIDO_(rc, ...)     \
  do                            \
  {                             \
    if (rc == FIDO_ERR_SUCCESS) \
      rc = __VA_ARGS__;         \
  }                             \
  while (0)

#define FHSE_FIDO(...) \
  FHSE_FIDO_(rc, __VA_ARGS__)

static int convert_rc(int rc)
{
  switch (rc)
  {
    default:
      break;
    case FIDO_ERR_SUCCESS:
      return fhse_success;
    case FIDO_ERR_PIN_REQUIRED:
      return fhse_fido_needs_pin;
    case FIDO_ERR_NO_CREDENTIALS:
      return fhse_key_unavailable;
    case FIDO_ERR_CREDENTIAL_EXCLUDED:
      return fhse_duplicate_key;
    case FIDO_ERR_PIN_INVALID:
      return fhse_fido_pin_invalid;
    case FIDO_ERR_PIN_BLOCKED:
    case FIDO_ERR_PIN_AUTH_BLOCKED:
      return fhse_fido_pin_blocked;
    case FIDO_ERR_UNSUPPORTED_EXTENSION:
    case FIDO_ERR_UNSUPPORTED_OPTION:
      return fhse_fido_unsupported;
  }
  return fhse_fido_failure;
}

// The UV bit of the authenticator data flags (WebAuthn §6.1).
#define FHSE_FIDO_FLAG_UV 0x04

int fhse_device_construct(fhse_device_t** self, const char* path, struct fhse_memory_t const* memory)
{
  fhse_memory_t defaults = {0};
  fhse_memory_defaults(&defaults);
  if (!memory)
    memory = &defaults;
  if (!memory->realloc || !memory->free)
    return fhse_bad_argument;

  fido_dev_t* device = fido_dev_new();
  if (!device)
    return fhse_bad_alloc;

  int rc = fhse_fido_failure;
  if (fido_dev_open(device, path) == FIDO_ERR_SUCCESS)
  {
    *self = memory->realloc(NULL, sizeof(fhse_device_t), memory->context);
    if (*self)
    {
      (*self)->device = device;
      (*self)->memory = *memory;
      return fhse_success;
    }
    rc = fhse_bad_alloc;
  }

  if (device)
  {
    fido_dev_close(device);
    fido_dev_free(&device);
  }
  return rc;
}

void fhse_device_free(fhse_device_t** self)
{
  if (!self || !*self || !(*self)->memory.free)
    return;

  if ((*self)->device)
  {
    fido_dev_close((*self)->device);
    fido_dev_free(&(*self)->device);
  }

  fhse_memory_t mem = (*self)->memory;
  mem.free(*self, mem.context);
  *self = NULL;
}

void fhse_device_sbytes_free(fhse_device_t* self, fhse_sbytes_t* bytes)
{
  if (self && bytes)
    fhse_sbytes_free(bytes, &self->memory);
}

int fhse_device_generate_cred(fhse_device_t* self, fhse_sbytes_t* out, fhse_cview_t userid, const char* pin)
{
  const fhse_cviews_t none = {0};
  return fhse_device_generate_cred_excluding(self, out, userid, none, pin);
}

int fhse_device_generate_cred_excluding(fhse_device_t* self, fhse_sbytes_t* out, fhse_cview_t userid, fhse_cviews_t exclude, const char* pin)
{
  if (!self || !out || !userid.data)
    return fhse_bad_argument;
  if (exclude.count && !exclude.data)
    return fhse_bad_argument;
  // User verification is required, not optional: the credential is created
  // with credProtect level 3 below, and the hmac-secret an authenticator
  // returns with UV differs from the one without (CTAP 2.1 CredRandomWithUV),
  // so enrolling without the PIN would also lock the key out of later unlocks.
  if (!pin)
    return fhse_fido_needs_pin;

  fido_cred_t* cred = fido_cred_new();
  if (!cred)
    return fhse_bad_alloc;

  int rc = FIDO_ERR_SUCCESS;
  uint8_t challenge[1] = {1};
  FHSE_FIDO(fido_cred_set_type(cred, COSE_ES256));
  FHSE_FIDO(fido_cred_set_clientdata(cred, challenge, sizeof(challenge)));
  FHSE_FIDO(fido_cred_set_rk(cred, FIDO_OPT_FALSE));
  FHSE_FIDO(fido_cred_set_user(cred, userid.data, userid.length, NULL, "FHSE Encryption", NULL));
  FHSE_FIDO(fido_cred_set_rp(cred, FHSE_FIDO2_RP, NULL));
  FHSE_FIDO(fido_cred_set_extensions(cred, FIDO_EXT_HMAC_SECRET));
  FHSE_FIDO(fido_cred_set_prot(cred, FIDO_CRED_PROT_UV_REQUIRED));
  for (size_t i = 0; i < exclude.count; ++i)
    FHSE_FIDO(fido_cred_exclude(cred, (exclude.data + i)->data, (exclude.data + i)->length));
  FHSE_FIDO(fido_dev_make_cred(self->device, cred, pin));

  // An authenticator that ignored credProtect would hand back a credential
  // that unlocks with a touch alone. fido_cred_prot() returns the level that
  // was asked for; the key's own answer is in the authenticator data.
  if (rc == FIDO_ERR_SUCCESS)
  {
    const fhse_cview_t authdata = {
      .data = fido_cred_authdata_raw_ptr(cred),
      .length = fido_cred_authdata_raw_len(cred)
    };
    uint64_t level = 0;
    if (fhse_cbor_authdata_cred_protect(authdata, &level) != fhse_success ||
        level != FIDO_CRED_PROT_UV_REQUIRED)
      rc = FIDO_ERR_UNSUPPORTED_EXTENSION;
  }

  int rc2 = fhse_success;
  if (rc == FIDO_ERR_SUCCESS)
  {
    size_t length = fido_cred_id_len(cred);
    unsigned char const* const ptr = fido_cred_id_ptr(cred);
    rc2 = fhse_sbytes_realloc(out, length, &self->memory);
    if (ptr && length && rc2 == fhse_success)
      memcpy(out->data, ptr, out->length);
    else
      rc = FIDO_ERR_INVALID_COMMAND;
  }
 
  fido_cred_free(&cred);
  // A buffer that could not be allocated or locked is not the key's doing.
  return rc2 != fhse_success ? rc2 : convert_rc(rc);
}

int fhse_device_get_hmac_secret(fhse_device_t* self, fhse_sbytes_t* out, fhse_cviews_t keys, fhse_cview_t salt, const char* pin)
{
  if (!self || !out || !keys.data || !keys.count)
    return fhse_bad_argument;
  if (!pin)
    return fhse_fido_needs_pin;

  int rc = FIDO_ERR_SUCCESS;
  fido_assert_t* ass = fido_assert_new();
  if (!ass)
    return fhse_bad_alloc;

  uint8_t challenge[1] = {1};
  FHSE_FIDO(fido_assert_set_rp(ass, FHSE_FIDO2_RP));
  FHSE_FIDO(fido_assert_set_clientdata(ass, challenge, sizeof(challenge)));
  for (size_t i = 0; i < keys.count; ++i)
    FHSE_FIDO(fido_assert_allow_cred(ass, (keys.data + i)->data, (keys.data + i)->length));
  FHSE_FIDO(fido_assert_set_extensions(ass, FIDO_EXT_HMAC_SECRET));
  FHSE_FIDO(fido_assert_set_hmac_salt(ass, salt.data, salt.length));
  FHSE_FIDO(fido_dev_get_assert(self->device, ass, pin));

  // The output must come from the with-UV secret, or it will not match the
  // one taken at enrollment.
  if (rc == FIDO_ERR_SUCCESS && !(fido_assert_flags(ass, 0) & FHSE_FIDO_FLAG_UV))
    rc = FIDO_ERR_PIN_REQUIRED;

  int rc2 = fhse_success;
  if (rc == FIDO_ERR_SUCCESS)
  {
    size_t length = fido_assert_hmac_secret_len(ass, 0);
    rc2 = fhse_sbytes_realloc(out, length, &self->memory);
    unsigned char const* const ptr = fido_assert_hmac_secret_ptr(ass, 0);
    if (ptr && length && rc2 == fhse_success)
      memcpy(out->data, ptr, out->length);
    else
      rc = FIDO_ERR_INVALID_COMMAND;
  }

  fido_assert_free(&ass);
  return rc2 != fhse_success ? rc2 : convert_rc(rc);
}

int fhse_device_cancel(fhse_device_t* self)
{
  if (!self || !self->device)
    return fhse_bad_argument;
  return convert_rc(fido_dev_cancel(self->device));
}

#endif // FHSE_USE_LIBFIDO2
