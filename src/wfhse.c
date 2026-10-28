// clock_gettime and CLOCK_BOOTTIME (wfhse_boot_ns) under the C11 the build asks
// for; Apple's headers expose both regardless.
#if !defined(__APPLE__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif

#include "wfhse.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

// A stable Linux ABI value (Android included), should a libc header not name it.
#if defined(__linux__) && !defined(CLOCK_BOOTTIME)
#define CLOCK_BOOTTIME 7
#endif

#include <sodium/core.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/crypto_kdf_blake2b.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

static fhse_cview_t cview(const uint8_t* data, size_t length)
{
  fhse_cview_t out = {.data = data, .length = length};
  return out;
}

int wfhse_init(void)
{
  return sodium_init() == -1 ? fhse_crypto_failure : fhse_success;
}

fhse_secret_t* wfhse_secret_new(void)
{
  if (wfhse_init() != fhse_success)
    return NULL;
  fhse_secret_t* self = NULL;
  if (fhse_secret_construct(&self, NULL, NULL) != fhse_success)
    return NULL;
  return self;
}

void wfhse_secret_free(fhse_secret_t* self)
{
  fhse_secret_free(&self);
}

int wfhse_secret_create(fhse_secret_t* self, const uint8_t* pass, size_t pass_len, const uint8_t* seed, size_t seed_len)
{
  if (!self)
    return fhse_bad_argument;
  return fhse_secret_create(self, cview(pass, pass_len), cview(seed, seed_len));
}

int wfhse_secret_open(fhse_secret_t* self, const uint8_t* blob, size_t blob_len, const uint8_t* pass, size_t pass_len)
{
  if (!self || !blob || !blob_len)
    return fhse_bad_argument;
  return fhse_secret_open(self, cview(blob, blob_len), cview(pass, pass_len));
}

int wfhse_secret_store(fhse_secret_t* self, uint8_t** out, size_t* out_len)
{
  if (!self || !out || !out_len)
    return fhse_bad_argument;
  *out = NULL;
  *out_len = 0;

  fhse_bytes_t stored = {0};
  int rc = fhse_secret_store(self, &stored);
  if (rc == fhse_success)
  {
    uint8_t* copy = malloc(stored.length);
    if (copy)
    {
      memcpy(copy, stored.data, stored.length);
      *out = copy;
      *out_len = stored.length;
    }
    else
      rc = fhse_bad_alloc;
  }
  fhse_secret_bytes_free(self, &stored);
  return rc;
}

size_t wfhse_secret_cred_count(fhse_secret_t* self)
{
  return fhse_secret_cred_count(self);
}

static int borrow(fhse_cview_t view, const uint8_t** out, size_t* out_len)
{
  if (!out || !out_len)
    return fhse_bad_argument;
  *out = view.data;
  *out_len = view.length;
  return view.data ? fhse_success : fhse_bad_argument;
}

int wfhse_secret_cred(fhse_secret_t* self, size_t index, const uint8_t** out, size_t* out_len)
{
  return borrow(fhse_secret_cred(self, index), out, out_len);
}

int wfhse_secret_fido_userid(fhse_secret_t* self, const uint8_t** out, size_t* out_len)
{
  return borrow(fhse_secret_fido_userid(self), out, out_len);
}

int wfhse_secret_fido_salt(fhse_secret_t* self, const uint8_t** out, size_t* out_len)
{
  return borrow(fhse_secret_fido_salt(self), out, out_len);
}

int wfhse_secret_unlock(fhse_secret_t* self, const uint8_t* hmac_secret, size_t hmac_secret_len)
{
  if (!self || !hmac_secret)
    return fhse_bad_argument;
  return fhse_secret_unlock(self, cview(hmac_secret, hmac_secret_len));
}

int wfhse_secret_add_key(fhse_secret_t* self, const uint8_t* cred, size_t cred_len, const uint8_t* hmac_secret, size_t hmac_secret_len)
{
  if (!self || !cred || !cred_len || !hmac_secret)
    return fhse_bad_argument;
  return fhse_secret_add_key(self, cview(cred, cred_len), cview(hmac_secret, hmac_secret_len));
}

int wfhse_secret_root_z85(fhse_secret_t* self, char* out, size_t out_len)
{
  if (!self || !out)
    return fhse_bad_argument;
  const char* ascii = fhse_secret_get_ascii(self);
  if (!ascii)
    return WFHSE_NOT_UNLOCKED;
  const size_t length = strlen(ascii) + 1;
  if (out_len < length)
    return WFHSE_BUFFER_TOO_SMALL;
  memcpy(out, ascii, length);
  return fhse_success;
}

int wfhse_kdf(const uint8_t* key, size_t key_len, const uint8_t* context, size_t context_len, uint8_t* out, size_t out_len)
{
  if (!key || key_len != crypto_kdf_blake2b_KEYBYTES || !out)
    return fhse_bad_argument;
  if (!context || crypto_kdf_blake2b_CONTEXTBYTES < context_len)
    return fhse_bad_argument;
  if (out_len < crypto_kdf_blake2b_BYTES_MIN || crypto_kdf_blake2b_BYTES_MAX < out_len)
    return fhse_bad_argument;
  if (wfhse_init() != fhse_success)
    return fhse_crypto_failure;

  char ctx[crypto_kdf_blake2b_CONTEXTBYTES] = {0};
  memcpy(ctx, context, context_len);
  return crypto_kdf_blake2b_derive_from_key(out, out_len, 0, ctx, key) == 0 ? fhse_success : fhse_crypto_failure;
}

int wfhse_hash_personal(const uint8_t* message, size_t message_len, const uint8_t* personal, size_t personal_len, uint8_t* out, size_t out_len)
{
  if (!message || !out || !personal || crypto_generichash_blake2b_PERSONALBYTES < personal_len)
    return fhse_bad_argument;
  if (out_len < crypto_generichash_blake2b_BYTES_MIN || crypto_generichash_blake2b_BYTES_MAX < out_len)
    return fhse_bad_argument;
  if (wfhse_init() != fhse_success)
    return fhse_crypto_failure;

  unsigned char salt[crypto_generichash_blake2b_SALTBYTES] = {0};
  unsigned char pers[crypto_generichash_blake2b_PERSONALBYTES] = {0};
  memcpy(pers, personal, personal_len);
  const int rc = crypto_generichash_blake2b_salt_personal(out, out_len, message, message_len, NULL, 0, salt, pers);
  return rc == 0 ? fhse_success : fhse_crypto_failure;
}

static int aead_arguments(const uint8_t* out, const uint8_t* in, size_t in_len, const uint8_t* ad, size_t ad_len, const uint8_t* nonce, size_t nonce_len, const uint8_t* key, size_t key_len)
{
  if (!out || (!in && in_len) || (!ad && ad_len) || !nonce || !key)
    return fhse_bad_argument;
  if (nonce_len != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES || key_len != crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
    return fhse_bad_argument;
  return wfhse_init() == fhse_success ? fhse_success : fhse_crypto_failure;
}

int wfhse_xchacha20poly1305_encrypt(uint8_t* out, size_t out_len, const uint8_t* in, size_t in_len, const uint8_t* ad, size_t ad_len, const uint8_t* nonce, size_t nonce_len, const uint8_t* key, size_t key_len)
{
  if (in_len > crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX || out_len != in_len + crypto_aead_xchacha20poly1305_ietf_ABYTES)
    return fhse_bad_argument;
  const int rc = aead_arguments(out, in, in_len, ad, ad_len, nonce, nonce_len, key, key_len);
  if (rc != fhse_success)
    return rc;
  unsigned long long written = 0;
  if (crypto_aead_xchacha20poly1305_ietf_encrypt(out, &written, in, in_len, ad, ad_len, NULL, nonce, key) != 0)
    return fhse_crypto_failure;
  return written == out_len ? fhse_success : fhse_crypto_failure;
}

int wfhse_xchacha20poly1305_decrypt(uint8_t* out, size_t out_len, const uint8_t* in, size_t in_len, const uint8_t* ad, size_t ad_len, const uint8_t* nonce, size_t nonce_len, const uint8_t* key, size_t key_len)
{
  if (in_len < crypto_aead_xchacha20poly1305_ietf_ABYTES || out_len != in_len - crypto_aead_xchacha20poly1305_ietf_ABYTES)
    return fhse_bad_argument;
  const int rc = aead_arguments(out, in, in_len, ad, ad_len, nonce, nonce_len, key, key_len);
  if (rc != fhse_success)
    return rc;
  unsigned long long written = 0;
  // libsodium checks the tag before it decrypts, and zeroes `out` on a mismatch.
  if (crypto_aead_xchacha20poly1305_ietf_decrypt(out, &written, NULL, in, in_len, ad, ad_len, nonce, key) != 0)
    return fhse_decryption_failure;
  return written == out_len ? fhse_success : fhse_crypto_failure;
}

int wfhse_random(uint8_t* out, size_t out_len)
{
  if (!out)
    return fhse_bad_argument;
  if (wfhse_init() != fhse_success)
    return fhse_crypto_failure;
  randombytes_buf(out, out_len);
  return fhse_success;
}

void wfhse_free(uint8_t* ptr, size_t len)
{
  if (!ptr)
    return;
  sodium_memzero(ptr, len);
  free(ptr);
}

void wfhse_memzero(void* ptr, size_t len)
{
  if (ptr)
    sodium_memzero(ptr, len);
}

int64_t wfhse_boot_ns(void)
{
#if defined(__APPLE__)
  // Apple's CLOCK_MONOTONIC keeps counting while the device sleeps
  // (CLOCK_UPTIME_RAW is the one that stops) and is not settable.
  const uint64_t ns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
  return ns == 0 ? -1 : (int64_t)ns;
#elif defined(_WIN32)
  // Milliseconds since boot. It is not settable, and unlike
  // QueryUnbiasedInterruptTime it does not leave out time asleep.
  return (int64_t)GetTickCount64() * 1000000LL;
#elif defined(CLOCK_BOOTTIME)
  // Linux's CLOCK_MONOTONIC stops during suspend; CLOCK_BOOTTIME does not.
  struct timespec ts;
  if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0)
    return -1;
  return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
#else
  return -1;
#endif
}
