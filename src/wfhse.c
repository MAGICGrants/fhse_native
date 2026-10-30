// clock_gettime and CLOCK_BOOTTIME (wfhse_boot_ns) under the C11 the build asks
// for; Apple's headers expose both regardless.
#if !defined(__APPLE__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif

#include "wfhse.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <pthread.h>
#endif

#include <stdint.h>
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

#include "fhse/memory.h"

static fhse_cview_t cview(const uint8_t* data, size_t length)
{
  fhse_cview_t out = {.data = data, .length = length};
  return out;
}

// ----- FHSE's memory: locked blocks -----
//
// FHSE's default memory functions lock each secret buffer on its own. Each
// allocator size class then sits on a page of its own, so setting a key up
// needs 5 locked pages, while Android lets an app lock 64 KiB: 4 pages on a
// 16 KB-page phone. Locks do not stack on Linux or Windows either, so freeing
// one buffer unlocked a page that other secrets still used. Instead, every
// FHSE allocation comes from blocks that are locked once, when made, and stay
// locked while the process runs. FHSE's mlock and munlock only check that a
// buffer lies in a block, so a secret still never sits in unlocked memory, and
// a block that cannot be locked is not used. One 16 KiB block holds what FHSE
// needs with up to 7 keys; more keys add blocks (3 for 20 keys, 5 for 50).
// FHSE's non-secret buffers come from the same blocks, as it has one allocator
// for both.
//
// When no block can be locked (the process has used up its RLIMIT_MEMLOCK),
// an allocation comes from the heap instead, as with FHSE's defaults. FHSE
// locks each secret buffer before writing to it, and memory_lock refuses one
// on the heap, so FHSE reports fhse_mlock_failure and frees it unused; only
// non-secret buffers stay on the heap.
//
// Build with WFHSE_SYSTEM_ALLOCATOR to use FHSE's default instead, so that
// AddressSanitizer sees each buffer.

#if !defined(WFHSE_SYSTEM_ALLOCATOR)

#define WFHSE_BLOCK_SIZE (16 * 1024)

// Each allocation follows one of these, inside its block. Sizes are multiples
// of it, so every allocation is 16-byte aligned on 32-bit targets as well.
typedef union wfhse_chunk
{
  struct
  {
    size_t size; // bytes after the header
    size_t used;
  } h;
  unsigned char align[16];
} wfhse_chunk;

typedef struct wfhse_block
{
  struct wfhse_block* next;
  unsigned char* data;
  size_t size;
} wfhse_block;

static wfhse_block* blocks;

#if defined(_WIN32)
static SRWLOCK blocks_mutex = SRWLOCK_INIT;
static void blocks_acquire(void) { AcquireSRWLockExclusive(&blocks_mutex); }
static void blocks_release(void) { ReleaseSRWLockExclusive(&blocks_mutex); }
#else
static pthread_mutex_t blocks_mutex = PTHREAD_MUTEX_INITIALIZER;
static void blocks_acquire(void) { pthread_mutex_lock(&blocks_mutex); }
static void blocks_release(void) { pthread_mutex_unlock(&blocks_mutex); }
#endif

// Appends a locked block with room for `size` bytes after a header.
static wfhse_block* block_new(size_t size)
{
  if (SIZE_MAX - 2 * WFHSE_BLOCK_SIZE < size)
    return NULL;
  // sodium_malloc gives the block pages of its own, between guard pages and
  // out of core dumps. Its 16-byte canary sits just before the data, so a
  // multiple of WFHSE_BLOCK_SIZE less 16 fills whole pages and keeps the data
  // 16-byte aligned.
  const size_t length = (size + sizeof(wfhse_chunk) + 16 + WFHSE_BLOCK_SIZE - 1) / WFHSE_BLOCK_SIZE * WFHSE_BLOCK_SIZE - 16;
  wfhse_block* block = malloc(sizeof(wfhse_block));
  if (!block)
    return NULL;
  block->next = NULL;
  block->data = sodium_malloc(length);
  // sodium_malloc counts a failed lock as no error, so lock again and check.
  // Pages already locked take nothing more from Linux's RLIMIT_MEMLOCK.
  if (!block->data || ((uintptr_t)block->data % sizeof(wfhse_chunk)) != 0 || sodium_mlock(block->data, length) != 0)
  {
    if (block->data)
      sodium_free(block->data);
    free(block);
    return NULL;
  }
  block->size = length;
  wfhse_chunk* first = (wfhse_chunk*)block->data;
  first->h.size = length - sizeof(wfhse_chunk);
  first->h.used = 0;

  wfhse_block** last = &blocks;
  while (*last)
    last = &(*last)->next;
  *last = block;
  return block;
}

// First fit, merging free neighbours on the way.
static void* block_alloc(wfhse_block* block, size_t size)
{
  unsigned char* const end = block->data + block->size;
  for (unsigned char* p = block->data; p < end; p += sizeof(wfhse_chunk) + ((wfhse_chunk*)p)->h.size)
  {
    wfhse_chunk* chunk = (wfhse_chunk*)p;
    if (chunk->h.used)
      continue;
    for (unsigned char* next = p + sizeof(wfhse_chunk) + chunk->h.size; next < end && !((wfhse_chunk*)next)->h.used;)
    {
      chunk->h.size += sizeof(wfhse_chunk) + ((wfhse_chunk*)next)->h.size;
      next = p + sizeof(wfhse_chunk) + chunk->h.size;
    }
    if (chunk->h.size < size)
      continue;
    if (2 * sizeof(wfhse_chunk) <= chunk->h.size - size)
    {
      wfhse_chunk* rest = (wfhse_chunk*)(p + sizeof(wfhse_chunk) + size);
      rest->h.size = chunk->h.size - size - sizeof(wfhse_chunk);
      rest->h.used = 0;
      chunk->h.size = size;
    }
    chunk->h.used = 1;
    return chunk + 1;
  }
  return NULL;
}

// The header of the allocation at `ptr`, or NULL if no block has one there.
static wfhse_chunk* chunk_of(const void* ptr)
{
  const uintptr_t at = (uintptr_t)ptr;
  for (wfhse_block* block = blocks; block; block = block->next)
  {
    const uintptr_t start = (uintptr_t)block->data;
    if (at < start || start + block->size <= at)
      continue;
    for (unsigned char* p = block->data; p < block->data + block->size; p += sizeof(wfhse_chunk) + ((wfhse_chunk*)p)->h.size)
    {
      if ((uintptr_t)(p + sizeof(wfhse_chunk)) == at)
        return ((wfhse_chunk*)p)->h.used ? (wfhse_chunk*)p : NULL;
    }
    return NULL;
  }
  return NULL;
}

static void chunk_free(wfhse_chunk* chunk)
{
  sodium_memzero(chunk + 1, chunk->h.size);
  chunk->h.used = 0;
}

// An allocation on the heap, which no block could take.
typedef union wfhse_spill
{
  struct
  {
    union wfhse_spill* next;
    size_t size; // bytes after the header
  } h;
  unsigned char align[16];
} wfhse_spill;

static wfhse_spill* spills;

static void* spill_new(size_t size)
{
  if (SIZE_MAX - sizeof(wfhse_spill) < size)
    return NULL;
  wfhse_spill* spill = malloc(sizeof(wfhse_spill) + size);
  if (!spill)
    return NULL;
  spill->h.next = spills;
  spill->h.size = size;
  spills = spill;
  return spill + 1;
}

// The header of the heap allocation at `ptr`, or NULL if there is none.
static wfhse_spill* spill_of(const void* ptr)
{
  for (wfhse_spill* spill = spills; spill; spill = spill->h.next)
  {
    if ((const void*)(spill + 1) == ptr)
      return spill;
  }
  return NULL;
}

static void spill_free(wfhse_spill* spill)
{
  wfhse_spill** link = &spills;
  while (*link != spill)
    link = &(*link)->h.next;
  *link = spill->h.next;
  sodium_memzero(spill + 1, spill->h.size);
  free(spill);
}

static void* chunk_realloc(void* ptr, size_t size)
{
  wfhse_chunk* old = NULL;
  wfhse_spill* spilled = NULL;
  if (ptr && !(old = chunk_of(ptr)) && !(spilled = spill_of(ptr)))
    return NULL;
  if (old && size <= old->h.size)
  {
    if (2 * sizeof(wfhse_chunk) <= old->h.size - size)
    {
      wfhse_chunk* rest = (wfhse_chunk*)((unsigned char*)ptr + size);
      rest->h.size = old->h.size - size - sizeof(wfhse_chunk);
      rest->h.used = 1;
      old->h.size = size;
      chunk_free(rest);
    }
    return ptr;
  }
  if (spilled && size <= spilled->h.size)
    return ptr;

  void* out = NULL;
  for (wfhse_block* block = blocks; block && !out; block = block->next)
    out = block_alloc(block, size);
  if (!out)
  {
    wfhse_block* block = block_new(size);
    if (block)
      out = block_alloc(block, size);
  }
  if (!out)
    out = spill_new(size);
  if (out && old)
  {
    memcpy(out, ptr, old->h.size);
    chunk_free(old);
  }
  else if (out && spilled)
  {
    memcpy(out, ptr, spilled->h.size);
    spill_free(spilled);
  }
  return out;
}

static void* memory_realloc(void* ptr, size_t size, void* context)
{
  (void)context;
  if (SIZE_MAX - 2 * WFHSE_BLOCK_SIZE < size)
    return NULL;
  // Rounded up to whole headers; zero bytes still get an allocation, as from
  // sodium_malloc.
  size = size ? (size + sizeof(wfhse_chunk) - 1) / sizeof(wfhse_chunk) * sizeof(wfhse_chunk) : sizeof(wfhse_chunk);
  blocks_acquire();
  void* out = chunk_realloc(ptr, size);
  blocks_release();
  return out;
}

static void memory_free(void* ptr, void* context)
{
  (void)context;
  if (!ptr)
    return;
  blocks_acquire();
  wfhse_chunk* chunk = chunk_of(ptr);
  wfhse_spill* spill = chunk ? NULL : spill_of(ptr);
  if (chunk)
    chunk_free(chunk);
  else if (spill)
    spill_free(spill);
  blocks_release();
}

// The blocks are locked already: a buffer only has to lie inside one. One on
// the heap is refused.
static int memory_lock(void* ptr, size_t length, void* context)
{
  (void)context;
  int rc = fhse_mlock_failure;
  const uintptr_t at = (uintptr_t)ptr;
  blocks_acquire();
  for (wfhse_block* block = blocks; block; block = block->next)
  {
    const uintptr_t start = (uintptr_t)block->data;
    if (start <= at && length <= block->size && at - start <= block->size - length)
    {
      rc = fhse_success;
      break;
    }
  }
  blocks_release();
  return rc;
}

// FHSE has wiped the buffer; its block stays locked for the rest.
static int memory_unlock(void* ptr, size_t length, void* context)
{
  return memory_lock(ptr, length, context);
}

static void memory_zero(void* ptr, size_t length, void* context)
{
  (void)context;
  if (ptr)
    sodium_memzero(ptr, length);
}

static const fhse_memory_t locked_memory = {
  .context = NULL,
  .realloc = memory_realloc,
  .free = memory_free,
  .mlock = memory_lock,
  .munlock = memory_unlock,
  .memzero = memory_zero,
};

#endif // !WFHSE_SYSTEM_ALLOCATOR

int wfhse_init(void)
{
  return sodium_init() == -1 ? fhse_crypto_failure : fhse_success;
}

fhse_secret_t* wfhse_secret_new(void)
{
  if (wfhse_init() != fhse_success)
    return NULL;
#if defined(WFHSE_SYSTEM_ALLOCATOR)
  const fhse_memory_t* memory = NULL;
#else
  const fhse_memory_t* memory = &locked_memory;
#endif
  fhse_secret_t* self = NULL;
  if (fhse_secret_construct(&self, memory, NULL) != fhse_success)
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
