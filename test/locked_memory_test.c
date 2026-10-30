// Tests the locked blocks FHSE allocates from (src/wfhse.c): what FHSE reports
// when no block can be locked, FHSE's own flows with 1 to 50 keys, which also
// report how much of the blocks they use at their peak, damaged files, and a
// random sequence of allocations, resizes and frees checked against what each
// allocation should hold. The flows must leave nothing allocated.
//
// cmake -S src -B build/test -DWFHSE_BUILD_TESTS=ON
// cmake --build build/test && build/test/wfhse_test

#include <sodium/utils.h>

// Every block fails to lock while this is set, as when the process has used up
// its RLIMIT_MEMLOCK.
static int locks_fail;

static int test_mlock(void* const addr, const size_t len)
{
  return locks_fail ? -1 : sodium_mlock(addr, len);
}

#define sodium_mlock test_mlock
#include "wfhse.c"
#undef sodium_mlock

#include <stdio.h>

static int failures;

#define CHECK(cond)                                                    \
  do                                                                   \
  {                                                                    \
    if (!(cond))                                                       \
    {                                                                  \
      fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond); \
      failures++;                                                      \
    }                                                                  \
  } while (0)

static uint64_t rng = 0x9e3779b97f4a7c15u;

static uint64_t next(void)
{
  rng ^= rng << 13;
  rng ^= rng >> 7;
  rng ^= rng << 17;
  return rng;
}

static unsigned char pattern(unsigned seed, size_t i)
{
  return (unsigned char)(seed + i * 31);
}

// Bytes the blocks hand out (headers included), and how many blocks there are.
static size_t in_use(size_t* count)
{
  size_t used = 0, n = 0;
  for (wfhse_block* block = blocks; block; block = block->next, n++)
  {
    for (unsigned char* p = block->data; p < block->data + block->size; p += sizeof(wfhse_chunk) + ((wfhse_chunk*)p)->h.size)
    {
      if (((wfhse_chunk*)p)->h.used)
        used += sizeof(wfhse_chunk) + ((wfhse_chunk*)p)->h.size;
    }
  }
  if (count)
    *count = n;
  return used;
}

// ----- random allocations -----

#define SLOTS 64

static struct
{
  unsigned char* data;
  size_t length;
  unsigned seed;
} slot[SLOTS];

static void check_slots(void)
{
  for (size_t k = 0; k < SLOTS; k++)
  {
    if (!slot[k].data)
      continue;
    CHECK((uintptr_t)slot[k].data % 16 == 0);
    CHECK(memory_lock(slot[k].data, slot[k].length, NULL) == fhse_success);
    CHECK(memory_unlock(slot[k].data, slot[k].length, NULL) == fhse_success);
    for (size_t i = 0; i < slot[k].length; i++)
    {
      if (slot[k].data[i] != pattern(slot[k].seed, i))
      {
        CHECK(!"allocation changed");
        break;
      }
    }
    // no two allocations overlap
    for (size_t j = k + 1; j < SLOTS; j++)
    {
      if (!slot[j].data)
        continue;
      const uintptr_t a = (uintptr_t)slot[k].data, b = (uintptr_t)slot[j].data;
      CHECK(a + (slot[k].length ? slot[k].length : 1) <= b || b + (slot[j].length ? slot[j].length : 1) <= a);
    }
  }
}

static void random_allocations(void)
{
  size_t peak_blocks = 0;
  for (unsigned op = 0; op < 200000; op++)
  {
    const size_t k = next() % SLOTS;
    const uint64_t r = next();
    if (slot[k].data && r % 4 == 0)
    {
      unsigned char* data = slot[k].data;
      const size_t length = slot[k].length;
      memory_free(data, NULL);
      for (size_t i = 0; i < length; i++)
      {
        if (data[i])
        {
          CHECK(!"freed allocation not wiped");
          break;
        }
      }
      slot[k].data = NULL;
      slot[k].length = 0;
      continue;
    }

    size_t length = (r >> 8) % 600;
    if (r % 50 == 1)
      length = (r >> 8) % 5000;
    else if (r % 1000 == 2)
      length = 20000 + (r >> 8) % 20000; // larger than a block
    unsigned char* data = memory_realloc(slot[k].data, length, NULL);
    CHECK(data != NULL);
    if (!data)
      continue;
    const size_t kept = slot[k].length < length ? slot[k].length : length;
    for (size_t i = 0; i < kept; i++)
    {
      if (data[i] != pattern(slot[k].seed, i))
      {
        CHECK(!"resize lost data");
        break;
      }
    }
    for (size_t i = kept; i < length; i++)
      data[i] = pattern(slot[k].seed, i);
    slot[k].data = data;
    slot[k].length = length;

    if (op % 1000 == 0)
    {
      check_slots();
      size_t count = 0;
      in_use(&count);
      if (peak_blocks < count)
        peak_blocks = count;
    }
  }
  check_slots();

  // Memory outside the blocks is refused, and so is a range running past one.
  unsigned char stack[32];
  void* heap = malloc(32);
  CHECK(memory_lock(stack, sizeof stack, NULL) == fhse_mlock_failure);
  CHECK(memory_lock(heap, 32, NULL) == fhse_mlock_failure);
  CHECK(memory_realloc(heap, 64, NULL) == NULL);
  free(heap);
  CHECK(memory_lock(blocks->data, blocks->size + 1, NULL) == fhse_mlock_failure);
  CHECK(memory_lock(blocks->data + blocks->size - 16, 32, NULL) == fhse_mlock_failure);

  for (size_t k = 0; k < SLOTS; k++)
    memory_free(slot[k].data, NULL);
  CHECK(in_use(NULL) == 0);
  printf("random allocations: 200000 operations, up to %zu blocks\n", peak_blocks);
}

// ----- FHSE's flows -----

static size_t peak;

static void* counting_realloc(void* ptr, size_t size, void* context)
{
  void* out = memory_realloc(ptr, size, context);
  blocks_acquire();
  const size_t used = in_use(NULL);
  blocks_release();
  if (peak < used)
    peak = used;
  return out;
}

static fhse_secret_t* secret_new(void)
{
  static fhse_memory_t counting;
  counting = locked_memory;
  counting.realloc = counting_realloc;
  fhse_secret_t* self = NULL;
  CHECK(wfhse_init() == fhse_success);
  CHECK(fhse_secret_construct(&self, &counting, NULL) == fhse_success);
  return self;
}

// FhseVault's order: a password from a seed, setting keys up, unlocking, and
// setting up again while the unlocked file is held.
static void flows(size_t keys)
{
  uint8_t outer[32], seed[32], cred[64], hmac[32];
  char root[WFHSE_ROOT_Z85_SIZE], unlocked[WFHSE_ROOT_Z85_SIZE];
  for (size_t i = 0; i < 32; i++)
  {
    outer[i] = (uint8_t)(0x40 + i);
    seed[i] = (uint8_t)i;
  }
  peak = 0;

  fhse_secret_t* s = secret_new();
  CHECK(wfhse_secret_create(s, (const uint8_t*)"", 0, seed, sizeof seed) == fhse_success);
  CHECK(wfhse_secret_root_z85(s, root, sizeof root) == fhse_success);
  wfhse_secret_free(s);

  s = secret_new();
  CHECK(wfhse_secret_create(s, outer, sizeof outer, seed, sizeof seed) == fhse_success);
  CHECK(wfhse_secret_root_z85(s, root, sizeof root) == fhse_success);
  for (size_t k = 0; k < keys; k++)
  {
    memset(cred, (int)(k + 1), sizeof cred);
    memset(hmac, (int)(0x80 + k), sizeof hmac);
    CHECK(wfhse_secret_add_key(s, cred, sizeof cred, hmac, sizeof hmac) == fhse_success);
  }
  uint8_t* blob = NULL;
  size_t blob_len = 0;
  CHECK(wfhse_secret_store(s, &blob, &blob_len) == fhse_success);
  wfhse_secret_free(s);
  if (!blob)
    return;

  fhse_secret_t* session = secret_new();
  CHECK(wfhse_secret_open(session, blob, blob_len, outer, sizeof outer) == fhse_success);
  CHECK(wfhse_secret_cred_count(session) == keys);
  memset(hmac, 0x7f, sizeof hmac);
  CHECK(wfhse_secret_unlock(session, hmac, sizeof hmac) != fhse_success);
  memset(hmac, (int)(0x80 + keys - 1), sizeof hmac);
  CHECK(wfhse_secret_unlock(session, hmac, sizeof hmac) == fhse_success);
  CHECK(wfhse_secret_root_z85(session, unlocked, sizeof unlocked) == fhse_success);
  CHECK(strcmp(root, unlocked) == 0);

  s = secret_new();
  CHECK(wfhse_secret_create(s, outer, sizeof outer, seed, sizeof seed) == fhse_success);
  for (size_t k = 0; k < keys; k++)
  {
    memset(cred, (int)(k + 1), sizeof cred);
    memset(hmac, (int)(0x80 + k), sizeof hmac);
    CHECK(wfhse_secret_add_key(s, cred, sizeof cred, hmac, sizeof hmac) == fhse_success);
  }
  uint8_t* again = NULL;
  size_t again_len = 0;
  CHECK(wfhse_secret_store(s, &again, &again_len) == fhse_success);
  wfhse_free(again, again_len);
  wfhse_secret_free(session);
  wfhse_secret_free(s);
  wfhse_free(blob, blob_len);

  size_t count = 0;
  CHECK(in_use(&count) == 0);
  printf("%2zu keys: file %5zu bytes, peak use %5zu bytes, %zu block(s) so far\n", keys, blob_len, peak, count);
}

// Opening a damaged file, which fails part way, must leave nothing allocated:
// what leaks here stays in locked memory. A few bit flips still open: they turn
// a CBOR text string into a byte string, which FHSE reads the same way, so
// they must give the same root.
static void damaged_files(void)
{
  uint8_t outer[32], seed[32], cred[64], hmac[32];
  memset(outer, 0x40, sizeof outer);
  memset(seed, 0x01, sizeof seed);
  memset(cred, 0x02, sizeof cred);
  memset(hmac, 0x03, sizeof hmac);
  fhse_secret_t* s = secret_new();
  CHECK(wfhse_secret_create(s, outer, sizeof outer, seed, sizeof seed) == fhse_success);
  CHECK(wfhse_secret_add_key(s, cred, sizeof cred, hmac, sizeof hmac) == fhse_success);
  uint8_t* blob = NULL;
  size_t blob_len = 0;
  CHECK(wfhse_secret_store(s, &blob, &blob_len) == fhse_success);
  char root[WFHSE_ROOT_Z85_SIZE], opened[WFHSE_ROOT_Z85_SIZE];
  CHECK(wfhse_secret_root_z85(s, root, sizeof root) == fhse_success);
  wfhse_secret_free(s);
  if (!blob)
    return;

  size_t tries = 0, refused = 0;
  for (size_t i = 0; i < blob_len * 8 + blob_len; i++)
  {
    // every bit flipped in turn, then every shorter length
    const size_t length = i < blob_len * 8 ? blob_len : i - blob_len * 8;
    if (i < blob_len * 8)
      blob[i / 8] ^= (uint8_t)(1u << (i % 8));
    s = secret_new();
    int rc = length ? wfhse_secret_open(s, blob, length, outer, sizeof outer) : fhse_bad_argument;
    if (rc == fhse_success)
      rc = wfhse_secret_unlock(s, hmac, sizeof hmac);
    if (rc == fhse_success)
    {
      CHECK(wfhse_secret_root_z85(s, opened, sizeof opened) == fhse_success);
      CHECK(strcmp(root, opened) == 0);
    }
    wfhse_secret_free(s);
    if (i < blob_len * 8)
      blob[i / 8] ^= (uint8_t)(1u << (i % 8));
    tries++;
    refused += rc != fhse_success;
    if (in_use(NULL) != 0)
    {
      CHECK(!"a failed open left memory allocated");
      break;
    }
  }
  wfhse_free(blob, blob_len);
  printf("damaged files: %zu of %zu refused, the rest give the same root, nothing left allocated\n", refused, tries);
}

// With no block to be had, FHSE's buffers go to the heap, and the first secret
// one fails as fhse_mlock_failure. Run first, while there are no blocks.
static void no_lockable_memory(void)
{
  locks_fail = 1;
  unsigned char* data = memory_realloc(NULL, 100, NULL);
  CHECK(data != NULL && blocks == NULL);
  if (data)
  {
    for (size_t i = 0; i < 100; i++)
      data[i] = pattern(7, i);
    CHECK(memory_lock(data, 100, NULL) == fhse_mlock_failure);
    data = memory_realloc(data, 3000, NULL);
    CHECK(data != NULL);
    for (size_t i = 0; data && i < 100; i++)
    {
      if (data[i] != pattern(7, i))
      {
        CHECK(!"resize lost data");
        break;
      }
    }
    memory_free(data, NULL);
  }

  uint8_t pass[32], seed[32];
  memset(pass, 0x40, sizeof pass);
  memset(seed, 0x01, sizeof seed);
  fhse_secret_t* s = wfhse_secret_new();
  CHECK(s != NULL);
  CHECK(wfhse_secret_create(s, pass, sizeof pass, seed, sizeof seed) == fhse_mlock_failure);
  wfhse_secret_free(s);
  CHECK(spills == NULL && blocks == NULL);

  locks_fail = 0;
  printf("no lockable memory: fhse_mlock_failure, nothing left allocated\n");
}

int main(void)
{
  CHECK(sodium_init() != -1);
  no_lockable_memory();
  // The flows first, so the block count is what FHSE needed.
  const size_t keys[] = {1, 2, 5, 8, 9, 10, 20, 50};
  for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++)
    flows(keys[i]);
  damaged_files();
  random_allocations();
  if (failures)
  {
    printf("%d check(s) failed\n", failures);
    return 1;
  }
  printf("ok\n");
  return 0;
}
