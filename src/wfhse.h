// The C interface the Dart sides of wallet_fhse and wallet_backup bind to by
// hand.
//
// A thin layer over FHSE's own API (vendor/fhse/include/fhse.h), so the only
// symbols this library exports are these. It adds what FHSE leaves to its
// caller: flat pointer+length arguments that are easy to pass through
// dart:ffi, copies of FHSE-owned output into buffers Dart frees with
// `wfhse_free`, the two libsodium hashes the wallet's key tree uses, and
// libsodium's XChaCha20-Poly1305, which seals wallet_backup's files.
//
// Every function returning int returns an `enum fhse_error` value (0 is
// success) or one of the WFHSE_* codes below.

#ifndef WFHSE_H
#define WFHSE_H

#include <stddef.h>
#include <stdint.h>

#include "fhse.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#define WFHSE_EXPORT __declspec(dllexport)
#else
#define WFHSE_EXPORT __attribute__((visibility("default"))) __attribute__((used))
#endif

// Codes above FHSE's own range.
#define WFHSE_BUFFER_TOO_SMALL 100
#define WFHSE_NOT_UNLOCKED 101

// Size of the z85 root FHSE produces, including the terminating NUL.
#define WFHSE_ROOT_Z85_SIZE 41

WFHSE_EXPORT int wfhse_init(void);

WFHSE_EXPORT fhse_secret_t* wfhse_secret_new(void);
WFHSE_EXPORT void wfhse_secret_free(fhse_secret_t* self);

WFHSE_EXPORT int wfhse_secret_create(fhse_secret_t* self, const uint8_t* pass, size_t pass_len, const uint8_t* seed, size_t seed_len);
WFHSE_EXPORT int wfhse_secret_open(fhse_secret_t* self, const uint8_t* blob, size_t blob_len, const uint8_t* pass, size_t pass_len);

//! On success `*out` is a malloc'd copy of the stored blob; free it with `wfhse_free`.
WFHSE_EXPORT int wfhse_secret_store(fhse_secret_t* self, uint8_t** out, size_t* out_len);

WFHSE_EXPORT size_t wfhse_secret_cred_count(fhse_secret_t* self);

//! Borrowed views into `self`; valid until the next call that changes it.
WFHSE_EXPORT int wfhse_secret_cred(fhse_secret_t* self, size_t index, const uint8_t** out, size_t* out_len);
WFHSE_EXPORT int wfhse_secret_fido_userid(fhse_secret_t* self, const uint8_t** out, size_t* out_len);
WFHSE_EXPORT int wfhse_secret_fido_salt(fhse_secret_t* self, const uint8_t** out, size_t* out_len);

WFHSE_EXPORT int wfhse_secret_unlock(fhse_secret_t* self, const uint8_t* hmac_secret, size_t hmac_secret_len);
WFHSE_EXPORT int wfhse_secret_add_key(fhse_secret_t* self, const uint8_t* cred, size_t cred_len, const uint8_t* hmac_secret, size_t hmac_secret_len);

//! Copies the unlocked (or just created) root as z85 text, NUL included, into
//! `out`, which must hold WFHSE_ROOT_Z85_SIZE bytes.
WFHSE_EXPORT int wfhse_secret_root_z85(fhse_secret_t* self, char* out, size_t out_len);

//! libsodium crypto_kdf_blake2b_derive_from_key with subkey id 0: a 32-byte
//! key and a context of at most 8 bytes (zero-padded) give a 32-byte subkey.
WFHSE_EXPORT int wfhse_kdf(const uint8_t* key, size_t key_len, const uint8_t* context, size_t context_len, uint8_t* out, size_t out_len);

//! Unkeyed BLAKE2b-256 of `message` with a personalisation of at most 16
//! bytes (zero-padded) and a zero salt.
WFHSE_EXPORT int wfhse_hash_personal(const uint8_t* message, size_t message_len, const uint8_t* personal, size_t personal_len, uint8_t* out, size_t out_len);

//! libsodium crypto_aead_xchacha20poly1305_ietf_encrypt: a 32-byte key and a
//! 24-byte nonce. `out` receives the ciphertext followed by the 16-byte tag,
//! so `out_len` must be `in_len + 16`.
WFHSE_EXPORT int wfhse_xchacha20poly1305_encrypt(uint8_t* out, size_t out_len, const uint8_t* in, size_t in_len, const uint8_t* ad, size_t ad_len, const uint8_t* nonce, size_t nonce_len, const uint8_t* key, size_t key_len);

//! libsodium crypto_aead_xchacha20poly1305_ietf_decrypt, the inverse: `in` is
//! the ciphertext followed by the tag, and `out_len` must be `in_len - 16`.
//! fhse_decryption_failure, with `out` zeroed, if the tag does not match the
//! key, nonce, `ad` and ciphertext.
WFHSE_EXPORT int wfhse_xchacha20poly1305_decrypt(uint8_t* out, size_t out_len, const uint8_t* in, size_t in_len, const uint8_t* ad, size_t ad_len, const uint8_t* nonce, size_t nonce_len, const uint8_t* key, size_t key_len);

WFHSE_EXPORT int wfhse_random(uint8_t* out, size_t out_len);

//! Wipes then frees a buffer this library returned.
WFHSE_EXPORT void wfhse_free(uint8_t* ptr, size_t len);

//! Wipes memory Dart allocated (calloc) before it frees it.
WFHSE_EXPORT void wfhse_memzero(void* ptr, size_t len);

//! Nanoseconds on a clock that keeps counting while the device sleeps and that
//! the user cannot set: CLOCK_BOOTTIME on Linux and Android, CLOCK_MONOTONIC on
//! Apple platforms (which, unlike Linux's, includes sleep), GetTickCount64 on
//! Windows (milliseconds). -1 when unreadable.
//! For "Fully lock after", whose deadline must survive both a sleeping phone and
//! a clock set back.
WFHSE_EXPORT int64_t wfhse_boot_ns(void);

#ifdef __cplusplus
}
#endif
#endif // WFHSE_H
