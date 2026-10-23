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

#ifndef FHSE_HPP
#define FHSE_HPP

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>
#include "fhse.h"

namespace fhse
{
  enum class status : int { success = 0 };
  
  inline const char* get_string(const status value) noexcept
  {
    switch (int(value))
    {
    default:
      break;
    case fhse_bad_alloc:
      return "allocation failure";
    case fhse_bad_argument:
      return "invalid argument";
    case fhse_cbor_failure:
      return "internal cbor issue";
    case fhse_crypto_failure:
      return "cryptography function failed";
    case fhse_decryption_failure:
      return "failed to unlock data with given password or FIDO key";
    case fhse_duplicate_key:
      return "FIDO key is already enrolled";
    case fhse_fido_failure:
      return "Error occured in libfido2 library";
    case fhse_fido_needs_pin:
      return "Fido operation requires PIN";
    case fhse_key_unavailable:
      return "FIDO key is not enrolled";
    case fhse_mlock_failure:
      return "failed to lock memory to RAM";
    case fhse_fido_pin_invalid:
      return "FIDO PIN is incorrect";
    case fhse_fido_pin_blocked:
      return "FIDO PIN is blocked; the key must be reset";
    case fhse_fido_unsupported:
      return "FIDO key does not support hmac-secret with credProtect";
    }
    return "Unknown fhse error";
  }

  inline const std::error_category& error_category() noexcept
  {
    struct category final : std::error_category
    {
      virtual const char* name() const noexcept override final
        {
          return "fhse::error_category()";
        }

        virtual std::string message(int value) const override final
        {
          return get_string(status(value));
        }
    };
    static const category instance{};
    return instance;
  }

  inline std::error_code make_error_code(const status value) noexcept
  {
    return std::error_code{int(value), error_category()};
  }

  template<typename T>
  fhse_cview_t to_cview(const T& val)
  {
    return fhse_cview_t{
      .data =reinterpret_cast<const unsigned char*>(val.data()),
      .length = val.size()
    };
  }

  inline fhse_cview_t to_cview(const fhse_sbytes_t val)
  {
    return fhse_cview_t{.data = val.data, .length = val.length };
  }

  template<typename T>
  fhse_cviews_t to_cviews(const T& val)
  {
    return fhse_cviews_t{.data = val.data(), .count = val.size()};
  }

  struct free_secret
  {
    void operator()(fhse_secret_t* ptr) const noexcept
    { fhse_secret_free(&ptr); }
  };

  class secret
  {  
    std::unique_ptr<fhse_secret_t, free_secret> self_;

  public:
    explicit secret(fhse_memory_t const* memory = nullptr, fhse_crypto_t const* crypto = nullptr)
      : self_(nullptr)
    {
      fhse_secret_t* self = nullptr;
      int rc = fhse_secret_construct(&self, memory, crypto);
      if (rc != fhse_success)
        throw std::system_error{make_error_code(status(rc)), "fhse::secret constructor"};
      self_.reset(self);
    }

    secret(secret&&) noexcept = default;
    secret(const secret&) = delete;
    secret& operator=(secret&&) noexcept = default;
    secret& operator=(const secret&) = delete;

    fhse_cview_t get_secret() const noexcept { return fhse_secret_get(self_.get()); } 
    const char* get_ascii_secret() const noexcept { return fhse_secret_get_ascii(self_.get()); } 

    fhse_cview_t fido_userid() const noexcept { return fhse_secret_fido_userid(self_.get()); } 
    fhse_cview_t fido_salt() const noexcept { return fhse_secret_fido_salt(self_.get()); }

    std::size_t cred_count() const noexcept { return fhse_secret_cred_count(self_.get()); }
    fhse_cview_t cred(std::size_t i) const noexcept { return fhse_secret_cred(self_.get(), i); }
 
    status create(fhse_cview_t pass, fhse_cview_t seed = {}) noexcept
    { return status(fhse_secret_create(self_.get(), pass, seed)); }

    status open(fhse_cview_t source, fhse_cview_t pass) noexcept
    { return status(fhse_secret_open(self_.get(), source, pass)) ; }

    status store(std::vector<std::uint8_t>& out) const noexcept
    {
      fhse_bytes_t temp = {0};
      int rc = fhse_secret_store(self_.get(), &temp);
      if (rc == fhse_success)
      {
        try { out.assign(temp.data, temp.data + temp.length); }
        catch (...) { rc = fhse_bad_alloc; }
      }
      fhse_secret_bytes_free(self_.get(), &temp);
      return status(rc);
    }

    status unlock(fhse_cview_t hmac_secret) noexcept
    { return status(fhse_secret_unlock(self_.get(), hmac_secret)); }

    status add_key(fhse_cview_t fido_id, fhse_cview_t hmac_secret) noexcept
    { return status(fhse_secret_add_key(self_.get(), fido_id, hmac_secret)); }

    status remove_key(fhse_cview_t hmac_secret) noexcept
    { return status(fhse_secret_remove_key(self_.get(), hmac_secret)); }
  };

  struct free_device
  {
    void operator()(fhse_device_t* ptr) const noexcept
    { fhse_device_free(&ptr); }
  };

  struct device
  {
    std::unique_ptr<fhse_device_t, free_device> self_;

    struct unlock_op
    {
      status operator()(secret& sec, fhse_cview_t hmac_secret) const noexcept
      { return sec.unlock(hmac_secret); }
    };

    struct remove_key_op
    {
      status operator()(secret& sec, fhse_cview_t hmac_secret) const noexcept
      { return sec.remove_key(hmac_secret); }
    };

    template<typename F>
    status run_op(secret& sec, const char* pin, const F f) noexcept
    {
      std::vector<fhse_cview_t> keys{};
      {
        const std::size_t cred_count = sec.cred_count();
        for (std::size_t i = 0; i < cred_count; ++i)
          keys.push_back(sec.cred(i));
      }

      fhse_sbytes_t hmac_secret = {0};
      status rc = status(fhse_device_get_hmac_secret(self_.get(), &hmac_secret, to_cviews(keys), sec.fido_salt(), pin));
      if (rc == status::success)
        rc = f(sec, to_cview(hmac_secret));
      fhse_device_sbytes_free(self_.get(), &hmac_secret);
      return rc;
    }

  public:
    explicit device(const char* path, fhse_memory_t const* memory = nullptr)
      : self_(nullptr)
    {
      fhse_device_t* self = nullptr;
      int rc = fhse_device_construct(&self, path, memory);
      if (rc != fhse_success)
        throw std::system_error{make_error_code(status(rc)), "fhse::device constructor"};
      self_.reset(self);
    }

    device(device&&) noexcept = default;
    device(const device&) noexcept = delete;
    device& operator=(device&&) noexcept = default;
    device& operator=(const device&) noexcept = delete;

    status cancel() noexcept { return status(fhse_device_cancel(self_.get())); }

    // These functions block on user device interaction. Use `std::async`
    // with cancel function.

    status unlock(secret& sec, const char* pin = nullptr) noexcept
    { return run_op(sec, pin, unlock_op{}); }

    status add_to(secret& sec, const char* pin = nullptr) noexcept
    {
      fhse_sbytes_t cred = {0};
      fhse_sbytes_t hmac_secret = {0};
      std::vector<fhse_cview_t> existing{};
      {
        const std::size_t cred_count = sec.cred_count();
        for (std::size_t i = 0; i < cred_count; ++i)
          existing.push_back(sec.cred(i));
      }

      status rc = status(fhse_device_generate_cred_excluding(self_.get(), &cred, sec.fido_userid(), to_cviews(existing), pin));
      if (rc == status::success)
      {
        const fhse_cview_t cred_view = to_cview(cred);
        const fhse_cviews_t creds{.data = &cred_view, .count = 1};
        rc = status(fhse_device_get_hmac_secret(self_.get(), &hmac_secret, creds, sec.fido_salt(), pin));
        if (rc == status::success)
          rc = sec.add_key(to_cview(cred), to_cview(hmac_secret));
      }
      
      fhse_device_sbytes_free(self_.get(), &cred);
      fhse_device_sbytes_free(self_.get(), &hmac_secret);
      return rc;
    }

    status remove_from(secret& sec, const char* pin = nullptr) noexcept
    { return run_op(sec, pin, remove_key_op{}); }
  };
}

namespace std
{
  template<>
  struct is_error_code_enum<::fhse::status>
    : true_type
  {};
}

#endif // FHSE_HPP

