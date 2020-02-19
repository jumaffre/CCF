// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

extern "C"
{
#include <evercrypt/EverCrypt_Curve25519.h>
#include <evercrypt/Hacl_NaCl.h>
}

#include <array>
#include <fmt/format_header_only.h>
#include <vector>

namespace crypto
{
  class BoxKey
  {
  public:
    static constexpr size_t KEY_SIZE = 32;

    static std::vector<uint8_t> public_from_private(
      std::vector<uint8_t>& private_key)
    {
      if (private_key.size() != KEY_SIZE)
      {
        throw std::logic_error(
          fmt::format("Private key size is not {}", KEY_SIZE));
      }

      std::vector<uint8_t> public_key(KEY_SIZE);
      EverCrypt_Curve25519_secret_to_public(
        public_key.data(), private_key.data());

      return public_key;
    }
  };

  class Box
  {
  public:
    static constexpr size_t NONCE_SIZE = 24;
    static constexpr size_t EXTRA_SIZE = 16;
    using Nonce = std::array<uint8_t, NONCE_SIZE>;

    static std::vector<uint8_t> create(
      std::vector<uint8_t>& plain,
      Nonce& nonce,
      std::vector<uint8_t>& recipient_public,
      std::vector<uint8_t>& sender_private)
    {
      std::vector<uint8_t> cipher(plain.size() + EXTRA_SIZE);

      if (
        Hacl_NaCl_crypto_box_easy(
          cipher.data(),
          plain.data(),
          plain.size(),
          nonce.data(),
          recipient_public.data(),
          sender_private.data()) != 0)
      {
        throw std::logic_error("Box create() failed");
      }

      return cipher;
    };

    static std::vector<uint8_t> open(
      const std::vector<uint8_t>& cipher,
      Nonce& nonce,
      const std::vector<uint8_t>& sender_public,
      const std::vector<uint8_t>& recipient_private)
    {
      if (cipher.size() < EXTRA_SIZE)
      {
        throw std::logic_error(fmt::format(
          "Box cipher to open should be of length > {}", EXTRA_SIZE));
      }

      std::vector<uint8_t> plain(cipher.size() - EXTRA_SIZE);

      if (
        Hacl_NaCl_crypto_box_open_easy(
          plain.data(),
          (uint8_t*)cipher.data(),
          cipher.size(),
          nonce.data(),
          (uint8_t*)sender_public.data(),
          (uint8_t*)recipient_private.data()) != 0)
      {
        throw std::logic_error("Box open() failed");
      }
      return plain;
    }
  };
}