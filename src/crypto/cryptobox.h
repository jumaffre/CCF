// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

extern "C"
{
#include <evercrypt/Hacl_NaCl.h>
}

#include <array>
#include <fmt/format_header_only.h>
#include <vector>

namespace crypto
{
  // Based on curve 25519
  constexpr size_t BOX_NONCE_SIZE = 24;
  constexpr size_t BOX_EXTRA_SIZE = 16;
  using BoxNonce = std::array<uint8_t, BOX_NONCE_SIZE>;

  class Box
  {
  public:
    static std::vector<uint8_t> create(
      const std::vector<uint8_t>& plain,
      BoxNonce& nonce,
      const std::vector<uint8_t>& recipient_public,
      const std::vector<uint8_t>& sender_private)
    {
      std::vector<uint8_t> cipher(plain.size() + BOX_EXTRA_SIZE);

      if (
        Hacl_NaCl_crypto_box_easy(
          cipher.data(),
          (uint8_t*)plain.data(),
          plain.size(),
          nonce.data(),
          (uint8_t*)recipient_public.data(),
          (uint8_t*)sender_private.data()) != 0)
      {
        throw std::logic_error("Box create() failed");
      }

      return cipher;
    };

    static std::vector<uint8_t> open(
      const std::vector<uint8_t>& cipher,
      BoxNonce& nonce,
      const std::vector<uint8_t>& sender_public,
      const std::vector<uint8_t>& recipient_private)
    {
      if (cipher.size() < BOX_EXTRA_SIZE)
      {
        throw std::logic_error(fmt::format(
          "Box cipher to open should be of length > {}", BOX_EXTRA_SIZE));
      }

      std::vector<uint8_t> plain(cipher.size() - BOX_EXTRA_SIZE);

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