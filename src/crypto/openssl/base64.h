// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/hex.h"
#include "ccf/ds/logger.h"
#include "crypto/openssl/openssl_wrappers.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <string>
#include <vector>

// Inspired by openssl/test/evp_test.c
// Ref: https://www.openssl.org/docs/man1.1.1/man3/EVP_DecodeBlock.html

namespace crypto
{
  struct Base64_openssl
  {
    // Decode Base64 into byte stream
    static std::vector<uint8_t> raw_from_b64(const std::string_view& b64_string)
    {
      const auto data = reinterpret_cast<const uint8_t*>(b64_string.data());
      const auto size = b64_string.size();

      if (size == 0)
      {
        return {};
      }

      // TODO: Check error codes

      BIO* bio_b64 = BIO_new(BIO_f_base64());
      BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);

      BIO* bio_mem = BIO_new_mem_buf(data, size);
      BIO_push(bio_b64, bio_mem);

      int max_size = EVP_DECODE_LENGTH(size);
      std::vector<uint8_t> buf(max_size);
      std::vector<uint8_t> ret;

      while (true)
      {
        auto nread = BIO_read(bio_b64, buf.data(), buf.size());
        if (nread < 0)
        {
          throw std::runtime_error(
            fmt::format("raw_from_b64: BIO_read failed: {}", nread));
        }
        if (nread == 0)
        {
          break;
        }

        ret.insert(ret.end(), buf.begin(), buf.begin() + nread);
      }

      BIO_free_all(bio_b64);

      return ret;
    }

    // Encode byte stream into Base64
    static std::string b64_from_raw(const uint8_t* data, size_t size)
    {
      if (size == 0)
      {
        return "";
      }

      // TODO: Check error codes

      BIO* bio_mem = BIO_new(BIO_s_mem());
      BIO* bio_b64 = BIO_new(BIO_f_base64());
      BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);

      bio_b64 = BIO_push(bio_b64, bio_mem);
      BIO_write(bio_b64, data, size);
      BIO_flush(bio_b64);

      char* encoded_data = nullptr;
      auto encoded_len = BIO_get_mem_data(bio_b64, &encoded_data);

      std::string ret(encoded_data, encoded_len);

      BIO_free_all(bio_b64);

      return ret;
    }
  };
}
