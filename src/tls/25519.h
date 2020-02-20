// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "pem.h"
#include "tls.h"

namespace tls
{
  // This function parses x25519 PEM keys generated by openssl (e.g. for
  // members' public encryption key) and returns the raw 32-byte key.
  static std::vector<uint8_t> parse_25519_public(const Pem& public_pem)
  {
    mbedtls_pem_context pem;
    mbedtls_pem_init(&pem);
    auto x25519_oid = std::vector<uint8_t>({0x2b, 0x65, 0x6e});
    auto pem_len = public_pem.size();

    if (
      mbedtls_pem_read_buffer(
        &pem,
        "-----BEGIN PUBLIC KEY-----",
        "-----END PUBLIC KEY-----",
        public_pem.data(),
        nullptr,
        0,
        &pem_len) != 0)
    {
      throw std::logic_error("parse_25519_public(): Failed to read PEM");
    }

    auto p = pem.buf;
    auto len = pem.buflen;
    auto end = pem.buf + pem.buflen;
    if (
      mbedtls_asn1_get_tag(
        &p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
    {
      throw std::logic_error("parse_25519_public(): Failed to parse tag");
    }

    mbedtls_pk_type_t pk_alg = MBEDTLS_PK_NONE;
    mbedtls_asn1_buf alg_oid;
    mbedtls_asn1_buf alg_params;
    if (mbedtls_asn1_get_alg(&p, end, &alg_oid, &alg_params) != 0)
    {
      throw std::logic_error("parse_25519_public(): Failed to parse alg");
    }

    if (memcmp(x25519_oid.data(), alg_oid.p, 3) != 0)
    {
      throw std::logic_error("parse_25519_public(): Key is not x25519");
    }

    if (mbedtls_asn1_get_bitstring_null(&p, end, &len) != 0)
    {
      throw std::logic_error("parse_25519_public(): Failed to parse bitstring");
    }

    std::vector<uint8_t> public_raw(p, end);
    mbedtls_pem_free(&pem);

    return public_raw;
  }
}