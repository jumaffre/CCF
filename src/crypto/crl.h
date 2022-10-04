// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "crypto/openssl/openssl_wrappers.h"

#include <openssl/bio.h>
#include <vector>

namespace crypto
{
  /** Converts a certificate revocation list (CRL) from DER to PEM.
   * @param crl_der CRL in DER format
   * @return CRL in PEM format
   */
  Pem crl_der_to_pem(const std::vector<uint8_t>& crl_der)
  {
    OpenSSL::Unique_X509_CRL crl(crl_der, false);

    Unique_BIO mem;
    CHECK1(PEM_write_bio_X509_CRL(mem, crl));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(mem, &bptr);
    return Pem((uint8_t*)bptr->data, bptr->length);
  }
}