// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../cryptobox.h"
#include "../hash.h"
#include "../symmkey.h"
#include "../tls/base64.h"

#include <doctest/doctest.h>
#include <iomanip>
#include <vector>

using namespace crypto;
using namespace std;

static const vector<uint8_t>& getRawKey()
{
  static const vector<uint8_t> v(16, '$');
  return v;
}

TEST_CASE("ExtendedIv0")
{
  KeyAesGcm k(getRawKey());
  // setup plain text
  unsigned char rawP[100];
  memset(rawP, 'x', sizeof(rawP));
  Buffer p{rawP, sizeof(rawP)};
  // test large IV
  GcmHeader<1234> h;
  k.encrypt(h.get_iv(), p, nullb, p.p, h.tag);

  KeyAesGcm k2(getRawKey());
  REQUIRE(k2.decrypt(h.get_iv(), h.tag, p, nullb, p.p));
}

TEST_CASE("SHA256 short consistency test")
{
  std::vector<uint8_t> data = {'a', 'b', 'c', '\n'};
  crypto::Sha256Hash h1, h2;
  crypto::Sha256Hash::evercrypt_sha256({data}, h1.h);
  crypto::Sha256Hash::mbedtls_sha256({data}, h2.h);
  REQUIRE(h1 == h2);
}

TEST_CASE("SHA256 %32 consistency test")
{
  std::vector<uint8_t> data(32);
  for (unsigned i = 0; i < 32; i++)
    data[i] = i;
  crypto::Sha256Hash h1, h2;
  crypto::Sha256Hash::evercrypt_sha256({data}, h1.h);
  crypto::Sha256Hash::mbedtls_sha256({data}, h2.h);
  REQUIRE(h1 == h2);
}

TEST_CASE("SHA256 long consistency test")
{
  std::vector<uint8_t> data(512);
  for (unsigned i = 0; i < 512; i++)
    data[i] = i;
  crypto::Sha256Hash h1, h2;
  crypto::Sha256Hash::evercrypt_sha256({data}, h1.h);
  crypto::Sha256Hash::mbedtls_sha256({data}, h2.h);
  REQUIRE(h1 == h2);
}

TEST_CASE("EverCrypt SHA256 no-collision check")
{
  std::vector<uint8_t> data1 = {'a', 'b', 'c', '\n'};
  std::vector<uint8_t> data2 = {'a', 'b', 'd', '\n'};
  crypto::Sha256Hash h1, h2;
  crypto::Sha256Hash::evercrypt_sha256({data1}, h1.h);
  crypto::Sha256Hash::evercrypt_sha256({data2}, h2.h);
  REQUIRE(h1 != h2);
}

TEST_CASE("Public key encryption")
{
  // Manually generated x25519 key pairs
  // One could use EverCrypt_Curve25519_secret_to_public() for key generation
  // too but members will generate their encryption from the command line.
  auto sender_sk_raw =
    tls::raw_from_b64("0FQphYDQwrdJIvkFJtiNyTQ277WlvZIgl8y5oCRBJFA=");
  auto sender_pk_raw =
    tls::raw_from_b64("DbnWc4wF8k2C2DqGvK3YEcF2hfivIJTHBcHYRfzSnDA=");
  auto recipient_sk_raw =
    tls::raw_from_b64("CMRbAAokc9fcEClWRn5CKK4tGWsCPvseUA6x4Ncdw3w=");
  auto recipient_pk_raw =
    tls::raw_from_b64("wHMY7N74MlAkGJlk+DGsbHarQ+f9dr0WmDZ0UsE4wB0=");

  std::string plaintext = "This is a plaintext message to encrypt";
  auto plaintext_raw = std::vector<uint8_t>(plaintext.begin(), plaintext.end());
  crypto::BoxNonce nonce = {};

  auto cipher =
    crypto::Box::create(plaintext_raw, nonce, recipient_pk_raw, sender_sk_raw);
  auto decrypted =
    crypto::Box::open(cipher, nonce, sender_pk_raw, recipient_sk_raw);
  REQUIRE(decrypted == plaintext_raw);

  INFO("Cipher too short");
  {
    REQUIRE_THROWS_AS(
      crypto::Box::open({}, nonce, sender_pk_raw, recipient_sk_raw),
      std::logic_error);
  }
}