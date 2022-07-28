#include "ccf/crypto/base64.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/logger.h"
#include "crypto/ecdsa.h"
#include "ds/std_formatters.h"

// SEV Secure Nested Paging Firmware ABI Specification
// https://www.amd.com/system/files/TechDocs/56860.pdf

// Table 3.
union tcb_version
{
  struct
  {
    uint8_t boot_loader;
    uint8_t tee;
    uint8_t reserved[4];
    uint8_t snp;
    uint8_t microcode;
  };
  uint64_t raw;
};

// Table 107.
static constexpr size_t ecdsa_point_size_bytes = 72;
struct signature
{
  uint8_t r[ecdsa_point_size_bytes];
  uint8_t s[ecdsa_point_size_bytes];
  uint8_t reserved[512 - 2 * ecdsa_point_size_bytes];
};

// Table. 105
enum class signature_algo_t : uint32_t
{
  invalid = 0,
  ecdsa_p384_sha384 = 1
};

// Table 21.
struct attestation_report
{
  uint32_t version;
  uint32_t guest_svn;
  uint64_t policy;
  uint8_t family_id[16];
  uint8_t image_id[16];
  uint32_t vmpl;
  signature_algo_t signature_algo;
  union tcb_version platform_version;
  uint64_t platform_info;
  uint32_t flags;
  uint32_t reserved0;
  uint8_t report_data[64];
  uint8_t measurement[48];
  uint8_t host_data[32];
  uint8_t id_key_digest[48];
  uint8_t author_key_digest[48];
  uint8_t report_id[32];
  uint8_t report_id_ma[32];
  union tcb_version reported_tcb;
  uint8_t reserved1[24];
  uint8_t chip_id[64];
  union tcb_version committed_tcb;
  uint8_t current_build;
  uint8_t current_minor;
  uint8_t current_major;
  uint8_t reserved2;
  uint8_t committed_build;
  uint8_t committed_minor;
  uint8_t committed_major;
  uint8_t reserved;
  union tcb_version launch_tcb;
  uint8_t reserved3[168];
  struct signature signature; /* 0x2A0 */
};

int main(int argc, char** argv)
{
  logger::config::default_init();

  std::string raw_quote_b64 =
    "AgAAAAIAAAAfAAMAAAAAAAEAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAEAAA"
    "ACAAAAAAAGXQEAAAAAAAAAAAAAAAAAAABCZJkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7egmiApOGkGJipaBDvsJ8gcFE6uzVe"
    "iWUlZM0Y8dQ6egMdH/"
    "VEkNvWFofeEBtm7Rq2zP6m6MnGIzsaRjHP1kQOz5EGlLNNfpLgI2c4dYgx7Jd7YxN5Mm9yaAsd"
    "voZmL6aQJIUWkv0us4lpcXm8svL3wLfrV2ayYju9fliLMU7TsAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACSqiGiawWqyOwubXda0D58i2rQqGHLu+"
    "8uferTJhVX+P//////////////////////////////////////////"
    "AgAAAAAABl0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADWiwAoyZ2EZNIhIgbsDvLuUxZFJQ2I6/"
    "oqd/"
    "QYdiK1vwqSmmQtHezwb9hq30jiK033Oe8EF2wMxB6FN4RHDBe8AgAAAAAABl0BMwEAATMBAAIA"
    "AAAAAAZdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAUJ1hNgDen1e1N8F4veFTCUmzWO2bj+rDxwEyBGJWykOZqIoSPQh2FgWMw/"
    "sRamP2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALdQd0wGm5vmzga4m6dx3ZYXAlmhxa0vr+"
    "bZT97ypsT3t0kYbm/"
    "XbX0BXynK8j81QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAA=";

  auto raw_quote = crypto::raw_from_b64(raw_quote_b64);
  LOG_INFO_FMT("Quote size: {}", raw_quote.size());

  attestation_report quote =
    *reinterpret_cast<attestation_report*>(raw_quote.data());

  LOG_INFO_FMT("Reported TCB: {}", quote.reported_tcb.raw);

  // 1. Retrieve VCEK certificate

  auto url_chip_id = fmt::format("{:02x}", fmt::join(quote.chip_id, ""));
  LOG_INFO_FMT("Url chip id: {}", url_chip_id);

  auto url_reported_tcb_buffer = fmt::format("{:0x}", quote.reported_tcb.raw);
  LOG_INFO_FMT("Url reported TCB: {}", url_reported_tcb_buffer);

  // TODO:
  // 1. This URL should be configurable via node configuration here:
  // https://microsoft.github.io/CCF/main/operations/configuration.html
  // 2. Also support extended guest report? (see
  // https://developer.amd.com/wp-content/resources/56421.pdf 4.1.8)
  // 3. Also support AMD server (see
  // https://www.amd.com/system/files/TechDocs/57230.pdf).

  auto url = fmt::format(
    "https://americas.test.acccache.azure.net/SevSnpVM/certificates/{}/"
    "{}?api-version=2020-10-15-preview",
    url_chip_id,
    url_reported_tcb_buffer);
  LOG_INFO_FMT("VECK certificate URL: {}", url);

  // Note: VECK is first certificate, ASK second, ARK last.
  auto curl_response_body = R"(-----BEGIN CERTIFICATE-----
MIIFTDCCAvugAwIBAgIBADBGBgkqhkiG9w0BAQowOaAPMA0GCWCGSAFlAwQCAgUA
oRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAgUAogMCATCjAwIBATB7MRQwEgYD
VQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDASBgNVBAcMC1NhbnRhIENs
YXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5jZWQgTWljcm8gRGV2aWNl
czESMBAGA1UEAwwJU0VWLU1pbGFuMB4XDTIyMDUyMDIyNTIyN1oXDTI5MDUyMDIy
NTIyN1owejEUMBIGA1UECwwLRW5naW5lZXJpbmcxCzAJBgNVBAYTAlVTMRQwEgYD
VQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExHzAdBgNVBAoMFkFkdmFuY2Vk
IE1pY3JvIERldmljZXMxETAPBgNVBAMMCFNFVi1WQ0VLMHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAE7ZlvMpQknEomxM6fzhOTsT+gP13kyRrAhLeHcumpKpNJO7kwBsmW
KBnn48G0LdbYk9vcQa7oFlUTXlJnwFdYflNsnxq5/D6jtITCDw6LwZqo/kKCcTLy
iJdG6zoA/PXio4IBFjCCARIwEAYJKwYBBAGceAEBBAMCAQAwFwYJKwYBBAGceAEC
BAoWCE1pbGFuLUIwMBEGCisGAQQBnHgBAwEEAwIBAjARBgorBgEEAZx4AQMCBAMC
AQAwEQYKKwYBBAGceAEDBAQDAgEAMBEGCisGAQQBnHgBAwUEAwIBADARBgorBgEE
AZx4AQMGBAMCAQAwEQYKKwYBBAGceAEDBwQDAgEAMBEGCisGAQQBnHgBAwMEAwIB
BjARBgorBgEEAZx4AQMIBAMCAV0wTQYJKwYBBAGceAEEBEDWiwAoyZ2EZNIhIgbs
DvLuUxZFJQ2I6/oqd/QYdiK1vwqSmmQtHezwb9hq30jiK033Oe8EF2wMxB6FN4RH
DBe8MEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0B
AQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBA4ICAQAj6LDorCibD4xmxZpbRAsW
dL12O2/KrKE432vc3OXbqNz1weV2CTnJTIZX3a8e1fFHm/J6o2v9bR+LLaWEFhyT
HNkNM3fS4MuEKTJuT5ePL73OUwi8a/DOF+YNaCt8DIXgoIfs5P/2lxy5G0889w+i
lhBWlru4rbmoP3zJG09JOzX6RQEVJ9DhfTdfiELYwRAtIxiPL9Kouy1dmn/JNuRy
AVf+btb8DwosmyU86+luyOenzJv5cF5ZXIiWTaUhm4sgPDoQ9ey9BDEdR25lQWcK
J7SZfGSQeM9Et/BayI+cDlMmtuey2htnwa1biXMlloDpu7TXAZQJ3cfedNS7rLVb
wEM24rQdYBSfVYdpyEsnFy5vMfVErbsh5m4U9p0OTG3Ymp+R/Ffd5e+CAjIHWkNn
/7bWtwcF0FkA8XvIHSRaJl+iOMP/x94DzXQN4VTY5vCcYEo+5qbmS40o/6U4wL/K
dmjkDK7rk5SU4veQkZmnnXFzG26f5RBiJSMK4PDHo93Y1P96taRmwkSJm8UekJhp
IgVk+2sXo38miztaco3PiFUD75A3CM46XOL9D8PKyNT2/bMdvhn59oo7eTvkZfJV
dMdjGSzumye9BggNy7kwUShq+W3jejToKiBbRvZr8dm7ESxKRm3+QzhPpE558tIO
bbecaQXTkKlUAP3ftmUgTA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIGYzCCBBKgAwIBAgIDAQAAMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAIC
BQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBMHsxFDAS
BgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEg
Q2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZp
Y2VzMRIwEAYDVQQDDAlBUkstTWlsYW4wHhcNMjAxMDIyMTcyMzA1WhcNNDUxMDIy
MTcyMzA1WjB7MRQwEgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDAS
BgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5j
ZWQgTWljcm8gRGV2aWNlczESMBAGA1UEAwwJQVJLLU1pbGFuMIICIjANBgkqhkiG
9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsVmD7FktuotWwX1fNg
W41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU0V5tkKiU1EesNFta
1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S1ju8X93+6dxDUrG2
SzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI52Naz5m2B+O+vjsC0
60d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3KFYXP59XmJgtcog05
gmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd/y8KxX7jksTEzAOg
bKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBkgnlENEWx1UcbQQrs
+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V9TJQqnN3Q53kt5vi
Qi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnqz55I0u33wh4r0ZNQ
eTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+OgpCCoMNit2uLo9M18
fHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXoQPHfbkH0CyPfhl1j
WhJFZasCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSFrBrRQ/fI
rFXUxR1BSKvVeErUUzAPBgNVHRMBAf8EBTADAQH/MDoGA1UdHwQzMDEwL6AtoCuG
KWh0dHBzOi8va2RzaW50Zi5hbWQuY29tL3ZjZWsvdjEvTWlsYW4vY3JsMEYGCSqG
SIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZI
AWUDBAICBQCiAwIBMKMDAgEBA4ICAQC6m0kDp6zv4Ojfgy+zleehsx6ol0ocgVel
ETobpx+EuCsqVFRPK1jZ1sp/lyd9+0fQ0r66n7kagRk4Ca39g66WGTJMeJdqYriw
STjjDCKVPSesWXYPVAyDhmP5n2v+BYipZWhpvqpaiO+EGK5IBP+578QeW/sSokrK
dHaLAxG2LhZxj9aF73fqC7OAJZ5aPonw4RE299FVarh1Tx2eT3wSgkDgutCTB1Yq
zT5DuwvAe+co2CIVIzMDamYuSFjPN0BCgojl7V+bTou7dMsqIu/TW/rPCX9/EUcp
KGKqPQ3P+N9r1hjEFY1plBg93t53OOo49GNI+V1zvXPLI6xIFVsh+mto2RtgEX/e
pmMKTNN6psW88qg7c1hTWtN6MbRuQ0vm+O+/2tKBF2h8THb94OvvHHoFDpbCELlq
HnIYhxy0YKXGyaW1NjfULxrrmxVW4wcn5E8GddmvNa6yYm8scJagEi13mhGu4Jqh
3QU3sf8iUSUr09xQDwHtOQUVIqx4maBZPBtSMf+qUDtjXSSq8lfWcd8bLr9mdsUn
JZJ0+tuPMKmBnSH860llKk+VpVQsgqbzDIvOLvD6W1Umq25boxCYJ+TuBoa4s+HH
CViAvgT9kf/rBq1d+ivj6skkHxuzcxbk1xv6ZGxrteJxVH7KlX7YRdZ6eARKwLe4
AFZEAwoKCQ==
-----END CERTIFICATE-----)";

  auto certificates = crypto::split_x509_cert_bundle(curl_response_body);

  // Verify endorsements
  // TODO: To find in spec
  constexpr auto amd_root_signing_key_public = R"(-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsV
mD7FktuotWwX1fNgW41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU
0V5tkKiU1EesNFta1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S
1ju8X93+6dxDUrG2SzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI5
2Naz5m2B+O+vjsC060d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3K
FYXP59XmJgtcog05gmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd
/y8KxX7jksTEzAOgbKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBk
gnlENEWx1UcbQQrs+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V
9TJQqnN3Q53kt5viQi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnq
z55I0u33wh4r0ZNQeTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+Og
pCCoMNit2uLo9M18fHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXo
QPHfbkH0CyPfhl1jWhJFZasCAwEAAQ==
-----END PUBLIC KEY-----
)";

  auto actual_amd_root_verifier =
    crypto::make_verifier(crypto::Pem(certificates[2]));
  if (
    actual_amd_root_verifier->public_key_pem() !=
    crypto::Pem(amd_root_signing_key_public))
  {
    LOG_FAIL_FMT("AMD root signing public key is not as expected");
    return 1;
  }

  // Verify that root certificate is self-signed
  if (!actual_amd_root_verifier->verify_certificate({&certificates[2]}))
  {
    LOG_FAIL_FMT("AMD root sigining public key certificate is not self-signed");
    return 1;
  }

  auto vcek_verifier = crypto::make_verifier(crypto::Pem(certificates[0]));
  if (!vcek_verifier->verify_certificate(
        {&certificates[2]}, {&certificates[1]}))
  {
    LOG_FAIL_FMT("VCEK endorsement verification failed!");
    return 1;
  }

  auto& sig = quote.signature;
  auto& sig_algo = quote.signature_algo;

  // Make ASN1 der signature
  auto sig_ = crypto::ecdsa_sig_from_r_s(
    sig.r, sizeof(sig.r), sig.s, sizeof(sig.s), false /* little endian */);

  std::vector<uint8_t> tbs = {raw_quote.begin(), raw_quote.end() - sizeof(sig)};

  if (quote.signature_algo != signature_algo_t::ecdsa_p384_sha384)
  {
    LOG_FAIL_FMT(
      "Unsupported signature algorithm: {} (supported: {})",
      quote.signature_algo,
      signature_algo_t::ecdsa_p384_sha384);
    return 1;
  }

  if (!vcek_verifier->verify(tbs, sig_))
  {
    LOG_FAIL_FMT("Signature verification failed!");
    return 1;
  }
  LOG_INFO_FMT("Signature successfully verified!");
}