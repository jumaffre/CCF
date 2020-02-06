// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"

extern "C"
{
#include "tls/randombytes.h"

#include <sss/sss.h>
}

#include <array>
#include <vector>

namespace ccf
{
  class SecretSharingContext
  {
  private:
    using share_t = uint8_t; // TODO: Better name for this

    // std::array<sss_Share, > shares;

  public:
    // SecretSharingContext(share_t n) : shares(n)
    // {
    //   // LOG_FAIL_FMT("SS Context: {}", n);
    // }

    // bool create_shares(std::vector<uint8_t> data_to_split, share_t n, share_t
    // k)
    // {
    //   // sss_create_shares(shares, data_to_split_raw.data(), n, k);
    // }

    // bool add_share(std::vector<uint8_t> share) {}

    // bool combine_shares() {}
  };
}

// std::cout << "so far" << std::endl;

// // TODO: Let's write some keyshare stuff here, and see if it works
// sss_Share shares[5];
// // uint8_t data[sss_MLEN];
// // uint8_t restored[sss_MLEN];

// std::string data_to_split = "Hello There1";
// auto data_to_split_raw =
//   std::vector<uint8_t>(data_to_split.begin(), data_to_split.end());
// auto data_restored = std::vector<uint8_t>(data_to_split_raw.size());

// std::cout << "so far2" << std::endl;

// sss_create_shares(shares, data_to_split_raw.data(), 5, 4);
// std::cout << "so far3" << std::endl;

// assert(sss_combine_shares(data_restored.data(), shares, 4) == 0);

// assert(memcmp(data_restored.data(), data_to_split_raw.data(), sss_MLEN) ==
// 0); std::cout << "Shares created and combined: success" << std::endl;
